"""Policy-constrained execution of security regression cases."""

import math
import re
from dataclasses import dataclass
from enum import StrEnum

import httpx

from vintar.checks.sqli.confirmation_runner import (
    ConfirmationOutcome,
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.error_contract import error_product_result
from vintar.checks.sqli.error_runner import (
    ERROR_REQUESTS,
    ErrorRunReport,
    verify_error_based_sqli,
)
from vintar.checks.sqli.models import Verdict, VerificationResult
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.checks.sqli.time_contract import time_product_result
from vintar.checks.sqli.time_plan import TIME_REQUESTS, TimePayloads
from vintar.checks.sqli.time_runner import TimeRunReport, verify_time_based_sqli
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import ScopePolicy, validate_scope
from vintar.core.template import validate_template
from vintar.regression.cases import (
    AnyRegressionCase,
    BooleanRegressionCase,
    ErrorRegressionCase,
    TimeRegressionCase,
)
from vintar.regression.errors import BatchRequestBudgetError

_CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class TimeExecutionPolicyError(ValueError):
    """A trusted time policy cannot execute a reviewed case safely."""


class TimeRequestBudgetError(ValueError):
    """The shared budget cannot grant a fresh time-case budget safely."""


@dataclass(frozen=True, slots=True, repr=False)
class TrustedExecutionPolicy:
    """Trusted limits supplied independently of regression cases.

    Never derive this policy from an untrusted case or pull request.
    Scope is origin-based, not DNS-resolved-IP-based. Use network-level
    egress controls for untrusted targets.

    max_requests applies to one run_regression_case call, or to an
    entire run_regression_batch call when used as a batch policy.
    """

    scope: ScopePolicy
    max_requests: int = 6
    max_requests_per_second: float = 2.0
    max_timeout_seconds: float = 10.0
    max_response_size: int = 1_048_576
    max_time_execution_seconds: float = 45.0

    def __post_init__(self) -> None:
        if not isinstance(self.scope, ScopePolicy):
            raise TypeError("scope must be a ScopePolicy.")

        if type(self.max_requests) is not int or self.max_requests <= 0:
            raise ValueError("Invalid trusted request budget.")

        if type(self.max_response_size) is not int or self.max_response_size <= 0:
            raise ValueError("Invalid trusted response size limit.")

        for name, minimum, maximum, minimum_inclusive in (
            ("max_requests_per_second", 0.1, 10.0, True),
            ("max_timeout_seconds", 0.0, 60.0, False),
            ("max_time_execution_seconds", 0.0, 120.0, False),
        ):
            value = getattr(self, name)

            if type(value) not in (int, float):
                raise ValueError("Invalid trusted execution limit.")

            valid_lower = value >= minimum if minimum_inclusive else value > minimum
            if not valid_lower or value > maximum:
                raise ValueError("Invalid trusted execution limit.")

            normalized = float(value)
            if not math.isfinite(normalized):
                raise ValueError("Invalid trusted execution limit.")

            object.__setattr__(self, name, normalized)


class RegressionStatus(StrEnum):
    """Security-gate result, independent of expected-verdict matching.

    PASS means only that the expected NOT_DETECTED verdict was observed for
    this check. It is not proof that the target is free of vulnerabilities.
    Vulnerable fixtures use expectation_match for detector evaluation while
    their security-gate status remains FAIL.
    """

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True, repr=False)
class RegressionOutcome:
    """Observed verdict, expectation match, and security-gate result."""

    case_id: str
    expected_verdict: Verdict
    verification: VerificationResult
    expectation_match: bool
    status: RegressionStatus
    confirmation: ConfirmationOutcome | None = None

    def __post_init__(self) -> None:
        if (
            type(self.case_id) is not str
            or _CASE_ID_PATTERN.fullmatch(self.case_id) is None
        ):
            raise ValueError("Invalid case identifier.")

        if not isinstance(self.expected_verdict, Verdict):
            raise TypeError("Invalid expected verdict.")
        if not isinstance(self.verification, VerificationResult):
            raise TypeError("Invalid verification result.")
        if (
            self.confirmation is not None
            and type(self.confirmation) is not ConfirmationOutcome
        ):
            raise TypeError("Invalid confirmation result.")
        if (
            self.confirmation is not None
            and self.confirmation.initial != self.verification
        ):
            raise ValueError("Confirmation initial result mismatch.")
        if type(self.expectation_match) is not bool:
            raise TypeError("Invalid expectation match.")
        if not isinstance(self.status, RegressionStatus):
            raise TypeError("Invalid regression status.")

        if self.verification.check_id != self.case_id:
            raise ValueError("Verification case identifier mismatch.")

        match = self.final_verdict is self.expected_verdict

        if self.expectation_match != match:
            raise ValueError("Inconsistent expectation match.")

        if self.status is not _classify(self.final_verdict, match):
            raise ValueError("Inconsistent regression status.")

    @property
    def final_verdict(self) -> Verdict:
        if (
            self.confirmation is None
            or self.confirmation.status is ConfirmationStatus.SKIPPED
        ):
            return self.verification.verdict
        return Verdict.INCONCLUSIVE

    @property
    def final_reason_code(self) -> str:
        if (
            self.confirmation is None
            or self.confirmation.status is ConfirmationStatus.SKIPPED
        ):
            return self.verification.reason_code
        if self.confirmation.status is ConfirmationStatus.CANDIDATE:
            return "boolean_candidate"
        return self.confirmation.reason_code

    @property
    def request_count(self) -> int:
        if self.confirmation is None:
            return self.verification.request_count
        return self.confirmation.total_requests


@dataclass(frozen=True, slots=True, repr=False)
class TimeRegressionOutcome:
    """Observed result for one time-based regression case."""

    case_id: str
    expected_verdict: Verdict
    time_run: TimeRunReport
    expectation_match: bool
    status: RegressionStatus

    def __post_init__(self) -> None:
        if (
            type(self.case_id) is not str
            or _CASE_ID_PATTERN.fullmatch(self.case_id) is None
        ):
            raise ValueError("Invalid case identifier.")
        if not isinstance(self.expected_verdict, Verdict):
            raise TypeError("Invalid expected verdict.")
        if type(self.time_run) is not TimeRunReport:
            raise TypeError("Invalid time run result.")
        if type(self.expectation_match) is not bool:
            raise TypeError("Invalid expectation match.")
        if not isinstance(self.status, RegressionStatus):
            raise TypeError("Invalid regression status.")
        match = self.final_verdict is self.expected_verdict
        if self.expectation_match != match:
            raise ValueError("Inconsistent expectation match.")
        if self.status is not _classify(self.final_verdict, match):
            raise ValueError("Inconsistent regression status.")

    @property
    def final_verdict(self) -> Verdict:
        return time_product_result(self.time_run.analysis).verdict

    @property
    def final_reason_code(self) -> str:
        return time_product_result(self.time_run.analysis).reason_code

    @property
    def request_count(self) -> int:
        return time_product_result(self.time_run.analysis).request_count


@dataclass(frozen=True, slots=True, repr=False)
class ErrorRegressionOutcome:
    """Observed result for one error-signature regression case."""

    case_id: str
    expected_verdict: Verdict
    error_run: ErrorRunReport
    expectation_match: bool
    status: RegressionStatus

    def __post_init__(self) -> None:
        if (
            type(self.case_id) is not str
            or _CASE_ID_PATTERN.fullmatch(self.case_id) is None
        ):
            raise ValueError("Invalid case identifier.")
        if not isinstance(self.expected_verdict, Verdict):
            raise TypeError("Invalid expected verdict.")
        if type(self.error_run) is not ErrorRunReport:
            raise TypeError("Invalid error run result.")
        if type(self.expectation_match) is not bool:
            raise TypeError("Invalid expectation match.")
        if not isinstance(self.status, RegressionStatus):
            raise TypeError("Invalid regression status.")
        match = self.final_verdict is self.expected_verdict
        if self.expectation_match != match:
            raise ValueError("Inconsistent expectation match.")
        if self.status is not _classify(self.final_verdict, match):
            raise ValueError("Inconsistent regression status.")

    @property
    def final_verdict(self) -> Verdict:
        return error_product_result(self.error_run.analysis).verdict

    @property
    def final_reason_code(self) -> str:
        return error_product_result(self.error_run.analysis).reason_code

    @property
    def request_count(self) -> int:
        return error_product_result(self.error_run.analysis).request_count


AnyRegressionOutcome = (
    RegressionOutcome | TimeRegressionOutcome | ErrorRegressionOutcome
)


def _classify(
    actual: Verdict,
    expectation_match: bool,
) -> RegressionStatus:
    """An inconclusive or vulnerable verdict never passes the gate."""
    if actual is Verdict.INCONCLUSIVE:
        return RegressionStatus.INCONCLUSIVE

    if actual is Verdict.VULNERABLE:
        return RegressionStatus.FAIL

    if actual is Verdict.NOT_DETECTED and expectation_match:
        return RegressionStatus.PASS

    return RegressionStatus.FAIL


def _effective_scope(
    case: AnyRegressionCase,
    policy: TrustedExecutionPolicy,
) -> ScopePolicy:
    """Preflight the complete probe plan without sending HTTP."""
    if not isinstance(case, AnyRegressionCase):
        raise TypeError("case must be a RegressionCase.")
    if not isinstance(policy, TrustedExecutionPolicy):
        raise TypeError("policy must be a TrustedExecutionPolicy.")

    allowed = case.scope.allowed_origins & policy.scope.allowed_origins

    if not allowed:
        raise ValueError("Case is outside the trusted execution scope.")

    scope = ScopePolicy(allowed_origins=frozenset(allowed))

    if isinstance(case, BooleanRegressionCase):
        templates = [
            case.template,
            inject(case.template, case.point, case.true_payload),
            inject(case.template, case.point, case.false_payload),
        ]
    elif isinstance(case, TimeRegressionCase):
        templates = [
            case.template,
            inject(case.template, case.point, case.control_payload),
            inject(case.template, case.point, case.delay_payload),
        ]
    else:
        templates = [
            case.template,
            inject(case.template, case.point, case.error_payload),
        ]
    if isinstance(case, BooleanRegressionCase) and case.confirmation is not None:
        templates.extend(
            (
                inject(case.template, case.point, case.confirmation.true_payload),
                inject(case.template, case.point, case.confirmation.false_payload),
                inject(
                    case.template,
                    case.point,
                    case.confirmation.baseline_preserving_control,
                ),
            )
        )

    if len(set(templates)) != len(templates):
        raise ValueError("Invalid regression probe plan.")

    for template in templates:
        validate_template(template)
        validate_scope(template.url, scope)

    if isinstance(case, TimeRegressionCase):
        effective_rate = min(case.requests_per_second, policy.max_requests_per_second)
        effective_timeout = min(case.timeout_seconds, policy.max_timeout_seconds)
        if effective_timeout < case.expected_delay_seconds + 0.5:
            raise ValueError(
                "Trusted timeout is too short for the time case. Increase max_timeout_seconds to at least expected_delay_seconds + 0.5, or use a smaller reviewed delay."
            )
        minimum_window = (
            TIME_REQUESTS * effective_timeout + (TIME_REQUESTS - 1) / effective_rate
        )
        if minimum_window > policy.max_time_execution_seconds:
            raise TimeExecutionPolicyError(
                "Trusted time execution deadline cannot accommodate the case timeout and request rate. Increase max_time_execution_seconds, increase the trusted request rate, or use a shorter valid timeout."
            )

    return scope


def _run_with_resources(
    case: AnyRegressionCase,
    *,
    policy: TrustedExecutionPolicy,
    budget: RequestBudget,
    rate_limiter: RateLimiter,
    transport: httpx.BaseTransport | None = None,
    scope: ScopePolicy | None = None,
) -> AnyRegressionOutcome:
    """Internal execution path for single-case and batch runners."""
    effective_scope = scope if scope is not None else _effective_scope(case, policy)

    if isinstance(case, TimeRegressionCase) and budget.remaining < TIME_REQUESTS:
        raise TimeRequestBudgetError(
            "Trusted batch request budget has fewer than nine requests remaining for the time case. Increase policy.max_requests to cover every selected case, or run fewer cases."
        )

    if isinstance(case, ErrorRegressionCase) and budget.remaining < ERROR_REQUESTS:
        raise BatchRequestBudgetError(
            "Trusted batch request budget has fewer than four requests remaining for the error case. Increase policy.max_requests to cover every selected case, or run fewer cases."
        )

    execution_budget = (
        RequestBudget(TIME_REQUESTS) if isinstance(case, TimeRegressionCase) else budget
    )
    context = ExecutionContext(
        scope=effective_scope,
        budget=execution_budget,
        timeout=min(
            case.timeout_seconds,
            policy.max_timeout_seconds,
        ),
        max_response_size=min(
            case.max_response_size,
            policy.max_response_size,
        ),
        rate_limiter=rate_limiter,
    )

    if isinstance(case, TimeRegressionCase):
        time_run = verify_time_based_sqli(
            template=case.template,
            point=case.point,
            payloads=TimePayloads(
                delay=case.delay_payload,
                control=case.control_payload,
            ),
            expected_delay_seconds=case.expected_delay_seconds,
            context=context,
            max_total_seconds=policy.max_time_execution_seconds,
            transport=transport,
        )
        for _ in range(time_run.budget_used):
            budget.consume()
        product = time_product_result(time_run.analysis)
        expectation_match = product.verdict is case.expected_verdict
        return TimeRegressionOutcome(
            case_id=case.case_id,
            expected_verdict=case.expected_verdict,
            time_run=time_run,
            expectation_match=expectation_match,
            status=_classify(product.verdict, expectation_match),
        )

    if isinstance(case, ErrorRegressionCase):
        error_run = verify_error_based_sqli(
            template=case.template,
            point=case.point,
            error_payload=case.error_payload,
            context=context,
            transport=transport,
        )
        error_product = error_product_result(error_run.analysis)
        expectation_match = error_product.verdict is case.expected_verdict
        return ErrorRegressionOutcome(
            case_id=case.case_id,
            expected_verdict=case.expected_verdict,
            error_run=error_run,
            expectation_match=expectation_match,
            status=_classify(error_product.verdict, expectation_match),
        )

    confirmation: ConfirmationOutcome | None = None
    if case.confirmation is None:
        verification = verify_boolean_sqli(
            check_id=case.case_id,
            template=case.template,
            point=case.point,
            true_payload=case.true_payload,
            false_payload=case.false_payload,
            context=context,
            transport=transport,
        )
        final_verdict = verification.verdict
    else:
        confirmation = verify_boolean_sqli_with_confirmation(
            check_id=case.case_id,
            template=case.template,
            point=case.point,
            true_1=case.true_payload,
            false_1=case.false_payload,
            true_2=case.confirmation.true_payload,
            false_2=case.confirmation.false_payload,
            baseline_preserving_control=case.confirmation.baseline_preserving_control,
            context=context,
            transport=transport,
        )
        verification = confirmation.initial
        final_verdict = (
            verification.verdict
            if confirmation.status is ConfirmationStatus.SKIPPED
            else Verdict.INCONCLUSIVE
        )

    expectation_match = final_verdict is case.expected_verdict

    return RegressionOutcome(
        case_id=case.case_id,
        expected_verdict=case.expected_verdict,
        verification=verification,
        expectation_match=expectation_match,
        status=_classify(
            final_verdict,
            expectation_match,
        ),
        confirmation=confirmation,
    )


def run_regression_case(
    case: AnyRegressionCase,
    *,
    policy: TrustedExecutionPolicy,
    transport: httpx.BaseTransport | None = None,
) -> AnyRegressionOutcome:
    """Execute one case within independent trusted limits.

    The policy must come from a trusted caller, not an untrusted case.
    Custom transports are trusted test dependencies only and must not be
    exposed through configuration, Discovery, CI input, or LLM tools.

    For aggregate limits across multiple cases, use
    run_regression_batch instead.
    """
    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError("Invalid test transport.")

    scope = _effective_scope(case, policy)

    if policy.max_requests < case.max_requests:
        raise ValueError("Trusted request budget is insufficient.")

    return _run_with_resources(
        case,
        policy=policy,
        scope=scope,
        budget=RequestBudget(case.max_requests),
        rate_limiter=RateLimiter(
            requests_per_second=min(
                case.requests_per_second,
                policy.max_requests_per_second,
            )
        ),
        transport=transport,
    )
