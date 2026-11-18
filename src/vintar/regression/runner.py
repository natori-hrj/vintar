"""Policy-constrained execution of security regression cases."""

import math
import re
from dataclasses import dataclass
from enum import StrEnum

import httpx

from vintar.checks.sqli.models import Verdict, VerificationResult
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import ScopePolicy, validate_scope
from vintar.core.template import validate_template
from vintar.regression.cases import RegressionCase

_CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


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
        if type(self.expectation_match) is not bool:
            raise TypeError("Invalid expectation match.")
        if not isinstance(self.status, RegressionStatus):
            raise TypeError("Invalid regression status.")

        if self.verification.check_id != self.case_id:
            raise ValueError("Verification case identifier mismatch.")

        match = self.verification.verdict is self.expected_verdict

        if self.expectation_match != match:
            raise ValueError("Inconsistent expectation match.")

        if self.status is not _classify(self.verification.verdict, match):
            raise ValueError("Inconsistent regression status.")


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
    case: RegressionCase,
    policy: TrustedExecutionPolicy,
) -> ScopePolicy:
    """Preflight the complete probe plan without sending HTTP."""
    if not isinstance(case, RegressionCase):
        raise TypeError("case must be a RegressionCase.")
    if not isinstance(policy, TrustedExecutionPolicy):
        raise TypeError("policy must be a TrustedExecutionPolicy.")

    allowed = case.scope.allowed_origins & policy.scope.allowed_origins

    if not allowed:
        raise ValueError("Case is outside the trusted execution scope.")

    scope = ScopePolicy(allowed_origins=frozenset(allowed))

    templates = (
        case.template,
        inject(case.template, case.point, case.true_payload),
        inject(case.template, case.point, case.false_payload),
    )

    if (
        templates[0] == templates[1]
        or templates[0] == templates[2]
        or templates[1] == templates[2]
    ):
        raise ValueError("Invalid regression probe plan.")

    for template in templates:
        validate_template(template)
        validate_scope(template.url, scope)

    return scope


def _run_with_resources(
    case: RegressionCase,
    *,
    policy: TrustedExecutionPolicy,
    budget: RequestBudget,
    rate_limiter: RateLimiter,
    transport: httpx.BaseTransport | None = None,
    scope: ScopePolicy | None = None,
) -> RegressionOutcome:
    """Internal execution path for single-case and batch runners."""
    effective_scope = scope if scope is not None else _effective_scope(case, policy)

    context = ExecutionContext(
        scope=effective_scope,
        budget=budget,
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

    verification = verify_boolean_sqli(
        check_id=case.case_id,
        template=case.template,
        point=case.point,
        true_payload=case.true_payload,
        false_payload=case.false_payload,
        context=context,
        transport=transport,
    )

    expectation_match = verification.verdict is case.expected_verdict

    return RegressionOutcome(
        case_id=case.case_id,
        expected_verdict=case.expected_verdict,
        verification=verification,
        expectation_match=expectation_match,
        status=_classify(
            verification.verdict,
            expectation_match,
        ),
    )


def run_regression_case(
    case: RegressionCase,
    *,
    policy: TrustedExecutionPolicy,
    transport: httpx.BaseTransport | None = None,
) -> RegressionOutcome:
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
