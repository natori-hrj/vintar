"""Policy-constrained execution of security regression cases."""

import hashlib
import math
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast

import httpx

from vintar.auth.apply import (
    AuthenticatedTransport,
    AuthenticationError,
    AuthenticationPlan,
    CredentialBinding,
    PlannedAuthenticatedRequest,
    preflight_authentication,
    resolve_credentials,
)
from vintar.checks.sqli.confirmation_runner import (
    ConfirmationOutcome,
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.error_analyzer import ERROR_PROBE_ORDER
from vintar.checks.sqli.error_contract import error_product_result
from vintar.checks.sqli.error_runner import (
    ERROR_REQUESTS,
    ErrorRunReport,
    verify_error_based_sqli,
)
from vintar.checks.sqli.models import BOOLEAN_PROBE_ORDER, Verdict, VerificationResult
from vintar.checks.sqli.observation_sink import SqliObservationSink
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.checks.sqli.time_contract import time_product_result
from vintar.checks.sqli.time_plan import TIME_PROBE_ORDER, TIME_REQUESTS, TimePayloads
from vintar.checks.sqli.time_runner import TimeRunReport, verify_time_based_sqli
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.json_body import json_leaf_at
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy, validate_scope
from vintar.core.template import validate_template
from vintar.regression.cases import (
    AnyRegressionCase,
    BooleanRegressionCase,
    ErrorRegressionCase,
    TimeRegressionCase,
)
from vintar.regression.cases_v2 import PostJsonRegressionCase, QueryRegressionCaseV2
from vintar.regression.errors import BatchRequestBudgetError
from vintar.regression.post_json_policy import (
    PostJsonPolicyApproval,
    PostJsonRuntimePolicy,
)

_CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class TimeExecutionPolicyError(ValueError):
    """A trusted time policy cannot execute a reviewed case safely."""


class TimeRequestBudgetError(ValueError):
    """The shared budget cannot grant a fresh time-case budget safely."""


class PostJsonExecutionError(ValueError):
    """A stable, redacted trusted POST execution rejection."""


@dataclass(frozen=True, slots=True)
class BatchExecutionSchedule:
    """Shared batch rate and conservative wall-clock execution bound."""

    requests_per_second: float
    planned_max_run_seconds: float


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
    post_json_policy: PostJsonRuntimePolicy | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scope, ScopePolicy):
            raise TypeError("scope must be a ScopePolicy.")
        if self.post_json_policy is not None and not isinstance(
            self.post_json_policy, PostJsonRuntimePolicy
        ):
            raise TypeError("post_json_policy must be a PostJsonRuntimePolicy or None.")

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

        if self.post_json_policy is not None:
            limits = self.post_json_policy.limits
            object.__setattr__(
                self, "max_requests", min(self.max_requests, limits.max_requests)
            )
            object.__setattr__(
                self,
                "max_requests_per_second",
                min(self.max_requests_per_second, limits.max_requests_per_second),
            )
            object.__setattr__(
                self,
                "max_timeout_seconds",
                min(self.max_timeout_seconds, limits.max_timeout_seconds),
            )
            object.__setattr__(
                self,
                "max_response_size",
                min(self.max_response_size, limits.max_response_size),
            )
            object.__setattr__(
                self,
                "max_time_execution_seconds",
                min(
                    self.max_time_execution_seconds,
                    limits.max_time_execution_seconds,
                ),
            )


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
    *,
    requests_per_second: float,
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

    if isinstance(case, PostJsonRegressionCase):
        template, point, _ = _post_json_execution_inputs(case, policy)
        templates = [
            template,
            *(inject(template, point, probe) for probe in case.probes),
        ]
    elif isinstance(case, QueryRegressionCaseV2):
        template, point, _ = _query_v2_execution_inputs(case, policy)
        templates = [
            template,
            *(inject(template, point, probe) for probe in case.probes),
        ]
    elif isinstance(case, BooleanRegressionCase):
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

    if case.check_type == "sqli.time":
        time_case = cast(
            TimeRegressionCase | PostJsonRegressionCase | QueryRegressionCaseV2,
            case,
        )
        effective_timeout = min(time_case.timeout_seconds, policy.max_timeout_seconds)
        expected_delay = time_case.expected_delay_seconds
        if expected_delay is None:
            raise ValueError("Time case requires an expected delay.")
        if effective_timeout < expected_delay + 0.5:
            raise ValueError(
                "Trusted timeout is too short for the time case. Increase max_timeout_seconds to at least expected_delay_seconds + 0.5, or use a smaller reviewed delay."
            )
        minimum_window = (
            TIME_REQUESTS * effective_timeout
            + (TIME_REQUESTS - 1) / requests_per_second
        )
        if minimum_window > policy.max_time_execution_seconds:
            raise TimeExecutionPolicyError(
                "Trusted time execution deadline cannot accommodate the case timeout and request rate. Increase max_time_execution_seconds, increase the trusted request rate, or use a shorter valid timeout."
            )

    return scope


def _post_json_error(code: str, reason: str, action: str) -> PostJsonExecutionError:
    return PostJsonExecutionError(f"{code}: {reason} {action}")


def _case_origin(case: PostJsonRegressionCase) -> AllowedOrigin:
    """Return the single origin guaranteed by validated Case Schema v2."""
    return next(iter(case.scope.allowed_origins))


def _post_json_approval(
    case: PostJsonRegressionCase, policy: TrustedExecutionPolicy
) -> PostJsonPolicyApproval:
    runtime_policy = policy.post_json_policy
    if runtime_policy is None:
        raise _post_json_error(
            "post_json_runtime_policy_required",
            "POST JSON execution has no trusted runtime policy.",
            "Supply a trusted runtime policy independently of the case and specification.",
        )
    origin = _case_origin(case)
    candidates = tuple(
        approval
        for approval in runtime_policy.approvals
        if approval.case_id == case.case_id and approval.identity_id == case.identity_id
    )
    if not candidates:
        raise _post_json_error(
            "post_json_case_not_approved",
            "The trusted runtime policy does not approve this case identifier.",
            "Add an exact operator-controlled approval or run a different reviewed case.",
        )
    matches = tuple(
        approval
        for approval in candidates
        if approval.method == case.approval.method
        and approval.path == case.approval.path
        and approval.origin == origin
    )
    if not matches:
        raise _post_json_error(
            "post_json_operation_not_approved",
            "The trusted runtime policy does not approve the exact POST operation and origin.",
            "Approve the bound origin and reviewed literal path in trusted operator configuration.",
        )
    approval = matches[0]
    if (
        case.approval.operation_definition_sha256
        != approval.operation_definition_sha256
    ):
        raise _post_json_error(
            "post_json_operation_integrity_mismatch",
            "The reviewed operation does not match the trusted approval.",
            "Review the current operation and update trusted policy independently.",
        )
    if case.approval.baseline_body_sha256 != approval.baseline_body_sha256:
        raise _post_json_error(
            "post_json_policy_baseline_mismatch",
            "The reviewed baseline does not match the trusted approval.",
            "Re-materialize the reviewed case and update trusted policy independently.",
        )
    if case.approval.environment_class not in approval.allowed_environment_classes:
        raise _post_json_error(
            "post_json_environment_not_approved",
            "The reviewed environment class is not allowed by the trusted policy.",
            "Approve that exact environment class or use a case reviewed for an allowed environment.",
        )
    if case.approval.side_effect != "no_side_effect":
        raise _post_json_error(
            "post_json_side_effect_not_allowed",
            "The reviewed POST operation is not classified as no_side_effect.",
            "Use a separately reviewed no_side_effect operation; mutation is not supported.",
        )
    return approval


def _post_json_execution_inputs(
    case: PostJsonRegressionCase, policy: TrustedExecutionPolicy
) -> tuple[RequestTemplate, InjectionPoint, PostJsonPolicyApproval]:
    """Re-check immutable integrity immediately before preparing a send plan."""
    approval = _post_json_approval(case, policy)
    digest = hashlib.sha256(case.json_body.to_bytes()).hexdigest()
    if (
        digest != case.approval.baseline_body_sha256
        or digest != approval.baseline_body_sha256
    ):
        raise _post_json_error(
            "post_json_baseline_integrity_mismatch",
            "The canonical baseline body no longer matches its reviewed and trusted digests.",
            "Re-materialize the case and approve its current baseline independently.",
        )
    try:
        selected = json_leaf_at(case.json_body, case.pointer)
    except (TypeError, ValueError):
        raise _post_json_error(
            "post_json_pointer_target_missing",
            "The reviewed JSON Pointer no longer selects an existing leaf.",
            "Re-materialize a case with one concrete existing JSON Pointer.",
        ) from None
    if type(selected) is not str:
        raise _post_json_error(
            "post_json_pointer_target_not_string",
            "The reviewed JSON Pointer no longer selects a string leaf.",
            "Re-materialize a case whose target is an existing JSON string.",
        )
    template = RequestTemplate(method="POST", url=case.url, json_body=case.json_body)
    point = InjectionPoint(
        location=InjectionLocation.JSON_BODY,
        mode=InjectionMode.REPLACE,
        pointer=case.pointer,
    )
    return template, point, approval


def _query_v2_execution_inputs(
    case: QueryRegressionCaseV2, policy: TrustedExecutionPolicy
) -> tuple[RequestTemplate, InjectionPoint, PostJsonPolicyApproval]:
    """Re-check the exact approved GET operation before planning probes."""
    runtime_policy = policy.post_json_policy
    if runtime_policy is None:
        raise _post_json_error(
            "post_json_runtime_policy_required",
            "Schema v2 GET execution has no trusted runtime policy.",
            "Supply a trusted runtime policy independently of the case.",
        )
    origin = next(iter(case.scope.allowed_origins))
    matches = tuple(
        approval
        for approval in runtime_policy.approvals
        if approval.case_id == case.case_id
        and approval.identity_id == case.identity_id
        and approval.method == "GET"
        and approval.path == httpx.URL(case.url).raw_path.decode("ascii")
        and approval.origin == origin
        and case.environment_class in approval.allowed_environment_classes
    )
    if len(matches) != 1:
        raise _post_json_error(
            "post_json_operation_not_approved",
            "The trusted runtime policy does not approve the exact GET operation, identity, environment, and origin.",
            "Approve the byte-preserved literal operation in trusted operator configuration.",
        )
    template = RequestTemplate(method="GET", url=case.url, params=case.params)
    point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name=case.injection_name,
        occurrence=case.injection_occurrence,
        mode=InjectionMode(case.injection_mode),
    )
    return template, point, matches[0]


def _v2_inputs(
    case: PostJsonRegressionCase | QueryRegressionCaseV2,
    policy: TrustedExecutionPolicy,
) -> tuple[RequestTemplate, InjectionPoint, PostJsonPolicyApproval]:
    if isinstance(case, PostJsonRegressionCase):
        return _post_json_execution_inputs(case, policy)
    return _query_v2_execution_inputs(case, policy)


def _v2_planned_templates(
    case: PostJsonRegressionCase | QueryRegressionCaseV2,
    template: RequestTemplate,
    point: InjectionPoint,
) -> tuple[RequestTemplate, ...]:
    probes = tuple(inject(template, point, probe) for probe in case.probes)
    if case.check_type == "sqli.boolean":
        by_kind = {"baseline": template, "true": probes[0], "false": probes[1]}
        return tuple(by_kind[kind.value] for kind in BOOLEAN_PROBE_ORDER)
    if case.check_type == "sqli.time":
        by_kind = {"baseline": template, "delay": probes[0], "control": probes[1]}
        return tuple(by_kind[kind.value] for kind in TIME_PROBE_ORDER)
    by_kind = {"baseline": template, "probe": probes[0]}
    return tuple(by_kind[kind.value] for kind in ERROR_PROBE_ORDER)


def _authentication_error(exc: AuthenticationError) -> PostJsonExecutionError:
    code = str(exc).partition(":")[0]
    return PostJsonExecutionError(
        f"{code}: Why: authenticated execution preflight failed. Instead: verify the trusted identity binding, exact origin, credential expiry, and protected environment variable."
    )


def _authentication_plan(
    cases: Sequence[AnyRegressionCase],
    policy: TrustedExecutionPolicy,
    *,
    planned_max_run_seconds: float,
) -> AuthenticationPlan | None:
    v2_cases = tuple(
        case
        for case in cases
        if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2))
    )
    if not v2_cases:
        return None
    if len(v2_cases) != len(cases):
        raise _post_json_error(
            "mixed_schema_batch_unsupported",
            "Authenticated Schema v2 and unauthenticated Schema v1 cases cannot share a batch.",
            "Run Schema v1 and v2 in separate invocations.",
        )
    identities = {case.identity_id for case in v2_cases}
    if len(identities) != 1:
        raise _post_json_error(
            "multiple_identities_unsupported",
            "A regression batch may use only one approved identity.",
            "Run each identity in a separate invocation and isolated execution context.",
        )
    runtime_policy = policy.post_json_policy
    if runtime_policy is None:
        raise _post_json_error(
            "post_json_runtime_policy_required",
            "Schema v2 execution has no trusted runtime policy.",
            "Supply trusted operator policy independently of cases.",
        )
    identity_id = next(iter(identities))
    sources = tuple(
        source
        for source in runtime_policy.identities
        if source.identity_id == identity_id
    )
    if len(sources) != 1:
        raise _post_json_error(
            "auth_configuration_invalid",
            "The approved identity has no unique credential source.",
            "Configure exactly one credential source for the selected identity.",
        )
    requests: list[PlannedAuthenticatedRequest] = []
    for case in v2_cases:
        template, point, approval = _v2_inputs(case, policy)
        for planned in _v2_planned_templates(case, template, point):
            requests.append(PlannedAuthenticatedRequest(case.identity_id, planned))
        if approval.origin not in policy.scope.allowed_origins:
            raise _post_json_error(
                "auth_origin_mismatch",
                "The credential origin is outside the trusted execution scope.",
                "Use the exact origin approved by both execution and credential policy.",
            )
    try:
        return preflight_authentication(
            (
                CredentialBinding(
                    sources[0],
                    frozenset({next(iter(v2_cases[0].scope.allowed_origins))}),
                ),
            ),
            requests,
            planned_max_run_seconds=planned_max_run_seconds,
        )
    except AuthenticationError as exc:
        raise _authentication_error(exc) from None


def batch_execution_schedule(
    cases: Sequence[AnyRegressionCase], policy: TrustedExecutionPolicy
) -> BatchExecutionSchedule:
    """Derive the one rate limiter and matching worst-case expiry duration."""
    if not cases:
        raise ValueError("Cannot schedule an empty regression batch.")
    shared_rate = min(
        policy.max_requests_per_second,
        *(case.requests_per_second for case in cases),
    )
    duration = 0.0
    requests_before = 0
    for case in cases:
        if case.check_type == "sqli.time":
            duration += policy.max_time_execution_seconds
        else:
            duration += case.max_requests * min(
                case.timeout_seconds, policy.max_timeout_seconds
            )
            waits = case.max_requests - 1 + int(requests_before > 0)
            duration += waits / shared_rate
        requests_before += case.max_requests
    return BatchExecutionSchedule(shared_rate, duration)


@dataclass(slots=True)
class _RunnerAuthentication:
    transport: AuthenticatedTransport

    def close(self) -> None:
        self.transport.close()


def _resolve_authentication(
    cases: Sequence[AnyRegressionCase],
    policy: TrustedExecutionPolicy,
    *,
    transport: httpx.BaseTransport | None,
    environ: Mapping[str, str],
    schedule: BatchExecutionSchedule,
) -> _RunnerAuthentication | None:
    plan = _authentication_plan(
        cases,
        policy,
        planned_max_run_seconds=schedule.planned_max_run_seconds,
    )
    if plan is None:
        return None
    try:
        run = resolve_credentials(plan, environ)
    except AuthenticationError as exc:
        raise _authentication_error(exc) from None
    first = cases[0]
    if not isinstance(first, (PostJsonRegressionCase, QueryRegressionCaseV2)):
        raise TypeError("Invalid authenticated execution plan.")
    underlying = transport or httpx.HTTPTransport(trust_env=False, proxy=None)
    return _RunnerAuthentication(
        AuthenticatedTransport(
            underlying,
            run,
            identity_id=first.identity_id,
            close_underlying=transport is None,
        )
    )


def _run_with_resources(
    case: AnyRegressionCase,
    *,
    policy: TrustedExecutionPolicy,
    budget: RequestBudget,
    rate_limiter: RateLimiter,
    transport: httpx.BaseTransport | None = None,
    scope: ScopePolicy | None = None,
    observation_sink: SqliObservationSink | None = None,
    authenticated_transport: AuthenticatedTransport | None = None,
    execution_clock: Callable[[], float] = time.monotonic,
) -> AnyRegressionOutcome:
    """Internal execution path for single-case and batch runners."""
    effective_scope = (
        scope
        if scope is not None
        else _effective_scope(
            case,
            policy,
            requests_per_second=rate_limiter.requests_per_second,
        )
    )

    is_time = isinstance(case, TimeRegressionCase) or (
        isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2))
        and case.check_type == "sqli.time"
    )
    is_error = isinstance(case, ErrorRegressionCase) or (
        isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2))
        and case.check_type == "sqli.error"
    )

    if is_time and budget.remaining < TIME_REQUESTS:
        raise TimeRequestBudgetError(
            "Trusted batch request budget has fewer than nine requests remaining for the time case. Increase policy.max_requests to cover every selected case, or run fewer cases."
        )

    if is_error and budget.remaining < ERROR_REQUESTS:
        raise BatchRequestBudgetError(
            "Trusted batch request budget has fewer than four requests remaining for the error case. Increase policy.max_requests to cover every selected case, or run fewer cases."
        )

    execution_budget = RequestBudget(TIME_REQUESTS) if is_time else budget
    context = ExecutionContext(
        scope=effective_scope,
        budget=execution_budget,
        timeout=min(
            case.timeout_seconds,
            policy.max_timeout_seconds,
        ),
        max_response_size=min(
            case.max_response_size
            if not isinstance(case, PostJsonRegressionCase)
            else policy.max_response_size,
            policy.max_response_size,
        ),
        rate_limiter=rate_limiter,
    )

    if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2)):
        template, point, _ = _v2_inputs(case, policy)
    else:
        template, point = case.template, case.point

    active_transport: httpx.BaseTransport | None = (
        authenticated_transport if authenticated_transport is not None else transport
    )
    auth_attempts_before = (
        authenticated_transport.attempts if authenticated_transport is not None else 0
    )

    if is_time:
        if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2)):
            delay_payload, control_payload = case.probes
            expected_delay = case.expected_delay_seconds
            if expected_delay is None:
                raise ValueError("Time case requires an expected delay.")
        elif isinstance(case, TimeRegressionCase):
            delay_payload = case.delay_payload
            control_payload = case.control_payload
            expected_delay = case.expected_delay_seconds
        else:
            raise TypeError("Invalid time regression case.")
        time_run = verify_time_based_sqli(
            template=template,
            point=point,
            payloads=TimePayloads(
                delay=delay_payload,
                control=control_payload,
            ),
            expected_delay_seconds=expected_delay,
            context=context,
            max_total_seconds=policy.max_time_execution_seconds,
            transport=active_transport,
            clock=execution_clock,
            observation_sink=observation_sink,
        )
        for _ in range(time_run.budget_used):
            budget.consume()
        product = time_product_result(time_run.analysis)
        expectation_match = product.verdict is case.expected_verdict
        time_outcome = TimeRegressionOutcome(
            case_id=case.case_id,
            expected_verdict=case.expected_verdict,
            time_run=time_run,
            expectation_match=expectation_match,
            status=_classify(product.verdict, expectation_match),
        )
        _raise_baseline_auth_failure(authenticated_transport, auth_attempts_before)
        return time_outcome

    if is_error:
        if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2)):
            error_payload = case.probes[0]
        elif isinstance(case, ErrorRegressionCase):
            error_payload = case.error_payload
        else:
            raise TypeError("Invalid error regression case.")
        error_run = verify_error_based_sqli(
            template=template,
            point=point,
            error_payload=error_payload,
            context=context,
            transport=active_transport,
            observation_sink=observation_sink,
        )
        error_product = error_product_result(error_run.analysis)
        expectation_match = error_product.verdict is case.expected_verdict
        error_outcome = ErrorRegressionOutcome(
            case_id=case.case_id,
            expected_verdict=case.expected_verdict,
            error_run=error_run,
            expectation_match=expectation_match,
            status=_classify(error_product.verdict, expectation_match),
        )
        _raise_baseline_auth_failure(authenticated_transport, auth_attempts_before)
        return error_outcome

    confirmation: ConfirmationOutcome | None = None
    if not isinstance(
        case, (PostJsonRegressionCase, QueryRegressionCaseV2, BooleanRegressionCase)
    ):
        raise TypeError("Invalid boolean regression case.")
    confirmation_config = (
        None
        if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2))
        else case.confirmation
    )
    if isinstance(case, (PostJsonRegressionCase, QueryRegressionCaseV2)):
        true_payload, false_payload = case.probes
    else:
        true_payload, false_payload = case.true_payload, case.false_payload
    if confirmation_config is None:
        verification = verify_boolean_sqli(
            check_id=case.case_id,
            template=template,
            point=point,
            true_payload=true_payload,
            false_payload=false_payload,
            context=context,
            transport=active_transport,
            observation_sink=observation_sink,
        )
        final_verdict = verification.verdict
    else:
        confirmation = verify_boolean_sqli_with_confirmation(
            check_id=case.case_id,
            template=template,
            point=point,
            true_1=true_payload,
            false_1=false_payload,
            true_2=confirmation_config.true_payload,
            false_2=confirmation_config.false_payload,
            baseline_preserving_control=confirmation_config.baseline_preserving_control,
            context=context,
            transport=active_transport,
            observation_sink=observation_sink,
        )
        verification = confirmation.initial
        final_verdict = (
            verification.verdict
            if confirmation.status is ConfirmationStatus.SKIPPED
            else Verdict.INCONCLUSIVE
        )

    expectation_match = final_verdict is case.expected_verdict

    boolean_outcome = RegressionOutcome(
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
    _raise_baseline_auth_failure(authenticated_transport, auth_attempts_before)
    return boolean_outcome


def _raise_baseline_auth_failure(
    transport: AuthenticatedTransport | None, attempts_before: int
) -> None:
    if (
        transport is not None
        and transport.auth_failure_attempt == attempts_before + 1
        and transport.auth_failure_status is not None
    ):
        raise _post_json_error(
            "authentication_baseline_rejected",
            "The baseline request was rejected before any SQLi comparison was measured.",
            "Verify the selected test identity, exact origin, expiry, protected CI variable, and target-side access independently before rerunning.",
        )


def run_regression_case(
    case: AnyRegressionCase,
    *,
    policy: TrustedExecutionPolicy,
    transport: httpx.BaseTransport | None = None,
    observation_sink: SqliObservationSink | None = None,
    environ: Mapping[str, str] | None = None,
    execution_clock: Callable[[], float] = time.monotonic,
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
    if not isinstance(case, AnyRegressionCase):
        raise TypeError("case must be a RegressionCase.")
    if not isinstance(policy, TrustedExecutionPolicy):
        raise TypeError("policy must be a TrustedExecutionPolicy.")

    schedule = batch_execution_schedule((case,), policy)
    scope = _effective_scope(
        case,
        policy,
        requests_per_second=schedule.requests_per_second,
    )

    if policy.max_requests < case.max_requests:
        raise ValueError("Trusted request budget is insufficient.")

    authentication = _resolve_authentication(
        (case,),
        policy,
        transport=transport,
        environ=os.environ if environ is None else environ,
        schedule=schedule,
    )
    try:
        return _run_with_resources(
            case,
            policy=policy,
            scope=scope,
            budget=RequestBudget(case.max_requests),
            rate_limiter=RateLimiter(requests_per_second=schedule.requests_per_second),
            transport=transport,
            observation_sink=observation_sink,
            authenticated_transport=(
                authentication.transport if authentication is not None else None
            ),
            execution_clock=execution_clock,
        )
    finally:
        if authentication is not None:
            authentication.close()
