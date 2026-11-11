"""Policy-constrained execution of security regression cases."""

import math
import re
from dataclasses import dataclass
from enum import Enum

import httpx

from vintar.checks.sqli.models import Verdict, VerificationResult
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import ScopePolicy, validate_scope
from vintar.regression.cases import RegressionCase

_CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


@dataclass(frozen=True, slots=True, repr=False)
class TrustedExecutionPolicy:
    """Trusted upper limits supplied by the runner's operator.

    Never construct this policy from an untrusted regression case.
    Scope enforcement compares URL origins and does not verify DNS-resolved
    destination IP addresses. Network egress controls remain necessary.

    Limits apply to one ``run_regression_case`` call. Aggregate limits for
    multi-case execution are not implemented by this runner.
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

            lower_bound_valid = (
                value >= minimum if minimum_inclusive else value > minimum
            )
            if not lower_bound_valid or value > maximum:
                raise ValueError("Invalid trusted execution limit.")

            normalized = float(value)
            if not math.isfinite(normalized):
                raise ValueError("Invalid trusted execution limit.")
            object.__setattr__(self, name, normalized)


class RegressionStatus(str, Enum):
    """Security-gate outcome, separate from a diagnostic verdict.

    PASS only means that this check returned the expected NOT_DETECTED result;
    it is not proof that the target has no vulnerability. Vulnerable fixtures
    use ``expectation_match`` for detector evaluation while their gate status
    remains FAIL.
    """

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True, repr=False)
class RegressionOutcome:
    """Observed verification result and independent expectation match."""

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

        expected_match = self.verification.verdict is self.expected_verdict
        if self.expectation_match != expected_match:
            raise ValueError("Inconsistent expectation match.")

        expected_status = _classify(
            self.verification.verdict,
            expected_match,
        )
        if self.status is not expected_status:
            raise ValueError("Inconsistent regression status.")


def _classify(
    actual: Verdict,
    expectation_match: bool,
) -> RegressionStatus:
    """An inconclusive or vulnerable result must never pass."""
    if actual is Verdict.INCONCLUSIVE:
        return RegressionStatus.INCONCLUSIVE

    if actual is Verdict.VULNERABLE:
        return RegressionStatus.FAIL

    if actual is Verdict.NOT_DETECTED and expectation_match:
        return RegressionStatus.PASS

    return RegressionStatus.FAIL


def run_regression_case(
    case: RegressionCase,
    *,
    policy: TrustedExecutionPolicy,
    transport: httpx.BaseTransport | None = None,
) -> RegressionOutcome:
    """Execute a case within independently trusted limits.

    The caller must obtain policy from a trusted source, never
    from the case or an untrusted pull request.

    The optional transport is for trusted tests only.
    Never expose it through user configuration or LLM tools.

    Each call owns an independent budget and rate limiter. A future batch
    runner must add aggregate request, rate, and concurrency limits rather
    than assuming this single-case policy provides them.
    """
    if not isinstance(case, RegressionCase):
        raise TypeError("case must be a RegressionCase.")
    if not isinstance(policy, TrustedExecutionPolicy):
        raise TypeError("policy must be a TrustedExecutionPolicy.")
    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError("Invalid test transport.")

    # The case may only restrict the trusted scope, never expand it.
    allowed = case.scope.allowed_origins & policy.scope.allowed_origins

    if not allowed:
        raise ValueError("Case is outside the trusted execution scope.")

    effective_scope = ScopePolicy(allowed_origins=frozenset(allowed))

    # Reject disallowed targets before any HTTP operation.
    validate_scope(case.template.url, effective_scope)

    # A six-probe verification requires six reserved requests.
    if policy.max_requests < case.max_requests:
        raise ValueError("Trusted request budget is insufficient.")

    context = ExecutionContext(
        scope=effective_scope,
        budget=RequestBudget(case.max_requests),
        timeout=min(
            case.timeout_seconds,
            policy.max_timeout_seconds,
        ),
        max_response_size=min(
            case.max_response_size,
            policy.max_response_size,
        ),
        rate_limiter=RateLimiter(
            requests_per_second=min(
                case.requests_per_second,
                policy.max_requests_per_second,
            )
        ),
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
