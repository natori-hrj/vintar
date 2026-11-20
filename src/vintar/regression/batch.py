"""Sequential regression batches with aggregate safety limits."""

from dataclasses import dataclass

import httpx

from vintar.checks.sqli.models import Verdict
from vintar.core.budget import RequestBudget
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import ScopePolicy
from vintar.regression.cases import RegressionCase
from vintar.regression.runner import (
    _CASE_ID_PATTERN,
    RegressionOutcome,
    RegressionStatus,
    TrustedExecutionPolicy,
    _effective_scope,
    _run_with_resources,
)

MAX_BATCH_CASES = 128


@dataclass(frozen=True, slots=True, repr=False)
class RegressionBatchResult:
    """Immutable ordered outcomes and the complete planned case identity.

    Outcomes contain only cases that actually ran. ``complete`` is false when
    a fail-closed stopping condition prevented remaining cases from running.
    ``requests_used`` counts attempts reserved at the transport boundary, so
    it equals the sum of recorded observations and probe failures, not always
    the number of requests dispatched by an underlying transport.
    """

    planned_case_ids: tuple[str, ...]
    outcomes: tuple[RegressionOutcome, ...]
    status: RegressionStatus
    requests_used: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.planned_case_ids, tuple)
            or not self.planned_case_ids
            or not all(
                type(item) is str and _CASE_ID_PATTERN.fullmatch(item) is not None
                for item in self.planned_case_ids
            )
            or len(self.planned_case_ids) > MAX_BATCH_CASES
            or len(set(self.planned_case_ids)) != len(self.planned_case_ids)
        ):
            raise ValueError("Invalid planned case identifiers.")

        if (
            not isinstance(self.outcomes, tuple)
            or not self.outcomes
            or not all(isinstance(item, RegressionOutcome) for item in self.outcomes)
        ):
            raise ValueError("Invalid batch outcomes.")

        if not isinstance(self.status, RegressionStatus):
            raise TypeError("Invalid batch status.")

        if type(self.requests_used) is not int or self.requests_used < 0:
            raise ValueError("Invalid request count.")

        completed_ids = tuple(item.case_id for item in self.outcomes)
        if completed_ids != self.planned_case_ids[: len(completed_ids)]:
            raise ValueError("Batch outcomes do not match the planned case order.")

        if len(self.outcomes) > len(self.planned_case_ids):
            raise ValueError("Batch contains unplanned outcomes.")

        if self.status is not _aggregate_status(self.outcomes, self.complete):
            raise ValueError("Inconsistent batch status.")

        if self.requests_used != sum(item.request_count for item in self.outcomes):
            raise ValueError("Inconsistent batch request count.")

    @property
    def complete(self) -> bool:
        """Whether every preflighted case produced an outcome."""
        return len(self.outcomes) == len(self.planned_case_ids)


def _aggregate_status(
    outcomes: tuple[RegressionOutcome, ...],
    complete: bool,
) -> RegressionStatus:
    """FAIL takes precedence over incomplete/INCONCLUSIVE, then PASS."""
    if any(item.status is RegressionStatus.FAIL for item in outcomes):
        return RegressionStatus.FAIL

    if not complete or any(
        item.status is RegressionStatus.INCONCLUSIVE for item in outcomes
    ):
        return RegressionStatus.INCONCLUSIVE

    return RegressionStatus.PASS


def _must_stop_batch(outcome: RegressionOutcome) -> bool:
    """Stop when continuing would ignore a safety or decisive condition."""
    verification = outcome.verification

    if verification.verdict is Verdict.VULNERABLE:
        return True

    if outcome.final_reason_code in {
        "rate_limited",
        "confirmation_rate_limited",
        "confirmation_rate_limit_interrupted",
    }:
        return True

    return bool(verification.failures)


def run_regression_batch(
    cases: list[RegressionCase] | tuple[RegressionCase, ...],
    *,
    policy: TrustedExecutionPolicy,
    transport: httpx.BaseTransport | None = None,
) -> RegressionBatchResult:
    """Run a bounded batch with one shared budget and rate limiter.

    policy must originate from a trusted operator or CI configuration.

    ALL cases, scope and the worst-case budget are validated before
    the first HTTP request. The batch runs sequentially.

    The slowest requested case rate is applied to the entire batch. HTTP 429,
    any recorded probe failure, or a VULNERABLE verdict stops all remaining
    cases.

    Custom transports are trusted test dependencies only.

    Origin matching does not protect against DNS rebinding. Enforce
    network-level egress restrictions in sensitive CI environments.
    """
    if not isinstance(policy, TrustedExecutionPolicy):
        raise TypeError("policy must be a TrustedExecutionPolicy.")

    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError("Invalid test transport.")

    if type(cases) not in (tuple, list):
        raise TypeError("cases must be a list or tuple.")

    if not 1 <= len(cases) <= MAX_BATCH_CASES:
        raise ValueError("Invalid batch size.")

    selected = tuple(cases)

    if not all(isinstance(case, RegressionCase) for case in selected):
        raise TypeError("Invalid regression case.")

    identifiers = [case.case_id for case in selected]

    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Duplicate regression case identifier")

    # Validate every case before any network request.
    scopes: list[ScopePolicy] = [_effective_scope(case, policy) for case in selected]

    required_requests = sum(case.max_requests for case in selected)

    if required_requests > policy.max_requests:
        raise ValueError("Trusted batch request budget is insufficient.")

    budget = RequestBudget(required_requests)
    rate_limiter = RateLimiter(
        requests_per_second=min(
            policy.max_requests_per_second,
            *(case.requests_per_second for case in selected),
        )
    )

    outcomes: list[RegressionOutcome] = []

    for case, scope in zip(selected, scopes, strict=True):
        outcome = _run_with_resources(
            case,
            policy=policy,
            scope=scope,
            budget=budget,
            rate_limiter=rate_limiter,
            transport=transport,
        )
        outcomes.append(outcome)

        if _must_stop_batch(outcome):
            break

    completed = tuple(outcomes)

    return RegressionBatchResult(
        planned_case_ids=tuple(identifiers),
        outcomes=completed,
        status=_aggregate_status(
            completed,
            len(completed) == len(selected),
        ),
        requests_used=budget.used_requests,
    )
