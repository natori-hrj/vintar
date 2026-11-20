"""Run bounded SQLi confirmation through a single trusted call.

The initial six probes and the additional twelve share one context.
No externally supplied initial result or confirmation plan is executed.

This API is not connected to Schema v1, CLI or the CI security gate.
A candidate is not proof of SQL injection.
"""

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

import httpx

from vintar.checks.sqli._errors import redact_runtime_errors
from vintar.checks.sqli.confirmation import (
    CONFIRMATION_ORDER,
    CONFIRMATION_REQUESTS,
    INITIAL_REQUESTS,
    TOTAL_REQUESTS,
    ConfirmationKind,
    ConfirmationPayloads,
    ConfirmationPlan,
    ConfirmationStep,
    confirmation_eligible,
    prepare_confirmation_plan,
)
from vintar.checks.sqli.models import (
    JSON_SAFE_INTEGER_MAX,
    VerificationResult,
)
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.core.budget import RequestBudgetExceededError
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimitInterruptedError
from vintar.core.request import InjectionPoint, RequestTemplate
from vintar.core.scope import validate_scope
from vintar.core.template import validate_template

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")

_INCONCLUSIVE_REASONS = frozenset(
    {
        "confirmation_budget_unavailable",
        "confirmation_preflight_failed",
        "confirmation_budget_exceeded",
        "confirmation_rate_limit_interrupted",
        "confirmation_timeout",
        "confirmation_request_failed",
        "confirmation_rate_limited",
        "confirmation_truncated",
        "confirmation_non_success_status",
        "confirmation_unstable",
        "confirmation_cross_phase_mismatch",
        "candidate_confirmation_mismatch",
    }
)


class ConfirmationStatus(StrEnum):
    SKIPPED = "skipped"
    CANDIDATE = "candidate"
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ConfirmationObservation:
    """Non-sensitive metadata for a completed confirmation probe."""

    kind: ConfirmationKind
    status_code: int
    body_size: int
    body_digest: str
    truncated: bool

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ConfirmationKind):
            raise TypeError("Invalid confirmation observation kind.")
        if type(self.status_code) is not int:
            raise TypeError("Invalid confirmation status code.")
        if not 100 <= self.status_code <= 599:
            raise ValueError("Invalid confirmation status code.")
        if type(self.body_size) is not int:
            raise TypeError("Invalid confirmation body size.")
        if not 0 <= self.body_size <= JSON_SAFE_INTEGER_MAX:
            raise ValueError("Invalid confirmation body size.")
        if type(self.body_digest) is not str:
            raise TypeError("Invalid confirmation body digest.")
        if _SHA256_PATTERN.fullmatch(self.body_digest) is None:
            raise ValueError("Invalid confirmation body digest.")
        if type(self.truncated) is not bool:
            raise TypeError("Invalid confirmation truncation flag.")


@dataclass(frozen=True, slots=True, repr=False)
class ConfirmationEvidence:
    """Stable response relation, not proof of SQL execution.

    Body digests avoid retaining response bodies, but low-entropy bodies may
    still be guessable by hashing candidate values offline.
    """

    observations: tuple[ConfirmationObservation, ...] = field(repr=False)
    baseline_matches_true: bool
    baseline_matches_control: bool
    false_pair_matches: bool
    baseline_differs_from_false: bool

    def __post_init__(self) -> None:
        if type(self.observations) is not tuple:
            raise TypeError("Confirmation observations must be a tuple.")
        if len(self.observations) != CONFIRMATION_REQUESTS:
            raise ValueError("Invalid confirmation observation count.")
        if not all(
            isinstance(item, ConfirmationObservation) for item in self.observations
        ):
            raise TypeError("Invalid confirmation observation.")
        if tuple(item.kind for item in self.observations) != CONFIRMATION_ORDER:
            raise ValueError("Invalid confirmation observation order.")
        if any(
            item.truncated or not 200 <= item.status_code < 300
            for item in self.observations
        ):
            raise ValueError("Invalid confirmation evidence response.")
        for value in (
            self.baseline_matches_true,
            self.baseline_matches_control,
            self.false_pair_matches,
            self.baseline_differs_from_false,
        ):
            if type(value) is not bool:
                raise TypeError("Invalid confirmation evidence relation.")

        pairs = {
            kind: tuple(item for item in self.observations if item.kind is kind)
            for kind in ConfirmationKind
        }
        if Counter(item.kind for item in self.observations) != Counter(
            {kind: 2 for kind in ConfirmationKind}
        ):
            raise ValueError("Invalid confirmation evidence probes.")

        def signature(
            item: ConfirmationObservation,
        ) -> tuple[int, int, str]:
            return item.status_code, item.body_size, item.body_digest

        if any(signature(items[0]) != signature(items[1]) for items in pairs.values()):
            raise ValueError("Unstable confirmation evidence.")

        baseline = signature(pairs[ConfirmationKind.BASELINE][0])
        true_1 = signature(pairs[ConfirmationKind.TRUE_1][0])
        false_1 = signature(pairs[ConfirmationKind.FALSE_1][0])
        true_2 = signature(pairs[ConfirmationKind.TRUE_2][0])
        false_2 = signature(pairs[ConfirmationKind.FALSE_2][0])
        control = signature(pairs[ConfirmationKind.BASELINE_PRESERVING_CONTROL][0])

        expected = (
            baseline == true_1 == true_2,
            baseline == control,
            false_1 == false_2,
            baseline != false_1,
        )
        actual = (
            self.baseline_matches_true,
            self.baseline_matches_control,
            self.false_pair_matches,
            self.baseline_differs_from_false,
        )
        if actual != expected:
            raise ValueError("Inconsistent confirmation evidence.")


@dataclass(frozen=True, slots=True, repr=False)
class ConfirmationOutcome:
    """Result of one initial-plus-confirmation execution.

    A relation mismatch is INCONCLUSIVE and is not evidence that the target is safe.
    """

    initial: VerificationResult = field(repr=False)
    status: ConfirmationStatus
    reason_code: str
    confirmation_requests: int
    total_requests: int
    evidence: ConfirmationEvidence | None = field(
        default=None,
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self.initial) is not VerificationResult:
            raise TypeError("Invalid initial verification result.")
        if not isinstance(self.status, ConfirmationStatus):
            raise TypeError("Invalid confirmation status.")
        if type(self.reason_code) is not str:
            raise TypeError("Invalid confirmation reason code.")

        for value in (
            self.confirmation_requests,
            self.total_requests,
        ):
            if type(value) is not int:
                raise TypeError("Invalid confirmation request count.")

        if not 0 <= self.confirmation_requests <= CONFIRMATION_REQUESTS:
            raise ValueError("Invalid confirmation request count.")
        if not 0 <= self.total_requests <= TOTAL_REQUESTS:
            raise ValueError("Invalid total request count.")
        if self.total_requests != (
            self.initial.request_count + self.confirmation_requests
        ):
            raise ValueError("Inconsistent confirmation request count.")

        if self.evidence is not None and not isinstance(
            self.evidence, ConfirmationEvidence
        ):
            raise TypeError("Invalid confirmation evidence.")

        if self.status is ConfirmationStatus.SKIPPED:
            if (
                self.reason_code != "initial_not_eligible"
                or self.confirmation_requests != 0
                or self.evidence is not None
                or confirmation_eligible(self.initial)
            ):
                raise ValueError("Inconsistent skipped confirmation outcome.")
            return

        if not confirmation_eligible(self.initial):
            raise ValueError("Confirmation requires an eligible initial result.")

        if self.status is ConfirmationStatus.INCONCLUSIVE:
            if self.reason_code not in _INCONCLUSIVE_REASONS or (
                self.evidence is not None
                and self.reason_code != "candidate_confirmation_mismatch"
            ):
                raise ValueError("Inconsistent inconclusive outcome.")

            if self.reason_code == "candidate_confirmation_mismatch" and (
                self.confirmation_requests != CONFIRMATION_REQUESTS
                or self.total_requests != TOTAL_REQUESTS
                or self.evidence is None
            ):
                raise ValueError("Incomplete confirmation mismatch outcome.")

            if self.reason_code == "confirmation_unstable" and (
                self.confirmation_requests != CONFIRMATION_REQUESTS
                or self.total_requests != TOTAL_REQUESTS
            ):
                raise ValueError("Incomplete unstable confirmation outcome.")

            if self.reason_code == "confirmation_cross_phase_mismatch" and (
                self.confirmation_requests != CONFIRMATION_REQUESTS
                or self.total_requests != TOTAL_REQUESTS
            ):
                raise ValueError("Incomplete cross-phase mismatch outcome.")

            if (
                self.reason_code
                in {
                    "confirmation_budget_unavailable",
                    "confirmation_preflight_failed",
                }
                and self.confirmation_requests != 0
            ):
                raise ValueError("Inconsistent pre-execution outcome.")

            if (
                self.reason_code
                not in {
                    "confirmation_budget_unavailable",
                    "confirmation_preflight_failed",
                    "confirmation_budget_exceeded",
                    "confirmation_unstable",
                    "confirmation_cross_phase_mismatch",
                }
                and self.confirmation_requests == 0
            ):
                raise ValueError("Missing confirmation request attempt.")
            return

        if (
            self.confirmation_requests != CONFIRMATION_REQUESTS
            or self.total_requests != TOTAL_REQUESTS
            or self.evidence is None
        ):
            raise ValueError("Incomplete confirmation outcome.")

        relation_matches = (
            self.evidence.baseline_matches_true
            and self.evidence.baseline_matches_control
            and self.evidence.false_pair_matches
            and self.evidence.baseline_differs_from_false
        )

        if self.status is ConfirmationStatus.CANDIDATE:
            if (
                self.reason_code != "confirmation_pattern_matched"
                or not relation_matches
            ):
                raise ValueError("Inconsistent candidate outcome.")

        elif self.status is ConfirmationStatus.NOT_CONFIRMED:
            raise ValueError("Inconsistent not-confirmed outcome.")

    @property
    def request_count(self) -> int:
        """Return budgeted HTTP attempts across both stages."""
        return self.total_requests


def _build_preflight_plan(
    *,
    template: RequestTemplate,
    point: InjectionPoint,
    payloads: ConfirmationPayloads,
    context: ExecutionContext,
) -> ConfirmationPlan:
    """Validate every possible request before the first HTTP call."""
    requests = {
        ConfirmationKind.BASELINE: template,
        ConfirmationKind.TRUE_1: inject(template, point, payloads.true_1),
        ConfirmationKind.FALSE_1: inject(template, point, payloads.false_1),
        ConfirmationKind.TRUE_2: inject(template, point, payloads.true_2),
        ConfirmationKind.FALSE_2: inject(template, point, payloads.false_2),
        ConfirmationKind.BASELINE_PRESERVING_CONTROL: inject(
            template, point, payloads.baseline_preserving_control
        ),
    }

    if len(set(requests.values())) != len(requests):
        raise ValueError("Invalid confirmation requests.")

    for request in requests.values():
        validate_template(request)
        validate_scope(request.url, context.scope)

    return ConfirmationPlan(
        steps=tuple(
            ConfirmationStep(
                kind=kind,
                template=requests[kind],
            )
            for kind in CONFIRMATION_ORDER
        ),
        point=point,
        payloads=payloads,
    )


def _observation(
    kind: ConfirmationKind,
    response: HttpResult,
) -> ConfirmationObservation:
    return ConfirmationObservation(
        kind=kind,
        status_code=response.status_code,
        body_size=len(response.body),
        body_digest=hashlib.sha256(response.body).hexdigest(),
        truncated=response.truncated,
    )


def _analyze(
    observations: tuple[ConfirmationObservation, ...],
) -> tuple[ConfirmationStatus, ConfirmationEvidence | None]:
    """Compare six stable response pairs using status, size and hash."""
    if len(observations) != CONFIRMATION_REQUESTS:
        return ConfirmationStatus.INCONCLUSIVE, None

    if tuple(item.kind for item in observations) != CONFIRMATION_ORDER:
        return ConfirmationStatus.INCONCLUSIVE, None

    pairs: dict[
        ConfirmationKind,
        list[ConfirmationObservation],
    ] = {kind: [] for kind in ConfirmationKind}

    for observation in observations:
        if observation.truncated or not 200 <= observation.status_code < 300:
            return ConfirmationStatus.INCONCLUSIVE, None

        pairs[observation.kind].append(observation)

    def signature(
        item: ConfirmationObservation,
    ) -> tuple[int, int, str]:
        return (
            item.status_code,
            item.body_size,
            item.body_digest,
        )

    if any(
        len(items) != 2 or signature(items[0]) != signature(items[1])
        for items in pairs.values()
    ):
        return ConfirmationStatus.INCONCLUSIVE, None

    baseline = signature(pairs[ConfirmationKind.BASELINE][0])
    true_1 = signature(pairs[ConfirmationKind.TRUE_1][0])
    false_1 = signature(pairs[ConfirmationKind.FALSE_1][0])
    true_2 = signature(pairs[ConfirmationKind.TRUE_2][0])
    false_2 = signature(pairs[ConfirmationKind.FALSE_2][0])
    control = signature(pairs[ConfirmationKind.BASELINE_PRESERVING_CONTROL][0])

    baseline_matches_true = baseline == true_1 == true_2
    baseline_matches_control = baseline == control
    false_pair_matches = false_1 == false_2
    baseline_differs_from_false = baseline != false_1

    evidence = ConfirmationEvidence(
        observations=observations,
        baseline_matches_true=baseline_matches_true,
        baseline_matches_control=baseline_matches_control,
        false_pair_matches=false_pair_matches,
        baseline_differs_from_false=baseline_differs_from_false,
    )

    candidate = (
        baseline_matches_true
        and baseline_matches_control
        and false_pair_matches
        and baseline_differs_from_false
    )

    return (
        ConfirmationStatus.CANDIDATE if candidate else ConfirmationStatus.NOT_CONFIRMED,
        evidence,
    )


def verify_boolean_sqli_with_confirmation(
    *,
    check_id: str,
    template: RequestTemplate,
    point: InjectionPoint,
    true_1: str,
    false_1: str,
    true_2: str,
    false_2: str,
    baseline_preserving_control: str,
    context: ExecutionContext,
    transport: httpx.BaseTransport | None = None,
) -> ConfirmationOutcome:
    """Run six initial probes and up to twelve confirmation probes.

    The caller must use this function with an explicitly authorized
    target. The function does not accept an external VerificationResult
    or ConfirmationPlan, preserving provenance within one call.

    Custom transports are trusted test dependencies only.

    ScopePolicy validates URL origins, not DNS-resolved destination IPs.
    Untrusted CI targets require network-level egress restrictions.
    """
    if not isinstance(context, ExecutionContext):
        raise TypeError("Invalid confirmation context.")
    if not isinstance(template, RequestTemplate):
        raise TypeError("Invalid confirmation template.")
    if not isinstance(point, InjectionPoint):
        raise TypeError("Invalid confirmation injection point.")
    if type(check_id) is not str or not check_id.strip():
        raise ValueError("Invalid confirmation check identifier.")
    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError("Invalid confirmation transport.")

    if (
        context.budget.max_requests != TOTAL_REQUESTS
        or context.budget.used_requests != 0
        or context.budget.remaining != TOTAL_REQUESTS
    ):
        raise ValueError("Invalid initial confirmation budget.")

    payloads = ConfirmationPayloads(
        true_1=true_1,
        false_1=false_1,
        true_2=true_2,
        false_2=false_2,
        baseline_preserving_control=baseline_preserving_control,
    )

    try:
        preflight_plan = _build_preflight_plan(
            template=template,
            point=point,
            payloads=payloads,
            context=context,
        )
    except (TypeError, ValueError):
        raise ValueError("Invalid or unauthorized confirmation inputs.") from None

    initial = verify_boolean_sqli(
        check_id=check_id,
        template=template,
        point=point,
        true_payload=payloads.true_1,
        false_payload=payloads.false_1,
        context=context,
        transport=transport,
    )

    def finish(
        status: ConfirmationStatus,
        reason_code: str,
        evidence: ConfirmationEvidence | None = None,
    ) -> ConfirmationOutcome:
        used = context.budget.used_requests

        return ConfirmationOutcome(
            initial=initial,
            status=status,
            reason_code=reason_code,
            confirmation_requests=max(0, used - initial.request_count),
            total_requests=used,
            evidence=evidence,
        )

    if not confirmation_eligible(initial):
        return finish(
            ConfirmationStatus.SKIPPED,
            "initial_not_eligible",
        )

    if (
        context.budget.used_requests != INITIAL_REQUESTS
        or context.budget.remaining != CONFIRMATION_REQUESTS
    ):
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_budget_unavailable",
        )

    try:
        plan = prepare_confirmation_plan(
            initial=initial,
            template=template,
            point=point,
            payloads=payloads,
            context=context,
        )
    except (TypeError, ValueError):
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_preflight_failed",
        )

    if plan is None or plan != preflight_plan:
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_preflight_failed",
        )

    if context.budget.remaining != CONFIRMATION_REQUESTS:
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_budget_unavailable",
        )

    observations: list[ConfirmationObservation] = []

    for step in plan.steps:
        try:
            response = context.execute(
                step.template,
                transport=transport,
            )
        except RequestBudgetExceededError:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_budget_exceeded",
            )
        except RateLimitInterruptedError:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_rate_limit_interrupted",
            )
        except httpx.TimeoutException:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_timeout",
            )
        except httpx.RequestError:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_request_failed",
            )

        observations.append(_observation(step.kind, response))

        if response.status_code == 429:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_rate_limited",
            )

        if response.truncated:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_truncated",
            )

        if not 200 <= response.status_code < 300:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_non_success_status",
            )

    status, evidence = _analyze(tuple(observations))

    if status is ConfirmationStatus.INCONCLUSIVE:
        return finish(
            status,
            "confirmation_unstable",
        )

    if status is ConfirmationStatus.CANDIDATE:
        with redact_runtime_errors("Cross-phase consistency assessment failed."):
            # Local import prevents the circular dependency.
            from vintar.checks.sqli.cross_phase import (
                CrossPhaseAssessment,
                CrossPhaseStatus,
                assess_cross_phase_consistency,
            )

            if type(evidence) is not ConfirmationEvidence:
                raise TypeError

            assessment = assess_cross_phase_consistency(
                initial=initial,
                confirmation=evidence,
            )

            if type(assessment) is not CrossPhaseAssessment:
                raise TypeError
        if assessment.status is not CrossPhaseStatus.MATCH:
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_cross_phase_mismatch",
            )

    if status is ConfirmationStatus.NOT_CONFIRMED:
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "candidate_confirmation_mismatch",
            evidence,
        )

    return finish(
        status,
        "confirmation_pattern_matched",
        evidence,
    )
