"""Run bounded SQLi confirmation through a single trusted call.

The initial six probes and the additional twelve share one context.
No externally supplied initial result or confirmation plan is executed.

This API is not connected to Schema v1, CLI or the CI security gate.
A candidate is not proof of SQL injection.
"""

import hashlib
import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

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
from vintar.checks.sqli.decision_facts import (
    ConfirmationDecisionFacts,
    ConfirmationRelation,
    ConfirmationRelationDecisionFacts,
    DecisionStage,
    OperationalCondition,
    OperationalDecisionFacts,
    PredicatePair,
    response_operational_condition,
)
from vintar.checks.sqli.echo_normalization import (
    EchoInput,
    NormalizedEcho,
    normalize_context_bound_echoes,
)
from vintar.checks.sqli.models import (
    JSON_SAFE_INTEGER_MAX,
    ProbeError,
    VerificationResult,
)
from vintar.checks.sqli.observation_sink import (
    SqliObservationSink,
    emit_observation,
)
from vintar.checks.sqli.orchestrator import (
    classify_probe_error,
    query_value_at_point,
    verify_boolean_sqli,
)
from vintar.core.budget import RequestBudgetExceededError
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimitInterruptedError
from vintar.core.request import InjectionPoint, RequestTemplate
from vintar.core.scope import validate_scope
from vintar.core.template import validate_template

_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


class ConfirmationStatus(StrEnum):
    SKIPPED = "skipped"
    CANDIDATE = "candidate"
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ConfirmationResultRule:
    """Machine-readable invariants shared with report validation."""

    status: ConfirmationStatus
    minimum_requests: int
    maximum_requests: int
    requires_eligible_initial: bool


def _rule(
    status: ConfirmationStatus,
    minimum_requests: int,
    maximum_requests: int,
    *,
    requires_eligible_initial: bool = True,
) -> ConfirmationResultRule:
    return ConfirmationResultRule(
        status=status,
        minimum_requests=minimum_requests,
        maximum_requests=maximum_requests,
        requires_eligible_initial=requires_eligible_initial,
    )


CONFIRMATION_RESULT_RULES: Mapping[str, ConfirmationResultRule] = MappingProxyType(
    {
        "initial_not_eligible": _rule(
            ConfirmationStatus.SKIPPED,
            0,
            0,
            requires_eligible_initial=False,
        ),
        "confirmation_pattern_matched": _rule(
            ConfirmationStatus.CANDIDATE,
            CONFIRMATION_REQUESTS,
            CONFIRMATION_REQUESTS,
        ),
        "candidate_confirmation_mismatch": _rule(
            ConfirmationStatus.INCONCLUSIVE,
            CONFIRMATION_REQUESTS,
            CONFIRMATION_REQUESTS,
        ),
        "confirmation_budget_unavailable": _rule(ConfirmationStatus.INCONCLUSIVE, 0, 0),
        "confirmation_preflight_failed": _rule(ConfirmationStatus.INCONCLUSIVE, 0, 0),
        "confirmation_budget_exceeded": _rule(
            ConfirmationStatus.INCONCLUSIVE, 0, CONFIRMATION_REQUESTS
        ),
        "confirmation_unstable": _rule(
            ConfirmationStatus.INCONCLUSIVE,
            CONFIRMATION_REQUESTS,
            CONFIRMATION_REQUESTS,
        ),
        "confirmation_cross_phase_mismatch": _rule(
            ConfirmationStatus.INCONCLUSIVE,
            CONFIRMATION_REQUESTS,
            CONFIRMATION_REQUESTS,
        ),
        "confirmation_rate_limit_interrupted": _rule(
            ConfirmationStatus.INCONCLUSIVE, 1, CONFIRMATION_REQUESTS
        ),
        "confirmation_timeout": _rule(
            ConfirmationStatus.INCONCLUSIVE, 1, CONFIRMATION_REQUESTS
        ),
        "confirmation_request_failed": _rule(
            ConfirmationStatus.INCONCLUSIVE, 1, CONFIRMATION_REQUESTS
        ),
        "confirmation_rate_limited": _rule(
            ConfirmationStatus.INCONCLUSIVE, 1, CONFIRMATION_REQUESTS
        ),
        "confirmation_truncated": _rule(
            ConfirmationStatus.INCONCLUSIVE, 1, CONFIRMATION_REQUESTS
        ),
        "confirmation_non_success_status": _rule(
            ConfirmationStatus.INCONCLUSIVE, 1, CONFIRMATION_REQUESTS
        ),
    }
)

_INCONCLUSIVE_REASONS = frozenset(
    reason
    for reason, rule in CONFIRMATION_RESULT_RULES.items()
    if rule.status is ConfirmationStatus.INCONCLUSIVE
)


@dataclass(frozen=True, slots=True)
class ConfirmationObservation:
    """Non-sensitive metadata for a completed confirmation probe."""

    kind: ConfirmationKind
    status_code: int
    body_size: int
    body_digest: str
    truncated: bool
    normalization_applied: bool = False
    normalized_echo_count: int = 0

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
        if type(self.normalization_applied) is not bool:
            raise TypeError("Invalid confirmation normalization flag.")
        if type(self.normalized_echo_count) is not int:
            raise TypeError("Invalid confirmation normalized echo count.")
        if self.normalized_echo_count < 0:
            raise ValueError("Invalid confirmation normalized echo count.")
        if self.normalization_applied != (self.normalized_echo_count > 0):
            raise ValueError(
                "Inconsistent confirmation normalization metadata. Record a "
                "positive echo count only when the comparison body changed."
            )


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
    decision_facts: ConfirmationDecisionFacts | None = None

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
        if self.decision_facts is not None:
            if not isinstance(
                self.decision_facts,
                (OperationalDecisionFacts, ConfirmationRelationDecisionFacts),
            ):
                raise TypeError("Invalid confirmation decision facts.")
            if self.decision_facts.reason_code != self.reason_code:
                raise ValueError(
                    "Confirmation decision facts contradict the reason. Use facts "
                    "produced by the same confirmation decision."
                )

        rule = CONFIRMATION_RESULT_RULES.get(self.reason_code)
        if rule is None or self.status is not rule.status:
            if self.status is ConfirmationStatus.CANDIDATE:
                raise ValueError("Inconsistent candidate outcome.")
            if self.status is ConfirmationStatus.INCONCLUSIVE:
                raise ValueError("Inconsistent inconclusive outcome.")
            raise ValueError("Inconsistent confirmation status and reason.")
        if (
            not rule.minimum_requests
            <= self.confirmation_requests
            <= rule.maximum_requests
        ):
            if self.reason_code == "candidate_confirmation_mismatch":
                raise ValueError("Incomplete confirmation mismatch outcome.")
            if self.reason_code == "confirmation_cross_phase_mismatch":
                raise ValueError("Incomplete cross-phase mismatch outcome.")
            if self.reason_code == "confirmation_unstable":
                raise ValueError("Incomplete unstable confirmation outcome.")
            if rule.maximum_requests == 0:
                raise ValueError("Inconsistent pre-execution outcome.")
            if self.confirmation_requests == 0:
                raise ValueError("Missing confirmation request attempt.")
            raise ValueError("Inconsistent confirmation request count for reason.")

        eligible = confirmation_eligible(self.initial)
        if eligible is not rule.requires_eligible_initial:
            raise ValueError("Inconsistent confirmation initial eligibility.")

        if self.status is ConfirmationStatus.SKIPPED:
            if self.evidence is not None:
                raise ValueError("Inconsistent skipped confirmation evidence.")
            return

        if self.status is ConfirmationStatus.INCONCLUSIVE:
            if (
                self.evidence is not None
                and self.reason_code != "candidate_confirmation_mismatch"
            ):
                raise ValueError("Inconsistent inconclusive outcome.")

            if (
                self.reason_code == "candidate_confirmation_mismatch"
                and self.evidence is None
            ):
                raise ValueError("Incomplete confirmation mismatch outcome.")
            if self.reason_code == "candidate_confirmation_mismatch":
                assert self.evidence is not None
                observations = {
                    kind: next(
                        item for item in self.evidence.observations if item.kind is kind
                    )
                    for kind in ConfirmationKind
                }
                pairs_stable = _predicate_pairs_are_stable(
                    true_1=observations[ConfirmationKind.TRUE_1],
                    true_2=observations[ConfirmationKind.TRUE_2],
                    false_1=observations[ConfirmationKind.FALSE_1],
                    false_2=observations[ConfirmationKind.FALSE_2],
                )
                relation_matches = (
                    self.evidence.baseline_matches_true
                    and self.evidence.baseline_matches_control
                    and self.evidence.false_pair_matches
                    and self.evidence.baseline_differs_from_false
                )
                if not pairs_stable or relation_matches:
                    raise ValueError(
                        "Confirmation mismatch requires reproduced TRUE/FALSE "
                        "predicate pairs and a mismatching remaining relation. Use "
                        "confirmation_unstable when a predicate pair does not reproduce."
                    )
            return

        if self.evidence is None:
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
    normalization: NormalizedEcho | None = None,
) -> ConfirmationObservation:
    comparison = normalization or NormalizedEcho(response.body, False, 0)
    return ConfirmationObservation(
        kind=kind,
        status_code=response.status_code,
        body_size=len(comparison.body),
        body_digest=hashlib.sha256(comparison.body).hexdigest(),
        truncated=response.truncated,
        normalization_applied=comparison.applied,
        normalized_echo_count=comparison.echo_count,
    )


def _confirmation_observations(
    completed: tuple[tuple[ConfirmationStep, HttpResult], ...],
    point: InjectionPoint,
    *,
    normalize: bool,
) -> tuple[ConfirmationObservation, ...]:
    if normalize:
        normalized = normalize_context_bound_echoes(
            tuple(
                EchoInput(
                    response.body,
                    query_value_at_point(step.template, point),
                )
                for step, response in completed
            )
        )
    else:
        normalized = tuple(
            NormalizedEcho(response.body, False, 0) for _, response in completed
        )
    return tuple(
        _observation(step.kind, response, item)
        for (step, response), item in zip(completed, normalized, strict=True)
    )


def _emit_confirmation_observations(
    sink: SqliObservationSink | None,
    observations: tuple[ConfirmationObservation, ...],
) -> None:
    for index, observation in enumerate(observations, start=1):
        emit_observation(
            sink,
            family="confirmation",
            sequence=INITIAL_REQUESTS + index,
            kind=observation.kind.value,
            observation=observation,
        )


def _confirmation_signature(
    observation: ConfirmationObservation,
) -> tuple[int, int, str]:
    return (
        observation.status_code,
        observation.body_size,
        observation.body_digest,
    )


def _predicate_pairs_are_stable(
    *,
    true_1: ConfirmationObservation,
    true_2: ConfirmationObservation,
    false_1: ConfirmationObservation,
    false_2: ConfirmationObservation,
) -> bool:
    """Require both independent predicates to reproduce their truth relation."""
    return _confirmation_signature(true_1) == _confirmation_signature(
        true_2
    ) and _confirmation_signature(false_1) == _confirmation_signature(false_2)


def _analyze(
    observations: tuple[ConfirmationObservation, ...],
) -> tuple[
    ConfirmationStatus,
    ConfirmationEvidence | None,
    ConfirmationRelationDecisionFacts | None,
]:
    """Compare six stable response pairs using status, size and hash."""
    if len(observations) != CONFIRMATION_REQUESTS:
        return ConfirmationStatus.INCONCLUSIVE, None, None

    if tuple(item.kind for item in observations) != CONFIRMATION_ORDER:
        return ConfirmationStatus.INCONCLUSIVE, None, None

    pairs: dict[
        ConfirmationKind,
        list[ConfirmationObservation],
    ] = {kind: [] for kind in ConfirmationKind}

    for observation in observations:
        if observation.truncated or not 200 <= observation.status_code < 300:
            return ConfirmationStatus.INCONCLUSIVE, None, None

        pairs[observation.kind].append(observation)

    unstable_repeat_kinds = tuple(
        kind
        for kind in ConfirmationKind
        if len(pairs[kind]) != 2
        or _confirmation_signature(pairs[kind][0])
        != _confirmation_signature(pairs[kind][1])
    )
    if unstable_repeat_kinds:
        return (
            ConfirmationStatus.INCONCLUSIVE,
            None,
            ConfirmationRelationDecisionFacts(
                reason_code="confirmation_unstable",
                unstable_repeat_kinds=unstable_repeat_kinds,
            ),
        )

    baseline_observation = pairs[ConfirmationKind.BASELINE][0]
    true_1_observation = pairs[ConfirmationKind.TRUE_1][0]
    false_1_observation = pairs[ConfirmationKind.FALSE_1][0]
    true_2_observation = pairs[ConfirmationKind.TRUE_2][0]
    false_2_observation = pairs[ConfirmationKind.FALSE_2][0]
    control_observation = pairs[ConfirmationKind.BASELINE_PRESERVING_CONTROL][0]

    if not _predicate_pairs_are_stable(
        true_1=true_1_observation,
        true_2=true_2_observation,
        false_1=false_1_observation,
        false_2=false_2_observation,
    ):
        unreproduced = tuple(
            pair
            for pair, matches in (
                (
                    PredicatePair.TRUE,
                    _confirmation_signature(true_1_observation)
                    == _confirmation_signature(true_2_observation),
                ),
                (
                    PredicatePair.FALSE,
                    _confirmation_signature(false_1_observation)
                    == _confirmation_signature(false_2_observation),
                ),
            )
            if not matches
        )
        return (
            ConfirmationStatus.INCONCLUSIVE,
            None,
            ConfirmationRelationDecisionFacts(
                reason_code="confirmation_unstable",
                unreproduced_predicate_pairs=unreproduced,
            ),
        )

    baseline = _confirmation_signature(baseline_observation)
    true_1 = _confirmation_signature(true_1_observation)
    false_1 = _confirmation_signature(false_1_observation)
    true_2 = _confirmation_signature(true_2_observation)
    false_2 = _confirmation_signature(false_2_observation)
    control = _confirmation_signature(control_observation)

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

    if candidate:
        return ConfirmationStatus.CANDIDATE, evidence, None
    mismatched_relations = tuple(
        relation
        for relation, matches in (
            (ConfirmationRelation.BASELINE_TRUE, baseline_matches_true),
            (ConfirmationRelation.BASELINE_CONTROL, baseline_matches_control),
            (
                ConfirmationRelation.BASELINE_FALSE,
                baseline_differs_from_false,
            ),
        )
        if not matches
    )
    return (
        ConfirmationStatus.NOT_CONFIRMED,
        evidence,
        ConfirmationRelationDecisionFacts(
            reason_code="candidate_confirmation_mismatch",
            mismatched_relations=mismatched_relations,
        ),
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
    observation_sink: SqliObservationSink | None = None,
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
        observation_sink=observation_sink,
    )

    def finish(
        status: ConfirmationStatus,
        reason_code: str,
        evidence: ConfirmationEvidence | None = None,
        decision_facts: ConfirmationDecisionFacts | None = None,
    ) -> ConfirmationOutcome:
        used = context.budget.used_requests

        return ConfirmationOutcome(
            initial=initial,
            status=status,
            reason_code=reason_code,
            confirmation_requests=max(0, used - initial.request_count),
            total_requests=used,
            evidence=evidence,
            decision_facts=decision_facts,
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
            decision_facts=OperationalDecisionFacts(
                reason_code="confirmation_budget_unavailable",
                stage=DecisionStage.CONFIRMATION,
                sequence=7,
                probe_kind=ConfirmationKind.BASELINE,
                condition=OperationalCondition.BUDGET_UNAVAILABLE,
            ),
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
            decision_facts=OperationalDecisionFacts(
                reason_code="confirmation_preflight_failed",
                stage=DecisionStage.CONFIRMATION,
                sequence=7,
                probe_kind=ConfirmationKind.BASELINE,
                condition=OperationalCondition.PREFLIGHT_FAILED,
            ),
        )

    if plan is None or plan != preflight_plan:
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_preflight_failed",
            decision_facts=OperationalDecisionFacts(
                reason_code="confirmation_preflight_failed",
                stage=DecisionStage.CONFIRMATION,
                sequence=7,
                probe_kind=ConfirmationKind.BASELINE,
                condition=OperationalCondition.PREFLIGHT_FAILED,
            ),
        )

    if context.budget.remaining != CONFIRMATION_REQUESTS:
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_budget_unavailable",
            decision_facts=OperationalDecisionFacts(
                reason_code="confirmation_budget_unavailable",
                stage=DecisionStage.CONFIRMATION,
                sequence=7,
                probe_kind=ConfirmationKind.BASELINE,
                condition=OperationalCondition.BUDGET_UNAVAILABLE,
            ),
        )

    completed: list[tuple[ConfirmationStep, HttpResult]] = []

    def emit_completed(*, normalize: bool) -> tuple[ConfirmationObservation, ...]:
        observations = _confirmation_observations(
            tuple(completed), plan.point, normalize=normalize
        )
        _emit_confirmation_observations(observation_sink, observations)
        return observations

    for confirmation_sequence, step in enumerate(plan.steps, start=1):
        sequence = INITIAL_REQUESTS + confirmation_sequence
        try:
            response = context.execute(
                step.template,
                transport=transport,
            )
        except RequestBudgetExceededError:
            emit_completed(normalize=False)
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_budget_exceeded",
                decision_facts=OperationalDecisionFacts(
                    reason_code="confirmation_budget_exceeded",
                    stage=DecisionStage.CONFIRMATION,
                    sequence=sequence,
                    probe_kind=step.kind,
                    condition=OperationalCondition.BUDGET_EXCEEDED,
                ),
            )
        except RateLimitInterruptedError:
            emit_completed(normalize=False)
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_rate_limit_interrupted",
                decision_facts=OperationalDecisionFacts(
                    reason_code="confirmation_rate_limit_interrupted",
                    stage=DecisionStage.CONFIRMATION,
                    sequence=sequence,
                    probe_kind=step.kind,
                    condition=OperationalCondition.RATE_LIMIT_INTERRUPTED,
                ),
            )
        except httpx.TimeoutException:
            emit_completed(normalize=False)
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_timeout",
                decision_facts=OperationalDecisionFacts(
                    reason_code="confirmation_timeout",
                    stage=DecisionStage.CONFIRMATION,
                    sequence=sequence,
                    probe_kind=step.kind,
                    condition=ProbeError.TIMEOUT,
                ),
            )
        except httpx.RequestError as exc:
            emit_completed(normalize=False)
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_request_failed",
                decision_facts=OperationalDecisionFacts(
                    reason_code="confirmation_request_failed",
                    stage=DecisionStage.CONFIRMATION,
                    sequence=sequence,
                    probe_kind=step.kind,
                    condition=classify_probe_error(exc),
                ),
            )

        completed.append((step, response))

        condition = response_operational_condition(
            response.status_code, truncated=response.truncated
        )
        if condition is OperationalCondition.RATE_LIMITED:
            emit_completed(normalize=False)
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_rate_limited",
                decision_facts=OperationalDecisionFacts(
                    reason_code="confirmation_rate_limited",
                    stage=DecisionStage.CONFIRMATION,
                    sequence=sequence,
                    probe_kind=step.kind,
                    condition=OperationalCondition.RATE_LIMITED,
                    status_code=response.status_code,
                ),
            )

        if condition is OperationalCondition.TRUNCATED:
            emit_completed(normalize=False)
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_truncated",
                decision_facts=OperationalDecisionFacts(
                    reason_code="confirmation_truncated",
                    stage=DecisionStage.CONFIRMATION,
                    sequence=sequence,
                    probe_kind=step.kind,
                    condition=OperationalCondition.TRUNCATED,
                    status_code=response.status_code,
                ),
            )

        if condition is OperationalCondition.NON_SUCCESS_STATUS:
            emit_completed(normalize=False)
            return finish(
                ConfirmationStatus.INCONCLUSIVE,
                "confirmation_non_success_status",
                decision_facts=OperationalDecisionFacts(
                    reason_code="confirmation_non_success_status",
                    stage=DecisionStage.CONFIRMATION,
                    sequence=sequence,
                    probe_kind=step.kind,
                    condition=OperationalCondition.NON_SUCCESS_STATUS,
                    status_code=response.status_code,
                ),
            )

    observations = emit_completed(normalize=True)
    status, evidence, decision_facts = _analyze(observations)

    if status is ConfirmationStatus.INCONCLUSIVE:
        return finish(
            status,
            "confirmation_unstable",
            decision_facts=decision_facts,
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
                decision_facts=ConfirmationRelationDecisionFacts(
                    reason_code="confirmation_cross_phase_mismatch",
                    cross_phase_mismatched_kinds=assessment.mismatched_kinds,
                ),
            )

    if status is ConfirmationStatus.NOT_CONFIRMED:
        return finish(
            ConfirmationStatus.INCONCLUSIVE,
            "candidate_confirmation_mismatch",
            evidence,
            decision_facts,
        )

    return finish(
        status,
        "confirmation_pattern_matched",
        evidence,
    )
