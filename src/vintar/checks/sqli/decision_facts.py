"""Bounded, non-sensitive facts explaining SQLi non-decisions."""

from dataclasses import dataclass
from enum import StrEnum

from vintar.checks.sqli.confirmation import ConfirmationKind
from vintar.checks.sqli.models import ProbeError, ProbeKind
from vintar.checks.sqli.time_plan import TIME_REQUESTS, TimeProbeKind


class DecisionStage(StrEnum):
    INITIAL = "initial"
    CONFIRMATION = "confirmation"
    TIME = "time"


class OperationalCondition(StrEnum):
    BUDGET_UNAVAILABLE = "budget_unavailable"
    PREFLIGHT_FAILED = "preflight_failed"
    BUDGET_EXCEEDED = "budget_exceeded"
    RATE_LIMIT_INTERRUPTED = "rate_limit_interrupted"
    RATE_LIMITED = "rate_limited"
    TRUNCATED = "truncated"
    NON_SUCCESS_STATUS = "non_success_status"


class TimeOperationalCondition(StrEnum):
    TIMEOUT = "timeout"
    REQUEST_FAILED = "request_failed"
    INTERRUPTED = "interrupted"
    RATE_LIMITED = "rate_limited"
    NON_SUCCESS_STATUS = "non_success_status"
    TRUNCATED = "truncated"
    DEADLINE = "deadline"


class TimingInstabilityCause(StrEnum):
    BASELINE_SPAN = "baseline_span"
    CONTROL_SPAN = "control_span"
    BASELINE_CONTROL_DIFFERENCE = "baseline_control_difference"
    DRIFT = "drift"
    DELAY_SPAN = "delay_span"


class PairLocalization(StrEnum):
    LOCALIZED = "localized"
    UNLOCALIZED = "unlocalized"


class PredicatePair(StrEnum):
    TRUE = "true"
    FALSE = "false"


class ConfirmationRelation(StrEnum):
    BASELINE_TRUE = "baseline_true"
    BASELINE_CONTROL = "baseline_control"
    BASELINE_FALSE = "baseline_false"


type DecisionProbeKind = ProbeKind | ConfirmationKind | TimeProbeKind
type DecisionCondition = ProbeError | OperationalCondition | TimeOperationalCondition


_OPERATIONAL_REASON_CONDITIONS: dict[
    str, tuple[DecisionStage, tuple[DecisionCondition, ...]]
] = {
    "budget_unavailable": (
        DecisionStage.INITIAL,
        (OperationalCondition.BUDGET_UNAVAILABLE,),
    ),
    "probe_failed": (DecisionStage.INITIAL, tuple(ProbeError)),
    "rate_limited": (
        DecisionStage.INITIAL,
        (OperationalCondition.RATE_LIMITED,),
    ),
    "truncated_response": (
        DecisionStage.INITIAL,
        (OperationalCondition.TRUNCATED,),
    ),
    "non_success_status": (
        DecisionStage.INITIAL,
        (OperationalCondition.NON_SUCCESS_STATUS,),
    ),
    "confirmation_budget_unavailable": (
        DecisionStage.CONFIRMATION,
        (OperationalCondition.BUDGET_UNAVAILABLE,),
    ),
    "confirmation_preflight_failed": (
        DecisionStage.CONFIRMATION,
        (OperationalCondition.PREFLIGHT_FAILED,),
    ),
    "confirmation_budget_exceeded": (
        DecisionStage.CONFIRMATION,
        (OperationalCondition.BUDGET_EXCEEDED,),
    ),
    "confirmation_rate_limit_interrupted": (
        DecisionStage.CONFIRMATION,
        (OperationalCondition.RATE_LIMIT_INTERRUPTED,),
    ),
    "confirmation_timeout": (
        DecisionStage.CONFIRMATION,
        (ProbeError.TIMEOUT,),
    ),
    "confirmation_request_failed": (
        DecisionStage.CONFIRMATION,
        (
            ProbeError.CONNECTION,
            ProbeError.RESPONSE_READ,
            ProbeError.UNKNOWN,
        ),
    ),
    "confirmation_rate_limited": (
        DecisionStage.CONFIRMATION,
        (OperationalCondition.RATE_LIMITED,),
    ),
    "confirmation_truncated": (
        DecisionStage.CONFIRMATION,
        (OperationalCondition.TRUNCATED,),
    ),
    "confirmation_non_success_status": (
        DecisionStage.CONFIRMATION,
        (OperationalCondition.NON_SUCCESS_STATUS,),
    ),
}

_TIME_OPERATIONAL_REASON_CONDITIONS = {
    "incomplete_probes": (TimeOperationalCondition.DEADLINE,),
    "probe_timeout": (TimeOperationalCondition.TIMEOUT,),
    "probe_failed": (TimeOperationalCondition.REQUEST_FAILED,),
    "probe_interrupted": (
        TimeOperationalCondition.INTERRUPTED,
        TimeOperationalCondition.DEADLINE,
    ),
    "rate_limited": (TimeOperationalCondition.RATE_LIMITED,),
    "non_success_status": (TimeOperationalCondition.NON_SUCCESS_STATUS,),
    "truncated_response": (TimeOperationalCondition.TRUNCATED,),
}

DECISION_FACT_CATEGORY_REASONS = {
    "operational": frozenset(
        _OPERATIONAL_REASON_CONDITIONS | _TIME_OPERATIONAL_REASON_CONDITIONS
    ),
    "response_dynamics": frozenset({"possible_dynamic_response", "unstable_response"}),
    "confirmation_relation": frozenset(
        {
            "confirmation_unstable",
            "candidate_confirmation_mismatch",
            "confirmation_cross_phase_mismatch",
        }
    ),
    "timing_dynamics": frozenset({"unstable_timing", "ambiguous_timing"}),
}


@dataclass(frozen=True, slots=True)
class OperationalDecisionFacts:
    reason_code: str
    stage: DecisionStage
    sequence: int
    probe_kind: DecisionProbeKind
    condition: DecisionCondition
    status_code: int | None = None

    def __post_init__(self) -> None:
        conditions: tuple[DecisionCondition, ...] | None
        if self.stage is DecisionStage.TIME:
            expected_stage = DecisionStage.TIME
            conditions = _TIME_OPERATIONAL_REASON_CONDITIONS.get(self.reason_code)
        else:
            expected = _OPERATIONAL_REASON_CONDITIONS.get(self.reason_code)
            if expected is None:
                expected_stage = self.stage
                conditions = None
            else:
                expected_stage, conditions = expected
        if conditions is None:
            raise ValueError(
                "Operational decision facts require a supported operational reason."
            )
        if self.stage is not expected_stage or self.condition not in conditions:
            raise ValueError(
                "Operational decision facts contradict the reason. Use the stage and "
                "condition produced by the bounded runner."
            )
        maximum_sequence = TIME_REQUESTS if self.stage is DecisionStage.TIME else 18
        if type(self.sequence) is not int or not 1 <= self.sequence <= maximum_sequence:
            raise ValueError(
                "Operational decision sequence must be from 1 through "
                f"{maximum_sequence} for the bounded stage plan."
            )
        expected_kind_type = {
            DecisionStage.INITIAL: ProbeKind,
            DecisionStage.CONFIRMATION: ConfirmationKind,
            DecisionStage.TIME: TimeProbeKind,
        }[self.stage]
        if not isinstance(self.probe_kind, expected_kind_type):
            raise TypeError("Operational probe kind is invalid.")
        response_condition = self.condition in {
            OperationalCondition.RATE_LIMITED,
            OperationalCondition.TRUNCATED,
            OperationalCondition.NON_SUCCESS_STATUS,
            TimeOperationalCondition.RATE_LIMITED,
            TimeOperationalCondition.TRUNCATED,
            TimeOperationalCondition.NON_SUCCESS_STATUS,
        }
        if response_condition:
            if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
                raise ValueError(
                    "Response-based operational facts require a valid HTTP status code."
                )
            if (
                self.condition is OperationalCondition.RATE_LIMITED
                or self.condition is TimeOperationalCondition.RATE_LIMITED
            ) and self.status_code != 429:
                raise ValueError("Rate-limited facts require HTTP status 429.")
            if (
                self.condition
                in {
                    OperationalCondition.NON_SUCCESS_STATUS,
                    TimeOperationalCondition.NON_SUCCESS_STATUS,
                }
                and 200 <= self.status_code < 300
            ):
                raise ValueError("Non-success facts require a non-2xx status.")
        elif self.status_code is not None:
            raise ValueError(
                "Facts without a completed response must omit the HTTP status code."
            )


@dataclass(frozen=True, slots=True)
class UnstablePairFacts:
    probe_kind: ProbeKind
    localization: PairLocalization
    prefix_size: int | None = None
    suffix_size: int | None = None
    first_changed_size: int | None = None
    second_changed_size: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.probe_kind, ProbeKind):
            raise TypeError("Unstable pair probe kind is invalid.")
        values = (
            self.prefix_size,
            self.suffix_size,
            self.first_changed_size,
            self.second_changed_size,
        )
        if self.localization is PairLocalization.LOCALIZED:
            if any(type(value) is not int or value < 0 for value in values):
                raise ValueError(
                    "Localized pair facts require nonnegative byte offsets and lengths."
                )
        elif self.localization is PairLocalization.UNLOCALIZED:
            if any(value is not None for value in values):
                raise ValueError(
                    "Unlocalized pair facts must omit byte offsets and lengths."
                )
        else:
            raise TypeError("Unstable pair localization is invalid.")


@dataclass(frozen=True, slots=True)
class ResponseDynamicsDecisionFacts:
    reason_code: str
    normalization_applied: bool
    normalized_echo_count: int
    unstable_pairs: tuple[UnstablePairFacts, ...]

    def __post_init__(self) -> None:
        if self.reason_code not in {
            "possible_dynamic_response",
            "unstable_response",
        }:
            raise ValueError(
                "Response-dynamics facts require a response-dynamics reason."
            )
        if type(self.normalization_applied) is not bool:
            raise TypeError("Response normalization flag must be a boolean.")
        if (
            type(self.normalized_echo_count) is not int
            or self.normalized_echo_count < 0
        ):
            raise ValueError("Normalized echo count must be a nonnegative integer.")
        if self.normalization_applied != (self.normalized_echo_count > 0):
            raise ValueError("Response normalization flag and echo count disagree.")
        if not self.unstable_pairs or any(
            not isinstance(item, UnstablePairFacts) for item in self.unstable_pairs
        ):
            raise ValueError("Response-dynamics facts require unstable pair facts.")
        order = tuple(ProbeKind)
        if self.unstable_pairs != tuple(
            item
            for kind in order
            for item in self.unstable_pairs
            if item.probe_kind is kind
        ):
            raise ValueError("Unstable pair facts must use deterministic probe order.")
        all_localized = all(
            item.localization is PairLocalization.LOCALIZED
            for item in self.unstable_pairs
        )
        if (self.reason_code == "possible_dynamic_response") is not all_localized:
            raise ValueError(
                "Response-dynamics facts contradict the reason. Use possible_dynamic_response "
                "only when every unstable pair has a localized region."
            )


@dataclass(frozen=True, slots=True)
class ConfirmationRelationDecisionFacts:
    reason_code: str
    unstable_repeat_kinds: tuple[ConfirmationKind, ...] = ()
    unreproduced_predicate_pairs: tuple[PredicatePair, ...] = ()
    mismatched_relations: tuple[ConfirmationRelation, ...] = ()
    cross_phase_mismatched_kinds: tuple[ProbeKind, ...] = ()

    def __post_init__(self) -> None:
        allowed = {
            "confirmation_unstable",
            "candidate_confirmation_mismatch",
            "confirmation_cross_phase_mismatch",
        }
        if self.reason_code not in allowed:
            raise ValueError(
                "Confirmation-relation facts require a supported confirmation reason."
            )
        for values, enum_type, name in (
            (self.unstable_repeat_kinds, ConfirmationKind, "repeat kinds"),
            (self.unreproduced_predicate_pairs, PredicatePair, "predicate pairs"),
            (self.mismatched_relations, ConfirmationRelation, "relations"),
            (self.cross_phase_mismatched_kinds, ProbeKind, "cross-phase kinds"),
        ):
            if type(values) is not tuple or any(
                not isinstance(value, enum_type) for value in values
            ):
                raise TypeError(f"Invalid confirmation {name}.")
            ordered = tuple(value for value in enum_type if value in values)
            if values != ordered:
                raise ValueError(f"Confirmation {name} must use deterministic order.")
        has_instability = bool(
            self.unstable_repeat_kinds or self.unreproduced_predicate_pairs
        )
        if self.reason_code == "confirmation_unstable":
            valid = (
                has_instability
                and not self.mismatched_relations
                and not self.cross_phase_mismatched_kinds
            )
        elif self.reason_code == "candidate_confirmation_mismatch":
            valid = (
                not has_instability
                and bool(self.mismatched_relations)
                and not self.cross_phase_mismatched_kinds
            )
        else:
            valid = (
                not has_instability
                and not self.mismatched_relations
                and bool(self.cross_phase_mismatched_kinds)
            )
        if not valid:
            raise ValueError(
                "Confirmation-relation facts contradict the reason. Use only the "
                "non-sensitive relation facts produced by confirmation analysis."
            )


@dataclass(frozen=True, slots=True)
class TimingDynamicsDecisionFacts:
    reason_code: str
    instability_causes: tuple[TimingInstabilityCause, ...] = ()
    candidate_median_met: bool | None = None
    candidate_margin_met: bool | None = None
    no_delay_condition_met: bool | None = None

    def __post_init__(self) -> None:
        if self.reason_code not in {"unstable_timing", "ambiguous_timing"}:
            raise ValueError(
                "Timing-dynamics facts require unstable_timing or ambiguous_timing."
            )
        if type(self.instability_causes) is not tuple or any(
            not isinstance(item, TimingInstabilityCause)
            for item in self.instability_causes
        ):
            raise TypeError("Invalid timing instability causes.")
        ordered = tuple(
            item for item in TimingInstabilityCause if item in self.instability_causes
        )
        if self.instability_causes != ordered:
            raise ValueError("Timing instability causes must use deterministic order.")
        candidate_values = (
            self.candidate_median_met,
            self.candidate_margin_met,
            self.no_delay_condition_met,
        )
        if self.reason_code == "unstable_timing":
            if not self.instability_causes or any(
                value is not None for value in candidate_values
            ):
                raise ValueError(
                    "Unstable timing facts require causes and must omit candidate flags."
                )
        elif self.instability_causes or any(
            type(value) is not bool for value in candidate_values
        ):
            raise ValueError(
                "Ambiguous timing facts require three boolean decision flags and no "
                "instability causes."
            )
        elif (
            self.candidate_median_met and self.candidate_margin_met
        ) or self.no_delay_condition_met:
            raise ValueError(
                "Ambiguous timing facts contradict the decision. Use candidate or "
                "not-matched classification for those flag combinations."
            )


type BooleanDecisionFacts = OperationalDecisionFacts | ResponseDynamicsDecisionFacts
type ConfirmationDecisionFacts = (
    OperationalDecisionFacts | ConfirmationRelationDecisionFacts
)
type TimeDecisionFacts = OperationalDecisionFacts | TimingDynamicsDecisionFacts


DECISION_FACT_REASONS = frozenset(
    reason for reasons in DECISION_FACT_CATEGORY_REASONS.values() for reason in reasons
)
