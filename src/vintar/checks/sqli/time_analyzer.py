"""Analyze bounded time-based SQL injection observations.

This module performs no HTTP I/O and does not verify SQL execution.
Timing thresholds are experimental and are not production-validated.
"""

import math
import statistics
from dataclasses import dataclass, field
from enum import StrEnum

from vintar.checks.sqli.decision_facts import (
    DecisionStage,
    OperationalCondition,
    OperationalDecisionFacts,
    TimeDecisionFacts,
    TimeOperationalCondition,
    TimingDynamicsDecisionFacts,
    TimingInstabilityCause,
    response_operational_condition,
)
from vintar.checks.sqli.time_contract import (
    TIME_RESULT_RULES,
    TimeAnalysisStatus,
)
from vintar.checks.sqli.time_plan import (
    MAX_DELAY_SECONDS,
    MIN_DELAY_SECONDS,
    TIME_PROBE_ORDER,
    TIME_REQUESTS,
    TimePlan,
    TimeProbeKind,
)

__all__ = ["TimeAnalysisStatus"]


class TimeProbeOutcome(StrEnum):
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    REQUEST_FAILED = "request_failed"
    INTERRUPTED = "interrupted"


REASONS = {
    status: frozenset(
        reason
        for reason, rule in TIME_RESULT_RULES.items()
        if rule.analysis_status is status
    )
    for status in TimeAnalysisStatus
}

_EVIDENCE_REASONS = frozenset(
    reason for reason, rule in TIME_RESULT_RULES.items() if rule.requires_evidence
)
_MAX_MEASUREMENT_SECONDS = 1_000_000
_COMPARISON_TOLERANCE = 1e-12


def _seconds(value: object, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None

    if type(value) is not int and type(value) is not float:
        raise TypeError("Invalid timing measurement.")

    # Check the range before converting huge integers to float.
    if value < 0 or value > _MAX_MEASUREMENT_SECONDS:
        raise ValueError("Invalid timing measurement.")

    if not math.isfinite(value):
        raise ValueError("Invalid timing measurement.")

    return float(value)


@dataclass(frozen=True, slots=True)
class TimeObservation:
    """Sanitized metadata for one attempted timing probe.

    elapsed_seconds is the completed transport-observed response
    duration, excluding rate-limiter waiting time.

    A failed or interrupted probe has no usable completed-response
    latency, even if partial elapsed time was observed elsewhere.
    """

    kind: TimeProbeKind
    sequence: int
    outcome: TimeProbeOutcome
    elapsed_seconds: float | None = None
    status_code: int | None = None
    truncated: bool = False
    rate_wait_seconds: float = 0.0

    def __post_init__(self) -> None:
        if type(self.kind) is not TimeProbeKind:
            raise TypeError("Invalid timing probe kind.")

        if type(self.sequence) is not int:
            raise TypeError("Invalid timing probe sequence.")

        if not 1 <= self.sequence <= TIME_REQUESTS:
            raise ValueError("Invalid timing probe sequence.")

        if type(self.outcome) is not TimeProbeOutcome:
            raise TypeError("Invalid timing probe outcome.")

        if type(self.truncated) is not bool:
            raise TypeError("Invalid timing truncation flag.")

        _seconds(self.rate_wait_seconds)

        if self.outcome is TimeProbeOutcome.COMPLETED:
            if self.elapsed_seconds is None:
                raise ValueError("Missing completed response time.")
            _seconds(self.elapsed_seconds)

            if type(self.status_code) is not int:
                raise TypeError("Invalid timing HTTP status.")

            if not 100 <= self.status_code <= 599:
                raise ValueError("Invalid timing HTTP status.")
        else:
            if (
                self.elapsed_seconds is not None
                or self.status_code is not None
                or self.truncated
            ):
                raise ValueError("Failure cannot contain completed response data.")


@dataclass(frozen=True, slots=True)
class _CompletedObservation:
    kind: TimeProbeKind
    elapsed_seconds: float
    status_code: int
    truncated: bool


def _terminal_reason(observation: _CompletedObservation) -> str | None:
    condition = response_operational_condition(
        observation.status_code, truncated=observation.truncated
    )
    if condition is OperationalCondition.TRUNCATED:
        return "truncated_response"
    return condition.value if condition is not None else None


def _validate_observation_series(
    observations: tuple[TimeObservation, ...],
) -> tuple[str | None, tuple[_CompletedObservation, ...]]:
    if len(observations) > TIME_REQUESTS:
        raise ValueError("Too many timing observations.")

    if any(type(item) is not TimeObservation for item in observations):
        raise TypeError("Invalid timing observation.")

    terminal_reason = None
    completed = []

    for sequence, item in enumerate(observations, start=1):
        if item.sequence != sequence or item.kind is not TIME_PROBE_ORDER[sequence - 1]:
            raise ValueError("Invalid time observation order.")

        if item.outcome is TimeProbeOutcome.COMPLETED:
            elapsed = item.elapsed_seconds
            status = item.status_code
            if elapsed is None:
                raise ValueError("Missing completed response time.")
            if type(status) is not int:
                raise TypeError("Invalid timing HTTP status.")
            response = _CompletedObservation(item.kind, elapsed, status, item.truncated)
            completed.append(response)
            reason = _terminal_reason(response)
        else:
            reason = {
                TimeProbeOutcome.TIMEOUT: "probe_timeout",
                TimeProbeOutcome.REQUEST_FAILED: "probe_failed",
                TimeProbeOutcome.INTERRUPTED: "probe_interrupted",
            }[item.outcome]
        if reason is not None:
            if sequence != len(observations):
                raise ValueError("Observations continued after terminal condition.")
            terminal_reason = reason

    return terminal_reason, tuple(completed)


def time_operational_decision_facts(
    *,
    reason_code: str,
    sequence: int,
    probe_kind: TimeProbeKind,
    status_code: int | None = None,
    deadline: bool = False,
) -> OperationalDecisionFacts:
    """Build bounded operational facts from the same terminal reason decision."""
    if type(deadline) is not bool:
        raise TypeError("Time deadline fact selector must be a boolean.")
    if deadline:
        condition = TimeOperationalCondition.DEADLINE
    else:
        conditions = {
            "incomplete_probes": TimeOperationalCondition.DEADLINE,
            "probe_timeout": TimeOperationalCondition.TIMEOUT,
            "probe_failed": TimeOperationalCondition.REQUEST_FAILED,
            "probe_interrupted": TimeOperationalCondition.INTERRUPTED,
            "rate_limited": TimeOperationalCondition.RATE_LIMITED,
            "non_success_status": TimeOperationalCondition.NON_SUCCESS_STATUS,
            "truncated_response": TimeOperationalCondition.TRUNCATED,
        }
        try:
            condition = conditions[reason_code]
        except KeyError:
            raise ValueError(
                "Time operational facts require a terminal Time reason. Use the "
                "reason selected by the timing analyzer."
            ) from None
    return OperationalDecisionFacts(
        reason_code=reason_code,
        stage=DecisionStage.TIME,
        sequence=sequence,
        probe_kind=probe_kind,
        condition=condition,
        status_code=status_code,
    )


def _validate_time_operational_facts(
    facts: TimeDecisionFacts,
    *,
    observations: tuple[TimeObservation, ...],
) -> None:
    if not isinstance(facts, OperationalDecisionFacts):
        raise TypeError(
            "Operational Time reason requires operational facts. Use facts produced "
            "by the timing analyzer or runner."
        )
    if facts.reason_code == "incomplete_probes":
        expected_sequence = len(observations) + 1
        expected_kind = TIME_PROBE_ORDER[expected_sequence - 1]
    else:
        last = observations[-1]
        expected_sequence = last.sequence
        expected_kind = last.kind
    if facts.sequence != expected_sequence or facts.probe_kind is not expected_kind:
        raise ValueError(
            "Time operational facts do not identify the stopping plan position. Use "
            "the sequence and probe kind selected by the bounded runner."
        )
    last_status = (
        observations[-1].status_code
        if facts.reason_code != "incomplete_probes"
        and observations
        and observations[-1].outcome is TimeProbeOutcome.COMPLETED
        else None
    )
    if facts.status_code != last_status:
        raise ValueError(
            "Time operational status facts contradict the stopping observation. Use "
            "the completed response status or omit it when no response exists."
        )


@dataclass(frozen=True, slots=True)
class TimeEvidence:
    """Experimental timing summary without raw HTTP response content."""

    baseline_median: float
    control_median: float
    delay_median: float
    median_excess: float
    baseline_control_difference: float
    baseline_span: float
    control_span: float
    delay_span: float
    drift: float
    minimum_delay_margin: float

    def __post_init__(self) -> None:
        signed = {
            "median_excess",
            "minimum_delay_margin",
        }

        for name in self.__dataclass_fields__:
            value = getattr(self, name)

            if type(value) is not int and type(value) is not float:
                raise TypeError("Invalid timing evidence.")

            if not -_MAX_MEASUREMENT_SECONDS <= value <= _MAX_MEASUREMENT_SECONDS:
                raise ValueError("Invalid timing evidence.")

            if not math.isfinite(value):
                raise ValueError("Invalid timing evidence.")

            if name not in signed and value < 0:
                raise ValueError("Invalid timing evidence.")

        if not math.isclose(
            self.median_excess,
            self.delay_median - self.control_median,
            rel_tol=_COMPARISON_TOLERANCE,
            abs_tol=_COMPARISON_TOLERANCE,
        ):
            raise ValueError("Inconsistent timing evidence.")

        if not math.isclose(
            self.baseline_control_difference,
            abs(self.baseline_median - self.control_median),
            rel_tol=_COMPARISON_TOLERANCE,
            abs_tol=_COMPARISON_TOLERANCE,
        ):
            raise ValueError("Inconsistent timing evidence.")


@dataclass(frozen=True, slots=True, repr=False)
class TimeAnalysis:
    """Experimental timing classification; never a vulnerability verdict."""

    status: TimeAnalysisStatus
    reason_code: str
    expected_delay_seconds: float
    observations: tuple[TimeObservation, ...] = field(repr=False)
    evidence: TimeEvidence | None = field(default=None, repr=False)
    decision_facts: TimeDecisionFacts | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not TimeAnalysisStatus:
            raise TypeError("Invalid timing analysis status.")

        if type(self.reason_code) is not str:
            raise TypeError("Invalid timing analysis reason.")

        rule = TIME_RESULT_RULES.get(self.reason_code)
        if rule is None:
            raise ValueError(
                "Unsupported timing analysis reason. Use a reason declared in TIME_RESULT_RULES."
            )
        if self.status is not rule.analysis_status:
            raise ValueError(
                "Timing analysis status does not match its reason. Use the status declared in TIME_RESULT_RULES."
            )

        expected_delay = self.expected_delay_seconds
        if type(expected_delay) is not int and type(expected_delay) is not float:
            raise TypeError("Invalid expected timing delay.")
        if not MIN_DELAY_SECONDS <= expected_delay <= MAX_DELAY_SECONDS:
            raise ValueError("Invalid expected timing delay.")
        if not math.isfinite(expected_delay):
            raise ValueError("Invalid expected timing delay.")

        if type(self.observations) is not tuple:
            raise TypeError("Invalid timing observations.")

        if any(type(item) is not TimeObservation for item in self.observations):
            raise TypeError("Invalid timing observation.")

        if self.evidence is not None and type(self.evidence) is not TimeEvidence:
            raise TypeError("Invalid timing evidence.")
        if self.decision_facts is not None:
            if not isinstance(
                self.decision_facts,
                (OperationalDecisionFacts, TimingDynamicsDecisionFacts),
            ):
                raise TypeError("Invalid timing decision facts.")
            if self.decision_facts.reason_code != self.reason_code:
                raise ValueError(
                    "Timing decision facts contradict the reason. Use facts produced "
                    "by the same timing decision."
                )

        request_count = len(self.observations)
        if not rule.minimum_requests <= request_count <= rule.maximum_requests:
            raise ValueError(
                "Timing observation count does not match its reason. Use the bounded request range declared in TIME_RESULT_RULES."
            )
        if rule.requires_complete_nine and request_count != TIME_REQUESTS:
            raise ValueError(
                "This timing reason requires all nine probes. Supply a complete nine-observation series instead."
            )
        if rule.requires_evidence != (self.evidence is not None):
            raise ValueError(
                "Incomplete timing classification evidence. Supply evidence only for complete evidence-based classifications."
            )

        terminal_reason, completed = _validate_observation_series(self.observations)

        if terminal_reason is not None:
            if (
                self.status is not TimeAnalysisStatus.INCONCLUSIVE
                or self.reason_code != terminal_reason
                or self.evidence is not None
            ):
                raise ValueError("Inconsistent terminal timing analysis.")
            if self.decision_facts is not None:
                _validate_time_operational_facts(
                    self.decision_facts,
                    observations=self.observations,
                )
            return

        if len(self.observations) != TIME_REQUESTS:
            if (
                self.status is not TimeAnalysisStatus.INCONCLUSIVE
                or self.reason_code != "incomplete_probes"
                or self.evidence is not None
            ):
                raise ValueError("Incomplete timing classification.")
            if self.decision_facts is not None:
                _validate_time_operational_facts(
                    self.decision_facts,
                    observations=self.observations,
                )
            return

        if self.reason_code not in _EVIDENCE_REASONS or self.evidence is None:
            raise ValueError("Incomplete timing classification evidence.")

        if self.evidence != _build_evidence(completed):
            raise ValueError("Evidence does not match timing observations.")

        expected_status, expected_reason, expected_facts = _classify_evidence(
            self.evidence,
            float(expected_delay),
        )
        if (self.status, self.reason_code) != (expected_status, expected_reason):
            raise ValueError("Classification does not match timing evidence.")
        if self.decision_facts is not None and self.decision_facts != expected_facts:
            raise ValueError(
                "Timing dynamics facts do not match timing evidence. Use facts "
                "computed by the timing analyzer."
            )

    @property
    def request_count(self) -> int:
        """Number of recorded probe attempts, not budget accounting."""
        return len(self.observations)


def _span(values: tuple[float, ...]) -> float:
    return max(values) - min(values)


def _build_evidence(
    observations: tuple[_CompletedObservation, ...],
) -> TimeEvidence:
    groups = {
        kind: tuple(item.elapsed_seconds for item in observations if item.kind is kind)
        for kind in TimeProbeKind
    }

    baseline = groups[TimeProbeKind.BASELINE]
    control = groups[TimeProbeKind.CONTROL]
    delayed = groups[TimeProbeKind.DELAY]

    baseline_median = statistics.median(baseline)
    control_median = statistics.median(control)
    delay_median = statistics.median(delayed)

    return TimeEvidence(
        baseline_median=baseline_median,
        control_median=control_median,
        delay_median=delay_median,
        median_excess=delay_median - control_median,
        baseline_control_difference=abs(baseline_median - control_median),
        baseline_span=_span(baseline),
        control_span=_span(control),
        delay_span=_span(delayed),
        drift=max(
            abs(baseline[-1] - baseline[0]),
            abs(control[-1] - control[0]),
        ),
        minimum_delay_margin=min(delayed) - max(control),
    )


def _greater_than(value: float, limit: float) -> bool:
    return value > limit and not math.isclose(
        value,
        limit,
        rel_tol=_COMPARISON_TOLERANCE,
        abs_tol=_COMPARISON_TOLERANCE,
    )


def _at_least(value: float, limit: float) -> bool:
    return value > limit or math.isclose(
        value,
        limit,
        rel_tol=_COMPARISON_TOLERANCE,
        abs_tol=_COMPARISON_TOLERANCE,
    )


def _at_most(value: float, limit: float) -> bool:
    return value < limit or math.isclose(
        value,
        limit,
        rel_tol=_COMPARISON_TOLERANCE,
        abs_tol=_COMPARISON_TOLERANCE,
    )


def _delay_stable_enough_to_conclude_absence(
    evidence: TimeEvidence,
    stability_limit: float,
) -> bool:
    return not _greater_than(evidence.delay_span, stability_limit)


def _classify_evidence(
    evidence: TimeEvidence,
    expected_delay: float,
) -> tuple[TimeAnalysisStatus, str, TimingDynamicsDecisionFacts | None]:
    # Conservative empirical limits for a laboratory experiment.
    # These thresholds are not production calibrated.
    stability_limit = max(0.12, expected_delay * 0.25)
    candidate_median_limit = expected_delay * 0.75
    candidate_margin_limit = expected_delay * 0.50
    no_delay_limit = expected_delay * 0.25
    drift_unstable = _greater_than(evidence.drift, stability_limit)

    instability_causes = tuple(
        cause
        for cause, unstable in (
            (
                TimingInstabilityCause.BASELINE_SPAN,
                _greater_than(evidence.baseline_span, stability_limit)
                and not drift_unstable,
            ),
            (
                TimingInstabilityCause.CONTROL_SPAN,
                _greater_than(evidence.control_span, stability_limit)
                and not drift_unstable,
            ),
            (
                TimingInstabilityCause.BASELINE_CONTROL_DIFFERENCE,
                _greater_than(
                    evidence.baseline_control_difference,
                    stability_limit,
                ),
            ),
            (
                TimingInstabilityCause.DRIFT,
                drift_unstable,
            ),
            (
                TimingInstabilityCause.DELAY_SPAN,
                not _delay_stable_enough_to_conclude_absence(evidence, stability_limit),
            ),
        )
        if unstable
    )
    baseline_control_unstable = any(
        cause is not TimingInstabilityCause.DELAY_SPAN for cause in instability_causes
    )
    candidate_median_met = _at_least(evidence.median_excess, candidate_median_limit)
    candidate_margin_met = _at_least(
        evidence.minimum_delay_margin, candidate_margin_limit
    )
    no_delay_condition_met = _at_most(evidence.median_excess, no_delay_limit)

    if baseline_control_unstable:
        return (
            TimeAnalysisStatus.INCONCLUSIVE,
            "unstable_timing",
            TimingDynamicsDecisionFacts(
                reason_code="unstable_timing",
                instability_causes=instability_causes,
            ),
        )

    if candidate_median_met and candidate_margin_met:
        return TimeAnalysisStatus.CANDIDATE, "timing_pattern_matched", None

    if TimingInstabilityCause.DELAY_SPAN in instability_causes:
        return (
            TimeAnalysisStatus.INCONCLUSIVE,
            "unstable_timing",
            TimingDynamicsDecisionFacts(
                reason_code="unstable_timing",
                instability_causes=instability_causes,
            ),
        )

    if no_delay_condition_met:
        return TimeAnalysisStatus.NOT_CONFIRMED, "timing_pattern_not_matched", None

    return (
        TimeAnalysisStatus.INCONCLUSIVE,
        "ambiguous_timing",
        TimingDynamicsDecisionFacts(
            reason_code="ambiguous_timing",
            candidate_median_met=candidate_median_met,
            candidate_margin_met=candidate_margin_met,
            no_delay_condition_met=no_delay_condition_met,
        ),
    )


def analyze_time_probes(
    *,
    plan: TimePlan,
    observations: tuple[TimeObservation, ...],
) -> TimeAnalysis:
    """Apply conservative experimental timing heuristics.

    Only a complete, successful, stable set of nine responses may
    become CANDIDATE or NOT_CONFIRMED.

    No clock, transport, authorization, or observation provenance
    is established by this pure function.
    """
    if type(plan) is not TimePlan:
        raise TypeError("Invalid time analysis plan.")

    if type(observations) is not tuple:
        raise TypeError("Invalid time analysis observations.")

    terminal_reason, completed = _validate_observation_series(observations)

    if terminal_reason is not None:
        last = observations[-1]
        return TimeAnalysis(
            status=TimeAnalysisStatus.INCONCLUSIVE,
            reason_code=terminal_reason,
            expected_delay_seconds=plan.expected_delay_seconds,
            observations=observations,
            decision_facts=time_operational_decision_facts(
                reason_code=terminal_reason,
                sequence=last.sequence,
                probe_kind=last.kind,
                status_code=(
                    last.status_code
                    if last.outcome is TimeProbeOutcome.COMPLETED
                    else None
                ),
            ),
        )

    if len(observations) != TIME_REQUESTS:
        next_sequence = len(observations) + 1
        return TimeAnalysis(
            status=TimeAnalysisStatus.INCONCLUSIVE,
            reason_code="incomplete_probes",
            expected_delay_seconds=plan.expected_delay_seconds,
            observations=observations,
            decision_facts=time_operational_decision_facts(
                reason_code="incomplete_probes",
                sequence=next_sequence,
                probe_kind=TIME_PROBE_ORDER[next_sequence - 1],
                deadline=True,
            ),
        )

    # Span-based jitter and endpoint drift are conservative
    # heuristics, not formal statistical tests.
    evidence = _build_evidence(completed)

    status, reason_code, decision_facts = _classify_evidence(
        evidence,
        plan.expected_delay_seconds,
    )
    return TimeAnalysis(
        status=status,
        reason_code=reason_code,
        expected_delay_seconds=plan.expected_delay_seconds,
        observations=observations,
        evidence=evidence,
        decision_facts=decision_facts,
    )
