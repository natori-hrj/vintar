"""Research-only extensions for time-based SQLi evaluation.

Confidence intervals describe observed binary rates within a defined
sample. Independent controls do not prove that SQL was executed.
"""

import math
from dataclasses import dataclass
from enum import Enum
from statistics import NormalDist

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_quality import (
    MAX_CASE_ID_LENGTH,
    MAX_CASES,
    MAX_REPETITIONS,
    QualitySummary,
)

MAX_INTERVAL_SAMPLES = MAX_CASES * MAX_REPETITIONS
_RATE_TOLERANCE = 1e-12


def _validate_case_id(value: object) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_CASE_ID_LENGTH
        or not all(
            char.isascii() and (char.isalnum() or char in "_-") for char in value
        )
    ):
        raise ValueError("Invalid research case identifier.")


def _validate_rate(value: object, expected: float) -> None:
    if type(value) is not float:
        raise TypeError("Invalid research rate.")
    if not 0 <= value <= 1 or not math.isfinite(value):
        raise ValueError("Invalid research rate.")
    if not math.isclose(
        value,
        expected,
        rel_tol=_RATE_TOLERANCE,
        abs_tol=_RATE_TOLERANCE,
    ):
        raise ValueError("Inconsistent research rate.")


@dataclass(frozen=True, slots=True)
class BinomialInterval:
    """Wilson score interval for an observed binomial proportion."""

    successes: int
    trials: int
    confidence_level: float
    estimate: float
    lower: float
    upper: float

    def __post_init__(self) -> None:
        if type(self.successes) is not int or type(self.trials) is not int:
            raise TypeError("Invalid binomial counts.")

        if not 0 <= self.successes <= self.trials <= MAX_INTERVAL_SAMPLES:
            raise ValueError("Invalid binomial counts.")

        if self.trials == 0:
            raise ValueError("A binomial interval requires observations.")

        if type(self.confidence_level) is not float:
            raise TypeError("Invalid confidence level.")

        if not math.isfinite(self.confidence_level) or not (
            0.5 <= self.confidence_level <= 0.999
        ):
            raise ValueError("Invalid confidence level.")

        expected = _wilson_values(
            self.successes,
            self.trials,
            self.confidence_level,
        )

        for observed, calculated in zip(
            (self.estimate, self.lower, self.upper),
            expected,
            strict=True,
        ):
            if type(observed) is not float or not math.isfinite(observed):
                raise TypeError("Invalid binomial interval.")
            if not math.isclose(
                observed,
                calculated,
                rel_tol=1e-12,
                abs_tol=1e-12,
            ):
                raise ValueError("Inconsistent binomial interval.")

        if not 0 <= self.lower <= self.estimate <= self.upper <= 1:
            raise ValueError("Invalid binomial interval bounds.")


def _wilson_values(
    successes: int,
    trials: int,
    confidence_level: float,
) -> tuple[float, float, float]:
    proportion = successes / trials
    z = NormalDist().inv_cdf((1 + confidence_level) / 2)
    z_squared = z * z
    denominator = 1 + z_squared / trials
    center = (proportion + z_squared / (2 * trials)) / denominator
    half_width = (
        z
        * math.sqrt(
            proportion * (1 - proportion) / trials + z_squared / (4 * trials * trials)
        )
        / denominator
    )
    return (
        proportion,
        max(0.0, min(proportion, center - half_width)),
        min(1.0, max(proportion, center + half_width)),
    )


def wilson_interval(
    *,
    successes: int,
    trials: int,
    confidence_level: float = 0.95,
) -> BinomialInterval | None:
    """Calculate a descriptive interval; return None for zero trials.

    Repeated runs of the same fixture may be dependent observations.
    In that case this interval must not be interpreted as an
    independent-sample coverage guarantee.
    """
    if type(successes) is not int or type(trials) is not int:
        raise TypeError("Invalid binomial counts.")

    if not 0 <= successes <= trials <= MAX_INTERVAL_SAMPLES:
        raise ValueError("Invalid binomial counts.")

    if type(confidence_level) is not float:
        raise TypeError("Invalid confidence level.")
    if not (0.5 <= confidence_level <= 0.999) or not math.isfinite(confidence_level):
        raise ValueError("Invalid confidence level.")

    if trials == 0:
        return None

    estimate, lower, upper = _wilson_values(
        successes,
        trials,
        confidence_level,
    )

    return BinomialInterval(
        successes=successes,
        trials=trials,
        confidence_level=confidence_level,
        estimate=estimate,
        lower=lower,
        upper=upper,
    )


@dataclass(frozen=True, slots=True)
class CaseStability:
    """Observed status and reason-code variation for one fixture."""

    case_id: str
    repetitions: int
    status_changed: bool
    reason_changed: bool

    def __post_init__(self) -> None:
        _validate_case_id(self.case_id)
        if type(self.repetitions) is not int or not (
            1 <= self.repetitions <= MAX_REPETITIONS
        ):
            raise ValueError("Invalid research repetition count.")
        if type(self.status_changed) is not bool:
            raise TypeError("Invalid status variability flag.")
        if type(self.reason_changed) is not bool:
            raise TypeError("Invalid reason variability flag.")


@dataclass(frozen=True, slots=True)
class ResearchSummary:
    """Additional descriptive metrics derived from a QualitySummary."""

    sensitivity_interval: BinomialInterval | None
    false_candidate_interval: BinomialInterval | None
    status_flaky_case_rate: float
    reason_flaky_case_rate: float
    case_stability: tuple[CaseStability, ...]

    def __post_init__(self) -> None:
        for interval in (
            self.sensitivity_interval,
            self.false_candidate_interval,
        ):
            if interval is not None and type(interval) is not BinomialInterval:
                raise TypeError("Invalid research interval.")

        if type(self.case_stability) is not tuple or not (
            1 <= len(self.case_stability) <= MAX_CASES
        ):
            raise ValueError("Invalid research case stability.")
        if any(type(case) is not CaseStability for case in self.case_stability):
            raise TypeError("Invalid research case stability.")

        case_ids = tuple(case.case_id for case in self.case_stability)
        if case_ids != tuple(sorted(case_ids)) or len(set(case_ids)) != len(case_ids):
            raise ValueError("Invalid research case ordering.")

        repetitions = {case.repetitions for case in self.case_stability}
        if len(repetitions) != 1:
            raise ValueError("Inconsistent research repetitions.")

        intervals = tuple(
            interval
            for interval in (
                self.sensitivity_interval,
                self.false_candidate_interval,
            )
            if interval is not None
        )
        total_runs = len(self.case_stability) * repetitions.pop()
        if sum(interval.trials for interval in intervals) != total_runs:
            raise ValueError("Inconsistent research interval trials.")
        if len({interval.confidence_level for interval in intervals}) > 1:
            raise ValueError("Inconsistent research confidence levels.")

        _validate_rate(
            self.status_flaky_case_rate,
            sum(case.status_changed for case in self.case_stability)
            / len(self.case_stability),
        )
        _validate_rate(
            self.reason_flaky_case_rate,
            sum(case.reason_changed for case in self.case_stability)
            / len(self.case_stability),
        )


def summarize_research(
    summary: QualitySummary,
    *,
    confidence_level: float = 0.95,
) -> ResearchSummary:
    """Extend an already validated quality summary."""
    if type(summary) is not QualitySummary:
        raise TypeError("Invalid research quality summary.")

    cases = tuple(
        CaseStability(
            case_id=case.case_id,
            repetitions=len(case.statuses),
            status_changed=len(set(case.statuses)) > 1,
            reason_changed=len(set(case.reasons)) > 1,
        )
        for case in summary.cases
    )

    return ResearchSummary(
        sensitivity_interval=wilson_interval(
            successes=summary.true_candidates,
            trials=summary.vulnerable_runs,
            confidence_level=confidence_level,
        ),
        false_candidate_interval=wilson_interval(
            successes=summary.false_candidates,
            trials=summary.non_vulnerable_runs,
            confidence_level=confidence_level,
        ),
        status_flaky_case_rate=(
            sum(case.status_changed for case in cases) / len(cases)
        ),
        reason_flaky_case_rate=(
            sum(case.reason_changed for case in cases) / len(cases)
        ),
        case_stability=cases,
    )


class ControlAssessment(str, Enum):
    """Research interpretation of an independently executed control."""

    CONTROL_REACTIVE = "control_reactive"
    CONTROL_NOT_REACTIVE = "control_not_reactive"
    UNDETERMINED = "undetermined"


@dataclass(frozen=True, slots=True)
class IndependentControlResult:
    """Pair results from two separately executed experiments.

    A control must be independently designed and authorized.
    The model cannot establish independence or target provenance.
    """

    primary_case_id: str
    primary_status: TimeAnalysisStatus
    control_status: TimeAnalysisStatus
    assessment: ControlAssessment

    def __post_init__(self) -> None:
        _validate_case_id(self.primary_case_id)

        if type(self.primary_status) is not TimeAnalysisStatus:
            raise TypeError("Invalid primary control status.")

        if type(self.control_status) is not TimeAnalysisStatus:
            raise TypeError("Invalid independent control status.")

        if type(self.assessment) is not ControlAssessment:
            raise TypeError("Invalid control assessment.")

        expected = _control_assessment(
            self.primary_status,
            self.control_status,
        )
        if self.assessment is not expected:
            raise ValueError("Inconsistent independent control assessment.")


def _control_assessment(
    primary: TimeAnalysisStatus,
    control: TimeAnalysisStatus,
) -> ControlAssessment:
    if primary is not TimeAnalysisStatus.CANDIDATE:
        return ControlAssessment.UNDETERMINED

    if control is TimeAnalysisStatus.CANDIDATE:
        return ControlAssessment.CONTROL_REACTIVE

    if control is TimeAnalysisStatus.NOT_CONFIRMED:
        return ControlAssessment.CONTROL_NOT_REACTIVE

    return ControlAssessment.UNDETERMINED


def assess_independent_control(
    *,
    primary_case_id: str,
    primary_status: TimeAnalysisStatus,
    control_status: TimeAnalysisStatus,
) -> IndependentControlResult:
    """Compare classifications without changing vulnerability verdicts.

    A reactive control indicates that an alternative condition can
    reproduce the timing signal, not necessarily why it occurred.

    A non-reactive control does not prove SQLi, and an observationally
    equivalent non-SQL mimic may remain undetectable.
    """
    if type(primary_status) is not TimeAnalysisStatus:
        raise TypeError("Invalid primary control status.")

    if type(control_status) is not TimeAnalysisStatus:
        raise TypeError("Invalid independent control status.")

    return IndependentControlResult(
        primary_case_id=primary_case_id,
        primary_status=primary_status,
        control_status=control_status,
        assessment=_control_assessment(
            primary_status,
            control_status,
        ),
    )
