"""Summarize experimental time-based SQLi classification reliability.

Ground truth must come from independently verified test fixtures.
These metrics do not establish real-world detector performance.
"""

import math
from dataclasses import dataclass
from enum import StrEnum

from vintar.checks.sqli.time_analyzer import (
    REASONS,
    TimeAnalysisStatus,
)
from vintar.checks.sqli.time_runner import TimeRunReport

MAX_CASES = 100
MAX_REPETITIONS = 100
MAX_CASE_ID_LENGTH = 100
MAX_REQUESTS_PER_RUN = 9
MAX_ELAPSED_SECONDS_PER_RUN = 1_000_000
_RATE_TOLERANCE = 1e-12


class GroundTruth(StrEnum):
    VULNERABLE = "vulnerable"
    NON_VULNERABLE = "non_vulnerable"


def _validate_case_id(value: object) -> None:
    if (
        type(value) is not str
        or not value
        or len(value) > MAX_CASE_ID_LENGTH
        or not all(
            char.isascii() and (char.isalnum() or char in "_-") for char in value
        )
    ):
        raise ValueError("Invalid evaluation case identifier.")


def _validate_rate(value: object, expected: float | None) -> None:
    if expected is None:
        if value is not None:
            raise ValueError("Inconsistent evaluation metric.")
        return

    if type(value) is not int and type(value) is not float:
        raise TypeError("Invalid evaluation metric.")
    if not 0 <= value <= 1 or not math.isfinite(value):
        raise ValueError("Invalid evaluation metric.")
    if not math.isclose(
        value,
        expected,
        rel_tol=_RATE_TOLERANCE,
        abs_tol=_RATE_TOLERANCE,
    ):
        raise ValueError("Inconsistent evaluation metric.")


@dataclass(frozen=True, slots=True)
class QualitySample:
    """One independently labeled execution result."""

    case_id: str
    iteration: int
    ground_truth: GroundTruth
    status: TimeAnalysisStatus | None
    reason_code: str
    budget_used: int
    transport_attempts: int
    server_received: int
    observation_count: int
    elapsed_seconds: float

    def __post_init__(self) -> None:
        _validate_case_id(self.case_id)

        if type(self.iteration) is not int or not (
            0 <= self.iteration < MAX_REPETITIONS
        ):
            raise ValueError("Invalid evaluation iteration.")

        if type(self.ground_truth) is not GroundTruth:
            raise TypeError("Invalid evaluation ground truth.")

        if self.status is None:
            if self.reason_code != "execution_error":
                raise ValueError("Invalid execution error classification.")
        elif type(self.status) is not TimeAnalysisStatus:
            raise TypeError("Invalid evaluation status.")
        elif self.reason_code not in REASONS[self.status]:
            raise ValueError("Invalid evaluation reason code.")

        counts = (
            self.budget_used,
            self.transport_attempts,
            self.server_received,
            self.observation_count,
        )
        if any(type(count) is not int for count in counts):
            raise TypeError("Invalid evaluation request count.")

        if not (
            0
            <= self.server_received
            <= self.transport_attempts
            <= self.budget_used
            <= MAX_REQUESTS_PER_RUN
        ):
            raise ValueError("Invalid evaluation request accounting.")

        if not 0 <= self.observation_count <= self.budget_used:
            raise ValueError("Invalid evaluation observation count.")

        if self.status is not None and (self.observation_count != self.budget_used):
            raise ValueError("Invalid completed evaluation accounting.")

        value = self.elapsed_seconds
        if type(value) is not int and type(value) is not float:
            raise TypeError("Invalid evaluation elapsed time.")
        if not 0 <= value <= MAX_ELAPSED_SECONDS_PER_RUN or not math.isfinite(value):
            raise ValueError("Invalid evaluation elapsed time.")


@dataclass(frozen=True, slots=True)
class CaseReliability:
    case_id: str
    ground_truth: GroundTruth
    statuses: tuple[str, ...]
    reasons: tuple[str, ...]
    flaky: bool
    execution_errors: int

    def __post_init__(self) -> None:
        _validate_case_id(self.case_id)

        if type(self.ground_truth) is not GroundTruth:
            raise TypeError("Invalid evaluation ground truth.")

        if type(self.statuses) is not tuple or not (
            1 <= len(self.statuses) <= MAX_REPETITIONS
        ):
            raise ValueError("Invalid case reliability statuses.")

        if type(self.reasons) is not tuple or len(self.reasons) != len(self.statuses):
            raise ValueError("Invalid case reliability reasons.")

        for status, reason in zip(self.statuses, self.reasons, strict=True):
            if type(status) is not str or type(reason) is not str:
                raise TypeError("Invalid case reliability outcome.")

            if status == "execution_error":
                if reason != "execution_error":
                    raise ValueError("Invalid case reliability outcome.")
                continue

            try:
                classified = TimeAnalysisStatus(status)
            except ValueError:
                raise ValueError("Invalid case reliability status.") from None

            if reason not in REASONS[classified]:
                raise ValueError("Invalid case reliability reason.")

        expected_flaky = len(set(self.statuses)) > 1
        if type(self.flaky) is not bool or self.flaky is not expected_flaky:
            raise ValueError("Inconsistent case reliability flag.")

        expected_errors = self.statuses.count("execution_error")
        if (
            type(self.execution_errors) is not int
            or self.execution_errors != expected_errors
        ):
            raise ValueError("Inconsistent case execution error count.")


@dataclass(frozen=True, slots=True)
class QualitySummary:
    """Metrics over runs, with separate case-level instability."""

    total_runs: int
    total_cases: int
    repetitions: int
    candidates: int
    not_confirmed: int
    inconclusive: int
    execution_errors: int
    vulnerable_runs: int
    non_vulnerable_runs: int
    true_candidates: int
    false_candidates: int
    candidate_sensitivity: float | None
    false_candidate_rate: float | None
    classification_coverage: float
    abstention_rate: float
    execution_error_rate: float
    conditional_false_candidate_proportion: float | None
    flaky_case_rate: float
    budget_used: int
    transport_attempts: int
    server_received: int
    observations: int
    total_elapsed_seconds: float
    cases: tuple[CaseReliability, ...]

    def __post_init__(self) -> None:
        if type(self.cases) is not tuple or not self.cases:
            raise ValueError("Invalid evaluation case summaries.")
        if any(type(case) is not CaseReliability for case in self.cases):
            raise TypeError("Invalid evaluation case summary.")

        case_ids = tuple(case.case_id for case in self.cases)
        if case_ids != tuple(sorted(case_ids)) or len(set(case_ids)) != len(case_ids):
            raise ValueError("Invalid evaluation case ordering.")

        integer_fields = (
            self.total_runs,
            self.total_cases,
            self.repetitions,
            self.candidates,
            self.not_confirmed,
            self.inconclusive,
            self.execution_errors,
            self.vulnerable_runs,
            self.non_vulnerable_runs,
            self.true_candidates,
            self.false_candidates,
            self.budget_used,
            self.transport_attempts,
            self.server_received,
            self.observations,
        )
        if any(type(value) is not int for value in integer_fields):
            raise TypeError("Invalid evaluation summary count.")

        if self.total_cases != len(self.cases) or not (
            1 <= self.total_cases <= MAX_CASES
        ):
            raise ValueError("Inconsistent evaluation case count.")
        if not 1 <= self.repetitions <= MAX_REPETITIONS:
            raise ValueError("Invalid evaluation repetition count.")
        if any(len(case.statuses) != self.repetitions for case in self.cases):
            raise ValueError("Inconsistent evaluation repetitions.")
        if self.total_runs != self.total_cases * self.repetitions:
            raise ValueError("Inconsistent evaluation run count.")

        statuses = tuple(status for case in self.cases for status in case.statuses)
        expected_candidates = statuses.count(TimeAnalysisStatus.CANDIDATE.value)
        expected_not_confirmed = statuses.count(TimeAnalysisStatus.NOT_CONFIRMED.value)
        expected_inconclusive = statuses.count(TimeAnalysisStatus.INCONCLUSIVE.value)
        expected_errors = statuses.count("execution_error")

        vulnerable_cases = tuple(
            case for case in self.cases if case.ground_truth is GroundTruth.VULNERABLE
        )
        non_vulnerable_cases = tuple(
            case
            for case in self.cases
            if case.ground_truth is GroundTruth.NON_VULNERABLE
        )
        expected_vulnerable = len(vulnerable_cases) * self.repetitions
        expected_non_vulnerable = len(non_vulnerable_cases) * self.repetitions
        expected_true_candidates = sum(
            case.statuses.count(TimeAnalysisStatus.CANDIDATE.value)
            for case in vulnerable_cases
        )
        expected_false_candidates = sum(
            case.statuses.count(TimeAnalysisStatus.CANDIDATE.value)
            for case in non_vulnerable_cases
        )
        classified_non_vulnerable = sum(
            status
            in {
                TimeAnalysisStatus.CANDIDATE.value,
                TimeAnalysisStatus.NOT_CONFIRMED.value,
            }
            for case in non_vulnerable_cases
            for status in case.statuses
        )

        expected_counts = (
            expected_candidates,
            expected_not_confirmed,
            expected_inconclusive,
            expected_errors,
            expected_vulnerable,
            expected_non_vulnerable,
            expected_true_candidates,
            expected_false_candidates,
        )
        actual_counts = (
            self.candidates,
            self.not_confirmed,
            self.inconclusive,
            self.execution_errors,
            self.vulnerable_runs,
            self.non_vulnerable_runs,
            self.true_candidates,
            self.false_candidates,
        )
        if actual_counts != expected_counts:
            raise ValueError("Inconsistent evaluation summary counts.")

        _validate_rate(
            self.candidate_sensitivity,
            expected_true_candidates / expected_vulnerable
            if expected_vulnerable
            else None,
        )
        _validate_rate(
            self.false_candidate_rate,
            expected_false_candidates / expected_non_vulnerable
            if expected_non_vulnerable
            else None,
        )
        _validate_rate(
            self.classification_coverage,
            (expected_candidates + expected_not_confirmed) / self.total_runs,
        )
        _validate_rate(
            self.abstention_rate,
            expected_inconclusive / self.total_runs,
        )
        _validate_rate(
            self.execution_error_rate,
            expected_errors / self.total_runs,
        )
        _validate_rate(
            self.conditional_false_candidate_proportion,
            expected_false_candidates / classified_non_vulnerable
            if classified_non_vulnerable
            else None,
        )
        _validate_rate(
            self.flaky_case_rate,
            sum(case.flaky for case in self.cases) / self.total_cases,
        )

        if not (
            0
            <= self.server_received
            <= self.transport_attempts
            <= self.budget_used
            <= self.total_runs * MAX_REQUESTS_PER_RUN
        ):
            raise ValueError("Invalid evaluation summary accounting.")
        if not 0 <= self.observations <= self.budget_used:
            raise ValueError("Invalid evaluation summary observations.")
        if (
            self.budget_used - self.observations
            > self.execution_errors * MAX_REQUESTS_PER_RUN
        ):
            raise ValueError("Inconsistent evaluation summary observations.")

        elapsed = self.total_elapsed_seconds
        if type(elapsed) is not int and type(elapsed) is not float:
            raise TypeError("Invalid evaluation summary duration.")
        if not (
            0 <= elapsed <= self.total_runs * MAX_ELAPSED_SECONDS_PER_RUN
        ) or not math.isfinite(elapsed):
            raise ValueError("Invalid evaluation summary duration.")


def sample_from_report(
    *,
    case_id: str,
    iteration: int,
    ground_truth: GroundTruth,
    report: TimeRunReport,
    server_received: int,
) -> QualitySample:
    """Convert an actual runner report into an evaluation record."""
    if type(report) is not TimeRunReport:
        raise TypeError("Invalid time evaluation report.")

    return QualitySample(
        case_id=case_id,
        iteration=iteration,
        ground_truth=ground_truth,
        status=report.analysis.status,
        reason_code=report.analysis.reason_code,
        budget_used=report.budget_used,
        transport_attempts=report.transport_attempts,
        server_received=server_received,
        observation_count=report.analysis.request_count,
        elapsed_seconds=report.total_elapsed_seconds,
    )


def summarize_quality(
    samples: tuple[QualitySample, ...],
) -> QualitySummary:
    """Calculate run-level rates and case-level classification changes.

    Each case must contain exactly the same number of indexed runs.
    Execution errors remain in the denominator.
    Undefined rates are returned as None.
    """
    if type(samples) is not tuple or not samples:
        raise ValueError("Evaluation samples must be a nonempty tuple.")

    if any(type(sample) is not QualitySample for sample in samples):
        raise TypeError("Invalid evaluation sample.")

    grouped: dict[str, list[QualitySample]] = {}

    for sample in samples:
        grouped.setdefault(sample.case_id, []).append(sample)

    if len(grouped) > MAX_CASES:
        raise ValueError("Too many evaluation cases.")

    repetitions = len(next(iter(grouped.values())))

    if not 1 <= repetitions <= MAX_REPETITIONS:
        raise ValueError("Invalid evaluation repetition count.")

    case_results: list[CaseReliability] = []

    for case_id in sorted(grouped):
        records = sorted(
            grouped[case_id],
            key=lambda record: record.iteration,
        )

        if len(records) != repetitions or tuple(
            record.iteration for record in records
        ) != tuple(range(repetitions)):
            raise ValueError("Unbalanced evaluation repetitions.")

        truths = {record.ground_truth for record in records}

        if len(truths) != 1:
            raise ValueError("Inconsistent evaluation ground truth.")

        statuses = tuple(
            record.status.value if record.status is not None else "execution_error"
            for record in records
        )

        case_results.append(
            CaseReliability(
                case_id=case_id,
                ground_truth=records[0].ground_truth,
                statuses=statuses,
                reasons=tuple(record.reason_code for record in records),
                flaky=len(set(statuses)) > 1,
                execution_errors=sum(record.status is None for record in records),
            )
        )

    total = len(samples)
    candidates = sum(
        sample.status is TimeAnalysisStatus.CANDIDATE for sample in samples
    )
    not_confirmed = sum(
        sample.status is TimeAnalysisStatus.NOT_CONFIRMED for sample in samples
    )
    inconclusive = sum(
        sample.status is TimeAnalysisStatus.INCONCLUSIVE for sample in samples
    )
    errors = sum(sample.status is None for sample in samples)

    vulnerable = sum(
        sample.ground_truth is GroundTruth.VULNERABLE for sample in samples
    )
    non_vulnerable = total - vulnerable

    true_candidates = sum(
        sample.ground_truth is GroundTruth.VULNERABLE
        and sample.status is TimeAnalysisStatus.CANDIDATE
        for sample in samples
    )
    false_candidates = sum(
        sample.ground_truth is GroundTruth.NON_VULNERABLE
        and sample.status is TimeAnalysisStatus.CANDIDATE
        for sample in samples
    )
    classified_non_vulnerable = sum(
        sample.ground_truth is GroundTruth.NON_VULNERABLE
        and sample.status
        in (
            TimeAnalysisStatus.CANDIDATE,
            TimeAnalysisStatus.NOT_CONFIRMED,
        )
        for sample in samples
    )

    return QualitySummary(
        total_runs=total,
        total_cases=len(grouped),
        repetitions=repetitions,
        candidates=candidates,
        not_confirmed=not_confirmed,
        inconclusive=inconclusive,
        execution_errors=errors,
        vulnerable_runs=vulnerable,
        non_vulnerable_runs=non_vulnerable,
        true_candidates=true_candidates,
        false_candidates=false_candidates,
        candidate_sensitivity=(true_candidates / vulnerable if vulnerable else None),
        false_candidate_rate=(
            false_candidates / non_vulnerable if non_vulnerable else None
        ),
        classification_coverage=(candidates + not_confirmed) / total,
        abstention_rate=inconclusive / total,
        execution_error_rate=errors / total,
        conditional_false_candidate_proportion=(
            false_candidates / classified_non_vulnerable
            if classified_non_vulnerable
            else None
        ),
        flaky_case_rate=(sum(case.flaky for case in case_results) / len(case_results)),
        budget_used=sum(sample.budget_used for sample in samples),
        transport_attempts=sum(sample.transport_attempts for sample in samples),
        server_received=sum(sample.server_received for sample in samples),
        observations=sum(sample.observation_count for sample in samples),
        total_elapsed_seconds=sum(sample.elapsed_seconds for sample in samples),
        cases=tuple(case_results),
    )
