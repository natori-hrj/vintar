"""Evaluate experimental timing classifications by application.

Repeated executions of one application do not create independent
application samples. No vulnerability verdict is produced.
"""

from dataclasses import dataclass
from enum import Enum

from vintar.checks.sqli.time_quality import (
    MAX_CASES,
    MAX_REPETITIONS,
    GroundTruth,
    QualitySample,
)
from vintar.checks.sqli.time_research import (
    BinomialInterval,
    wilson_interval,
)

MAX_TAG_LENGTH = 100


def _validate_tag(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_TAG_LENGTH
        or not all(
            char.isascii() and (char.isalnum() or char in "_-") for char in value
        )
    ):
        raise ValueError("Invalid application evaluation identifier.")


class ApplicationOutcome(str, Enum):
    CANDIDATE = "candidate"
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE = "inconclusive"
    MIXED = "mixed"
    EXECUTION_ERROR = "execution_error"


@dataclass(frozen=True, slots=True, repr=False)
class ApplicationUnit:
    """One application with independently assigned ground truth."""

    application_id: str
    ground_truth: GroundTruth
    framework: str
    dbms: str
    sql_context: str
    samples: tuple[QualitySample, ...]

    def __post_init__(self) -> None:
        for tag in (
            self.application_id,
            self.framework,
            self.dbms,
            self.sql_context,
        ):
            _validate_tag(tag)

        if type(self.ground_truth) is not GroundTruth:
            raise TypeError("Invalid application ground truth.")

        if type(self.samples) is not tuple or not (
            1 <= len(self.samples) <= MAX_REPETITIONS
        ):
            raise ValueError("Invalid application repetitions.")

        if any(type(sample) is not QualitySample for sample in self.samples):
            raise TypeError("Invalid application sample.")

        if any(
            sample.case_id != self.application_id
            or sample.ground_truth is not self.ground_truth
            for sample in self.samples
        ):
            raise ValueError("Inconsistent application provenance.")

        iterations = tuple(sample.iteration for sample in self.samples)
        if iterations != tuple(range(len(self.samples))):
            raise ValueError("Invalid application iteration sequence.")

    @property
    def outcome(self) -> ApplicationOutcome:
        values = {
            sample.status.value if sample.status is not None else "execution_error"
            for sample in self.samples
        }

        if len(values) != 1:
            return ApplicationOutcome.MIXED

        return ApplicationOutcome(next(iter(values)))

    @property
    def status_flaky(self) -> bool:
        return self.outcome is ApplicationOutcome.MIXED

    @property
    def reason_flaky(self) -> bool:
        return len({sample.reason_code for sample in self.samples}) > 1

    @property
    def request_count(self) -> int:
        return sum(sample.budget_used for sample in self.samples)

    @property
    def dispatch_count(self) -> int:
        return sum(sample.transport_attempts for sample in self.samples)

    @property
    def server_received(self) -> int:
        return sum(sample.server_received for sample in self.samples)

    @property
    def execution_error_count(self) -> int:
        """Return failed runs, including failures inside MIXED outcomes."""
        return sum(sample.status is None for sample in self.samples)


@dataclass(frozen=True, slots=True, repr=False)
class ApplicationBenchmark:
    """Application-weighted results, never run-weighted results."""

    applications: tuple[ApplicationUnit, ...]

    def __post_init__(self) -> None:
        if type(self.applications) is not tuple or not (
            1 <= len(self.applications) <= MAX_CASES
        ):
            raise ValueError("Invalid application benchmark size.")

        if any(
            type(application) is not ApplicationUnit
            for application in self.applications
        ):
            raise TypeError("Invalid application benchmark entry.")

        identifiers = tuple(
            application.application_id for application in self.applications
        )

        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("Invalid application benchmark ordering.")

    @property
    def application_count(self) -> int:
        return len(self.applications)

    @property
    def run_count(self) -> int:
        return sum(len(app.samples) for app in self.applications)

    @property
    def vulnerable_count(self) -> int:
        return sum(
            app.ground_truth is GroundTruth.VULNERABLE for app in self.applications
        )

    @property
    def non_vulnerable_count(self) -> int:
        return self.application_count - self.vulnerable_count

    @property
    def true_candidates(self) -> int:
        return sum(
            app.ground_truth is GroundTruth.VULNERABLE
            and app.outcome is ApplicationOutcome.CANDIDATE
            for app in self.applications
        )

    @property
    def false_candidates(self) -> int:
        return sum(
            app.ground_truth is GroundTruth.NON_VULNERABLE
            and app.outcome is ApplicationOutcome.CANDIDATE
            for app in self.applications
        )

    @property
    def candidate_sensitivity(self) -> float | None:
        if not self.vulnerable_count:
            return None
        return self.true_candidates / self.vulnerable_count

    @property
    def false_candidate_rate(self) -> float | None:
        if not self.non_vulnerable_count:
            return None
        return self.false_candidates / self.non_vulnerable_count

    @property
    def classification_coverage(self) -> float:
        return (
            sum(
                app.outcome
                in (
                    ApplicationOutcome.CANDIDATE,
                    ApplicationOutcome.NOT_CONFIRMED,
                )
                for app in self.applications
            )
            / self.application_count
        )

    @property
    def abstention_rate(self) -> float:
        return (
            sum(
                app.outcome
                in (
                    ApplicationOutcome.INCONCLUSIVE,
                    ApplicationOutcome.MIXED,
                )
                for app in self.applications
            )
            / self.application_count
        )

    @property
    def execution_error_rate(self) -> float:
        return (
            sum(
                app.outcome is ApplicationOutcome.EXECUTION_ERROR
                for app in self.applications
            )
            / self.application_count
        )

    @property
    def mixed_case_rate(self) -> float:
        return (
            sum(app.status_flaky for app in self.applications) / self.application_count
        )

    @property
    def reason_flaky_rate(self) -> float:
        return (
            sum(app.reason_flaky for app in self.applications) / self.application_count
        )

    @property
    def request_count(self) -> int:
        return sum(app.request_count for app in self.applications)

    @property
    def dispatch_count(self) -> int:
        return sum(app.dispatch_count for app in self.applications)

    @property
    def server_received(self) -> int:
        return sum(app.server_received for app in self.applications)

    @property
    def execution_error_run_count(self) -> int:
        """Preserve partial run failures hidden by application outcomes."""
        return sum(app.execution_error_count for app in self.applications)

    def sensitivity_interval(
        self,
        *,
        confidence_level: float = 0.95,
    ) -> BinomialInterval | None:
        return wilson_interval(
            successes=self.true_candidates,
            trials=self.vulnerable_count,
            confidence_level=confidence_level,
        )

    def false_candidate_interval(
        self,
        *,
        confidence_level: float = 0.95,
    ) -> BinomialInterval | None:
        return wilson_interval(
            successes=self.false_candidates,
            trials=self.non_vulnerable_count,
            confidence_level=confidence_level,
        )

    def strata(
        self,
        dimension: str,
    ) -> tuple[tuple[str, "ApplicationBenchmark"], ...]:
        """Partition applications without counting runs as new units."""
        if dimension not in ("framework", "dbms", "sql_context"):
            raise ValueError("Unsupported application stratum.")

        names = sorted({getattr(app, dimension) for app in self.applications})

        return tuple(
            (
                name,
                ApplicationBenchmark(
                    applications=tuple(
                        app
                        for app in self.applications
                        if getattr(app, dimension) == name
                    )
                ),
            )
            for name in names
        )


def summarize_applications(
    applications: tuple[ApplicationUnit, ...],
) -> ApplicationBenchmark:
    """Canonicalize ordering without modifying application outcomes."""
    if type(applications) is not tuple:
        raise TypeError("Invalid application collection.")

    if any(type(app) is not ApplicationUnit for app in applications):
        raise TypeError("Invalid application collection.")

    return ApplicationBenchmark(
        applications=tuple(
            sorted(
                applications,
                key=lambda app: app.application_id,
            )
        )
    )
