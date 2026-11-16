"""Describe timing evaluation across application dependency clusters.

Clusters represent declared shared provenance, not verified
statistical independence. No vulnerability verdict is produced.
"""

import math
from dataclasses import dataclass

from vintar.checks.sqli.time_application_quality import (
    ApplicationBenchmark,
    ApplicationUnit,
    summarize_applications,
)
from vintar.checks.sqli.time_quality import MAX_CASES, MAX_REPETITIONS

MAX_CLUSTER_ID_LENGTH = 100
_METRICS = frozenset(
    {
        "candidate_sensitivity",
        "false_candidate_rate",
        "classification_coverage",
    }
)


def _validate_cluster_id(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_CLUSTER_ID_LENGTH
        or not all(
            character.isascii() and (character.isalnum() or character in "_-")
            for character in value
        )
    ):
        raise ValueError("Invalid evaluation cluster identifier.")


@dataclass(frozen=True, slots=True, repr=False)
class ClusterUnit:
    """Applications with a declared common dependency boundary."""

    cluster_id: str
    applications: tuple[ApplicationUnit, ...]

    def __post_init__(self) -> None:
        _validate_cluster_id(self.cluster_id)

        if type(self.applications) is not tuple or not (
            1 <= len(self.applications) <= MAX_CASES
        ):
            raise ValueError("Invalid cluster application collection.")

        if any(
            type(application) is not ApplicationUnit
            for application in self.applications
        ):
            raise TypeError("Invalid cluster application type.")

        identifiers = tuple(
            application.application_id for application in self.applications
        )

        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("Invalid cluster application ordering.")

    @property
    def benchmark(self) -> ApplicationBenchmark:
        return ApplicationBenchmark(self.applications)

    @property
    def application_count(self) -> int:
        return len(self.applications)

    @property
    def run_count(self) -> int:
        return sum(len(app.samples) for app in self.applications)

    @property
    def execution_error_run_count(self) -> int:
        return sum(app.execution_error_count for app in self.applications)


@dataclass(frozen=True, slots=True, repr=False)
class ClusterRate:
    """Equal-weight mean of observed, eligible cluster proportions."""

    metric: str
    clusters: tuple[ClusterUnit, ...]
    values: tuple[tuple[str, float], ...]

    def __post_init__(self) -> None:
        if type(self.metric) is not str or self.metric not in _METRICS:
            raise ValueError("Invalid cluster rate metric.")

        if type(self.clusters) is not tuple or not (
            1 <= len(self.clusters) <= MAX_CASES
        ):
            raise ValueError("Invalid cluster rate provenance.")
        if any(type(cluster) is not ClusterUnit for cluster in self.clusters):
            raise TypeError("Invalid cluster rate provenance.")

        cluster_ids = tuple(cluster.cluster_id for cluster in self.clusters)
        if cluster_ids != tuple(sorted(set(cluster_ids))):
            raise ValueError("Invalid cluster rate provenance ordering.")

        if type(self.values) is not tuple or not (1 <= len(self.values) <= MAX_CASES):
            raise ValueError("Invalid cluster rate observations.")

        identifiers = []

        for item in self.values:
            if type(item) is not tuple or len(item) != 2:
                raise TypeError("Invalid cluster rate observation.")

            identifier, value = item
            _validate_cluster_id(identifier)
            identifiers.append(identifier)

            if type(value) is not float:
                raise TypeError("Invalid cluster rate value.")

            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError("Invalid cluster rate value.")

        if tuple(identifiers) != tuple(sorted(set(identifiers))):
            raise ValueError("Invalid cluster rate ordering.")

        expected = tuple(
            (cluster.cluster_id, float(rate))
            for cluster in self.clusters
            if (rate := getattr(cluster.benchmark, self.metric)) is not None
        )
        if self.values != expected:
            raise ValueError("Inconsistent cluster rate observations.")

    @property
    def contributing_clusters(self) -> int:
        return len(self.values)

    @property
    def estimate(self) -> float:
        return math.fsum(value for _, value in self.values) / len(self.values)

    @property
    def leave_one_out_range(self) -> tuple[float, float] | None:
        """Return descriptive sensitivity to removing one cluster.

        This is not a statistical confidence interval.
        """
        count = len(self.values)
        if count < 2:
            return None

        raw_values = tuple(value for _, value in self.values)
        estimates = tuple(
            math.fsum(raw_values[:index] + raw_values[index + 1 :]) / (count - 1)
            for index in range(count)
        )

        return min(estimates), max(estimates)


@dataclass(frozen=True, slots=True, repr=False)
class ClusterBenchmark:
    """Validated application partition with a repetition policy."""

    clusters: tuple[ClusterUnit, ...]
    minimum_repetitions: int = 2

    def __post_init__(self) -> None:
        if type(self.clusters) is not tuple or not (
            1 <= len(self.clusters) <= MAX_CASES
        ):
            raise ValueError("Invalid evaluation cluster collection.")

        if any(type(cluster) is not ClusterUnit for cluster in self.clusters):
            raise TypeError("Invalid evaluation cluster type.")

        if type(self.minimum_repetitions) is not int or not (
            1 <= self.minimum_repetitions <= MAX_REPETITIONS
        ):
            raise ValueError("Invalid minimum repetition policy.")

        cluster_ids = tuple(cluster.cluster_id for cluster in self.clusters)

        if cluster_ids != tuple(sorted(set(cluster_ids))):
            raise ValueError("Invalid evaluation cluster ordering.")

        application_ids = tuple(
            app.application_id
            for cluster in self.clusters
            for app in cluster.applications
        )

        if len(application_ids) > MAX_CASES or len(set(application_ids)) != len(
            application_ids
        ):
            raise ValueError("Duplicate or excessive applications.")

    @property
    def cluster_count(self) -> int:
        return len(self.clusters)

    @property
    def application_count(self) -> int:
        return sum(cluster.application_count for cluster in self.clusters)

    @property
    def run_count(self) -> int:
        return sum(cluster.run_count for cluster in self.clusters)

    @property
    def execution_error_run_count(self) -> int:
        return sum(cluster.execution_error_run_count for cluster in self.clusters)

    @property
    def application_benchmark(self) -> ApplicationBenchmark:
        return summarize_applications(
            tuple(app for cluster in self.clusters for app in cluster.applications)
        )

    @property
    def under_replicated_applications(self) -> tuple[str, ...]:
        return tuple(
            sorted(
                app.application_id
                for cluster in self.clusters
                for app in cluster.applications
                if len(app.samples) < self.minimum_repetitions
            )
        )

    @property
    def meets_repetition_policy(self) -> bool:
        return not self.under_replicated_applications

    def cluster_rate(self, metric: str) -> ClusterRate | None:
        """Average within-cluster rates over eligible clusters only.

        Missing ground-truth denominators are excluded, not imputed.
        The number of contributing clusters remains visible.
        """
        if type(metric) is not str or metric not in _METRICS:
            raise ValueError("Unsupported cluster quality metric.")

        values = []

        for cluster in self.clusters:
            rate = getattr(cluster.benchmark, metric)
            if rate is not None:
                values.append((cluster.cluster_id, float(rate)))

        if not values:
            return None

        return ClusterRate(
            metric=metric,
            clusters=self.clusters,
            values=tuple(values),
        )

    def strata(
        self,
        dimension: str,
    ) -> tuple[tuple[str, ApplicationBenchmark], ...]:
        """Return descriptive application strata, retaining all units."""
        return self.application_benchmark.strata(dimension)


def summarize_clusters(
    clusters: tuple[ClusterUnit, ...],
    *,
    minimum_repetitions: int = 2,
) -> ClusterBenchmark:
    """Canonicalize cluster ordering; do not infer cluster membership."""
    if type(clusters) is not tuple:
        raise TypeError("Invalid cluster collection.")

    if any(type(cluster) is not ClusterUnit for cluster in clusters):
        raise TypeError("Invalid cluster collection.")

    return ClusterBenchmark(
        clusters=tuple(sorted(clusters, key=lambda cluster: cluster.cluster_id)),
        minimum_repetitions=minimum_repetitions,
    )
