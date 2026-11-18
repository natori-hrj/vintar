"""Track declared provenance of experimental timing evaluation corpora.

Identifiers and evidence references are metadata supplied by a trusted
researcher. This module cannot verify external evidence or statistical
independence. It performs no network or filesystem I/O.
"""

from dataclasses import dataclass, field
from enum import StrEnum

from vintar.checks.sqli.time_cluster_quality import ClusterBenchmark
from vintar.checks.sqli.time_quality import GroundTruth

MAX_IDENTIFIER_LENGTH = 100
MAX_DEPENDENCIES = 100


def _identifier(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_IDENTIFIER_LENGTH
        or not all(
            char.isascii() and (char.isalnum() or char in "_-") for char in value
        )
    ):
        raise ValueError("Invalid provenance identifier.")


def _identifiers(values: object, *, allow_empty: bool = False) -> None:
    if type(values) is not tuple:
        raise TypeError("Invalid provenance identifiers.")

    minimum = 0 if allow_empty else 1
    if not minimum <= len(values) <= MAX_DEPENDENCIES:
        raise ValueError("Invalid provenance identifier count.")

    for value in values:
        _identifier(value)

    if values != tuple(sorted(set(values))):
        raise ValueError("Invalid provenance identifier ordering.")


class RegistrationStatus(StrEnum):
    PRE_REGISTERED = "pre_registered"
    RETROSPECTIVE = "retrospective"


class ClusterBasis(StrEnum):
    SHARED_SOURCE = "shared_source"
    SHARED_RUNTIME = "shared_runtime"
    SHARED_HARNESS = "shared_harness"
    MULTIPLE_DEPENDENCIES = "multiple_dependencies"


class GroundTruthMethod(StrEnum):
    SQL_EXECUTION_TRACE = "sql_execution_trace"
    SOURCE_REVIEW = "source_review"
    NON_SQL_IMPLEMENTATION = "non_sql_implementation"


@dataclass(frozen=True, slots=True, repr=False)
class ClusterProvenance:
    """Declared grouping rationale and shared dependency identifiers."""

    cluster_id: str
    basis: ClusterBasis
    rationale_evidence_id: str
    dependency_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.cluster_id)
        _identifier(self.rationale_evidence_id)

        if type(self.basis) is not ClusterBasis:
            raise TypeError("Invalid cluster grouping basis.")

        _identifiers(self.dependency_ids)

        if (
            self.basis is ClusterBasis.MULTIPLE_DEPENDENCIES
            and len(self.dependency_ids) < 2
        ):
            raise ValueError("Multiple-dependency basis requires multiple identifiers.")


@dataclass(frozen=True, slots=True, repr=False)
class ApplicationProvenance:
    """Declared application lineage and ground-truth evidence."""

    application_id: str
    cluster_id: str
    source_family_id: str
    runtime_family_id: str
    ground_truth: GroundTruth
    ground_truth_method: GroundTruthMethod
    ground_truth_evidence_id: str
    evaluation_plan_id: str

    def __post_init__(self) -> None:
        for value in (
            self.application_id,
            self.cluster_id,
            self.source_family_id,
            self.runtime_family_id,
            self.ground_truth_evidence_id,
            self.evaluation_plan_id,
        ):
            _identifier(value)

        if type(self.ground_truth) is not GroundTruth:
            raise TypeError("Invalid provenance ground truth.")

        if type(self.ground_truth_method) is not GroundTruthMethod:
            raise TypeError("Invalid provenance ground truth method.")

        if (
            self.ground_truth_method is GroundTruthMethod.NON_SQL_IMPLEMENTATION
            and self.ground_truth is GroundTruth.VULNERABLE
        ):
            raise ValueError("Inconsistent non-SQL ground truth declaration.")


@dataclass(frozen=True, slots=True)
class DependencyOverlap:
    """One declared dependency shared across different clusters."""

    category: str
    dependency_id: str
    cluster_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.category) is not str or self.category not in (
            "source_family",
            "runtime_family",
            "declared_dependency",
        ):
            raise ValueError("Invalid overlap category.")

        _identifier(self.dependency_id)
        _identifiers(self.cluster_ids)

        if len(self.cluster_ids) < 2:
            raise ValueError("An overlap requires multiple clusters.")


@dataclass(frozen=True, slots=True, repr=False)
class ProvenanceManifest:
    """Validated coverage of a cluster benchmark's declared origins."""

    benchmark: ClusterBenchmark = field(repr=False)
    registration: RegistrationStatus
    registration_evidence_id: str
    clusters: tuple[ClusterProvenance, ...] = field(repr=False)
    applications: tuple[ApplicationProvenance, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.benchmark) is not ClusterBenchmark:
            raise TypeError("Invalid provenance benchmark.")

        if type(self.registration) is not RegistrationStatus:
            raise TypeError("Invalid evaluation registration status.")

        _identifier(self.registration_evidence_id)

        if type(self.clusters) is not tuple or type(self.applications) is not tuple:
            raise TypeError("Invalid provenance collection.")

        if any(type(item) is not ClusterProvenance for item in self.clusters):
            raise TypeError("Invalid cluster provenance.")

        if any(type(item) is not ApplicationProvenance for item in self.applications):
            raise TypeError("Invalid application provenance.")

        expected_clusters = tuple(
            cluster.cluster_id for cluster in self.benchmark.clusters
        )
        actual_clusters = tuple(item.cluster_id for item in self.clusters)

        if actual_clusters != expected_clusters:
            raise ValueError("Cluster provenance does not match benchmark.")

        benchmark_applications = {
            application.application_id: (cluster.cluster_id, application.ground_truth)
            for cluster in self.benchmark.clusters
            for application in cluster.applications
        }

        actual_application_ids = tuple(
            item.application_id for item in self.applications
        )

        if actual_application_ids != tuple(sorted(benchmark_applications)):
            raise ValueError("Application provenance does not match benchmark.")

        for item in self.applications:
            expected_cluster, expected_truth = benchmark_applications[
                item.application_id
            ]
            if (
                item.cluster_id != expected_cluster
                or item.ground_truth is not expected_truth
            ):
                raise ValueError("Inconsistent application provenance.")

        applications_by_cluster = {
            cluster_id: tuple(
                item for item in self.applications if item.cluster_id == cluster_id
            )
            for cluster_id in expected_clusters
        }

        for cluster in self.clusters:
            records = applications_by_cluster[cluster.cluster_id]
            if (
                cluster.basis is ClusterBasis.SHARED_SOURCE
                and len({item.source_family_id for item in records}) != 1
            ):
                raise ValueError("Inconsistent shared-source cluster provenance.")
            if (
                cluster.basis is ClusterBasis.SHARED_RUNTIME
                and len({item.runtime_family_id for item in records}) != 1
            ):
                raise ValueError("Inconsistent shared-runtime cluster provenance.")

    @property
    def cluster_count(self) -> int:
        return self.benchmark.cluster_count

    @property
    def application_count(self) -> int:
        return self.benchmark.application_count

    @property
    def run_count(self) -> int:
        return self.benchmark.run_count

    @property
    def is_pre_registered(self) -> bool:
        """Return the declaration, not proof of actual pre-registration."""
        return self.registration is RegistrationStatus.PRE_REGISTERED

    @property
    def dependency_overlaps(self) -> tuple[DependencyOverlap, ...]:
        """Find declared dependencies spanning more than one cluster."""
        index: dict[tuple[str, str], set[str]] = {}

        for item in self.applications:
            index.setdefault(("source_family", item.source_family_id), set()).add(
                item.cluster_id
            )
            index.setdefault(("runtime_family", item.runtime_family_id), set()).add(
                item.cluster_id
            )

        for cluster in self.clusters:
            for dependency_id in cluster.dependency_ids:
                index.setdefault(("declared_dependency", dependency_id), set()).add(
                    cluster.cluster_id
                )

        return tuple(
            DependencyOverlap(
                category=category,
                dependency_id=dependency_id,
                cluster_ids=tuple(sorted(cluster_ids)),
            )
            for (category, dependency_id), cluster_ids in sorted(index.items())
            if len(cluster_ids) > 1
        )

    @property
    def has_cross_cluster_dependencies(self) -> bool:
        return bool(self.dependency_overlaps)

    @property
    def meets_repetition_policy(self) -> bool:
        return self.benchmark.meets_repetition_policy


def create_provenance_manifest(
    *,
    benchmark: ClusterBenchmark,
    registration: RegistrationStatus,
    registration_evidence_id: str,
    clusters: tuple[ClusterProvenance, ...],
    applications: tuple[ApplicationProvenance, ...],
) -> ProvenanceManifest:
    """Canonicalize records while retaining the exact benchmark."""
    if type(clusters) is not tuple or type(applications) is not tuple:
        raise TypeError("Invalid provenance collection.")

    if any(type(item) is not ClusterProvenance for item in clusters):
        raise TypeError("Invalid cluster provenance.")

    if any(type(item) is not ApplicationProvenance for item in applications):
        raise TypeError("Invalid application provenance.")

    return ProvenanceManifest(
        benchmark=benchmark,
        registration=registration,
        registration_evidence_id=registration_evidence_id,
        clusters=tuple(sorted(clusters, key=lambda item: item.cluster_id)),
        applications=tuple(sorted(applications, key=lambda item: item.application_id)),
    )
