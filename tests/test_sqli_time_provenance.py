"""Tests for declared cluster and application evaluation provenance."""

from dataclasses import replace

import pytest

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_application_quality import ApplicationUnit
from vintar.checks.sqli.time_cluster_quality import (
    ClusterUnit,
    summarize_clusters,
)
from vintar.checks.sqli.time_provenance import (
    ApplicationProvenance,
    ClusterBasis,
    ClusterProvenance,
    DependencyOverlap,
    GroundTruthMethod,
    ProvenanceManifest,
    RegistrationStatus,
    create_provenance_manifest,
)
from vintar.checks.sqli.time_quality import GroundTruth, QualitySample


def make_application(
    identifier: str,
    truth: GroundTruth,
) -> ApplicationUnit:
    status = (
        TimeAnalysisStatus.CANDIDATE
        if truth is GroundTruth.VULNERABLE
        else TimeAnalysisStatus.NOT_CONFIRMED
    )
    reason = (
        "timing_pattern_matched"
        if status is TimeAnalysisStatus.CANDIDATE
        else "timing_pattern_not_matched"
    )

    samples = tuple(
        QualitySample(
            case_id=identifier,
            iteration=index,
            ground_truth=truth,
            status=status,
            reason_code=reason,
            budget_used=9,
            transport_attempts=9,
            server_received=9,
            observation_count=9,
            elapsed_seconds=1.0,
        )
        for index in range(2)
    )

    return ApplicationUnit(
        application_id=identifier,
        ground_truth=truth,
        framework="fastapi",
        dbms="sqlite",
        sql_context="where",
        samples=samples,
    )


def make_manifest(
    *,
    registration: RegistrationStatus = RegistrationStatus.RETROSPECTIVE,
    shared_runtime: bool = True,
) -> ProvenanceManifest:
    app_a = make_application("vulnerable_a", GroundTruth.VULNERABLE)
    app_b = make_application("safe_b", GroundTruth.NON_VULNERABLE)

    benchmark = summarize_clusters(
        (
            ClusterUnit("family_a", (app_a,)),
            ClusterUnit("family_b", (app_b,)),
        )
    )

    return create_provenance_manifest(
        benchmark=benchmark,
        registration=registration,
        registration_evidence_id="registration_record_a",
        clusters=(
            ClusterProvenance(
                cluster_id="family_b",
                basis=ClusterBasis.SHARED_HARNESS,
                rationale_evidence_id="rationale_b",
                dependency_ids=("fixture_harness", "runtime_shared"),
            ),
            ClusterProvenance(
                cluster_id="family_a",
                basis=ClusterBasis.SHARED_SOURCE,
                rationale_evidence_id="rationale_a",
                dependency_ids=("fixture_harness", "source_family_a"),
            ),
        ),
        applications=(
            ApplicationProvenance(
                application_id="safe_b",
                cluster_id="family_b",
                source_family_id="source_b",
                runtime_family_id=("runtime_shared" if shared_runtime else "runtime_b"),
                ground_truth=GroundTruth.NON_VULNERABLE,
                ground_truth_method=GroundTruthMethod.SOURCE_REVIEW,
                ground_truth_evidence_id="safe_source_review",
                evaluation_plan_id="plan_b",
            ),
            ApplicationProvenance(
                application_id="vulnerable_a",
                cluster_id="family_a",
                source_family_id="source_a",
                runtime_family_id="runtime_shared",
                ground_truth=GroundTruth.VULNERABLE,
                ground_truth_method=GroundTruthMethod.SQL_EXECUTION_TRACE,
                ground_truth_evidence_id="sql_trace_a",
                evaluation_plan_id="plan_a",
            ),
        ),
    )


def test_manifest_counts_and_canonical_order():
    manifest = make_manifest()

    assert manifest.cluster_count == 2
    assert manifest.application_count == 2
    assert manifest.run_count == 4
    assert manifest.meets_repetition_policy

    assert tuple(item.cluster_id for item in manifest.clusters) == (
        "family_a",
        "family_b",
    )
    assert tuple(item.application_id for item in manifest.applications) == (
        "safe_b",
        "vulnerable_a",
    )


def test_shared_dependencies_are_reported():
    manifest = make_manifest()

    observed = {
        (item.category, item.dependency_id): item.cluster_ids
        for item in manifest.dependency_overlaps
    }

    assert observed == {
        ("declared_dependency", "fixture_harness"): (
            "family_a",
            "family_b",
        ),
        ("runtime_family", "runtime_shared"): (
            "family_a",
            "family_b",
        ),
    }
    assert manifest.has_cross_cluster_dependencies


def test_source_family_overlap_is_reported():
    manifest = make_manifest(shared_runtime=False)
    changed = replace(
        manifest.applications[1],
        source_family_id=manifest.applications[0].source_family_id,
    )
    manifest = replace(
        manifest,
        applications=(manifest.applications[0], changed),
    )

    assert any(
        item.category == "source_family"
        and item.cluster_ids == ("family_a", "family_b")
        for item in manifest.dependency_overlaps
    )


def test_no_overlap_when_declared_dependencies_are_distinct():
    manifest = make_manifest(shared_runtime=False)

    changed_clusters = (
        replace(
            manifest.clusters[0],
            dependency_ids=("source_family_a",),
        ),
        replace(
            manifest.clusters[1],
            dependency_ids=("runtime_b",),
        ),
    )
    changed = replace(manifest, clusters=changed_clusters)

    assert changed.dependency_overlaps == ()
    assert not changed.has_cross_cluster_dependencies


def test_source_and_runtime_identifier_namespaces_remain_distinct():
    manifest = make_manifest(shared_runtime=False)
    applications = (
        replace(
            manifest.applications[0],
            runtime_family_id="same_identifier",
        ),
        replace(
            manifest.applications[1],
            source_family_id="same_identifier",
        ),
    )
    changed = replace(manifest, applications=applications)

    assert not any(
        overlap.dependency_id == "same_identifier"
        for overlap in changed.dependency_overlaps
    )


def test_pre_registration_is_a_declaration():
    manifest = make_manifest(registration=RegistrationStatus.PRE_REGISTERED)

    assert manifest.is_pre_registered
    assert manifest.registration_evidence_id == "registration_record_a"


def test_retrospective_registration_is_not_pre_registration():
    assert not make_manifest().is_pre_registered


def test_ground_truth_is_independent_of_analyzer_status():
    manifest = make_manifest()
    records = {record.application_id: record for record in manifest.applications}

    assert records["vulnerable_a"].ground_truth is GroundTruth.VULNERABLE
    assert (
        records["vulnerable_a"].ground_truth_method
        is GroundTruthMethod.SQL_EXECUTION_TRACE
    )
    assert records["safe_b"].ground_truth is GroundTruth.NON_VULNERABLE


def test_analyzer_classification_does_not_define_ground_truth():
    application = make_application("vulnerable", GroundTruth.VULNERABLE)
    application = replace(
        application,
        samples=tuple(
            replace(
                sample,
                status=TimeAnalysisStatus.NOT_CONFIRMED,
                reason_code="timing_pattern_not_matched",
            )
            for sample in application.samples
        ),
    )
    benchmark = summarize_clusters((ClusterUnit("family", (application,)),))

    manifest = create_provenance_manifest(
        benchmark=benchmark,
        registration=RegistrationStatus.RETROSPECTIVE,
        registration_evidence_id="registration_record",
        clusters=(
            ClusterProvenance(
                cluster_id="family",
                basis=ClusterBasis.SHARED_SOURCE,
                rationale_evidence_id="rationale",
                dependency_ids=("source_family",),
            ),
        ),
        applications=(
            ApplicationProvenance(
                application_id="vulnerable",
                cluster_id="family",
                source_family_id="source_family",
                runtime_family_id="runtime_family",
                ground_truth=GroundTruth.VULNERABLE,
                ground_truth_method=GroundTruthMethod.SQL_EXECUTION_TRACE,
                ground_truth_evidence_id="trace_record",
                evaluation_plan_id="plan_record",
            ),
        ),
    )

    assert manifest.applications[0].ground_truth is GroundTruth.VULNERABLE
    assert all(
        sample.status is TimeAnalysisStatus.NOT_CONFIRMED
        for sample in application.samples
    )


def test_manifest_rejects_missing_application():
    manifest = make_manifest()

    with pytest.raises(ValueError, match="Application provenance"):
        replace(
            manifest,
            applications=manifest.applications[:1],
        )


def test_manifest_rejects_duplicate_application():
    manifest = make_manifest()

    with pytest.raises(ValueError, match="Application provenance"):
        replace(
            manifest,
            applications=(
                manifest.applications[0],
                manifest.applications[0],
            ),
        )


def test_manifest_rejects_extra_cluster():
    manifest = make_manifest()

    additional = replace(
        manifest.clusters[0],
        cluster_id="extra_family",
    )

    with pytest.raises(ValueError, match="Cluster provenance"):
        replace(
            manifest,
            clusters=manifest.clusters + (additional,),
        )


def test_manifest_rejects_wrong_cluster_membership():
    manifest = make_manifest()

    with pytest.raises(ValueError, match="Inconsistent application"):
        replace(
            manifest,
            applications=(
                replace(
                    manifest.applications[0],
                    cluster_id="family_a",
                ),
                manifest.applications[1],
            ),
        )


def test_manifest_rejects_changed_ground_truth():
    manifest = make_manifest()

    with pytest.raises(ValueError, match="Inconsistent application"):
        replace(
            manifest,
            applications=(
                replace(
                    manifest.applications[0],
                    ground_truth=GroundTruth.VULNERABLE,
                ),
                manifest.applications[1],
            ),
        )


def test_manifest_rejects_reordered_records():
    manifest = make_manifest()

    with pytest.raises(ValueError, match="Cluster provenance"):
        replace(
            manifest,
            clusters=tuple(reversed(manifest.clusters)),
        )

    with pytest.raises(ValueError, match="Application provenance"):
        replace(
            manifest,
            applications=tuple(reversed(manifest.applications)),
        )


def test_non_sql_evidence_cannot_declare_vulnerable():
    manifest = make_manifest()

    with pytest.raises(ValueError, match="non-SQL"):
        replace(
            manifest.applications[1],
            ground_truth_method=GroundTruthMethod.NON_SQL_IMPLEMENTATION,
        )


def test_non_sql_evidence_allowed_for_safe_fixture():
    manifest = make_manifest()
    result = replace(
        manifest.applications[0],
        ground_truth_method=GroundTruthMethod.NON_SQL_IMPLEMENTATION,
    )

    assert result.ground_truth is GroundTruth.NON_VULNERABLE


def test_multiple_dependency_basis_requires_multiple_dependencies():
    record = make_manifest().clusters[0]

    with pytest.raises(ValueError, match="requires multiple"):
        replace(
            record,
            basis=ClusterBasis.MULTIPLE_DEPENDENCIES,
            dependency_ids=("only_one",),
        )

    changed = replace(
        record,
        basis=ClusterBasis.MULTIPLE_DEPENDENCIES,
        dependency_ids=("dependency_a", "dependency_b"),
    )
    assert changed.basis is ClusterBasis.MULTIPLE_DEPENDENCIES


@pytest.mark.parametrize(
    ("basis", "family_field", "message"),
    [
        (ClusterBasis.SHARED_SOURCE, "source_family_id", "shared-source"),
        (ClusterBasis.SHARED_RUNTIME, "runtime_family_id", "shared-runtime"),
    ],
)
def test_manifest_rejects_family_basis_with_mixed_families(
    basis,
    family_field,
    message,
):
    manifest = make_manifest(shared_runtime=False)
    extra_application = make_application(
        "vulnerable_extra",
        GroundTruth.VULNERABLE,
    )
    family_a = replace(
        manifest.benchmark.clusters[0],
        applications=(
            manifest.benchmark.clusters[0].applications[0],
            extra_application,
        ),
    )
    benchmark = summarize_clusters((family_a, manifest.benchmark.clusters[1]))
    cluster_records = (
        replace(manifest.clusters[0], basis=basis),
        manifest.clusters[1],
    )
    extra_record = ApplicationProvenance(
        application_id="vulnerable_extra",
        cluster_id="family_a",
        source_family_id="source_extra",
        runtime_family_id="runtime_extra",
        ground_truth=GroundTruth.VULNERABLE,
        ground_truth_method=GroundTruthMethod.SQL_EXECUTION_TRACE,
        ground_truth_evidence_id="trace_extra",
        evaluation_plan_id="plan_extra",
    )
    original = manifest.applications[1]
    if family_field == "source_family_id":
        assert original.source_family_id != extra_record.source_family_id
    else:
        assert original.runtime_family_id != extra_record.runtime_family_id

    with pytest.raises(ValueError, match=message):
        create_provenance_manifest(
            benchmark=benchmark,
            registration=manifest.registration,
            registration_evidence_id=manifest.registration_evidence_id,
            clusters=cluster_records,
            applications=manifest.applications + (extra_record,),
        )


@pytest.mark.parametrize(
    "value",
    ("", "raw/path", "contains space", "日本語", "a" * 101, True),
)
def test_rejects_invalid_evidence_identifiers(value):
    manifest = make_manifest()

    with pytest.raises(ValueError, match="identifier"):
        replace(
            manifest.applications[0],
            ground_truth_evidence_id=value,
        )


def test_invalid_identifier_error_does_not_echo_secret_input():
    secret = "Bearer_secret.value"
    record = make_manifest().applications[0]

    with pytest.raises(ValueError) as raised:
        replace(record, ground_truth_evidence_id=secret)

    assert secret not in str(raised.value)


@pytest.mark.parametrize(
    "dependencies",
    (
        (),
        ("shared", "shared"),
        ("z", "a"),
        ("valid", "raw/path"),
        ("x",) * 101,
    ),
)
def test_rejects_invalid_dependency_collections(dependencies):
    record = make_manifest().clusters[0]

    with pytest.raises(ValueError, match="provenance"):
        replace(record, dependency_ids=dependencies)


def test_rejects_list_dependencies():
    record = make_manifest().clusters[0]

    with pytest.raises(TypeError):
        replace(record, dependency_ids=["shared"])


def test_maximum_dependency_boundary():
    record = make_manifest().clusters[0]
    dependencies = tuple(f"dependency_{index:03d}" for index in range(100))

    changed = replace(
        record,
        basis=ClusterBasis.MULTIPLE_DEPENDENCIES,
        dependency_ids=dependencies,
    )

    assert changed.dependency_ids == dependencies


def test_rejects_wrong_registration_type():
    manifest = make_manifest()

    with pytest.raises(TypeError, match="registration"):
        replace(manifest, registration="pre_registered")


def test_rejects_wrong_ground_truth_method_type():
    record = make_manifest().applications[0]

    with pytest.raises(TypeError, match="method"):
        replace(record, ground_truth_method="source_review")


def test_rejects_wrong_cluster_basis_type():
    record = make_manifest().clusters[0]

    with pytest.raises(TypeError, match="basis"):
        replace(record, basis="shared_source")


def test_rejects_non_tuple_manifest_collection():
    manifest = make_manifest()

    with pytest.raises(TypeError):
        replace(manifest, applications=list(manifest.applications))


def test_rejects_invalid_benchmark():
    manifest = make_manifest()

    with pytest.raises(TypeError, match="benchmark"):
        replace(manifest, benchmark=object())


def test_dependency_overlap_rejects_invalid_direct_state():
    valid = make_manifest().dependency_overlaps[0]

    with pytest.raises(ValueError, match="category"):
        replace(valid, category="unknown")
    with pytest.raises(ValueError, match="multiple clusters"):
        replace(valid, cluster_ids=("family_a",))
    with pytest.raises(ValueError, match="ordering"):
        replace(valid, cluster_ids=("family_b", "family_a"))
    with pytest.raises(TypeError, match="identifiers"):
        replace(valid, cluster_ids=["family_a", "family_b"])

    with pytest.raises(ValueError, match="multiple clusters"):
        DependencyOverlap(
            category="source_family",
            dependency_id="source",
            cluster_ids=("family_a",),
        )


def test_model_does_not_retain_raw_secret_fields():
    manifest = make_manifest()

    for item in (
        manifest,
        manifest.applications[0],
        manifest.clusters[0],
    ):
        for attribute in (
            "url",
            "payload",
            "cookie",
            "authorization",
            "request_body",
            "response_body",
            "credential",
        ):
            assert not hasattr(item, attribute)


def test_repr_does_not_expose_nested_benchmark():
    manifest = make_manifest()

    rendered = repr(manifest)

    assert "QualitySample" not in rendered
    assert "RequestTemplate" not in rendered
    assert "sql_trace_a" not in rendered


def test_maximum_manifest_boundary_and_overlap_detection():
    applications = tuple(
        make_application(
            f"application_{index:03d}",
            GroundTruth.NON_VULNERABLE,
        )
        for index in range(100)
    )
    clusters = tuple(
        ClusterUnit(
            cluster_id=f"cluster_{index:03d}",
            applications=(application,),
        )
        for index, application in enumerate(applications)
    )
    benchmark = summarize_clusters(clusters)
    cluster_records = tuple(
        ClusterProvenance(
            cluster_id=cluster.cluster_id,
            basis=ClusterBasis.SHARED_HARNESS,
            rationale_evidence_id=f"rationale_{index:03d}",
            dependency_ids=("shared_harness",),
        )
        for index, cluster in enumerate(clusters)
    )
    application_records = tuple(
        ApplicationProvenance(
            application_id=application.application_id,
            cluster_id=cluster.cluster_id,
            source_family_id=f"source_{index:03d}",
            runtime_family_id=f"runtime_{index:03d}",
            ground_truth=GroundTruth.NON_VULNERABLE,
            ground_truth_method=GroundTruthMethod.SOURCE_REVIEW,
            ground_truth_evidence_id=f"review_{index:03d}",
            evaluation_plan_id=f"plan_{index:03d}",
        )
        for index, (application, cluster) in enumerate(
            zip(applications, clusters, strict=True)
        )
    )

    manifest = create_provenance_manifest(
        benchmark=benchmark,
        registration=RegistrationStatus.RETROSPECTIVE,
        registration_evidence_id="registration_record",
        clusters=tuple(reversed(cluster_records)),
        applications=tuple(reversed(application_records)),
    )

    assert manifest.cluster_count == 100
    assert manifest.application_count == 100
    assert manifest.run_count == 200
    assert len(manifest.dependency_overlaps) == 1
    overlap = manifest.dependency_overlaps[0]
    assert overlap.category == "declared_dependency"
    assert overlap.dependency_id == "shared_harness"
    assert len(overlap.cluster_ids) == 100
