"""Tests for content-addressed timing evaluation evidence."""

import math
from dataclasses import replace

import pytest

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_application_quality import ApplicationUnit
from vintar.checks.sqli.time_cluster_quality import (
    ClusterUnit,
    summarize_clusters,
)
from vintar.checks.sqli.time_evidence import (
    EvidenceBinding,
    EvidenceKind,
    bind_evidence,
    create_evidence_index,
    create_evidence_record,
    verify_evidence_bytes,
)
from vintar.checks.sqli.time_provenance import (
    ApplicationProvenance,
    ClusterBasis,
    ClusterProvenance,
    GroundTruthMethod,
    RegistrationStatus,
    create_provenance_manifest,
)
from vintar.checks.sqli.time_quality import GroundTruth, QualitySample


def make_application(
    identifier: str,
    truth: GroundTruth,
) -> ApplicationUnit:
    status = TimeAnalysisStatus.NOT_CONFIRMED

    samples = tuple(
        QualitySample(
            case_id=identifier,
            iteration=iteration,
            ground_truth=truth,
            status=status,
            reason_code="timing_pattern_not_matched",
            budget_used=9,
            transport_attempts=9,
            server_received=9,
            observation_count=9,
            elapsed_seconds=1.0,
        )
        for iteration in range(2)
    )

    return ApplicationUnit(
        application_id=identifier,
        ground_truth=truth,
        framework="fastapi",
        dbms="sqlite",
        sql_context="where",
        samples=samples,
    )


def make_manifest():
    vulnerable = make_application(
        "vulnerable",
        GroundTruth.VULNERABLE,
    )
    safe = make_application(
        "safe",
        GroundTruth.NON_VULNERABLE,
    )

    benchmark = summarize_clusters(
        (
            ClusterUnit(
                cluster_id="family_a",
                applications=(vulnerable,),
            ),
            ClusterUnit(
                cluster_id="family_b",
                applications=(safe,),
            ),
        )
    )

    return create_provenance_manifest(
        benchmark=benchmark,
        registration=RegistrationStatus.RETROSPECTIVE,
        registration_evidence_id="registration",
        clusters=(
            ClusterProvenance(
                cluster_id="family_a",
                basis=ClusterBasis.SHARED_SOURCE,
                rationale_evidence_id="rationale_a",
                dependency_ids=("source_a",),
            ),
            ClusterProvenance(
                cluster_id="family_b",
                basis=ClusterBasis.SHARED_RUNTIME,
                rationale_evidence_id="rationale_b",
                dependency_ids=("runtime_b",),
            ),
        ),
        applications=(
            ApplicationProvenance(
                application_id="vulnerable",
                cluster_id="family_a",
                source_family_id="source_a",
                runtime_family_id="runtime_shared",
                ground_truth=GroundTruth.VULNERABLE,
                ground_truth_method=GroundTruthMethod.SQL_EXECUTION_TRACE,
                ground_truth_evidence_id="truth_a",
                evaluation_plan_id="plan_a",
            ),
            ApplicationProvenance(
                application_id="safe",
                cluster_id="family_b",
                source_family_id="source_b",
                runtime_family_id="runtime_b",
                ground_truth=GroundTruth.NON_VULNERABLE,
                ground_truth_method=GroundTruthMethod.SOURCE_REVIEW,
                ground_truth_evidence_id="truth_b",
                evaluation_plan_id="plan_b",
            ),
        ),
    )


def evidence_records():
    definitions = (
        ("registration", EvidenceKind.REGISTRATION),
        ("rationale_a", EvidenceKind.CLUSTER_RATIONALE),
        ("rationale_b", EvidenceKind.CLUSTER_RATIONALE),
        ("truth_a", EvidenceKind.GROUND_TRUTH),
        ("truth_b", EvidenceKind.GROUND_TRUTH),
        ("plan_a", EvidenceKind.EVALUATION_PLAN),
        ("plan_b", EvidenceKind.EVALUATION_PLAN),
    )

    return tuple(
        create_evidence_record(
            evidence_id=identifier,
            kind=kind,
            content=f"fixture:{identifier}".encode("ascii"),
        )
        for identifier, kind in definitions
    )


def make_binding() -> EvidenceBinding:
    return bind_evidence(
        manifest=make_manifest(),
        index=create_evidence_index(evidence_records()),
    )


def test_known_sha256_digest():
    record = create_evidence_record(
        evidence_id="example",
        kind=EvidenceKind.GROUND_TRUTH,
        content=b"abc",
    )

    assert record.sha256 == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
    assert record.size_bytes == 3
    assert verify_evidence_bytes(record=record, content=b"abc")


def test_modified_content_is_rejected():
    record = create_evidence_record(
        evidence_id="example",
        kind=EvidenceKind.GROUND_TRUTH,
        content=b"first",
    )

    assert not verify_evidence_bytes(
        record=record,
        content=b"other",
    )
    assert not verify_evidence_bytes(
        record=record,
        content=b"shorter",
    )


def test_empty_content_is_rejected():
    with pytest.raises(ValueError, match="size"):
        create_evidence_record(
            evidence_id="empty",
            kind=EvidenceKind.GROUND_TRUTH,
            content=b"",
        )


def test_oversized_content_is_rejected():
    with pytest.raises(ValueError, match="size"):
        create_evidence_record(
            evidence_id="large",
            kind=EvidenceKind.GROUND_TRUTH,
            content=b"x" * (16 * 1024 * 1024 + 1),
        )


def test_maximum_content_size_is_accepted_and_verified():
    content = b"x" * (16 * 1024 * 1024)
    record = create_evidence_record(
        evidence_id="maximum",
        kind=EvidenceKind.GROUND_TRUTH,
        content=content,
    )

    assert record.size_bytes == 16 * 1024 * 1024
    assert verify_evidence_bytes(record=record, content=content)


@pytest.mark.parametrize("content", ["abc", bytearray(b"abc"), None])
def test_only_immutable_bytes_are_accepted(content):
    with pytest.raises(TypeError, match="bytes"):
        create_evidence_record(
            evidence_id="example",
            kind=EvidenceKind.GROUND_TRUTH,
            content=content,
        )

    record = evidence_records()[0]
    with pytest.raises(TypeError, match="bytes"):
        verify_evidence_bytes(record=record, content=content)


def test_binding_matches_all_references():
    binding = make_binding()

    assert binding.evidence_count == 7
    assert binding.cluster_count == 2
    assert binding.application_count == 2

    assert binding.index.get("truth_a") is not None
    assert binding.index.get("unknown") is None


def test_binding_does_not_change_ground_truth():
    binding = make_binding()
    applications = binding.manifest.applications

    vulnerable = next(
        item for item in applications if item.application_id == "vulnerable"
    )

    assert vulnerable.ground_truth is GroundTruth.VULNERABLE

    benchmark_application = next(
        app
        for cluster in binding.manifest.benchmark.clusters
        for app in cluster.applications
        if app.application_id == "vulnerable"
    )

    assert all(
        sample.status is TimeAnalysisStatus.NOT_CONFIRMED
        for sample in benchmark_application.samples
    )


def test_missing_evidence_is_rejected():
    binding = make_binding()

    with pytest.raises(ValueError, match="Evidence does not match"):
        replace(
            binding,
            index=create_evidence_index(binding.index.records[:-1]),
        )


def test_extra_evidence_is_rejected():
    binding = make_binding()

    extra = create_evidence_record(
        evidence_id="unused",
        kind=EvidenceKind.GROUND_TRUTH,
        content=b"extra",
    )

    with pytest.raises(ValueError, match="Evidence does not match"):
        replace(
            binding,
            index=create_evidence_index((*binding.index.records, extra)),
        )


def test_wrong_evidence_kind_is_rejected():
    binding = make_binding()

    altered = tuple(
        replace(record, kind=EvidenceKind.EVALUATION_PLAN)
        if record.evidence_id == "truth_a"
        else record
        for record in binding.index.records
    )

    with pytest.raises(ValueError, match="Evidence does not match"):
        replace(
            binding,
            index=create_evidence_index(altered),
        )


def test_each_provenance_reference_role_is_bound():
    binding = make_binding()
    manifest = binding.manifest
    mutations = (
        replace(manifest, registration_evidence_id="changed_registration"),
        replace(
            manifest,
            clusters=(
                replace(
                    manifest.clusters[0],
                    rationale_evidence_id="changed_rationale",
                ),
                manifest.clusters[1],
            ),
        ),
        replace(
            manifest,
            applications=(
                replace(
                    manifest.applications[0],
                    ground_truth_evidence_id="changed_truth",
                ),
                manifest.applications[1],
            ),
        ),
        replace(
            manifest,
            applications=(
                replace(
                    manifest.applications[0],
                    evaluation_plan_id="changed_plan",
                ),
                manifest.applications[1],
            ),
        ),
    )

    for changed in mutations:
        with pytest.raises(ValueError, match="Evidence does not match"):
            replace(binding, manifest=changed)


def test_same_kind_reference_can_share_one_record():
    binding = make_binding()
    manifest = binding.manifest
    shared_plan_id = manifest.applications[0].evaluation_plan_id
    removed_plan_id = manifest.applications[1].evaluation_plan_id
    shared_applications = (
        manifest.applications[0],
        replace(
            manifest.applications[1],
            evaluation_plan_id=shared_plan_id,
        ),
    )
    shared_manifest = replace(manifest, applications=shared_applications)
    shared_index = create_evidence_index(
        tuple(
            record
            for record in binding.index.records
            if record.evidence_id != removed_plan_id
        )
    )

    shared = bind_evidence(manifest=shared_manifest, index=shared_index)

    assert shared.evidence_count == binding.evidence_count - 1


def test_duplicate_evidence_ids_are_rejected():
    record = evidence_records()[0]

    with pytest.raises(ValueError, match="ordering"):
        create_evidence_index((record, record))


def test_index_canonicalizes_order():
    original = create_evidence_index(evidence_records())
    reversed_index = create_evidence_index(tuple(reversed(evidence_records())))

    assert original == reversed_index


def test_direct_index_rejects_unsorted_records():
    original = create_evidence_index(evidence_records())

    with pytest.raises(ValueError, match="ordering"):
        replace(
            original,
            records=tuple(reversed(original.records)),
        )

    with pytest.raises(TypeError, match="records"):
        replace(original, records=list(original.records))
    with pytest.raises(ValueError, match="size"):
        replace(original, records=())
    with pytest.raises(TypeError, match="record"):
        replace(original, records=(object(),))


def test_direct_record_rejects_tampered_digest():
    record = evidence_records()[0]

    with pytest.raises(ValueError, match="SHA-256"):
        replace(record, sha256="x" * 64)

    with pytest.raises(ValueError, match="SHA-256"):
        replace(record, sha256=record.sha256.upper())

    with pytest.raises(ValueError, match="SHA-256"):
        replace(record, sha256="0" * 63)

    with pytest.raises(ValueError, match="SHA-256"):
        replace(record, sha256="g" * 64)


def test_record_metadata_alone_cannot_prove_bytes():
    record = evidence_records()[0]

    altered = replace(
        record,
        sha256="0" * 64,
    )

    assert not verify_evidence_bytes(
        record=altered,
        content=b"fixture:registration",
    )


def test_replacing_both_content_and_metadata_remains_outside_trust_model():
    substituted = create_evidence_record(
        evidence_id="registration",
        kind=EvidenceKind.REGISTRATION,
        content=b"attacker-controlled-record",
    )

    assert verify_evidence_bytes(
        record=substituted,
        content=b"attacker-controlled-record",
    )
    assert not hasattr(substituted, "authentic")


def test_direct_binding_rejects_different_manifest():
    binding = make_binding()

    altered_manifest = replace(
        binding.manifest,
        registration_evidence_id="different_registration",
    )

    with pytest.raises(ValueError, match="Evidence does not match"):
        replace(binding, manifest=altered_manifest)


@pytest.mark.parametrize(
    "value",
    ("", "secret/token", "contains space", "日本語", "x" * 101, True),
)
def test_invalid_evidence_ids_are_rejected(value):
    record = evidence_records()[0]

    with pytest.raises(ValueError, match="identifier"):
        replace(record, evidence_id=value)


@pytest.mark.parametrize(
    "value",
    (
        True,
        -1,
        0,
        16 * 1024 * 1024 + 1,
        math.nan,
        math.inf,
        10**1000,
    ),
)
def test_invalid_evidence_sizes_are_rejected(value):
    record = evidence_records()[0]

    with pytest.raises((TypeError, ValueError), match="size"):
        replace(record, size_bytes=value)


def test_invalid_evidence_kind_is_rejected():
    record = evidence_records()[0]

    with pytest.raises(TypeError, match="kind"):
        replace(record, kind="registration")


def test_invalid_identifier_error_does_not_echo_secret_input():
    secret = "Bearer_secret.value"
    record = evidence_records()[0]

    with pytest.raises(ValueError) as raised:
        replace(record, evidence_id=secret)

    assert secret not in str(raised.value)


def test_conflicting_reference_roles_are_rejected():
    manifest = make_manifest()

    altered_applications = (
        replace(
            manifest.applications[0],
            ground_truth_evidence_id="registration",
        ),
        manifest.applications[1],
    )
    altered_manifest = replace(
        manifest,
        applications=altered_applications,
    )

    with pytest.raises(ValueError, match="conflicting roles"):
        bind_evidence(
            manifest=altered_manifest,
            index=create_evidence_index(evidence_records()),
        )


def test_index_limit():
    records = tuple(
        create_evidence_record(
            evidence_id=f"evidence_{number:03d}",
            kind=EvidenceKind.EVALUATION_PLAN,
            content=b"ok",
        )
        for number in range(301)
    )

    index = create_evidence_index(records)
    assert len(index.records) == 301

    with pytest.raises(ValueError, match="size"):
        create_evidence_index(
            (
                *records,
                create_evidence_record(
                    evidence_id="overflow",
                    kind=EvidenceKind.EVALUATION_PLAN,
                    content=b"ok",
                ),
            )
        )


def test_models_do_not_retain_raw_evidence_bytes():
    binding = make_binding()

    for name in (
        "content",
        "raw_bytes",
        "payload",
        "authorization",
        "cookie",
        "response_body",
        "request_template",
    ):
        assert not hasattr(binding, name)
        assert not hasattr(binding.index.records[0], name)


def test_repr_hides_nested_provenance():
    binding = make_binding()

    rendered = repr(binding)

    assert "QualitySample" not in rendered
    assert "registration" not in rendered
    assert "truth_a" not in rendered
    assert not hasattr(binding, "content_verified")
