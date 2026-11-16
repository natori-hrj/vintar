"""Tests for immutable timing evidence verification sessions."""

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
    EvidenceKind,
    bind_evidence,
    create_evidence_index,
    create_evidence_record,
)
from vintar.checks.sqli.time_evidence_session import (
    EvidenceCheckStatus,
    EvidenceObservation,
    SessionStatus,
    check_evidence_in_session,
    create_verification_session,
    observe_evidence_bytes,
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


def fixture_binding():
    """Build a minimal real provenance-to-evidence binding."""
    application = ApplicationUnit(
        application_id="application_a",
        ground_truth=GroundTruth.VULNERABLE,
        framework="fastapi",
        dbms="sqlite",
        sql_context="where",
        samples=(
            QualitySample(
                case_id="application_a",
                iteration=0,
                ground_truth=GroundTruth.VULNERABLE,
                status=TimeAnalysisStatus.NOT_CONFIRMED,
                reason_code="timing_pattern_not_matched",
                budget_used=9,
                transport_attempts=9,
                server_received=9,
                observation_count=9,
                elapsed_seconds=1.0,
            ),
        ),
    )

    benchmark = summarize_clusters(
        (
            ClusterUnit(
                cluster_id="family_a",
                applications=(application,),
            ),
        ),
        minimum_repetitions=1,
    )

    manifest = create_provenance_manifest(
        benchmark=benchmark,
        registration=RegistrationStatus.RETROSPECTIVE,
        registration_evidence_id="registration",
        clusters=(
            ClusterProvenance(
                cluster_id="family_a",
                basis=ClusterBasis.SHARED_SOURCE,
                rationale_evidence_id="rationale",
                dependency_ids=("source_a",),
            ),
        ),
        applications=(
            ApplicationProvenance(
                application_id="application_a",
                cluster_id="family_a",
                source_family_id="source_a",
                runtime_family_id="runtime_a",
                ground_truth=GroundTruth.VULNERABLE,
                ground_truth_method=GroundTruthMethod.SQL_EXECUTION_TRACE,
                ground_truth_evidence_id="truth",
                evaluation_plan_id="plan",
            ),
        ),
    )

    kinds = {
        "registration": EvidenceKind.REGISTRATION,
        "rationale": EvidenceKind.CLUSTER_RATIONALE,
        "truth": EvidenceKind.GROUND_TRUTH,
        "plan": EvidenceKind.EVALUATION_PLAN,
    }

    records = tuple(
        create_evidence_record(
            evidence_id=identifier,
            kind=kind,
            content=f"fixture:{identifier}".encode("ascii"),
        )
        for identifier, kind in kinds.items()
    )

    return bind_evidence(
        manifest=manifest,
        index=create_evidence_index(records),
    )


def content_for(identifier: str) -> bytes:
    return f"fixture:{identifier}".encode("ascii")


def complete_session():
    session = create_verification_session(binding=fixture_binding())

    for record in session.binding.index.records:
        session = check_evidence_in_session(
            session=session,
            evidence_id=record.evidence_id,
            content=content_for(record.evidence_id),
        )

    return session


def maximum_binding():
    applications = tuple(make_application_for_maximum(index) for index in range(100))
    clusters = tuple(
        ClusterUnit(
            cluster_id=f"cluster_{index:03d}",
            applications=(application,),
        )
        for index, application in enumerate(applications)
    )
    benchmark = summarize_clusters(clusters, minimum_repetitions=1)
    cluster_provenance = tuple(
        ClusterProvenance(
            cluster_id=cluster.cluster_id,
            basis=ClusterBasis.SHARED_SOURCE,
            rationale_evidence_id=f"rationale_{index:03d}",
            dependency_ids=(f"source_{index:03d}",),
        )
        for index, cluster in enumerate(clusters)
    )
    application_provenance = tuple(
        ApplicationProvenance(
            application_id=application.application_id,
            cluster_id=cluster.cluster_id,
            source_family_id=f"source_{index:03d}",
            runtime_family_id=f"runtime_{index:03d}",
            ground_truth=GroundTruth.NON_VULNERABLE,
            ground_truth_method=GroundTruthMethod.SOURCE_REVIEW,
            ground_truth_evidence_id=f"truth_{index:03d}",
            evaluation_plan_id=f"plan_{index:03d}",
        )
        for index, (application, cluster) in enumerate(
            zip(applications, clusters, strict=True)
        )
    )
    manifest = create_provenance_manifest(
        benchmark=benchmark,
        registration=RegistrationStatus.RETROSPECTIVE,
        registration_evidence_id="registration",
        clusters=cluster_provenance,
        applications=application_provenance,
    )
    definitions = [("registration", EvidenceKind.REGISTRATION)]
    definitions.extend(
        (f"rationale_{index:03d}", EvidenceKind.CLUSTER_RATIONALE)
        for index in range(100)
    )
    definitions.extend(
        (f"truth_{index:03d}", EvidenceKind.GROUND_TRUTH) for index in range(100)
    )
    definitions.extend(
        (f"plan_{index:03d}", EvidenceKind.EVALUATION_PLAN) for index in range(100)
    )
    records = tuple(
        create_evidence_record(
            evidence_id=evidence_id,
            kind=kind,
            content=content_for(evidence_id),
        )
        for evidence_id, kind in definitions
    )
    return bind_evidence(
        manifest=manifest,
        index=create_evidence_index(records),
    )


def make_application_for_maximum(index: int) -> ApplicationUnit:
    identifier = f"application_{index:03d}"
    return ApplicationUnit(
        application_id=identifier,
        ground_truth=GroundTruth.NON_VULNERABLE,
        framework="fastapi",
        dbms="sqlite",
        sql_context="where",
        samples=(
            QualitySample(
                case_id=identifier,
                iteration=0,
                ground_truth=GroundTruth.NON_VULNERABLE,
                status=TimeAnalysisStatus.NOT_CONFIRMED,
                reason_code="timing_pattern_not_matched",
                budget_used=9,
                transport_attempts=9,
                server_received=9,
                observation_count=9,
                elapsed_seconds=1.0,
            ),
        ),
    )


def test_new_session_is_incomplete():
    session = create_verification_session(binding=fixture_binding())

    assert session.status is SessionStatus.INCOMPLETE
    assert not session.is_complete
    assert session.evidence_count == 4
    assert session.checked_count == 0
    assert session.matched_count == 0
    assert session.mismatched_count == 0
    assert session.unchecked_count == 4
    assert session.matched_ids == ()
    assert session.mismatched_ids == ()
    assert session.unchecked_ids == (
        "plan",
        "rationale",
        "registration",
        "truth",
    )


def test_checking_content_returns_new_session():
    initial = create_verification_session(binding=fixture_binding())

    updated = check_evidence_in_session(
        session=initial,
        evidence_id="truth",
        content=content_for("truth"),
    )

    assert initial.checked_count == 0
    assert updated.checked_count == 1
    assert updated.matched_count == 1
    assert updated.mismatched_count == 0
    assert updated.unchecked_count == 3
    assert updated.matched_ids == ("truth",)
    assert updated.status is SessionStatus.INCOMPLETE


def test_all_expected_evidence_is_complete():
    session = complete_session()

    assert session.status is SessionStatus.COMPLETE
    assert session.is_complete
    assert session.checked_count == 4
    assert session.matched_count == 4
    assert session.mismatched_count == 0
    assert session.unchecked_count == 0
    assert session.matched_ids == (
        "plan",
        "rationale",
        "registration",
        "truth",
    )
    assert session.mismatched_ids == ()
    assert session.unchecked_ids == ()
    assert session.checked_count == (session.matched_count + session.mismatched_count)
    assert session.evidence_count == (session.checked_count + session.unchecked_count)


def test_same_length_mismatch_is_failed():
    session = create_verification_session(binding=fixture_binding())

    session = check_evidence_in_session(
        session=session,
        evidence_id="truth",
        content=b"fixture:other",
    )

    assert session.evidence_status("truth") is (EvidenceCheckStatus.MISMATCHED)
    assert session.status is SessionStatus.FAILED
    assert session.mismatched_ids == ("truth",)


def test_different_length_mismatch_is_failed():
    session = create_verification_session(binding=fixture_binding())

    session = check_evidence_in_session(
        session=session,
        evidence_id="truth",
        content=b"x",
    )

    assert session.status is SessionStatus.FAILED
    assert session.mismatched_ids == ("truth",)


def test_mismatch_has_priority_over_unchecked():
    session = create_verification_session(binding=fixture_binding())

    session = check_evidence_in_session(
        session=session,
        evidence_id="truth",
        content=b"x",
    )

    assert session.status is SessionStatus.FAILED
    assert len(session.unchecked_ids) == 3


def test_full_coverage_with_mismatch_is_not_complete():
    session = create_verification_session(binding=fixture_binding())

    for record in session.binding.index.records:
        content = (
            b"incorrect"
            if record.evidence_id == "truth"
            else content_for(record.evidence_id)
        )
        session = check_evidence_in_session(
            session=session,
            evidence_id=record.evidence_id,
            content=content,
        )

    assert session.checked_count == session.evidence_count
    assert session.unchecked_ids == ()
    assert session.mismatched_ids == ("truth",)
    assert session.status is SessionStatus.FAILED
    assert not session.is_complete


def test_per_evidence_status_is_derived():
    session = create_verification_session(binding=fixture_binding())

    assert session.evidence_status("truth") is (EvidenceCheckStatus.UNCHECKED)

    session = check_evidence_in_session(
        session=session,
        evidence_id="truth",
        content=content_for("truth"),
    )

    assert session.evidence_status("truth") is (EvidenceCheckStatus.MATCHED)


def test_unknown_evidence_is_rejected():
    session = create_verification_session(binding=fixture_binding())

    with pytest.raises(ValueError, match="not bound"):
        session.evidence_status("unknown")

    with pytest.raises(ValueError, match="not bound"):
        check_evidence_in_session(
            session=session,
            evidence_id="unknown",
            content=b"abc",
        )


def test_duplicate_check_is_rejected():
    session = create_verification_session(binding=fixture_binding())

    session = check_evidence_in_session(
        session=session,
        evidence_id="truth",
        content=content_for("truth"),
    )

    with pytest.raises(ValueError, match="already checked"):
        check_evidence_in_session(
            session=session,
            evidence_id="truth",
            content=b"different",
        )


def test_checks_are_canonically_sorted():
    session = create_verification_session(binding=fixture_binding())

    for identifier in ("truth", "registration", "plan"):
        session = check_evidence_in_session(
            session=session,
            evidence_id=identifier,
            content=content_for(identifier),
        )

    assert tuple(item.evidence_id for item in session.observations) == (
        "plan",
        "registration",
        "truth",
    )


def test_direct_session_rejects_unsorted_observations():
    session = complete_session()

    with pytest.raises(ValueError, match="ordering"):
        replace(
            session,
            observations=tuple(reversed(session.observations)),
        )


def test_direct_session_rejects_duplicate_observations():
    session = complete_session()

    with pytest.raises(ValueError, match="ordering"):
        replace(
            session,
            observations=(
                session.observations[0],
                session.observations[0],
            ),
        )


def test_observation_cannot_be_attached_to_other_record():
    session = complete_session()

    wrong_record = create_evidence_record(
        evidence_id="truth",
        kind=EvidenceKind.GROUND_TRUTH,
        content=b"substituted expected content",
    )

    modified_index = create_evidence_index(
        tuple(
            wrong_record if record.evidence_id == "truth" else record
            for record in session.binding.index.records
        )
    )
    modified_binding = replace(session.binding, index=modified_index)
    altered = replace(session.observations[-1], binding=modified_binding)

    with pytest.raises(ValueError, match="bound evidence"):
        replace(session, observations=session.observations[:-1] + (altered,))


def test_observation_cannot_be_attached_to_other_binding():
    session = complete_session()
    replacement = replace(
        session.binding.index.get("truth"),
        sha256="0" * 64,
    )

    modified_index = create_evidence_index(
        tuple(
            replacement if record.evidence_id == "truth" else record
            for record in session.binding.index.records
        )
    )

    modified_binding = replace(
        session.binding,
        index=modified_index,
    )

    with pytest.raises(ValueError, match="bound evidence"):
        replace(session, binding=modified_binding)


def test_direct_observation_rejects_invalid_digest():
    binding = fixture_binding()

    with pytest.raises(ValueError, match="SHA-256"):
        EvidenceObservation(
            binding=binding,
            evidence_id="truth",
            observed_sha256="X" * 64,
            observed_size=5,
        )


@pytest.mark.parametrize(
    "digest",
    (None, True, "0" * 63, "G" * 64),
)
def test_direct_observation_rejects_invalid_digest_types_and_shapes(digest):
    with pytest.raises(ValueError, match="SHA-256"):
        EvidenceObservation(
            binding=fixture_binding(),
            evidence_id="truth",
            observed_sha256=digest,
            observed_size=5,
        )


@pytest.mark.parametrize(
    "size",
    (
        0,
        -1,
        True,
        16 * 1024 * 1024 + 1,
        math.nan,
        math.inf,
        10**1000,
    ),
)
def test_direct_observation_rejects_invalid_size(size):
    binding = fixture_binding()

    with pytest.raises((TypeError, ValueError), match="size"):
        EvidenceObservation(
            binding=binding,
            evidence_id="truth",
            observed_sha256="0" * 64,
            observed_size=size,
        )


@pytest.mark.parametrize(
    "content",
    ("abc", bytearray(b"abc"), None),
)
def test_check_rejects_non_bytes(content):
    session = create_verification_session(binding=fixture_binding())

    with pytest.raises(TypeError, match="bytes"):
        check_evidence_in_session(
            session=session,
            evidence_id="truth",
            content=content,
        )


def test_empty_and_oversized_content_are_rejected():
    session = create_verification_session(binding=fixture_binding())

    for content in (b"", b"x" * (16 * 1024 * 1024 + 1)):
        with pytest.raises(ValueError, match="size"):
            check_evidence_in_session(
                session=session,
                evidence_id="truth",
                content=content,
            )


def test_maximum_content_size_is_observed_without_retention():
    session = create_verification_session(binding=fixture_binding())
    content = b"x" * (16 * 1024 * 1024)

    updated = check_evidence_in_session(
        session=session,
        evidence_id="truth",
        content=content,
    )

    observation = updated.observations[0]
    assert observation.observed_size == 16 * 1024 * 1024
    assert observation.status is EvidenceCheckStatus.MISMATCHED
    assert not hasattr(observation, "content")


def test_direct_session_rejects_invalid_collections():
    session = create_verification_session(binding=fixture_binding())

    with pytest.raises(TypeError, match="observations"):
        replace(session, observations=[])

    with pytest.raises(TypeError, match="observation"):
        replace(session, observations=(object(),))


def test_direct_session_rejects_invalid_binding():
    session = create_verification_session(binding=fixture_binding())

    with pytest.raises(TypeError, match="binding"):
        replace(session, binding=object())


def test_observation_rejects_unknown_id_and_invalid_binding():
    binding = fixture_binding()

    with pytest.raises(ValueError, match="not bound"):
        EvidenceObservation(
            binding=binding,
            evidence_id="unknown",
            observed_sha256="0" * 64,
            observed_size=1,
        )

    with pytest.raises(TypeError, match="binding"):
        EvidenceObservation(
            binding=object(),
            evidence_id="truth",
            observed_sha256="0" * 64,
            observed_size=1,
        )


def test_observation_status_cannot_be_overridden():
    binding = fixture_binding()
    observation = observe_evidence_bytes(
        binding=binding,
        evidence_id="truth",
        content=content_for("truth"),
    )

    assert observation.status is EvidenceCheckStatus.MATCHED

    with pytest.raises(TypeError):
        replace(
            observation,
            status=EvidenceCheckStatus.MISMATCHED,
        )


def test_metadata_can_be_fabricated_without_original_bytes():
    """Digest assertions cannot authenticate their own origin."""
    binding = fixture_binding()
    record = binding.index.get("truth")
    assert record is not None

    fabricated = EvidenceObservation(
        binding=binding,
        evidence_id="truth",
        observed_sha256=record.sha256,
        observed_size=record.size_bytes,
    )

    assert fabricated.status is EvidenceCheckStatus.MATCHED


def test_original_bytes_are_not_retained():
    session = complete_session()
    observation = session.observations[0]

    for name in (
        "content",
        "raw_bytes",
        "payload",
        "cookie",
        "authorization",
        "request_body",
        "response_body",
    ):
        assert not hasattr(session, name)
        assert not hasattr(observation, name)


def test_nested_data_is_hidden_from_repr():
    session = complete_session()
    rendered = repr(session)

    assert "sha256" not in rendered
    assert "QualitySample" not in rendered
    assert "EvidenceRecord" not in rendered


def test_session_does_not_change_ground_truth():
    session = complete_session()
    application = session.binding.manifest.benchmark.clusters[0].applications[0]

    assert application.ground_truth is GroundTruth.VULNERABLE
    assert all(
        sample.status is TimeAnalysisStatus.NOT_CONFIRMED
        for sample in application.samples
    )


def test_maximum_session_boundary():
    session = create_verification_session(binding=maximum_binding())

    for record in session.binding.index.records:
        session = check_evidence_in_session(
            session=session,
            evidence_id=record.evidence_id,
            content=content_for(record.evidence_id),
        )

    assert session.evidence_count == 301
    assert session.checked_count == 301
    assert session.matched_count == 301
    assert session.mismatched_count == 0
    assert session.unchecked_count == 0
    assert session.status is SessionStatus.COMPLETE
