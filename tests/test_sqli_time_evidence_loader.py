"""Tests for confined local evidence acquisition."""

import os
import socket
from pathlib import Path

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
from vintar.checks.sqli.time_evidence_loader import (
    EvidenceAcquisitionError,
    check_local_evidence_in_session,
    read_local_evidence,
)
from vintar.checks.sqli.time_evidence_session import (
    EvidenceCheckStatus,
    SessionStatus,
    create_verification_session,
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

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="Local evidence loader requires POSIX.",
)


def make_session(
    contents: dict[str, bytes] | None = None,
):
    if contents is None:
        contents = {
            "registration": b"registration evidence",
            "rationale": b"cluster rationale",
            "truth": b"ground truth evidence",
            "plan": b"evaluation plan",
        }

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

    kinds = (
        ("registration", EvidenceKind.REGISTRATION),
        ("rationale", EvidenceKind.CLUSTER_RATIONALE),
        ("truth", EvidenceKind.GROUND_TRUTH),
        ("plan", EvidenceKind.EVALUATION_PLAN),
    )

    records = tuple(
        create_evidence_record(
            evidence_id=identifier,
            kind=kind,
            content=contents[identifier],
        )
        for identifier, kind in kinds
    )

    binding = bind_evidence(
        manifest=manifest,
        index=create_evidence_index(records),
    )

    return create_verification_session(binding=binding)


def test_read_regular_file(tmp_path: Path):
    file = tmp_path / "evidence.txt"
    file.write_bytes(b"expected evidence")

    assert (
        read_local_evidence(
            root=tmp_path,
            relative_path="evidence.txt",
        )
        == b"expected evidence"
    )


def test_nested_regular_file(tmp_path: Path):
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "evidence.json").write_bytes(b'{"ok":true}')

    assert (
        read_local_evidence(
            root=str(tmp_path),
            relative_path="nested/evidence.json",
        )
        == b'{"ok":true}'
    )


def test_local_file_updates_session(tmp_path: Path):
    session = make_session()
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    updated = check_local_evidence_in_session(
        session=session,
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
    )

    assert session.checked_count == 0
    assert updated.checked_count == 1
    assert updated.matched_ids == ("truth",)
    assert updated.status is SessionStatus.INCOMPLETE


def test_full_local_verification(tmp_path: Path):
    session = make_session()

    files = {
        "registration": b"registration evidence",
        "rationale": b"cluster rationale",
        "truth": b"ground truth evidence",
        "plan": b"evaluation plan",
    }

    for identifier, content in files.items():
        (tmp_path / identifier).write_bytes(content)

    for identifier in files:
        session = check_local_evidence_in_session(
            session=session,
            evidence_id=identifier,
            root=tmp_path,
            relative_path=identifier,
        )

    assert session.is_complete
    assert session.matched_count == 4
    assert session.unchecked_count == 0


def test_digest_mismatch_is_recorded_not_raised(tmp_path: Path):
    session = make_session()
    (tmp_path / "truth").write_bytes(b"modified truth evidence")

    result = check_local_evidence_in_session(
        session=session,
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
    )

    assert result.evidence_status("truth") is EvidenceCheckStatus.MISMATCHED
    assert result.status is SessionStatus.FAILED
    assert session.checked_count == 0


def test_missing_file_does_not_change_session(tmp_path: Path):
    session = make_session()

    with pytest.raises(EvidenceAcquisitionError):
        check_local_evidence_in_session(
            session=session,
            evidence_id="truth",
            root=tmp_path,
            relative_path="missing",
        )

    assert session.checked_count == 0
    assert session.status is SessionStatus.INCOMPLETE


@pytest.mark.parametrize(
    "relative_path",
    (
        "",
        "../outside",
        "nested/../../outside",
        "/etc/passwd",
        "nested//file",
        "./file",
        "nested/./file",
        "nested/../file",
        "file\\other",
        "file name",
        "日本語",
        "x" * 1025,
    ),
)
def test_invalid_relative_paths(tmp_path: Path, relative_path: str):
    with pytest.raises(ValueError, match="relative evidence path"):
        read_local_evidence(
            root=tmp_path,
            relative_path=relative_path,
        )


def test_relative_path_depth_limit(tmp_path: Path):
    too_deep = "/".join(["nested"] * 17)

    with pytest.raises(ValueError, match="relative evidence path"):
        read_local_evidence(
            root=tmp_path,
            relative_path=too_deep,
        )


def test_relative_root_is_rejected():
    with pytest.raises(ValueError, match="root"):
        read_local_evidence(
            root="relative",
            relative_path="evidence.txt",
        )


@pytest.mark.parametrize("root", (b"/tmp", True, None))
def test_invalid_root_types_are_rejected(root):
    with pytest.raises(TypeError, match="root"):
        read_local_evidence(
            root=root,
            relative_path="evidence.txt",
        )


@pytest.mark.parametrize(
    "relative_path",
    (Path("evidence"), b"evidence", True, None),
)
def test_invalid_relative_path_types_are_rejected(
    tmp_path: Path,
    relative_path,
):
    with pytest.raises(TypeError, match="relative evidence path"):
        read_local_evidence(
            root=tmp_path,
            relative_path=relative_path,
        )


@pytest.mark.parametrize(
    "root",
    (
        "/",
        "/tmp/../outside",
        "/tmp/./outside",
        "/tmp//outside",
        "/tmp/",
        "",
        "/" + "x" * 4096,
        "/" + "/".join("x" for _ in range(65)),
        "/" + "x" * 256,
    ),
)
def test_invalid_roots(root: str):
    with pytest.raises(ValueError, match="root"):
        read_local_evidence(
            root=root,
            relative_path="evidence.txt",
        )


def test_symlink_file_is_rejected(tmp_path: Path):
    target = tmp_path / "target"
    target.write_bytes(b"secret")

    (tmp_path / "alias").symlink_to(target)

    with pytest.raises(EvidenceAcquisitionError):
        read_local_evidence(
            root=tmp_path,
            relative_path="alias",
        )


def test_symlink_directory_is_rejected(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "evidence").write_bytes(b"valid")

    (tmp_path / "alias").symlink_to(real, target_is_directory=True)

    with pytest.raises(EvidenceAcquisitionError):
        read_local_evidence(
            root=tmp_path,
            relative_path="alias/evidence",
        )


def test_symlink_inside_root_path_is_rejected(tmp_path: Path):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "evidence").write_bytes(b"valid")

    alias = tmp_path / "root_alias"
    alias.symlink_to(actual, target_is_directory=True)

    with pytest.raises(EvidenceAcquisitionError):
        read_local_evidence(
            root=alias,
            relative_path="evidence",
        )


def test_symlink_parent_of_root_is_rejected(tmp_path: Path):
    actual_parent = tmp_path / "actual_parent"
    actual_parent.mkdir()
    root = actual_parent / "root"
    root.mkdir()
    (root / "evidence").write_bytes(b"valid")

    alias_parent = tmp_path / "alias_parent"
    alias_parent.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(EvidenceAcquisitionError):
        read_local_evidence(
            root=alias_parent / "root",
            relative_path="evidence",
        )


def test_directory_as_file_is_rejected(tmp_path: Path):
    (tmp_path / "directory").mkdir()

    with pytest.raises(EvidenceAcquisitionError):
        read_local_evidence(
            root=tmp_path,
            relative_path="directory",
        )


@pytest.mark.skipif(
    not hasattr(os, "mkfifo"),
    reason="FIFO creation unavailable.",
)
def test_fifo_is_rejected_without_blocking(tmp_path: Path):
    os.mkfifo(tmp_path / "pipe")

    with pytest.raises(EvidenceAcquisitionError):
        read_local_evidence(
            root=tmp_path,
            relative_path="pipe",
        )


def test_unix_socket_is_rejected(tmp_path: Path):
    socket_path = tmp_path / "evidence.sock"

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))

        with pytest.raises(EvidenceAcquisitionError):
            read_local_evidence(
                root=tmp_path,
                relative_path="evidence.sock",
            )


@pytest.mark.skipif(
    not Path("/dev/null").exists(),
    reason="POSIX null device unavailable.",
)
def test_device_is_rejected_without_opening_it(
    monkeypatch: pytest.MonkeyPatch,
):
    from vintar.checks.sqli import time_evidence_loader

    original_open = time_evidence_loader.os.open
    final_opened = False

    def tracking_open(path, *args, **kwargs) -> int:
        nonlocal final_opened
        if path == "null":
            final_opened = True
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(time_evidence_loader, "_require_posix", lambda: None)
    monkeypatch.setattr(time_evidence_loader.os, "open", tracking_open)

    with pytest.raises(EvidenceAcquisitionError):
        read_local_evidence(
            root="/dev",
            relative_path="null",
        )

    assert not final_opened


def test_hardlink_is_rejected(tmp_path: Path):
    original = tmp_path / "original"
    original.write_bytes(b"shared")
    alias = tmp_path / "alias"
    os.link(original, alias)

    with pytest.raises(EvidenceAcquisitionError, match="link count"):
        read_local_evidence(
            root=tmp_path,
            relative_path="alias",
        )


def test_empty_file_is_rejected(tmp_path: Path):
    (tmp_path / "empty").write_bytes(b"")

    with pytest.raises(EvidenceAcquisitionError, match="size"):
        read_local_evidence(
            root=tmp_path,
            relative_path="empty",
        )


def test_oversized_file_is_rejected(tmp_path: Path):
    file = tmp_path / "large"
    with file.open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)

    with pytest.raises(EvidenceAcquisitionError, match="size"):
        read_local_evidence(
            root=tmp_path,
            relative_path="large",
        )


def test_maximum_size_is_allowed(tmp_path: Path):
    content = b"x" * (16 * 1024 * 1024)
    (tmp_path / "maximum").write_bytes(content)

    assert (
        read_local_evidence(
            root=tmp_path,
            relative_path="maximum",
        )
        == content
    )


def test_changed_file_during_read_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from vintar.checks.sqli import time_evidence_loader

    file = tmp_path / "changing"
    file.write_bytes(b"original evidence")

    original_read = time_evidence_loader.os.read
    changed = False

    def read_and_mutate(fd: int, amount: int) -> bytes:
        nonlocal changed
        result = original_read(fd, amount)
        if not changed:
            changed = True
            file.write_bytes(b"changed evidence with different length")
        return result

    monkeypatch.setattr(time_evidence_loader.os, "read", read_and_mutate)

    with pytest.raises(EvidenceAcquisitionError, match="changed"):
        read_local_evidence(
            root=tmp_path,
            relative_path="changing",
        )


def test_short_read_without_metadata_change_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from vintar.checks.sqli import time_evidence_loader

    (tmp_path / "short").write_bytes(b"expected")
    monkeypatch.setattr(time_evidence_loader.os, "read", lambda fd, amount: b"")

    with pytest.raises(EvidenceAcquisitionError, match="length changed"):
        read_local_evidence(
            root=tmp_path,
            relative_path="short",
        )


def test_stream_growth_beyond_limit_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from vintar.checks.sqli import time_evidence_loader

    (tmp_path / "growing").write_bytes(b"x")

    def endless_read(fd: int, amount: int) -> bytes:
        return b"x" * amount

    monkeypatch.setattr(time_evidence_loader.os, "read", endless_read)

    with pytest.raises(EvidenceAcquisitionError, match="maximum size"):
        read_local_evidence(
            root=tmp_path,
            relative_path="growing",
        )


@pytest.mark.parametrize("existing", (True, False))
def test_all_opened_file_descriptors_are_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
):
    from vintar.checks.sqli import time_evidence_loader

    if existing:
        (tmp_path / "evidence").write_bytes(b"evidence")

    original_open = time_evidence_loader.os.open
    opened: list[int] = []

    def tracking_open(*args, **kwargs) -> int:
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(time_evidence_loader, "_require_posix", lambda: None)
    monkeypatch.setattr(time_evidence_loader.os, "open", tracking_open)

    if existing:
        assert (
            read_local_evidence(
                root=tmp_path,
                relative_path="evidence",
            )
            == b"evidence"
        )
    else:
        with pytest.raises(EvidenceAcquisitionError):
            read_local_evidence(
                root=tmp_path,
                relative_path="missing",
            )

    assert opened
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_unknown_id_does_not_trigger_file_read(tmp_path: Path):
    session = make_session()

    with pytest.raises(ValueError, match="not bound"):
        check_local_evidence_in_session(
            session=session,
            evidence_id="unknown",
            root=tmp_path,
            relative_path="missing",
        )


def test_duplicate_id_does_not_trigger_second_read(tmp_path: Path):
    session = make_session()
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    updated = check_local_evidence_in_session(
        session=session,
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
    )

    (tmp_path / "truth").unlink()

    with pytest.raises(ValueError, match="already checked"):
        check_local_evidence_in_session(
            session=updated,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )


def test_invalid_session_is_rejected(tmp_path: Path):
    with pytest.raises(TypeError, match="session"):
        check_local_evidence_in_session(
            session=object(),
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )


def test_evidence_id_does_not_determine_file_path(tmp_path: Path):
    session = make_session()

    directory = tmp_path / "evidence"
    directory.mkdir()
    (directory / "record.txt").write_bytes(b"ground truth evidence")

    updated = check_local_evidence_in_session(
        session=session,
        evidence_id="truth",
        root=tmp_path,
        relative_path="evidence/record.txt",
    )

    assert updated.matched_ids == ("truth",)
    assert updated.checked_count == 1


def test_acquisition_error_does_not_leak_path(tmp_path: Path):
    sensitive_name = "private_token"

    with pytest.raises(EvidenceAcquisitionError) as error:
        read_local_evidence(
            root=tmp_path,
            relative_path=sensitive_name,
        )

    assert sensitive_name not in str(error.value)
    assert str(tmp_path) not in str(error.value)


def test_regular_read_does_not_change_ground_truth(tmp_path: Path):
    session = make_session()
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    updated = check_local_evidence_in_session(
        session=session,
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
    )

    application = updated.binding.manifest.benchmark.clusters[0].applications[0]

    assert application.ground_truth is GroundTruth.VULNERABLE
    assert application.samples[0].status is TimeAnalysisStatus.NOT_CONFIRMED
