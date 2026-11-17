"""Tests for bounded streaming acquisition of local timing evidence."""

import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_sqli_time_evidence_loader import make_session

from vintar.checks.sqli import time_evidence_stream
from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_evidence_session import (
    EvidenceCheckStatus,
    SessionStatus,
    add_evidence_observation,
    observe_evidence_bytes,
)
from vintar.checks.sqli.time_evidence_stream import (
    AcquisitionAttempt,
    AcquisitionOutcome,
    AcquisitionPolicy,
    acquire_evidence_stream,
    start_acquisition_run,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="Streaming evidence acquisition requires POSIX.",
)


def make_run(
    *,
    max_files: int = 4,
    max_total_bytes: int = 1024,
    max_elapsed_seconds: float = 30.0,
    session=None,
):
    if session is None:
        session = make_session()

    return start_acquisition_run(
        session=session,
        policy=AcquisitionPolicy(
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_elapsed_seconds=max_elapsed_seconds,
        ),
    )


def acquire(run, root: Path, evidence_id: str):
    return acquire_evidence_stream(
        run=run,
        evidence_id=evidence_id,
        root=root,
        relative_path=evidence_id,
    )


def test_streaming_match(tmp_path: Path):
    content = b"ground truth evidence"
    (tmp_path / "truth").write_bytes(content)

    initial = make_run()
    result = acquire(initial, tmp_path, "truth")

    assert initial.attempted_files == 0
    assert initial.session.checked_count == 0
    assert result.attempted_files == 1
    assert result.total_bytes == len(content)
    assert result.remaining_files == 3
    assert result.failed_attempts == 0
    assert result.attempts[0].outcome is AcquisitionOutcome.MATCHED
    assert result.session.evidence_status("truth") is EvidenceCheckStatus.MATCHED
    assert result.session.status is SessionStatus.INCOMPLETE


def test_streaming_digest_mismatch(tmp_path: Path):
    content = b"modified truth evidence"
    (tmp_path / "truth").write_bytes(content)

    result = acquire(make_run(), tmp_path, "truth")

    assert result.total_bytes == len(content)
    assert result.attempts[0].outcome is AcquisitionOutcome.MISMATCHED
    assert result.session.mismatched_ids == ("truth",)
    assert result.session.status is SessionStatus.FAILED


def test_cumulative_file_and_byte_budget(tmp_path: Path):
    contents = {
        "truth": b"ground truth evidence",
        "plan": b"evaluation plan",
    }
    for identifier, content in contents.items():
        (tmp_path / identifier).write_bytes(content)

    total = sum(len(content) for content in contents.values())
    run = make_run(max_files=2, max_total_bytes=total)

    for identifier in contents:
        run = acquire(run, tmp_path, identifier)

    assert run.attempted_files == 2
    assert run.total_bytes == total
    assert run.remaining_files == 0
    assert run.remaining_bytes == 0
    assert run.session.matched_count == 2


def test_byte_budget_prevents_oversized_acquisition(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    run = acquire(
        make_run(max_total_bytes=4),
        tmp_path,
        "truth",
    )

    assert run.attempts[0].outcome is AcquisitionOutcome.BUDGET_EXCEEDED
    assert run.total_bytes == 0
    assert run.session.checked_count == 0


def test_file_count_budget_rejects_new_attempt(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    run = acquire(make_run(max_files=1), tmp_path, "truth")

    with pytest.raises(ValueError, match="file budget"):
        acquire(run, tmp_path, "plan")

    assert run.attempted_files == 1


def test_missing_file_is_accounted(tmp_path: Path):
    initial = make_run()
    run = acquire(initial, tmp_path, "truth")

    assert run.attempted_files == 1
    assert run.failed_attempts == 1
    assert run.total_bytes == 0
    assert run.attempts[0].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert run.session is initial.session
    assert run.session.unchecked_count == 4


def test_failed_evidence_cannot_be_retried(tmp_path: Path):
    run = acquire(make_run(), tmp_path, "truth")
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    with pytest.raises(ValueError, match="already attempted"):
        acquire(run, tmp_path, "truth")


def test_symlink_is_rejected(tmp_path: Path):
    target = tmp_path / "target"
    target.write_bytes(b"ground truth evidence")
    (tmp_path / "truth").symlink_to(target)

    run = acquire(make_run(), tmp_path, "truth")

    assert run.attempts[0].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert run.total_bytes == 0
    assert run.session.checked_count == 0


def test_partial_failure_retains_read_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    original = time_evidence_stream.os.read
    calls = 0

    def fail_after_partial(fd: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(fd, min(size, 5))
        raise OSError("simulated failure")

    monkeypatch.setattr(time_evidence_stream.os, "read", fail_after_partial)

    run = acquire(make_run(), tmp_path, "truth")

    assert calls == 2
    assert run.total_bytes == 5
    assert run.remaining_bytes == 1019
    assert run.failed_attempts == 1
    assert run.session.checked_count == 0


def test_budget_remains_consumed_after_partial_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    (tmp_path / "plan").write_bytes(b"evaluation plan")

    original = time_evidence_stream.os.read
    calls = 0

    def fail_first_file(fd: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(fd, min(size, 5))
        if calls == 2:
            raise OSError("simulated failure")
        return original(fd, size)

    monkeypatch.setattr(time_evidence_stream.os, "read", fail_first_file)

    run = make_run(max_total_bytes=25)
    run = acquire(run, tmp_path, "truth")
    run = acquire(run, tmp_path, "plan")

    assert run.attempted_files == 2
    assert run.total_bytes == 5 + len(b"evaluation plan")
    assert run.session.matched_ids == ("plan",)


def test_expired_deadline_blocks_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    run = make_run(max_elapsed_seconds=1.0)

    monkeypatch.setattr(
        time_evidence_stream.time,
        "monotonic",
        lambda: run.started_at + 2.0,
    )

    result = acquire(run, tmp_path, "truth")

    assert result.attempts[0].outcome is AcquisitionOutcome.BUDGET_EXCEEDED
    assert result.total_bytes == 0
    assert result.session.checked_count == 0


def test_deadline_after_read_preserves_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    content = b"ground truth evidence"
    (tmp_path / "truth").write_bytes(content)

    run = make_run(max_elapsed_seconds=1.0)
    original = time_evidence_stream.os.read
    expired = False

    def expire_after_read(fd: int, size: int) -> bytes:
        nonlocal expired
        chunk = original(fd, size)
        expired = True
        return chunk

    monkeypatch.setattr(
        time_evidence_stream.os,
        "read",
        expire_after_read,
    )
    monkeypatch.setattr(
        time_evidence_stream.time,
        "monotonic",
        lambda: run.started_at + (2.0 if expired else 0.1),
    )

    result = acquire(run, tmp_path, "truth")

    assert result.attempts[0].outcome is AcquisitionOutcome.BUDGET_EXCEEDED
    assert result.total_bytes == len(content)
    assert result.session.checked_count == 0


def test_short_chunks_are_hashed_incrementally(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    content = b"ground truth evidence"
    (tmp_path / "truth").write_bytes(content)

    original = time_evidence_stream.os.read
    calls = 0

    def small_reads(fd: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        return original(fd, min(size, 3))

    monkeypatch.setattr(time_evidence_stream.os, "read", small_reads)

    run = acquire(make_run(), tmp_path, "truth")

    assert calls > 1
    assert run.attempts[0].outcome is AcquisitionOutcome.MATCHED
    assert run.total_bytes == len(content)


def test_multiple_maximum_sized_chunks_produce_matching_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    content = b"streaming-evidence-" * 10_000
    (tmp_path / "truth").write_bytes(content)
    contents = {
        "registration": b"registration evidence",
        "rationale": b"cluster rationale",
        "truth": content,
        "plan": b"evaluation plan",
    }
    requested_sizes: list[int] = []
    original = time_evidence_stream.os.read

    def record_size(fd: int, size: int) -> bytes:
        requested_sizes.append(size)
        return original(fd, size)

    monkeypatch.setattr(time_evidence_stream.os, "read", record_size)
    run = make_run(
        max_total_bytes=len(content),
        session=make_session(contents),
    )

    result = acquire(run, tmp_path, "truth")

    assert result.attempts[0].outcome is AcquisitionOutcome.MATCHED
    assert len(requested_sizes) >= 3
    assert max(requested_sizes) <= 64 * 1024


@pytest.mark.parametrize("size", (1, 16 * 1024 * 1024))
def test_streaming_file_size_boundaries(tmp_path: Path, size: int):
    content = b"x" * size
    (tmp_path / "truth").write_bytes(content)
    contents = {
        "registration": b"registration evidence",
        "rationale": b"cluster rationale",
        "truth": content,
        "plan": b"evaluation plan",
    }
    run = make_run(
        max_total_bytes=size,
        session=make_session(contents),
    )

    result = acquire(run, tmp_path, "truth")

    assert result.attempts[0].outcome is AcquisitionOutcome.MATCHED
    assert result.total_bytes == size


def test_file_larger_than_individual_limit_is_rejected(tmp_path: Path):
    with (tmp_path / "truth").open("wb") as stream:
        stream.truncate(16 * 1024 * 1024 + 1)

    result = acquire(
        make_run(max_total_bytes=16 * 1024 * 1024),
        tmp_path,
        "truth",
    )

    assert result.attempts[0].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert result.total_bytes == 0
    assert result.session.checked_count == 0


def test_early_eof_preserves_partial_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    original = time_evidence_stream.os.read
    calls = 0

    def end_early(fd: int, size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return original(fd, 5)
        return b""

    monkeypatch.setattr(time_evidence_stream.os, "read", end_early)

    result = acquire(make_run(), tmp_path, "truth")

    assert result.attempts[0].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert result.total_bytes == 5
    assert result.session.checked_count == 0


def test_file_change_after_read_is_failed_and_charged(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    content = b"ground truth evidence"
    file = tmp_path / "truth"
    file.write_bytes(content)
    original = time_evidence_stream.os.read
    changed = False

    def read_and_change(fd: int, size: int) -> bytes:
        nonlocal changed
        chunk = original(fd, size)
        if not changed:
            changed = True
            file.write_bytes(b"changed evidence")
        return chunk

    monkeypatch.setattr(time_evidence_stream.os, "read", read_and_change)

    result = acquire(make_run(), tmp_path, "truth")

    assert result.attempts[0].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert result.total_bytes == len(content)
    assert result.session.checked_count == 0


def test_remaining_byte_budget_prevents_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    def forbidden_read(fd: int, size: int) -> bytes:
        raise AssertionError("Byte budget must be checked before reading.")

    monkeypatch.setattr(time_evidence_stream.os, "read", forbidden_read)

    result = acquire(make_run(max_total_bytes=4), tmp_path, "truth")

    assert result.attempts[0].outcome is AcquisitionOutcome.BUDGET_EXCEEDED
    assert result.total_bytes == 0


@pytest.mark.parametrize("existing", (True, False))
def test_streaming_closes_all_opened_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    existing: bool,
):
    if existing:
        (tmp_path / "truth").write_bytes(b"ground truth evidence")

    original_open = time_evidence_stream.os.open
    opened: list[int] = []

    def tracking_open(*args, **kwargs) -> int:
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    monkeypatch.setattr(time_evidence_stream, "_require_posix", lambda: None)
    monkeypatch.setattr(time_evidence_stream.os, "open", tracking_open)

    result = acquire(make_run(), tmp_path, "truth")

    assert opened
    expected = (
        AcquisitionOutcome.MATCHED
        if existing
        else AcquisitionOutcome.ACQUISITION_FAILED
    )
    assert result.attempts[0].outcome is expected
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_full_file_loader_is_not_used(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    from vintar.checks.sqli import time_evidence_loader

    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    def forbidden_loader(**kwargs):
        raise AssertionError("Full-file read must not be used.")

    monkeypatch.setattr(
        time_evidence_loader,
        "read_local_evidence",
        forbidden_loader,
    )

    run = acquire(make_run(), tmp_path, "truth")
    assert run.session.matched_ids == ("truth",)


def test_unknown_id_is_rejected_before_file_access(tmp_path: Path):
    with pytest.raises(ValueError, match="not bound"):
        acquire(make_run(), tmp_path, "unknown")


def test_invalid_path_is_rejected_without_attempt_or_file_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    run = make_run()

    def forbidden_open(*args, **kwargs):
        raise AssertionError("Invalid path must not reach file access.")

    monkeypatch.setattr(time_evidence_stream.os, "open", forbidden_open)

    with pytest.raises(ValueError, match="relative evidence path"):
        acquire_evidence_stream(
            run=run,
            evidence_id="truth",
            root=tmp_path,
            relative_path="../truth",
        )

    assert run.attempted_files == 0


def test_duplicate_attempts_are_rejected():
    run = make_run()
    first = AcquisitionAttempt(
        evidence_id="plan",
        outcome=AcquisitionOutcome.ACQUISITION_FAILED,
        bytes_read=0,
    )
    second = AcquisitionAttempt(
        evidence_id="truth",
        outcome=AcquisitionOutcome.ACQUISITION_FAILED,
        bytes_read=0,
    )

    valid = replace(run, attempts=(first, second))
    assert valid.attempted_files == 2

    with pytest.raises(ValueError, match="Duplicate"):
        replace(valid, attempts=(first, first))


@pytest.mark.parametrize(
    "value",
    (0, -1, 302, True, 1.2, None, float("nan"), float("inf"), 10**1000),
)
def test_invalid_file_limit(value):
    with pytest.raises(ValueError, match="file budget"):
        AcquisitionPolicy(max_files=value)


@pytest.mark.parametrize(
    "value",
    (
        0,
        -1,
        True,
        1.2,
        None,
        float("nan"),
        float("inf"),
        301 * 16 * 1024 * 1024 + 1,
        10**1000,
    ),
)
def test_invalid_byte_limit(value):
    with pytest.raises(ValueError, match="byte budget"):
        AcquisitionPolicy(max_total_bytes=value)


@pytest.mark.parametrize(
    "value",
    (0.0, -1.0, 3600.1, float("nan"), float("inf"), 5, True, None),
)
def test_invalid_time_limit(value):
    with pytest.raises(ValueError, match="time budget"):
        AcquisitionPolicy(max_elapsed_seconds=value)


def test_unbound_attempt_is_rejected():
    run = make_run()
    item = AcquisitionAttempt(
        evidence_id="unknown",
        outcome=AcquisitionOutcome.ACQUISITION_FAILED,
        bytes_read=0,
    )

    with pytest.raises(ValueError, match="not bound"):
        replace(run, attempts=(item,))


def test_session_observation_must_have_matching_attempt():
    run = make_run()
    observation = observe_evidence_bytes(
        binding=run.session.binding,
        evidence_id="truth",
        content=b"ground truth evidence",
    )
    altered_session = add_evidence_observation(
        session=run.session,
        observation=observation,
    )

    with pytest.raises(ValueError, match="Inconsistent acquisition session"):
        replace(run, session=altered_session)


def test_successful_attempt_byte_count_must_match_observation():
    run = make_run()
    observation = observe_evidence_bytes(
        binding=run.binding,
        evidence_id="truth",
        content=b"ground truth evidence",
    )
    altered_session = add_evidence_observation(
        session=run.session,
        observation=observation,
    )
    attempt = AcquisitionAttempt(
        evidence_id="truth",
        outcome=AcquisitionOutcome.MATCHED,
        bytes_read=1,
    )

    with pytest.raises(ValueError, match="Inconsistent acquisition outcome"):
        replace(run, session=altered_session, attempts=(attempt,))


def test_run_rejects_session_from_another_binding():
    run = make_run()
    other_session = make_session()

    with pytest.raises(ValueError, match="does not match binding"):
        replace(run, session=other_session)

    with pytest.raises(ValueError, match="does not match binding"):
        replace(run, binding=other_session.binding)


def test_invalid_attempt_types_are_rejected():
    run = make_run()

    with pytest.raises(TypeError, match="attempts"):
        replace(run, attempts=[])

    with pytest.raises(TypeError, match="attempt"):
        replace(run, attempts=(object(),))


@pytest.mark.parametrize(
    "field,value",
    (
        ("binding", object()),
        ("session", object()),
        ("policy", object()),
        ("started_at", True),
        ("started_at", -1.0),
        ("started_at", float("nan")),
        ("started_at", float("inf")),
    ),
)
def test_run_rejects_invalid_direct_state(field, value):
    run = make_run()

    with pytest.raises((TypeError, ValueError)):
        replace(run, **{field: value})


def test_failed_attempt_can_have_partial_byte_count():
    attempt = AcquisitionAttempt(
        evidence_id="truth",
        outcome=AcquisitionOutcome.ACQUISITION_FAILED,
        bytes_read=123,
    )

    assert attempt.bytes_read == 123


def test_attempt_rejects_invalid_outcome_and_identifier():
    with pytest.raises(TypeError, match="outcome"):
        AcquisitionAttempt(
            evidence_id="truth",
            outcome="matched",
            bytes_read=1,
        )

    with pytest.raises(ValueError, match="identifier") as error:
        AcquisitionAttempt(
            evidence_id="secret/path",
            outcome=AcquisitionOutcome.ACQUISITION_FAILED,
            bytes_read=0,
        )

    assert "secret/path" not in str(error.value)


def test_direct_attempt_rejects_invalid_count():
    with pytest.raises(ValueError, match="byte count"):
        AcquisitionAttempt(
            evidence_id="truth",
            outcome=AcquisitionOutcome.MATCHED,
            bytes_read=0,
        )

    with pytest.raises(ValueError, match="byte count"):
        AcquisitionAttempt(
            evidence_id="truth",
            outcome=AcquisitionOutcome.ACQUISITION_FAILED,
            bytes_read=True,
        )


def test_raw_content_and_paths_are_not_stored(tmp_path: Path):
    run = acquire(make_run(), tmp_path, "truth")

    for name in ("content", "relative_path", "root", "payload"):
        assert not hasattr(run, name)
        assert not hasattr(run.attempts[0], name)

    assert str(tmp_path) not in repr(run)


def test_ground_truth_and_analyzer_result_are_unchanged(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    run = acquire(make_run(), tmp_path, "truth")
    application = run.session.binding.manifest.benchmark.clusters[0].applications[0]

    assert application.samples[0].status is TimeAnalysisStatus.NOT_CONFIRMED
