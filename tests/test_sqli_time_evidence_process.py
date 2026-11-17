"""Tests for process-isolated evidence acquisition."""

import hashlib
import os
import time
from dataclasses import replace
from pathlib import Path

import pytest
from test_sqli_time_evidence_loader import make_session

from vintar.checks.sqli import time_evidence_process
from vintar.checks.sqli.time_evidence import MAX_EVIDENCE_BYTES
from vintar.checks.sqli.time_evidence_process import (
    ProcessAcquisitionResult,
    ProcessAcquisitionStatus,
    _stop_worker,
    _validate_message,
    acquire_evidence_isolated,
)
from vintar.checks.sqli.time_evidence_session import EvidenceCheckStatus
from vintar.checks.sqli.time_evidence_stream import (
    AcquisitionOutcome,
    AcquisitionPolicy,
    start_acquisition_run,
)

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="Process isolation requires POSIX.",
)


def _blocking_worker(connection, *args) -> None:
    try:
        time.sleep(10)
    finally:
        connection.close()


def _crashing_worker(connection, *args) -> None:
    connection.close()
    os._exit(7)


def make_run(
    *,
    max_files: int = 4,
    max_total_bytes: int = 1024,
    max_elapsed_seconds: float = 30.0,
):
    return start_acquisition_run(
        session=make_session(),
        policy=AcquisitionPolicy(
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_elapsed_seconds=max_elapsed_seconds,
        ),
    )


def acquire(
    run,
    root: Path,
    evidence_id: str = "truth",
    timeout_seconds: float = 10.0,
):
    return acquire_evidence_isolated(
        run=run,
        evidence_id=evidence_id,
        root=root,
        relative_path=evidence_id,
        timeout_seconds=timeout_seconds,
    )


def test_spawned_worker_matches_evidence(tmp_path: Path):
    content = b"ground truth evidence"
    (tmp_path / "truth").write_bytes(content)
    initial = make_run()

    result = acquire(initial, tmp_path)

    assert result.status is ProcessAcquisitionStatus.COMPLETED
    assert result.can_continue
    assert result.run is not None
    assert result.run.binding is initial.binding
    assert result.run.session.binding is initial.binding
    assert result.run.attempted_files == 1
    assert result.run.total_bytes == len(content)
    assert result.run.attempts[0].outcome is AcquisitionOutcome.MATCHED
    assert result.run.session.evidence_status("truth") is EvidenceCheckStatus.MATCHED
    assert initial.attempted_files == 0


def test_spawned_worker_records_digest_mismatch(tmp_path: Path):
    content = b"modified truth evidence"
    (tmp_path / "truth").write_bytes(content)

    result = acquire(make_run(), tmp_path)

    assert result.run is not None
    assert result.status is ProcessAcquisitionStatus.COMPLETED
    assert result.run.attempts[0].outcome is AcquisitionOutcome.MISMATCHED
    assert result.run.total_bytes == len(content)
    assert result.run.session.mismatched_ids == ("truth",)


def test_missing_file_is_a_completed_failed_attempt(tmp_path: Path):
    result = acquire(make_run(), tmp_path)

    assert result.status is ProcessAcquisitionStatus.COMPLETED
    assert result.run is not None
    assert result.run.attempts[0].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert result.run.total_bytes == 0
    assert result.run.session.checked_count == 0


def test_symlink_is_rejected_by_spawned_worker(tmp_path: Path):
    real = tmp_path / "real"
    real.write_bytes(b"ground truth evidence")
    (tmp_path / "truth").symlink_to(real)

    result = acquire(make_run(), tmp_path)

    assert result.status is ProcessAcquisitionStatus.COMPLETED
    assert result.run is not None
    assert result.run.attempts[0].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert result.run.session.checked_count == 0


def test_successful_run_can_continue(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    (tmp_path / "plan").write_bytes(b"evaluation plan")

    first = acquire(make_run(), tmp_path, "truth")
    assert first.run is not None

    second = acquire(first.run, tmp_path, "plan")

    assert second.status is ProcessAcquisitionStatus.COMPLETED
    assert second.run is not None
    assert second.run.session.matched_ids == ("plan", "truth")
    assert second.run.attempted_files == 2


def test_byte_budget_rejects_before_worker_read(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    result = acquire(
        make_run(max_total_bytes=4),
        tmp_path,
    )

    assert result.status is ProcessAcquisitionStatus.COMPLETED
    assert result.run is not None
    assert result.run.attempts[0].outcome is AcquisitionOutcome.BUDGET_EXCEEDED
    assert result.run.total_bytes == 0


def test_expired_run_does_not_start_worker(tmp_path: Path, monkeypatch):
    run = make_run(max_elapsed_seconds=1.0)
    run = replace(run, started_at=0.0)

    def forbidden_context(*args, **kwargs):
        pytest.fail("Expired run must not create a worker.")

    monkeypatch.setattr(
        time_evidence_process.multiprocessing,
        "get_context",
        forbidden_context,
    )

    result = acquire(run, tmp_path)

    assert result.status is ProcessAcquisitionStatus.COMPLETED
    assert result.run is not None
    assert result.run.attempts[0].outcome is AcquisitionOutcome.BUDGET_EXCEEDED


def test_real_spawn_timeout_terminates_and_reaps_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    stopped: list[tuple[int | None, bool, bool]] = []
    original_stop = time_evidence_process._stop_worker

    def tracked_stop(process) -> bool:
        result = original_stop(process)
        stopped.append((process.pid, result, process.is_alive()))
        return result

    monkeypatch.setattr(time_evidence_process, "_worker", _blocking_worker)
    monkeypatch.setattr(time_evidence_process, "_stop_worker", tracked_stop)

    started = time.monotonic()
    result = acquire(make_run(), tmp_path, timeout_seconds=0.1)
    elapsed = time.monotonic() - started

    assert result.status is ProcessAcquisitionStatus.TIMED_OUT
    assert result.run is None
    assert stopped
    assert all(reaped and not alive for _, reaped, alive in stopped)
    assert elapsed < 5.0


def test_abnormal_worker_exit_returns_terminal_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    monkeypatch.setattr(time_evidence_process, "_worker", _crashing_worker)

    result = acquire(make_run(), tmp_path)

    assert result.status is ProcessAcquisitionStatus.WORKER_FAILED
    assert result.run is None


def test_start_failure_closes_pipe_ends_and_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    class FakeConnection:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        pid = None
        exitcode = None

        def __init__(self) -> None:
            self.closed = False

        def start(self) -> None:
            raise AssertionError("daemonic processes cannot create children")

        def is_alive(self) -> bool:
            return False

        def close(self) -> None:
            self.closed = True

    parent_connection = FakeConnection()
    child_connection = FakeConnection()
    process = FakeProcess()

    class FakeContext:
        def Pipe(self, *, duplex):
            assert duplex is False
            return parent_connection, child_connection

        def Process(self, **kwargs):
            return process

    monkeypatch.setattr(
        time_evidence_process.multiprocessing,
        "get_context",
        lambda method: FakeContext(),
    )

    result = acquire(make_run(), tmp_path)

    assert result.status is ProcessAcquisitionStatus.WORKER_FAILED
    assert result.run is None
    assert parent_connection.closed
    assert child_connection.closed
    assert process.closed


def test_deadline_expiring_before_start_closes_all_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    class FakeConnection:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FakeProcess:
        pid = None
        exitcode = None

        def __init__(self) -> None:
            self.started = False
            self.closed = False

        def start(self) -> None:
            self.started = True

        def is_alive(self) -> bool:
            return False

        def close(self) -> None:
            self.closed = True

    parent_connection = FakeConnection()
    child_connection = FakeConnection()
    process = FakeProcess()
    run = make_run()

    class FakeContext:
        def Pipe(self, *, duplex):
            assert duplex is False
            return parent_connection, child_connection

        def Process(self, **kwargs):
            return process

    clock = iter((0.0, 1.0))
    monkeypatch.setattr(time_evidence_process.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(
        time_evidence_process.multiprocessing,
        "get_context",
        lambda method: FakeContext(),
    )

    result = acquire(run, tmp_path, timeout_seconds=0.5)

    assert result.status is ProcessAcquisitionStatus.TIMED_OUT
    assert result.run is None
    assert not process.started
    assert parent_connection.closed
    assert child_connection.closed
    assert process.closed


def test_unknown_evidence_id_is_rejected_before_spawn(tmp_path: Path):
    with pytest.raises(ValueError, match="not bound"):
        acquire(make_run(), tmp_path, "unknown")


def test_duplicate_evidence_is_rejected(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    first = acquire(make_run(), tmp_path)
    assert first.run is not None

    with pytest.raises(ValueError, match="already attempted"):
        acquire(first.run, tmp_path)


def test_file_count_budget_is_enforced(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    initial = start_acquisition_run(
        session=make_session(),
        policy=AcquisitionPolicy(
            max_files=1,
            max_total_bytes=1024,
            max_elapsed_seconds=30.0,
        ),
    )
    first = acquire(initial, tmp_path)
    assert first.run is not None

    with pytest.raises(ValueError, match="file budget"):
        acquire(first.run, tmp_path, "plan")


@pytest.mark.parametrize(
    "relative_path",
    ("../secret", "/etc/passwd", "a//b", "./truth"),
)
def test_invalid_paths_rejected_before_spawn(
    tmp_path: Path,
    relative_path: str,
    monkeypatch,
):
    def forbidden_context(*args, **kwargs):
        pytest.fail("Invalid path must not spawn a process.")

    monkeypatch.setattr(
        time_evidence_process.multiprocessing,
        "get_context",
        forbidden_context,
    )

    with pytest.raises(ValueError, match="relative evidence path"):
        acquire_evidence_isolated(
            run=make_run(),
            evidence_id="truth",
            root=tmp_path,
            relative_path=relative_path,
        )


@pytest.mark.parametrize(
    "value",
    (0.0, -1.0, 3600.1, 5, True, None, float("nan"), float("inf")),
)
def test_invalid_timeout_rejected(value):
    with pytest.raises(ValueError, match="timeout"):
        acquire_evidence_isolated(
            run=make_run(),
            evidence_id="truth",
            root="/tmp",
            relative_path="truth",
            timeout_seconds=value,
        )


def test_success_worker_message_validation():
    digest = hashlib.sha256(b"abc").hexdigest()

    result = _validate_message(
        ("success", digest, 3),
        byte_limit=10,
    )

    assert result == (AcquisitionOutcome.MATCHED, digest, 3)


@pytest.mark.parametrize(
    "message",
    (
        [],
        (),
        ("success", "invalid", 3),
        (1, "0" * 64, 3),
        ("success", "0" * 64, 0),
        ("success", "0" * 64, True),
        ("success", "0" * 64, -1),
        ("success", "0" * 64, 100),
        ("failure", "unknown", 0),
        ("failure", "acquisition_failed", 100),
        ("success", "0" * 64, 1, "extra"),
    ),
)
def test_invalid_worker_messages(message):
    assert _validate_message(message, byte_limit=10) is None


@pytest.mark.parametrize("byte_limit", (True, 0, -1, MAX_EVIDENCE_BYTES + 1))
def test_invalid_worker_message_byte_limit(byte_limit):
    assert (
        _validate_message(
            ("failure", "acquisition_failed", 0),
            byte_limit=byte_limit,
        )
        is None
    )


def test_partial_failure_worker_message():
    result = _validate_message(
        ("failure", "acquisition_failed", 5),
        byte_limit=20,
    )

    assert result == (
        AcquisitionOutcome.ACQUISITION_FAILED,
        None,
        5,
    )


def test_timeout_result_has_no_resumable_run():
    result = ProcessAcquisitionResult(
        status=ProcessAcquisitionStatus.TIMED_OUT,
    )

    assert not result.can_continue
    assert result.run is None


def test_worker_failure_has_no_resumable_run():
    result = ProcessAcquisitionResult(
        status=ProcessAcquisitionStatus.WORKER_FAILED,
    )

    assert not result.can_continue
    assert result.run is None


def test_unreaped_result_has_no_resumable_run():
    result = ProcessAcquisitionResult(
        status=ProcessAcquisitionStatus.UNREAPED,
    )

    assert not result.can_continue
    assert result.run is None


def test_invalid_result_construction():
    with pytest.raises(ValueError, match="requires a run"):
        ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
        )

    with pytest.raises(ValueError, match="must not expose a run"):
        ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.TIMED_OUT,
            run=make_run(),
        )

    with pytest.raises(TypeError, match="status"):
        ProcessAcquisitionResult(status="completed")


def test_stop_worker_terminates_and_reaps():
    class FakeProcess:
        def __init__(self):
            self.alive = True
            self.exitcode = None
            self.terminated = False

        def is_alive(self):
            return self.alive

        def terminate(self):
            self.terminated = True
            self.alive = False
            self.exitcode = -15

        def join(self, timeout=None):
            pass

        def kill(self):
            pytest.fail("Terminate should have been sufficient.")

    process = FakeProcess()

    assert _stop_worker(process)
    assert process.terminated


def test_stop_worker_escalates_to_kill():
    class FakeProcess:
        def __init__(self):
            self.alive = True
            self.exitcode = None
            self.killed = False

        def is_alive(self):
            return self.alive

        def terminate(self):
            pass

        def join(self, timeout=None):
            pass

        def kill(self):
            self.killed = True
            self.alive = False
            self.exitcode = -9

    process = FakeProcess()

    assert _stop_worker(process)
    assert process.killed


def test_stop_worker_reports_unreaped():
    class FakeProcess:
        exitcode = None

        def is_alive(self):
            return True

        def terminate(self):
            pass

        def join(self, timeout=None):
            pass

        def kill(self):
            pass

    assert not _stop_worker(FakeProcess())


def test_no_raw_content_in_result(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    result = acquire(make_run(), tmp_path)

    assert not hasattr(result, "content")
    assert not hasattr(result, "root")
    assert not hasattr(result, "relative_path")
    assert "ground truth evidence" not in repr(result)


def test_ground_truth_is_unchanged(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    result = acquire(make_run(), tmp_path)

    assert result.run is not None
    application = result.run.session.binding.manifest.benchmark.clusters[
        0
    ].applications[0]
    assert application.samples[0].status.value == "not_confirmed"
