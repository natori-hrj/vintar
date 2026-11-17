"""Tests for supervised acquisition lifecycle and handle revocation."""

import threading
from dataclasses import replace
from pathlib import Path

import pytest
from test_sqli_time_evidence_loader import make_session

from vintar.checks.sqli import time_evidence_lifecycle
from vintar.checks.sqli.time_evidence_lifecycle import (
    AcquisitionHandle,
    AcquisitionLifecycleError,
    AcquisitionLifecycleStatus,
    LifecycleAcquisitionResult,
    create_acquisition_supervisor,
)
from vintar.checks.sqli.time_evidence_process import (
    ProcessAcquisitionResult,
    ProcessAcquisitionStatus,
    _append_attempt,
)
from vintar.checks.sqli.time_evidence_stream import (
    AcquisitionOutcome,
    AcquisitionPolicy,
    AcquisitionRun,
)


def make_supervisor():
    return create_acquisition_supervisor(
        session=make_session(),
        policy=AcquisitionPolicy(
            max_files=4,
            max_total_bytes=1024,
            max_elapsed_seconds=30.0,
        ),
    )


def test_initial_supervisor_is_active():
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    run = supervisor.snapshot(handle=handle)

    assert supervisor.status is AcquisitionLifecycleStatus.ACTIVE
    assert supervisor.can_continue
    assert supervisor.last_process_status is None
    assert handle.generation == 0
    assert handle.run_id == supervisor.run_id
    assert run.attempted_files == 0


def test_real_process_acquisition_rotates_handle(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    supervisor = make_supervisor()
    first_handle = supervisor.initial_handle()

    result = supervisor.acquire(
        handle=first_handle,
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
        timeout_seconds=10.0,
    )

    assert result.status is AcquisitionLifecycleStatus.ACTIVE
    assert result.can_continue
    assert result.process_status is ProcessAcquisitionStatus.COMPLETED
    assert result.run is not None
    assert result.handle is not None
    assert result.handle is not first_handle
    assert result.handle.generation == 1
    assert result.run.attempted_files == 1
    assert result.run.attempts[0].outcome is AcquisitionOutcome.MATCHED
    assert supervisor.snapshot(handle=result.handle) is result.run

    with pytest.raises(AcquisitionLifecycleError, match="Stale or foreign"):
        supervisor.snapshot(handle=first_handle)


def test_two_real_acquisitions_advance_generations(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    (tmp_path / "plan").write_bytes(b"evaluation plan")

    supervisor = make_supervisor()
    first = supervisor.acquire(
        handle=supervisor.initial_handle(),
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
        timeout_seconds=10.0,
    )
    assert first.handle is not None

    second = supervisor.acquire(
        handle=first.handle,
        evidence_id="plan",
        root=tmp_path,
        relative_path="plan",
        timeout_seconds=10.0,
    )

    assert second.handle is not None
    assert second.run is not None
    assert second.handle.generation == 2
    assert second.run.session.matched_ids == ("plan", "truth")


@pytest.mark.parametrize(
    "status",
    (
        ProcessAcquisitionStatus.TIMED_OUT,
        ProcessAcquisitionStatus.WORKER_FAILED,
        ProcessAcquisitionStatus.UNREAPED,
    ),
)
def test_worker_terminal_state_invalidates_supervisor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: ProcessAcquisitionStatus,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    def fake_acquisition(**kwargs):
        return ProcessAcquisitionResult(status=status)

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        fake_acquisition,
    )

    result = supervisor.acquire(
        handle=handle,
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
    )

    assert result.status is AcquisitionLifecycleStatus.INVALIDATED
    assert result.process_status is status
    assert not result.can_continue
    assert result.handle is None
    assert result.run is None
    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED
    assert supervisor.last_process_status is status

    with pytest.raises(AcquisitionLifecycleError, match="not active"):
        supervisor.snapshot(handle=handle)

    with pytest.raises(AcquisitionLifecycleError, match="not active"):
        supervisor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )


def test_forged_handle_with_same_values_is_rejected():
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    forged = AcquisitionHandle(
        run_id=handle.run_id,
        generation=handle.generation,
    )

    assert forged is not handle

    with pytest.raises(AcquisitionLifecycleError, match="Stale or foreign"):
        supervisor.snapshot(handle=forged)


def test_dataclass_replace_handle_is_rejected():
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    with pytest.raises(AcquisitionLifecycleError, match="Stale or foreign"):
        supervisor.snapshot(handle=replace(handle))


def test_foreign_supervisor_handle_is_rejected():
    supervisor_a = make_supervisor()
    supervisor_b = make_supervisor()

    with pytest.raises(AcquisitionLifecycleError, match="Stale or foreign"):
        supervisor_a.snapshot(handle=supervisor_b.initial_handle())


def test_explicit_termination_revokes_handle():
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    supervisor.terminate(handle=handle)

    assert supervisor.status is AcquisitionLifecycleStatus.TERMINATED
    assert not supervisor.can_continue
    assert supervisor.last_process_status is None

    with pytest.raises(AcquisitionLifecycleError, match="not active"):
        supervisor.initial_handle()

    with pytest.raises(AcquisitionLifecycleError, match="not active"):
        supervisor.snapshot(handle=handle)


def test_explicit_invalidation_revokes_handle():
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    supervisor.invalidate(handle=handle)

    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED
    assert not supervisor.can_continue

    with pytest.raises(AcquisitionLifecycleError, match="not active"):
        supervisor.terminate(handle=handle)


def test_invalid_arguments_conservatively_invalidate_run(tmp_path: Path):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    with pytest.raises(ValueError, match="not bound"):
        supervisor.acquire(
            handle=handle,
            evidence_id="unknown",
            root=tmp_path,
            relative_path="unknown",
        )

    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED


def test_worker_exception_invalidates_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    def worker_raises(**kwargs):
        raise RuntimeError("simulated worker failure")

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        worker_raises,
    )

    with pytest.raises(RuntimeError, match="simulated worker failure"):
        supervisor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )

    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED
    assert not supervisor.can_continue


@pytest.mark.parametrize("invalid_result", (None, object()))
def test_invalid_worker_result_type_invalidates_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    invalid_result,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        lambda **kwargs: invalid_result,
    )

    with pytest.raises(AcquisitionLifecycleError, match="process result"):
        supervisor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )

    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED
    assert not supervisor.can_continue


def test_malformed_completed_result_invalidates_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    malformed = object.__new__(ProcessAcquisitionResult)
    object.__setattr__(malformed, "status", ProcessAcquisitionStatus.COMPLETED)
    object.__setattr__(malformed, "run", None)

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        lambda **kwargs: malformed,
    )

    with pytest.raises(AcquisitionLifecycleError, match="Inconsistent"):
        supervisor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )

    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED


def test_old_snapshot_cannot_restore_supervisor_state(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    original_run = supervisor.snapshot(handle=handle)

    result = supervisor.acquire(
        handle=handle,
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
        timeout_seconds=10.0,
    )

    assert result.run is not None
    assert original_run.attempted_files == 0

    with pytest.raises(AcquisitionLifecycleError, match="Stale or foreign"):
        supervisor.acquire(
            handle=handle,
            evidence_id="plan",
            root=tmp_path,
            relative_path="plan",
        )


def test_terminal_supervisor_cannot_be_reactivated():
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()

    supervisor.terminate(handle=handle)

    with pytest.raises(AcquisitionLifecycleError, match="not active"):
        supervisor.invalidate(handle=handle)

    assert supervisor.status is AcquisitionLifecycleStatus.TERMINATED


def test_invalid_handle_type_is_rejected():
    supervisor = make_supervisor()

    with pytest.raises(TypeError, match="handle"):
        supervisor.snapshot(handle="invalid")


@pytest.mark.parametrize(
    "run_id,generation",
    (
        ("invalid", 0),
        ("0" * 32, -1),
        ("0" * 32, True),
        ("0" * 32, 1.5),
    ),
)
def test_invalid_handle_construction(run_id, generation):
    with pytest.raises(ValueError):
        AcquisitionHandle(run_id=run_id, generation=generation)


def test_active_result_requires_complete_components():
    with pytest.raises(ValueError, match="requires completed"):
        LifecycleAcquisitionResult(
            status=AcquisitionLifecycleStatus.ACTIVE,
            process_status=ProcessAcquisitionStatus.COMPLETED,
        )


def test_terminal_result_rejects_continuation():
    supervisor = make_supervisor()
    run = supervisor.snapshot(handle=supervisor.initial_handle())

    with pytest.raises(ValueError, match="must not expose"):
        LifecycleAcquisitionResult(
            status=AcquisitionLifecycleStatus.INVALIDATED,
            process_status=ProcessAcquisitionStatus.TIMED_OUT,
            run=run,
        )


def test_invalidated_result_rejects_completed_process():
    with pytest.raises(ValueError, match="cannot be completed"):
        LifecycleAcquisitionResult(
            status=AcquisitionLifecycleStatus.INVALIDATED,
            process_status=ProcessAcquisitionStatus.COMPLETED,
        )


def test_completed_worker_result_preserves_binding_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    run = supervisor.snapshot(handle=handle)

    altered = AcquisitionRun(
        binding=run.binding,
        session=run.session,
        policy=run.policy,
        started_at=run.started_at,
        attempts=(),
    )

    def fake_acquisition(**kwargs):
        return ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
            run=altered,
        )

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        fake_acquisition,
    )

    with pytest.raises(AcquisitionLifecycleError, match="Inconsistent"):
        supervisor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )

    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED


@pytest.mark.parametrize("alteration", ("policy", "started_at", "evidence_id"))
def test_completed_worker_result_rejects_changed_run_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    alteration: str,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    run = supervisor.snapshot(handle=handle)
    attempted_id = "plan" if alteration == "evidence_id" else "truth"
    altered = _append_attempt(
        run=run,
        evidence_id=attempted_id,
        outcome=AcquisitionOutcome.ACQUISITION_FAILED,
        consumed=0,
    )

    if alteration == "policy":
        altered = replace(
            altered,
            policy=AcquisitionPolicy(
                max_files=4,
                max_total_bytes=1024,
                max_elapsed_seconds=30.0,
            ),
        )
    elif alteration == "started_at":
        altered = replace(altered, started_at=run.started_at + 1.0)

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        lambda **kwargs: ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
            run=altered,
        ),
    )

    with pytest.raises(AcquisitionLifecycleError, match="Inconsistent"):
        supervisor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
        )

    assert supervisor.status is AcquisitionLifecycleStatus.INVALIDATED


def test_two_threads_cannot_use_same_handle_successfully(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    entered = threading.Event()
    release = threading.Event()
    successes = []
    failures = []

    original_run = supervisor.snapshot(handle=handle)

    updated_run = _append_attempt(
        run=original_run,
        evidence_id="truth",
        outcome=AcquisitionOutcome.ACQUISITION_FAILED,
        consumed=0,
    )

    def blocking_acquisition(**kwargs):
        entered.set()
        assert release.wait(timeout=5.0)
        return ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
            run=updated_run,
        )

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        blocking_acquisition,
    )

    def attempt():
        try:
            result = supervisor.acquire(
                handle=handle,
                evidence_id="truth",
                root=tmp_path,
                relative_path="truth",
            )
            successes.append(result)
        except AcquisitionLifecycleError as exc:
            failures.append(exc)

    first = threading.Thread(target=attempt)
    second = threading.Thread(target=attempt)

    first.start()
    assert entered.wait(timeout=5.0)
    second.start()
    release.set()

    first.join(timeout=5.0)
    second.join(timeout=5.0)

    assert not first.is_alive()
    assert not second.is_alive()
    assert len(successes) == 1
    assert len(failures) == 1
    assert supervisor.status is AcquisitionLifecycleStatus.ACTIVE


@pytest.mark.parametrize("operation", ("terminate", "invalidate"))
def test_terminal_operation_waits_for_inflight_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
):
    supervisor = make_supervisor()
    handle = supervisor.initial_handle()
    entered = threading.Event()
    release = threading.Event()
    acquisition_results = []
    terminal_errors = []
    updated_run = _append_attempt(
        run=supervisor.snapshot(handle=handle),
        evidence_id="truth",
        outcome=AcquisitionOutcome.ACQUISITION_FAILED,
        consumed=0,
    )

    def blocking_acquisition(**kwargs):
        entered.set()
        assert release.wait(timeout=5.0)
        return ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
            run=updated_run,
        )

    monkeypatch.setattr(
        time_evidence_lifecycle,
        "acquire_evidence_isolated",
        blocking_acquisition,
    )

    def perform_acquisition() -> None:
        acquisition_results.append(
            supervisor.acquire(
                handle=handle,
                evidence_id="truth",
                root=tmp_path,
                relative_path="truth",
            )
        )

    def perform_terminal_operation() -> None:
        try:
            getattr(supervisor, operation)(handle=handle)
        except AcquisitionLifecycleError as exc:
            terminal_errors.append(exc)

    acquisition_thread = threading.Thread(target=perform_acquisition)
    terminal_thread = threading.Thread(target=perform_terminal_operation)
    acquisition_thread.start()
    assert entered.wait(timeout=5.0)
    terminal_thread.start()
    assert terminal_thread.is_alive()
    release.set()
    acquisition_thread.join(timeout=5.0)
    terminal_thread.join(timeout=5.0)

    assert not acquisition_thread.is_alive()
    assert not terminal_thread.is_alive()
    assert len(acquisition_results) == 1
    assert len(terminal_errors) == 1
    assert supervisor.status is AcquisitionLifecycleStatus.ACTIVE


def test_explicit_termination_after_success(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    supervisor = make_supervisor()

    result = supervisor.acquire(
        handle=supervisor.initial_handle(),
        evidence_id="truth",
        root=tmp_path,
        relative_path="truth",
        timeout_seconds=10.0,
    )

    assert result.handle is not None
    supervisor.terminate(handle=result.handle)

    assert supervisor.status is AcquisitionLifecycleStatus.TERMINATED
    assert not supervisor.can_continue
