"""Tests for shared evidence acquisition resource governance."""

import threading
from dataclasses import replace
from pathlib import Path

import pytest
from test_sqli_time_evidence_loader import make_session

from vintar.checks.sqli.time_evidence_governor import (
    AcquisitionGovernanceError,
    GovernedAcquisitionResult,
    GovernorHandle,
    GovernorPolicy,
    GovernorUsage,
    ResourceBudgetError,
    create_resource_governor,
)
from vintar.checks.sqli.time_evidence_lifecycle import (
    AcquisitionLifecycleStatus,
    AcquisitionSupervisor,
    LifecycleAcquisitionResult,
)
from vintar.checks.sqli.time_evidence_process import ProcessAcquisitionStatus
from vintar.checks.sqli.time_evidence_stream import (
    AcquisitionOutcome,
    AcquisitionPolicy,
)

_MIB = 1024 * 1024
_FILE_LIMIT = 16 * _MIB


def make_governor(
    *,
    max_files: int = 8,
    max_total_bytes: int = 4 * _FILE_LIMIT,
    max_workers: int = 2,
):
    return create_resource_governor(
        policy=GovernorPolicy(
            max_files=max_files,
            max_total_bytes=max_total_bytes,
            max_workers=max_workers,
        )
    )


def register(governor, *, run_bytes: int = 4 * _FILE_LIMIT):
    return governor.register(
        session=make_session(),
        policy=AcquisitionPolicy(
            max_files=4,
            max_total_bytes=run_bytes,
            max_elapsed_seconds=30.0,
        ),
    )


def acquire(governor, handle, tmp_path: Path, evidence_id: str = "truth"):
    return governor.acquire(
        handle=handle,
        evidence_id=evidence_id,
        root=tmp_path,
        relative_path=evidence_id,
        timeout_seconds=10.0,
    )


def test_new_governor_has_zero_usage():
    governor = make_governor()
    usage = governor.usage()

    assert usage.files_used == 0
    assert usage.bytes_used == 0
    assert usage.slots_in_use == 0
    assert usage.unknown_slots == 0
    assert usage.can_admit


def test_registration_owns_a_supervisor():
    governor = make_governor()
    handle = register(governor)

    assert handle.generation == 0
    assert len(handle.run_id) == 32
    assert governor.snapshot(handle=handle).attempted_files == 0


def test_real_acquisition_refunds_unused_reservation(tmp_path: Path):
    content = b"ground truth evidence"
    (tmp_path / "truth").write_bytes(content)

    governor = make_governor()
    handle = register(governor)

    result = acquire(governor, handle, tmp_path)

    assert result.can_continue
    assert result.handle is not None
    assert result.run is not None
    assert result.handle.generation == 1
    assert result.run.attempts[-1].outcome is AcquisitionOutcome.MATCHED

    usage = governor.usage()
    assert usage.files_used == 1
    assert usage.bytes_used == len(content)
    assert usage.slots_in_use == 0
    assert usage.unknown_slots == 0

    with pytest.raises(AcquisitionGovernanceError, match="Stale"):
        governor.snapshot(handle=handle)


def test_two_supervisors_share_byte_accounting(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    (tmp_path / "plan").write_bytes(b"evaluation plan")

    governor = make_governor(max_workers=2)
    first_handle = register(governor)
    second_handle = register(governor)

    first = acquire(governor, first_handle, tmp_path, "truth")
    second = acquire(governor, second_handle, tmp_path, "plan")

    assert first.can_continue
    assert second.can_continue
    assert governor.usage().files_used == 2
    assert governor.usage().bytes_used == (
        len(b"ground truth evidence") + len(b"evaluation plan")
    )


def test_shared_file_limit_rejects_without_charging(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor(max_files=1)
    first_handle = register(governor)
    second_handle = register(governor)

    acquire(governor, first_handle, tmp_path)

    with pytest.raises(ResourceBudgetError, match="file budget"):
        acquire(governor, second_handle, tmp_path)

    assert governor.usage().files_used == 1
    assert governor.snapshot(handle=second_handle).attempted_files == 0


def test_reservation_requires_entire_possible_file_budget(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor(
        max_total_bytes=_FILE_LIMIT - 1,
    )
    handle = register(governor)

    with pytest.raises(ResourceBudgetError, match="byte budget"):
        acquire(governor, handle, tmp_path)

    assert governor.usage().files_used == 0
    assert governor.usage().bytes_used == 0
    assert governor.snapshot(handle=handle).attempted_files == 0


def test_smaller_run_budget_can_be_reserved(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor(max_total_bytes=64)
    handle = register(governor, run_bytes=64)

    result = acquire(governor, handle, tmp_path)

    assert result.can_continue
    assert governor.usage().bytes_used == len(b"ground truth evidence")


def test_missing_file_charges_file_not_bytes(tmp_path: Path):
    governor = make_governor()
    handle = register(governor)

    result = acquire(governor, handle, tmp_path)

    assert result.can_continue
    assert result.run is not None
    assert result.run.attempts[-1].outcome is AcquisitionOutcome.ACQUISITION_FAILED
    assert governor.usage().files_used == 1
    assert governor.usage().bytes_used == 0


def test_invalid_path_is_not_reserved(tmp_path: Path):
    governor = make_governor()
    handle = register(governor)

    with pytest.raises(ValueError, match="relative evidence path"):
        governor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="../secret",
        )

    assert governor.usage().files_used == 0
    assert governor.usage().bytes_used == 0
    assert governor.usage().slots_in_use == 0


def test_unknown_evidence_is_not_reserved(tmp_path: Path):
    governor = make_governor()
    handle = register(governor)

    with pytest.raises(ValueError, match="not bound"):
        acquire(governor, handle, tmp_path, "unknown")

    assert governor.usage().files_used == 0


def test_timeout_charges_full_bytes_but_releases_worker_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    governor = make_governor()
    handle = register(governor)

    def fake_timeout(self, **kwargs):
        return LifecycleAcquisitionResult(
            status=AcquisitionLifecycleStatus.INVALIDATED,
            process_status=ProcessAcquisitionStatus.TIMED_OUT,
        )

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", fake_timeout)

    result = acquire(governor, handle, tmp_path)

    assert not result.can_continue
    assert result.handle is None
    assert result.run is None

    usage = governor.usage()
    assert usage.files_used == 1
    assert usage.bytes_used == _FILE_LIMIT
    assert usage.slots_in_use == 0
    assert usage.unknown_slots == 0
    assert usage.can_admit

    with pytest.raises(AcquisitionGovernanceError, match="Stale"):
        governor.snapshot(handle=handle)


@pytest.mark.parametrize(
    "status",
    (
        ProcessAcquisitionStatus.WORKER_FAILED,
        ProcessAcquisitionStatus.UNREAPED,
    ),
)
def test_uncertain_worker_halts_governor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: ProcessAcquisitionStatus,
):
    governor = make_governor()
    handle = register(governor)

    def fake_terminal(self, **kwargs):
        return LifecycleAcquisitionResult(
            status=AcquisitionLifecycleStatus.INVALIDATED,
            process_status=status,
        )

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", fake_terminal)

    result = acquire(governor, handle, tmp_path)

    assert not result.can_continue
    usage = governor.usage()
    assert usage.halted
    assert usage.files_used == 1
    assert usage.bytes_used == _FILE_LIMIT
    assert usage.slots_in_use == 1
    assert usage.unknown_slots == 1

    with pytest.raises(AcquisitionGovernanceError, match="halted"):
        register(governor)


def test_unexpected_exception_halts_and_preserves_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    governor = make_governor()
    handle = register(governor)

    def crash(self, **kwargs):
        raise RuntimeError("simulated unexpected exception")

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", crash)

    with pytest.raises(RuntimeError, match="unexpected"):
        acquire(governor, handle, tmp_path)

    usage = governor.usage()
    assert usage.halted
    assert usage.files_used == 1
    assert usage.bytes_used == _FILE_LIMIT
    assert usage.slots_in_use == 1
    assert usage.unknown_slots == 1


def test_malformed_lifecycle_result_halts_governor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    governor = make_governor()
    handle = register(governor)

    def malformed(self, **kwargs):
        return None

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", malformed)

    with pytest.raises(AcquisitionGovernanceError, match="Invalid supervised"):
        acquire(governor, handle, tmp_path)

    assert governor.usage().halted
    assert governor.usage().bytes_used == _FILE_LIMIT


def test_foreign_and_cloned_handles_are_rejected():
    governor_a = make_governor()
    governor_b = make_governor()

    handle = register(governor_a)
    foreign = register(governor_b)

    with pytest.raises(AcquisitionGovernanceError, match="Stale or foreign"):
        governor_a.snapshot(handle=foreign)

    with pytest.raises(AcquisitionGovernanceError, match="Stale or foreign"):
        governor_a.snapshot(handle=replace(handle))


def test_explicit_termination_does_not_refund_past_reads(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor()
    first = acquire(governor, register(governor), tmp_path)

    assert first.handle is not None
    before = governor.usage()

    governor.terminate(handle=first.handle)

    assert governor.usage() == before

    with pytest.raises(AcquisitionGovernanceError, match="Stale"):
        governor.snapshot(handle=first.handle)


def test_explicit_invalidation_revokes_handle():
    governor = make_governor()
    handle = register(governor)

    governor.invalidate(handle=handle)

    with pytest.raises(AcquisitionGovernanceError, match="Stale"):
        governor.snapshot(handle=handle)


def test_worker_slot_limit_does_not_hold_global_lock(
    worker_pool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor(max_workers=1)
    first_handle = register(governor)
    second_handle = register(governor)

    entered = threading.Event()
    release = threading.Event()

    original_acquire = AcquisitionSupervisor.acquire

    def blocking_acquire(self, **kwargs):
        entered.set()
        if not release.wait(timeout=10.0):
            raise RuntimeError("Test worker gate timed out.")
        return original_acquire(self, **kwargs)

    monkeypatch.setattr(
        AcquisitionSupervisor,
        "acquire",
        blocking_acquire,
    )

    future = worker_pool.submit(acquire, governor, first_handle, tmp_path)

    try:
        assert entered.wait(timeout=5.0)
        usage = governor.usage()
        assert usage.slots_in_use == 1
        assert usage.bytes_used == _FILE_LIMIT

        with pytest.raises(ResourceBudgetError, match="worker limit"):
            acquire(governor, second_handle, tmp_path)
    finally:
        release.set()
        future.result(timeout=15.0)
    assert governor.usage().slots_in_use == 0


def test_parallel_reservations_cannot_overcommit_bytes(
    worker_pool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor(
        max_total_bytes=_FILE_LIMIT,
        max_workers=2,
    )
    first_handle = register(governor)
    second_handle = register(governor)

    entered = threading.Event()
    release = threading.Event()

    original_acquire = AcquisitionSupervisor.acquire

    def blocking_acquire(self, **kwargs):
        entered.set()
        if not release.wait(timeout=10.0):
            raise RuntimeError("Test gate timed out.")
        return original_acquire(self, **kwargs)

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", blocking_acquire)

    future = worker_pool.submit(acquire, governor, first_handle, tmp_path)

    try:
        assert entered.wait(timeout=5.0)

        with pytest.raises(ResourceBudgetError, match="byte budget"):
            acquire(governor, second_handle, tmp_path)

        assert governor.usage().bytes_used == _FILE_LIMIT
    finally:
        release.set()
        future.result(timeout=15.0)


def test_same_supervisor_cannot_start_two_operations(
    worker_pool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    governor = make_governor()
    handle = register(governor)

    entered = threading.Event()
    release = threading.Event()
    original_acquire = AcquisitionSupervisor.acquire

    def blocking_acquire(self, **kwargs):
        entered.set()
        if not release.wait(timeout=10.0):
            raise RuntimeError("Test gate timed out.")
        return original_acquire(self, **kwargs)

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", blocking_acquire)

    future = worker_pool.submit(acquire, governor, handle, tmp_path)

    try:
        assert entered.wait(timeout=5.0)
        with pytest.raises(AcquisitionGovernanceError, match="in progress"):
            acquire(governor, handle, tmp_path)
        with pytest.raises(AcquisitionGovernanceError, match="in progress"):
            governor.terminate(handle=handle)
    finally:
        release.set()
        future.result(timeout=15.0)


@pytest.mark.parametrize(
    "changes",
    (
        {"files_used": -1},
        {"bytes_used": True},
        {"slots_in_use": 0, "unknown_slots": 1, "halted": True},
        {"slots_in_use": 1, "unknown_slots": 1, "halted": False},
        {"halted": 1},
    ),
)
def test_invalid_governor_usage_is_rejected(changes):
    values = {
        "files_used": 0,
        "bytes_used": 0,
        "slots_in_use": 0,
        "unknown_slots": 0,
        "halted": False,
    }
    values.update(changes)

    with pytest.raises((TypeError, ValueError)):
        GovernorUsage(**values)


def test_governed_result_requires_matching_lifecycle_handle():
    supervisor = AcquisitionSupervisor(
        session=make_session(),
        policy=AcquisitionPolicy(
            max_files=4,
            max_total_bytes=4 * _FILE_LIMIT,
            max_elapsed_seconds=30.0,
        ),
    )
    lifecycle_handle = supervisor.initial_handle()
    lifecycle = LifecycleAcquisitionResult(
        status=AcquisitionLifecycleStatus.ACTIVE,
        process_status=ProcessAcquisitionStatus.COMPLETED,
        handle=lifecycle_handle,
        run=supervisor.snapshot(handle=lifecycle_handle),
    )

    with pytest.raises(ValueError, match="does not match"):
        GovernedAcquisitionResult(
            lifecycle=lifecycle,
            handle=GovernorHandle(
                run_id="0" * 32,
                generation=lifecycle_handle.generation,
            ),
        )


@pytest.mark.parametrize(
    "value",
    (0, -1, True, 1.5, None, 301**2 + 1),
)
def test_invalid_governor_file_budget(value):
    with pytest.raises(ValueError, match="file budget"):
        GovernorPolicy(max_files=value)


@pytest.mark.parametrize(
    "value",
    (
        0,
        -1,
        True,
        1.5,
        None,
        16 * _MIB * 301**2 + 1,
    ),
)
def test_invalid_governor_byte_budget(value):
    with pytest.raises(ValueError, match="byte budget"):
        GovernorPolicy(max_total_bytes=value)


@pytest.mark.parametrize("value", (0, -1, 65, True, 1.5, None))
def test_invalid_governor_worker_limit(value):
    with pytest.raises(ValueError, match="worker limit"):
        GovernorPolicy(max_workers=value)


def test_invalid_timeout_is_rejected_before_reservation(tmp_path: Path):
    governor = make_governor()
    handle = register(governor)

    with pytest.raises(ValueError, match="timeout"):
        governor.acquire(
            handle=handle,
            evidence_id="truth",
            root=tmp_path,
            relative_path="truth",
            timeout_seconds=True,
        )

    assert governor.usage().files_used == 0


def test_governor_rejects_invalid_handle_type():
    governor = make_governor()

    with pytest.raises(TypeError, match="handle"):
        governor.snapshot(handle=object())


def test_wrong_policy_type_is_rejected():
    with pytest.raises(TypeError, match="policy"):
        create_resource_governor(policy=object())


def test_ground_truth_is_not_modified(tmp_path: Path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor()
    result = acquire(governor, register(governor), tmp_path)

    assert result.run is not None
    application = result.run.binding.manifest.benchmark.clusters[0].applications[0]

    assert application.samples[0].status.value == "not_confirmed"
