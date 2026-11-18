"""Integration tests for governed acquisition audit event emission."""

import threading

import pytest
from test_sqli_time_evidence_loader import make_session

from vintar.checks.sqli.time_evidence_audit import (
    AuditEventType,
    verify_audit_chain,
)
from vintar.checks.sqli.time_evidence_governor import (
    AcquisitionAuditError,
    AcquisitionGovernanceError,
    GovernorPolicy,
    ResourceBudgetError,
    create_resource_governor,
)
from vintar.checks.sqli.time_evidence_lifecycle import (
    AcquisitionLifecycleStatus,
    AcquisitionSupervisor,
    LifecycleAcquisitionResult,
)
from vintar.checks.sqli.time_evidence_process import (
    ProcessAcquisitionStatus,
)
from vintar.checks.sqli.time_evidence_stream import AcquisitionPolicy

_MIB = 1024 * 1024
_FILE_RESERVATION = 16 * _MIB


def make_governor(*, audited: bool = True, workers: int = 2):
    return create_resource_governor(
        policy=GovernorPolicy(
            max_files=20,
            max_total_bytes=8 * _FILE_RESERVATION,
            max_workers=workers,
        ),
        audited=audited,
    )


def register(governor):
    return governor.register(
        session=make_session(),
        policy=AcquisitionPolicy(
            max_files=4,
            max_total_bytes=4 * _FILE_RESERVATION,
            max_elapsed_seconds=30.0,
        ),
    )


def acquire(governor, handle, root, *, evidence_id="truth"):
    return governor.acquire(
        handle=handle,
        evidence_id=evidence_id,
        root=root,
        relative_path=evidence_id,
        timeout_seconds=10.0,
    )


def types(governor):
    return tuple(record.event.event_type for record in governor.audit_snapshot())


def test_audit_is_opt_in():
    governor = make_governor(audited=False)
    handle = register(governor)

    assert not governor.audit_enabled
    assert governor.snapshot(handle=handle).attempted_files == 0

    with pytest.raises(AcquisitionGovernanceError, match="disabled"):
        governor.audit_snapshot()

    with pytest.raises(AcquisitionGovernanceError, match="disabled"):
        governor.audit_verify()


def test_invalid_audited_flag():
    with pytest.raises(TypeError, match="audited"):
        create_resource_governor(
            policy=GovernorPolicy(),
            audited=1,
        )


def test_registration_automatically_records_event():
    governor = make_governor()
    handle = register(governor)

    assert types(governor) == (AuditEventType.REGISTERED,)
    record = governor.audit_snapshot()[0]

    assert record.event.run_id == handle.run_id
    assert record.event.evidence_id is None
    assert record.event.usage == governor.usage()
    assert governor.audit_verify().record_count == 1


def test_completed_acquisition_records_reservation_and_settlement(tmp_path):
    content = b"ground truth evidence"
    (tmp_path / "truth").write_bytes(content)

    governor = make_governor()
    handle = register(governor)
    result = acquire(governor, handle, tmp_path)

    assert result.can_continue
    assert result.handle is not None
    assert types(governor) == (
        AuditEventType.REGISTERED,
        AuditEventType.RESERVED,
        AuditEventType.SETTLED,
    )

    registration, reservation, settlement = governor.audit_snapshot()

    assert registration.event.run_id == handle.run_id
    assert reservation.event.evidence_id == "truth"
    assert reservation.event.usage.files_used == 1
    assert reservation.event.usage.bytes_used == _FILE_RESERVATION
    assert reservation.event.usage.slots_in_use == 1

    assert settlement.event.process_status is ProcessAcquisitionStatus.COMPLETED
    assert settlement.event.usage.bytes_used == len(content)
    assert settlement.event.usage.slots_in_use == 0
    assert settlement.event.usage == governor.usage()

    assert governor.audit_verify().record_count == 3


def test_normal_read_failure_is_settled(tmp_path):
    governor = make_governor()
    handle = register(governor)

    result = acquire(governor, handle, tmp_path)

    assert result.can_continue
    assert types(governor)[-2:] == (
        AuditEventType.RESERVED,
        AuditEventType.SETTLED,
    )
    assert governor.usage().bytes_used == 0
    assert governor.audit_snapshot()[-1].event.usage.bytes_used == 0


def test_explicit_termination_is_recorded():
    governor = make_governor()
    handle = register(governor)

    governor.terminate(handle=handle)

    assert types(governor) == (
        AuditEventType.REGISTERED,
        AuditEventType.TERMINATED,
    )
    assert governor.audit_snapshot()[-1].event.run_id == handle.run_id


def test_explicit_invalidation_is_recorded():
    governor = make_governor()
    handle = register(governor)

    governor.invalidate(handle=handle)

    assert types(governor) == (
        AuditEventType.REGISTERED,
        AuditEventType.INVALIDATED,
    )


def test_rejected_request_does_not_create_audit_event(tmp_path):
    governor = make_governor()
    handle = register(governor)
    before = governor.audit_snapshot()

    with pytest.raises(ValueError, match="not bound"):
        acquire(governor, handle, tmp_path, evidence_id="unknown")

    assert governor.audit_snapshot() is before
    assert governor.usage().files_used == 0


def test_timeout_records_settlement_and_invalidation(
    tmp_path,
    monkeypatch,
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
    assert types(governor) == (
        AuditEventType.REGISTERED,
        AuditEventType.RESERVED,
        AuditEventType.SETTLED,
        AuditEventType.INVALIDATED,
    )

    settlement = governor.audit_snapshot()[2].event
    invalidation = governor.audit_snapshot()[3].event

    assert settlement.process_status is ProcessAcquisitionStatus.TIMED_OUT
    assert invalidation.process_status is ProcessAcquisitionStatus.TIMED_OUT
    assert settlement.usage.bytes_used == _FILE_RESERVATION
    assert settlement.usage.slots_in_use == 0
    assert governor.usage().can_admit


@pytest.mark.parametrize(
    "status",
    (
        ProcessAcquisitionStatus.WORKER_FAILED,
        ProcessAcquisitionStatus.UNREAPED,
    ),
)
def test_uncertain_worker_records_invalidation_and_halt(
    tmp_path,
    monkeypatch,
    status,
):
    governor = make_governor()
    handle = register(governor)

    def fake_failure(self, **kwargs):
        return LifecycleAcquisitionResult(
            status=AcquisitionLifecycleStatus.INVALIDATED,
            process_status=status,
        )

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", fake_failure)

    result = acquire(governor, handle, tmp_path)

    assert not result.can_continue
    assert types(governor)[-2:] == (
        AuditEventType.INVALIDATED,
        AuditEventType.HALTED,
    )

    last = governor.audit_snapshot()[-1].event
    assert last.process_status is status
    assert last.usage.halted
    assert last.usage.unknown_slots == 1
    assert governor.usage().unknown_slots == 1

    with pytest.raises(AcquisitionGovernanceError, match="halted"):
        register(governor)


def test_worker_exception_records_halt_and_retains_reservation(
    tmp_path,
    monkeypatch,
):
    governor = make_governor()
    handle = register(governor)

    def raise_worker(self, **kwargs):
        raise RuntimeError("simulated worker exception")

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", raise_worker)

    with pytest.raises(RuntimeError, match="simulated worker"):
        acquire(governor, handle, tmp_path)

    assert types(governor) == (
        AuditEventType.REGISTERED,
        AuditEventType.RESERVED,
        AuditEventType.HALTED,
    )

    usage = governor.usage()
    assert usage.halted
    assert usage.bytes_used == _FILE_RESERVATION
    assert usage.slots_in_use == 1
    assert usage.unknown_slots == 1


def test_register_audit_failure_prevents_registration(monkeypatch):
    governor = make_governor()
    assert governor._journal is not None

    def reject(*, event):
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(governor._journal, "append", reject)

    with pytest.raises(AcquisitionAuditError, match="audit recording"):
        register(governor)

    assert governor.usage().halted
    assert governor.audit_snapshot() == ()
    assert governor.usage().files_used == 0


class SimulatedAuditAbort(BaseException):
    """Non-Exception audit failure used to verify fail-closed handling."""


def test_register_base_exception_from_audit_halts(monkeypatch):
    governor = make_governor()
    assert governor._journal is not None

    def reject(*, event):
        raise SimulatedAuditAbort

    monkeypatch.setattr(governor._journal, "append", reject)

    with pytest.raises(AcquisitionAuditError, match="audit recording"):
        register(governor)

    assert governor.usage().halted
    assert governor.audit_snapshot() == ()


def test_reservation_audit_failure_prevents_worker(
    tmp_path,
    monkeypatch,
):
    governor = make_governor()
    handle = register(governor)
    assert governor._journal is not None

    def reject(*, event):
        raise RuntimeError("audit write failed")

    def forbidden_worker(self, **kwargs):
        pytest.fail("Worker must not run after audit failure.")

    monkeypatch.setattr(governor._journal, "append", reject)
    monkeypatch.setattr(AcquisitionSupervisor, "acquire", forbidden_worker)

    with pytest.raises(AcquisitionAuditError):
        acquire(governor, handle, tmp_path)

    usage = governor.usage()
    assert usage.halted
    assert usage.files_used == 0
    assert usage.bytes_used == 0
    assert usage.slots_in_use == 0


def test_reservation_base_exception_prevents_worker(
    tmp_path,
    monkeypatch,
):
    governor = make_governor()
    handle = register(governor)
    assert governor._journal is not None

    def reject(*, event):
        raise SimulatedAuditAbort

    def forbidden_worker(self, **kwargs):
        pytest.fail("Worker must not run after audit failure.")

    monkeypatch.setattr(governor._journal, "append", reject)
    monkeypatch.setattr(AcquisitionSupervisor, "acquire", forbidden_worker)

    with pytest.raises(AcquisitionAuditError, match="audit recording"):
        acquire(governor, handle, tmp_path)

    usage = governor.usage()
    assert usage.halted
    assert usage.files_used == 0
    assert usage.bytes_used == 0
    assert usage.slots_in_use == 0


def test_terminal_audit_capacity_is_reserved_before_worker(
    tmp_path,
    monkeypatch,
):
    governor = make_governor()
    handle = register(governor)

    monkeypatch.setattr(
        "vintar.checks.sqli.time_evidence_audit.MAX_AUDIT_RECORDS",
        3,
    )

    def forbidden_worker(self, **kwargs):
        pytest.fail("Worker must not run without terminal audit capacity.")

    monkeypatch.setattr(AcquisitionSupervisor, "acquire", forbidden_worker)

    with pytest.raises(ResourceBudgetError, match="audit capacity"):
        acquire(governor, handle, tmp_path)

    assert types(governor) == (AuditEventType.REGISTERED,)
    assert governor.usage().files_used == 0


def test_settlement_audit_failure_halts_after_completion(
    tmp_path,
    monkeypatch,
):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")

    governor = make_governor()
    handle = register(governor)
    assert governor._journal is not None

    original_append = governor._journal.append

    def reject_settlement(*, event):
        if event.event_type is AuditEventType.SETTLED:
            raise RuntimeError("simulated settlement audit failure")
        return original_append(event=event)

    monkeypatch.setattr(
        governor._journal,
        "append",
        reject_settlement,
    )

    with pytest.raises(RuntimeError, match="settlement audit"):
        acquire(governor, handle, tmp_path)

    usage = governor.usage()
    assert usage.halted
    assert usage.files_used == 1
    assert usage.slots_in_use == 0
    assert usage.unknown_slots == 0
    assert usage.bytes_used == len(b"ground truth evidence")
    assert types(governor)[-1] is AuditEventType.HALTED

    with pytest.raises(AcquisitionGovernanceError, match="halted"):
        register(governor)


def test_termination_audit_failure_halts(
    monkeypatch,
):
    governor = make_governor()
    handle = register(governor)
    assert governor._journal is not None

    original_append = governor._journal.append

    def reject_termination(*, event):
        if event.event_type is AuditEventType.TERMINATED:
            raise RuntimeError("termination append failed")
        return original_append(event=event)

    monkeypatch.setattr(governor._journal, "append", reject_termination)

    with pytest.raises(RuntimeError, match="termination append"):
        governor.terminate(handle=handle)

    assert governor.usage().halted
    assert types(governor)[-1] is AuditEventType.HALTED


def test_multiple_runs_share_one_audit_chain(tmp_path):
    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    (tmp_path / "plan").write_bytes(b"evaluation plan")

    governor = make_governor()
    first = register(governor)
    second = register(governor)

    acquire(governor, first, tmp_path)
    acquire(governor, second, tmp_path, evidence_id="plan")

    records = governor.audit_snapshot()
    assert len(records) == 6
    assert tuple(record.sequence for record in records) == tuple(range(1, 7))
    assert governor.audit_verify().record_count == 6

    verification = verify_audit_chain(
        records=records,
        expected_head=records[-1].digest,
        expected_count=6,
    )
    assert verification.head_digest == records[-1].digest


def test_concurrent_registration_is_serialized():
    governor = make_governor()
    errors = []
    handles = []
    lock = threading.Lock()

    def task():
        try:
            result = register(governor)
            with lock:
                handles.append(result)
        except BaseException as exc:  # noqa: BLE001 - surface thread failures
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=task) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5.0)

    assert all(not thread.is_alive() for thread in threads)
    assert not errors
    assert len(handles) == 8
    assert len({handle.run_id for handle in handles}) == 8
    assert governor.audit_verify().record_count == 8
    assert types(governor) == (AuditEventType.REGISTERED,) * 8


def test_readonly_audit_snapshot_is_independent(tmp_path):
    governor = make_governor()
    before = governor.audit_snapshot()
    handle = register(governor)
    after_register = governor.audit_snapshot()

    (tmp_path / "truth").write_bytes(b"ground truth evidence")
    acquire(governor, handle, tmp_path)

    assert before == ()
    assert len(after_register) == 1
    assert len(governor.audit_snapshot()) == 3
    assert governor.audit_verify().record_count == 3
