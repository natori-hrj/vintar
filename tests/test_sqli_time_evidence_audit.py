"""Tests for deterministic evidence acquisition audit chains."""

import hashlib
import json
import threading
from dataclasses import replace

import pytest

from vintar.checks.sqli import time_evidence_audit
from vintar.checks.sqli.time_evidence_audit import (
    GENESIS_DIGEST,
    MAX_AUDIT_RECORDS,
    AcquisitionAuditJournal,
    AuditEvent,
    AuditEventType,
    AuditIntegrityError,
    AuditRecord,
    AuditVerification,
    create_audit_journal,
    verify_audit_chain,
)
from vintar.checks.sqli.time_evidence_governor import GovernorUsage
from vintar.checks.sqli.time_evidence_process import ProcessAcquisitionStatus

_RUN_A = "a" * 32
_RUN_B = "b" * 32


def usage(
    *,
    files: int = 0,
    bytes_used: int = 0,
    slots: int = 0,
    unknown: int = 0,
    halted: bool = False,
) -> GovernorUsage:
    return GovernorUsage(
        files_used=files,
        bytes_used=bytes_used,
        slots_in_use=slots,
        unknown_slots=unknown,
        halted=halted,
    )


def registered(run_id: str = _RUN_A) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.REGISTERED,
        run_id=run_id,
        usage=usage(),
    )


def reserved(run_id: str = _RUN_A) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.RESERVED,
        run_id=run_id,
        evidence_id="truth",
        usage=usage(files=1, bytes_used=16 * 1024 * 1024, slots=1),
    )


def settled(run_id: str = _RUN_A) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.SETTLED,
        run_id=run_id,
        evidence_id="truth",
        process_status=ProcessAcquisitionStatus.COMPLETED,
        usage=usage(files=1, bytes_used=len(b"ground truth evidence")),
    )


def timed_out() -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.SETTLED,
        run_id=_RUN_A,
        evidence_id="truth",
        process_status=ProcessAcquisitionStatus.TIMED_OUT,
        usage=usage(files=1, bytes_used=16 * 1024 * 1024),
    )


def halted() -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.HALTED,
        run_id=_RUN_A,
        process_status=ProcessAcquisitionStatus.UNREAPED,
        usage=usage(
            files=1,
            bytes_used=16 * 1024 * 1024,
            slots=1,
            unknown=1,
            halted=True,
        ),
    )


def create_chain():
    journal = create_audit_journal()
    journal.append(event=registered())
    journal.append(event=reserved())
    journal.append(event=settled())
    return journal


def test_empty_journal_has_genesis_digest():
    journal = create_audit_journal()

    assert journal.record_count == 0
    assert journal.head_digest == GENESIS_DIGEST
    assert journal.snapshot() == ()
    assert journal.verify() == AuditVerification(
        record_count=0,
        head_digest=GENESIS_DIGEST,
    )


def test_append_creates_contiguous_chain():
    journal = create_chain()
    records = journal.snapshot()

    assert tuple(record.sequence for record in records) == (1, 2, 3)
    assert records[0].previous_digest == GENESIS_DIGEST
    assert records[1].previous_digest == records[0].digest
    assert records[2].previous_digest == records[1].digest
    assert journal.record_count == 3
    assert journal.head_digest == records[-1].digest

    result = journal.verify()
    assert result.record_count == 3
    assert result.head_digest == records[-1].digest


def test_identical_event_sequences_have_identical_digests():
    first = create_chain()
    second = create_chain()

    assert first.snapshot() == second.snapshot()
    assert first.head_digest == second.head_digest


def test_event_order_changes_digest():
    first = create_audit_journal()
    first.append(event=registered())
    first.append(event=reserved())

    second = create_audit_journal()
    second.append(event=reserved())
    second.append(event=registered())

    assert first.head_digest != second.head_digest
    assert first.verify().record_count == 2
    assert second.verify().record_count == 2


def test_event_content_changes_digest():
    first = create_audit_journal()
    second = create_audit_journal()

    first.append(event=registered(_RUN_A))
    second.append(event=registered(_RUN_B))

    assert first.head_digest != second.head_digest


def test_canonical_digest_uses_versioned_json():
    journal = create_audit_journal()
    event = registered()
    record = journal.append(event=event)

    document = {
        "version": 1,
        "sequence": 1,
        "previous_digest": GENESIS_DIGEST,
        "event": {
            "event_type": "registered",
            "run_id": _RUN_A,
            "evidence_id": None,
            "process_status": None,
            "usage": {
                "files_used": 0,
                "bytes_used": 0,
                "slots_in_use": 0,
                "unknown_slots": 0,
                "halted": False,
            },
        },
    }

    encoded = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")

    expected = hashlib.sha256(b"vintar.evidence.audit.v1\x00" + encoded).hexdigest()

    assert record.digest == expected


def test_snapshot_is_immutable_and_not_updated_retroactively():
    journal = create_audit_journal()
    first_snapshot = journal.snapshot()
    journal.append(event=registered())
    second_snapshot = journal.snapshot()

    assert first_snapshot == ()
    assert len(second_snapshot) == 1

    with pytest.raises((AttributeError, TypeError)):
        second_snapshot[0].digest = GENESIS_DIGEST


def test_modified_event_is_detected():
    journal = create_chain()
    records = journal.snapshot()
    changed = replace(
        records[1],
        event=replace(
            records[1].event,
            run_id=_RUN_B,
        ),
    )

    with pytest.raises(AuditIntegrityError, match="digest mismatch"):
        verify_audit_chain(
            records=(records[0], changed, records[2]),
        )


def test_modified_usage_is_detected():
    records = create_chain().snapshot()
    modified_event = replace(
        records[2].event,
        usage=usage(files=1, bytes_used=999),
    )

    with pytest.raises(AuditIntegrityError, match="digest mismatch"):
        verify_audit_chain(
            records=(
                records[0],
                records[1],
                replace(records[2], event=modified_event),
            ),
        )


def test_swapped_records_are_rejected():
    records = create_chain().snapshot()

    with pytest.raises(AuditIntegrityError, match="sequence"):
        verify_audit_chain(
            records=(records[0], records[2], records[1]),
        )


def test_deleted_middle_record_is_rejected():
    records = create_chain().snapshot()

    with pytest.raises(AuditIntegrityError, match="sequence"):
        verify_audit_chain(
            records=(records[0], records[2]),
        )


def test_previous_digest_tampering_is_rejected():
    records = create_chain().snapshot()
    tampered = replace(records[1], previous_digest="f" * 64)

    with pytest.raises(AuditIntegrityError, match="predecessor"):
        verify_audit_chain(
            records=(records[0], tampered, records[2]),
        )


def test_record_digest_tampering_is_rejected():
    records = create_chain().snapshot()
    tampered = replace(records[1], digest="f" * 64)

    with pytest.raises(AuditIntegrityError, match="digest mismatch"):
        verify_audit_chain(
            records=(records[0], tampered, records[2]),
        )


def test_truncated_tail_requires_independent_anchor():
    journal = create_chain()
    full = journal.snapshot()
    truncated = full[:-1]

    # Internally valid prefixes cannot prove that later events existed.
    assert verify_audit_chain(records=truncated).record_count == 2

    with pytest.raises(AuditIntegrityError, match="count"):
        verify_audit_chain(
            records=truncated,
            expected_count=journal.record_count,
            expected_head=journal.head_digest,
        )


def test_anchor_head_rejects_tail_replacement():
    original = create_chain()
    replacement = create_audit_journal()
    replacement.append(event=registered())
    replacement.append(event=reserved())
    replacement.append(event=timed_out())

    assert replacement.record_count == original.record_count

    with pytest.raises(AuditIntegrityError, match="head"):
        verify_audit_chain(
            records=replacement.snapshot(),
            expected_head=original.head_digest,
            expected_count=original.record_count,
        )


def test_empty_chain_rejects_non_genesis_anchor():
    with pytest.raises(AuditIntegrityError, match="head"):
        verify_audit_chain(
            records=(),
            expected_head="f" * 64,
        )


@pytest.mark.parametrize(
    "records",
    (
        [],
        None,
        (object(),),
        ("invalid",),
    ),
)
def test_invalid_record_collection_is_rejected(records):
    with pytest.raises((TypeError, AuditIntegrityError)):
        verify_audit_chain(records=records)


@pytest.mark.parametrize(
    "expected_head",
    ("invalid", "A" * 64, 123, True),
)
def test_invalid_expected_head_is_rejected(expected_head):
    with pytest.raises(ValueError, match="expected audit head"):
        verify_audit_chain(records=(), expected_head=expected_head)


@pytest.mark.parametrize(
    "expected_count",
    (-1, True, 1.5, MAX_AUDIT_RECORDS + 1),
)
def test_invalid_expected_count_is_rejected(expected_count):
    with pytest.raises(ValueError, match="expected audit count"):
        verify_audit_chain(records=(), expected_count=expected_count)


@pytest.mark.parametrize(
    "event_type",
    (
        AuditEventType.REGISTERED,
        AuditEventType.RESERVED,
        AuditEventType.SETTLED,
        AuditEventType.INVALIDATED,
        AuditEventType.TERMINATED,
    ),
)
def test_non_halt_events_require_run_id(event_type):
    with pytest.raises(ValueError, match="run identifier"):
        AuditEvent(
            event_type=event_type,
            usage=usage(),
            evidence_id=(
                "truth"
                if event_type in (AuditEventType.RESERVED, AuditEventType.SETTLED)
                else None
            ),
            process_status=(
                ProcessAcquisitionStatus.COMPLETED
                if event_type is AuditEventType.SETTLED
                else None
            ),
        )


@pytest.mark.parametrize(
    "run_id",
    ("invalid", "A" * 32, "g" * 32, True, 123),
)
def test_invalid_run_id_is_rejected(run_id):
    with pytest.raises(ValueError, match="run identifier"):
        AuditEvent(
            event_type=AuditEventType.REGISTERED,
            run_id=run_id,
            usage=usage(),
        )


@pytest.mark.parametrize(
    "evidence_id",
    ("", "../secret", "name with spaces", True, 1, "a" * 101),
)
def test_invalid_evidence_id_is_rejected(evidence_id):
    with pytest.raises(ValueError, match="evidence identifier"):
        AuditEvent(
            event_type=AuditEventType.RESERVED,
            run_id=_RUN_A,
            evidence_id=evidence_id,
            usage=usage(),
        )


def test_reservation_and_settlement_require_evidence_id():
    for event_type in (
        AuditEventType.RESERVED,
        AuditEventType.SETTLED,
    ):
        with pytest.raises(ValueError, match="evidence identifier"):
            AuditEvent(
                event_type=event_type,
                run_id=_RUN_A,
                usage=usage(),
            )


@pytest.mark.parametrize(
    "process_status",
    (
        None,
        ProcessAcquisitionStatus.WORKER_FAILED,
        ProcessAcquisitionStatus.UNREAPED,
    ),
)
def test_settlement_rejects_unsupported_process_status(process_status):
    with pytest.raises(ValueError, match="settled process status"):
        AuditEvent(
            event_type=AuditEventType.SETTLED,
            run_id=_RUN_A,
            evidence_id="truth",
            process_status=process_status,
            usage=usage(),
        )


def test_timeout_settlement_is_accepted():
    journal = create_audit_journal()
    record = journal.append(event=timed_out())

    assert record.event.process_status is ProcessAcquisitionStatus.TIMED_OUT
    assert journal.verify().record_count == 1


def test_invalidation_rejects_completed_process():
    with pytest.raises(ValueError, match="invalidation process status"):
        AuditEvent(
            event_type=AuditEventType.INVALIDATED,
            run_id=_RUN_A,
            process_status=ProcessAcquisitionStatus.COMPLETED,
            usage=usage(),
        )


def test_halted_event_requires_halted_usage():
    with pytest.raises(ValueError, match="halted usage"):
        AuditEvent(
            event_type=AuditEventType.HALTED,
            usage=usage(),
        )


def test_halted_event_supports_unknown_worker():
    journal = create_audit_journal()
    journal.append(event=halted())

    assert journal.verify().record_count == 1


def test_halted_event_rejects_completed_process():
    with pytest.raises(ValueError, match="halted process status"):
        AuditEvent(
            event_type=AuditEventType.HALTED,
            usage=usage(halted=True),
            process_status=ProcessAcquisitionStatus.COMPLETED,
        )


def test_halted_event_rejects_evidence_identifier():
    with pytest.raises(ValueError, match="halted evidence identifier"):
        AuditEvent(
            event_type=AuditEventType.HALTED,
            usage=usage(halted=True),
            evidence_id="truth",
        )


@pytest.mark.parametrize(
    "process_status",
    (
        ProcessAcquisitionStatus.WORKER_FAILED,
        ProcessAcquisitionStatus.UNREAPED,
    ),
)
def test_halted_worker_requires_unknown_slot(process_status):
    with pytest.raises(ValueError, match="unknown usage"):
        AuditEvent(
            event_type=AuditEventType.HALTED,
            usage=usage(halted=True),
            process_status=process_status,
        )


@pytest.mark.parametrize(
    "audit_usage",
    (
        usage(files=301**2 + 1),
        usage(bytes_used=16 * 1024 * 1024 * 301**2 + 1),
        usage(slots=65),
        usage(slots=65, unknown=65, halted=True),
    ),
)
def test_event_rejects_usage_above_schema_limits(audit_usage):
    with pytest.raises(ValueError, match="schema limits"):
        AuditEvent(
            event_type=AuditEventType.REGISTERED,
            run_id=_RUN_A,
            usage=audit_usage,
        )


def test_unexpected_process_status_is_rejected():
    with pytest.raises(ValueError, match="Unexpected audit process status"):
        AuditEvent(
            event_type=AuditEventType.REGISTERED,
            run_id=_RUN_A,
            usage=usage(),
            process_status=ProcessAcquisitionStatus.TIMED_OUT,
        )


def test_event_rejects_wrong_types():
    with pytest.raises(TypeError, match="event type"):
        AuditEvent(event_type="registered", usage=usage(), run_id=_RUN_A)

    with pytest.raises(TypeError, match="audit usage"):
        AuditEvent(
            event_type=AuditEventType.REGISTERED,
            usage=object(),
            run_id=_RUN_A,
        )

    with pytest.raises(TypeError, match="process status"):
        AuditEvent(
            event_type=AuditEventType.INVALIDATED,
            usage=usage(),
            run_id=_RUN_A,
            process_status="timed_out",
        )


@pytest.mark.parametrize(
    "sequence",
    (0, -1, True, 1.5, MAX_AUDIT_RECORDS + 1),
)
def test_invalid_record_sequence(sequence):
    with pytest.raises(ValueError, match="sequence"):
        AuditRecord(
            sequence=sequence,
            previous_digest=GENESIS_DIGEST,
            event=registered(),
            digest="a" * 64,
        )


def test_record_rejects_invalid_hashes_and_event():
    with pytest.raises(ValueError, match="previous audit digest"):
        AuditRecord(
            sequence=1,
            previous_digest="invalid",
            event=registered(),
            digest="a" * 64,
        )

    with pytest.raises(ValueError, match="record digest"):
        AuditRecord(
            sequence=1,
            previous_digest=GENESIS_DIGEST,
            event=registered(),
            digest="A" * 64,
        )

    with pytest.raises(TypeError, match="record event"):
        AuditRecord(
            sequence=1,
            previous_digest=GENESIS_DIGEST,
            event=object(),
            digest="a" * 64,
        )


def test_journal_rejects_non_event_append():
    journal = create_audit_journal()

    with pytest.raises(TypeError, match="audit event"):
        journal.append(event=object())

    assert journal.record_count == 0


def test_journal_limit_is_enforced_without_partial_append():
    journal = create_audit_journal()
    initial = journal.append(event=registered())

    # Inject a prefilled immutable tuple to test the cap without
    # performing ten thousand quadratic tuple appends.
    journal._records = (initial,) * MAX_AUDIT_RECORDS
    previous_head = journal.head_digest

    with pytest.raises(ValueError, match="record limit"):
        journal.append(event=registered())

    assert journal.record_count == MAX_AUDIT_RECORDS
    assert journal.head_digest == previous_head


def test_verify_detects_corrupted_internal_record():
    journal = create_chain()
    records = journal.snapshot()
    journal._records = (
        records[0],
        replace(records[1], digest="f" * 64),
        records[2],
    )

    with pytest.raises(AuditIntegrityError):
        journal.verify()


def test_verify_detects_corrupted_internal_head():
    journal = create_chain()
    journal._head = "f" * 64

    with pytest.raises(AuditIntegrityError, match="head"):
        journal.verify()


def test_immutable_verification_model_rejects_invalid_fields():
    with pytest.raises(ValueError, match="record count"):
        AuditVerification(record_count=True, head_digest=GENESIS_DIGEST)

    with pytest.raises(ValueError, match="audit digest"):
        AuditVerification(record_count=0, head_digest="invalid")

    with pytest.raises(ValueError, match="genesis"):
        AuditVerification(record_count=0, head_digest="f" * 64)


def test_append_failure_does_not_partially_update_journal(
    monkeypatch: pytest.MonkeyPatch,
):
    journal = create_chain()
    before_records = journal.snapshot()
    before_head = journal.head_digest

    def fail_digest(**kwargs):
        raise RuntimeError("simulated digest failure")

    monkeypatch.setattr(time_evidence_audit, "_record_digest", fail_digest)

    with pytest.raises(RuntimeError, match="digest failure"):
        journal.append(event=registered())

    assert journal.snapshot() is before_records
    assert journal.head_digest == before_head


def test_concurrent_appends_have_contiguous_sequences():
    journal = AcquisitionAuditJournal()
    errors: list[BaseException] = []
    threads = []
    thread_count = 8
    records_per_thread = 25

    def append_events() -> None:
        try:
            for _ in range(records_per_thread):
                journal.append(event=registered())
        except BaseException as exc:  # noqa: BLE001 - surface thread failures
            errors.append(exc)

    for _ in range(thread_count):
        thread = threading.Thread(target=append_events)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join(timeout=5.0)

    assert all(not thread.is_alive() for thread in threads)
    assert not errors

    records = journal.snapshot()
    assert len(records) == thread_count * records_per_thread
    assert tuple(record.sequence for record in records) == tuple(
        range(1, len(records) + 1)
    )
    assert journal.verify().record_count == len(records)
