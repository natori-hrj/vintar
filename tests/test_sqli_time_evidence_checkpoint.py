"""Tests for versioned evidence audit checkpoints and independent anchors."""

import json
import threading
from dataclasses import replace

import pytest

from vintar.checks.sqli.time_evidence_audit import (
    GENESIS_DIGEST,
    MAX_AUDIT_RECORDS,
    AuditEvent,
    AuditEventType,
    AuditIntegrityError,
    create_audit_journal,
)
from vintar.checks.sqli.time_evidence_checkpoint import (
    CHECKPOINT_VERSION,
    MAX_CHECKPOINT_JSON_BYTES,
    AuditCheckpoint,
    AuditCheckpointError,
    CheckpointVerification,
    checkpoint_from_journal,
    checkpoint_from_json,
    create_audit_checkpoint,
    create_journal_id,
    verify_audit_checkpoint,
)
from vintar.checks.sqli.time_evidence_governor import GovernorUsage

_JOURNAL_A = "a" * 32
_JOURNAL_B = "b" * 32
_RUN_A = "c" * 32
_RUN_B = "d" * 32


def usage() -> GovernorUsage:
    return GovernorUsage(
        files_used=0,
        bytes_used=0,
        slots_in_use=0,
        unknown_slots=0,
        halted=False,
    )


def event(run_id: str = _RUN_A) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.REGISTERED,
        run_id=run_id,
        usage=usage(),
    )


def populated_journal(count: int = 3):
    journal = create_audit_journal()
    for index in range(count):
        journal.append(event=event(_RUN_A if index % 2 == 0 else _RUN_B))
    return journal


def checkpoint_for(journal, journal_id: str = _JOURNAL_A):
    return checkpoint_from_journal(
        journal=journal,
        journal_id=journal_id,
    )


def test_random_journal_id_format_and_uniqueness():
    identifiers = [create_journal_id() for _ in range(20)]

    assert len(set(identifiers)) == len(identifiers)
    assert all(
        len(identifier) == 32
        and all(character in "0123456789abcdef" for character in identifier)
        for identifier in identifiers
    )


def test_empty_checkpoint_uses_genesis_digest():
    journal = create_audit_journal()
    checkpoint = checkpoint_for(journal)

    assert checkpoint.version == CHECKPOINT_VERSION
    assert checkpoint.journal_id == _JOURNAL_A
    assert checkpoint.record_count == 0
    assert checkpoint.head_digest == GENESIS_DIGEST

    verified = verify_audit_checkpoint(
        records=(),
        checkpoint=checkpoint,
        expected_journal_id=_JOURNAL_A,
    )
    assert verified.additional_records == 0


def test_checkpoint_matches_full_chain():
    journal = populated_journal()
    checkpoint = checkpoint_for(journal)

    verified = verify_audit_checkpoint(
        records=journal.snapshot(),
        checkpoint=checkpoint,
        expected_journal_id=_JOURNAL_A,
    )

    assert verified.chain_record_count == 3
    assert verified.additional_records == 0
    assert verified.chain_head_digest == journal.head_digest
    assert verified.checkpoint == checkpoint


def test_checkpoint_from_records_matches_journal():
    journal = populated_journal()

    from_records = create_audit_checkpoint(
        records=journal.snapshot(),
        journal_id=_JOURNAL_A,
    )
    from_journal = checkpoint_for(journal)

    assert from_records == from_journal


def test_checkpoint_is_deterministic_for_same_chain():
    first = populated_journal()
    second = populated_journal()

    assert checkpoint_for(first) == checkpoint_for(second)
    assert checkpoint_for(first).to_json() == checkpoint_for(second).to_json()


def test_different_journal_ids_produce_distinct_checkpoints():
    journal = populated_journal()
    first = checkpoint_for(journal, _JOURNAL_A)
    second = checkpoint_for(journal, _JOURNAL_B)

    assert first.head_digest == second.head_digest
    assert first != second


def test_exact_verification_rejects_additional_records():
    journal = populated_journal(2)
    checkpoint = checkpoint_for(journal)
    journal.append(event=event())

    with pytest.raises(AuditCheckpointError, match="record count"):
        verify_audit_checkpoint(
            records=journal.snapshot(),
            checkpoint=checkpoint,
        )


def test_prefix_verification_accepts_append_only_extension():
    journal = populated_journal(2)
    checkpoint = checkpoint_for(journal)

    journal.append(event=event())
    journal.append(event=event(_RUN_B))

    verified = verify_audit_checkpoint(
        records=journal.snapshot(),
        checkpoint=checkpoint,
        allow_extensions=True,
    )

    assert verified.chain_record_count == 4
    assert verified.additional_records == 2
    assert verified.checkpoint.head_digest == checkpoint.head_digest
    assert verified.chain_head_digest == journal.head_digest


def test_rollback_below_checkpoint_count_is_rejected():
    journal = populated_journal(3)
    checkpoint = checkpoint_for(journal)

    with pytest.raises(AuditCheckpointError, match="shorter"):
        verify_audit_checkpoint(
            records=journal.snapshot()[:2],
            checkpoint=checkpoint,
            allow_extensions=True,
        )


def test_hundred_record_checkpoint_rejects_rollback_and_accepts_extension():
    journal = populated_journal(100)
    checkpoint = checkpoint_for(journal)
    records_at_checkpoint = journal.snapshot()

    with pytest.raises(AuditCheckpointError, match="shorter"):
        verify_audit_checkpoint(
            records=records_at_checkpoint[:90],
            checkpoint=checkpoint,
            allow_extensions=True,
        )

    for _ in range(20):
        journal.append(event=event())

    verified = verify_audit_checkpoint(
        records=journal.snapshot(),
        checkpoint=checkpoint,
        allow_extensions=True,
    )
    assert verified.chain_record_count == 120
    assert verified.additional_records == 20


def test_same_length_replacement_is_rejected():
    original = populated_journal(3)
    checkpoint = checkpoint_for(original)
    replacement = populated_journal(2)
    replacement.append(event=event(_RUN_B))

    with pytest.raises(AuditCheckpointError, match="head digest"):
        verify_audit_checkpoint(
            records=replacement.snapshot(),
            checkpoint=checkpoint,
        )


def test_divergent_prefix_is_rejected_even_with_extensions():
    journal = populated_journal(2)
    checkpoint = checkpoint_for(journal)

    replacement = create_audit_journal()
    replacement.append(event=event(_RUN_B))
    replacement.append(event=event(_RUN_B))
    replacement.append(event=event())

    with pytest.raises(AuditCheckpointError, match="head digest"):
        verify_audit_checkpoint(
            records=replacement.snapshot(),
            checkpoint=checkpoint,
            allow_extensions=True,
        )


def test_corrupted_extension_is_rejected():
    journal = populated_journal(2)
    checkpoint = checkpoint_for(journal)
    journal.append(event=event())

    records = journal.snapshot()
    corrupted = (
        records[0],
        records[1],
        replace(records[2], digest="f" * 64),
    )

    with pytest.raises(AuditIntegrityError, match="digest mismatch"):
        verify_audit_checkpoint(
            records=corrupted,
            checkpoint=checkpoint,
            allow_extensions=True,
        )


def test_wrong_trusted_journal_id_is_rejected():
    journal = populated_journal()
    checkpoint = checkpoint_for(journal)

    with pytest.raises(AuditCheckpointError, match="journal identifier"):
        verify_audit_checkpoint(
            records=journal.snapshot(),
            checkpoint=checkpoint,
            expected_journal_id=_JOURNAL_B,
        )


def test_self_declared_journal_id_is_not_authenticated():
    journal = populated_journal()
    checkpoint = checkpoint_for(journal, _JOURNAL_B)

    # Without an independently trusted expected_journal_id,
    # the caller's declaration is accepted.
    verified = verify_audit_checkpoint(
        records=journal.snapshot(),
        checkpoint=checkpoint,
    )

    assert verified.checkpoint.journal_id == _JOURNAL_B


def test_empty_checkpoint_is_valid_prefix_of_longer_chain():
    journal = populated_journal()
    empty_checkpoint = AuditCheckpoint(
        version=CHECKPOINT_VERSION,
        journal_id=_JOURNAL_A,
        record_count=0,
        head_digest=GENESIS_DIGEST,
    )

    verified = verify_audit_checkpoint(
        records=journal.snapshot(),
        checkpoint=empty_checkpoint,
        allow_extensions=True,
    )

    assert verified.additional_records == 3


def test_empty_checkpoint_requires_exact_empty_chain_by_default():
    journal = populated_journal()
    checkpoint = AuditCheckpoint(
        version=CHECKPOINT_VERSION,
        journal_id=_JOURNAL_A,
        record_count=0,
        head_digest=GENESIS_DIGEST,
    )

    with pytest.raises(AuditCheckpointError, match="record count"):
        verify_audit_checkpoint(
            records=journal.snapshot(),
            checkpoint=checkpoint,
        )


def test_checkpoint_json_round_trip():
    checkpoint = checkpoint_for(populated_journal())

    decoded = checkpoint_from_json(payload=checkpoint.to_json())

    assert decoded == checkpoint
    assert decoded.to_json() == checkpoint.to_json()


def test_checkpoint_json_is_sorted_and_compact():
    checkpoint = checkpoint_for(populated_journal())
    payload = checkpoint.to_json()

    expected = json.dumps(
        {
            "version": CHECKPOINT_VERSION,
            "journal_id": _JOURNAL_A,
            "record_count": checkpoint.record_count,
            "head_digest": checkpoint.head_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )

    assert payload == expected
    assert payload.startswith('{"head_digest":')


@pytest.mark.parametrize(
    "value",
    (
        0,
        2,
        True,
        1.0,
        "1",
        None,
    ),
)
def test_invalid_checkpoint_version(value):
    with pytest.raises(ValueError, match="version"):
        AuditCheckpoint(
            version=value,
            journal_id=_JOURNAL_A,
            record_count=0,
            head_digest=GENESIS_DIGEST,
        )


@pytest.mark.parametrize(
    "value",
    (
        "",
        "A" * 32,
        "z" * 32,
        "a" * 31,
        "a" * 33,
        True,
        123,
        None,
    ),
)
def test_invalid_journal_id(value):
    with pytest.raises(ValueError, match="journal identifier"):
        AuditCheckpoint(
            version=CHECKPOINT_VERSION,
            journal_id=value,
            record_count=0,
            head_digest=GENESIS_DIGEST,
        )


@pytest.mark.parametrize(
    "value",
    (
        -1,
        True,
        1.5,
        None,
        MAX_AUDIT_RECORDS + 1,
    ),
)
def test_invalid_record_count(value):
    with pytest.raises(ValueError, match="record count"):
        AuditCheckpoint(
            version=CHECKPOINT_VERSION,
            journal_id=_JOURNAL_A,
            record_count=value,
            head_digest=GENESIS_DIGEST,
        )


@pytest.mark.parametrize(
    "value",
    ("invalid", "F" * 64, "g" * 64, True, 123, None),
)
def test_invalid_head_digest(value):
    with pytest.raises(ValueError, match="head digest"):
        AuditCheckpoint(
            version=CHECKPOINT_VERSION,
            journal_id=_JOURNAL_A,
            record_count=1,
            head_digest=value,
        )


def test_empty_checkpoint_rejects_non_genesis_head():
    with pytest.raises(ValueError, match="genesis"):
        AuditCheckpoint(
            version=CHECKPOINT_VERSION,
            journal_id=_JOURNAL_A,
            record_count=0,
            head_digest="f" * 64,
        )


def test_checkpoint_rejects_unsupported_json_fields():
    original = json.loads(checkpoint_for(populated_journal()).to_json())
    original["unexpected"] = "value"

    with pytest.raises(ValueError, match="fields"):
        checkpoint_from_json(payload=json.dumps(original))


def test_checkpoint_rejects_missing_json_field():
    original = json.loads(checkpoint_for(populated_journal()).to_json())
    del original["journal_id"]

    with pytest.raises(ValueError, match="fields"):
        checkpoint_from_json(payload=json.dumps(original))


def test_checkpoint_rejects_duplicate_json_keys():
    payload = (
        '{"version":1,"version":1,'
        f'"journal_id":"{_JOURNAL_A}",'
        '"record_count":0,'
        f'"head_digest":"{GENESIS_DIGEST}"'
        "}"
    )

    with pytest.raises(ValueError, match="Invalid checkpoint JSON"):
        checkpoint_from_json(payload=payload)


@pytest.mark.parametrize(
    "payload",
    (
        "",
        "[]",
        "null",
        "not json",
        '{"version":NaN}',
        '{"version":Infinity}',
        "あ",
    ),
)
def test_checkpoint_rejects_invalid_json(payload):
    with pytest.raises(ValueError):
        checkpoint_from_json(payload=payload)


def test_checkpoint_rejects_oversized_json():
    with pytest.raises(ValueError, match="length"):
        checkpoint_from_json(payload=" " * (MAX_CHECKPOINT_JSON_BYTES + 1))


def test_checkpoint_rejects_non_string_json():
    with pytest.raises(TypeError, match="string"):
        checkpoint_from_json(payload=b"{}")


def test_checkpoint_rejects_bool_in_json_integer():
    original = json.loads(checkpoint_for(populated_journal()).to_json())
    original["record_count"] = True

    with pytest.raises(ValueError, match="record count"):
        checkpoint_from_json(payload=json.dumps(original))


def test_invalid_extension_mode_is_rejected():
    checkpoint = checkpoint_for(populated_journal())

    with pytest.raises(TypeError, match="extension mode"):
        verify_audit_checkpoint(
            records=populated_journal().snapshot(),
            checkpoint=checkpoint,
            allow_extensions=1,
        )


def test_invalid_expected_journal_id_is_rejected():
    checkpoint = checkpoint_for(populated_journal())

    with pytest.raises(ValueError, match="expected journal identifier"):
        verify_audit_checkpoint(
            records=populated_journal().snapshot(),
            checkpoint=checkpoint,
            expected_journal_id="invalid",
        )


def test_wrong_checkpoint_model_is_rejected():
    with pytest.raises(TypeError, match="checkpoint"):
        verify_audit_checkpoint(
            records=(),
            checkpoint=object(),
        )


def test_invalid_journal_model_is_rejected():
    with pytest.raises(TypeError, match="journal"):
        checkpoint_from_journal(
            journal=object(),
            journal_id=_JOURNAL_A,
        )


def test_invalid_chain_cannot_create_checkpoint():
    journal = populated_journal()
    records = journal.snapshot()

    with pytest.raises(AuditIntegrityError, match="digest mismatch"):
        create_audit_checkpoint(
            records=(
                records[0],
                replace(records[1], digest="f" * 64),
                records[2],
            ),
            journal_id=_JOURNAL_A,
        )


def test_verification_model_rejects_inconsistent_extension():
    checkpoint = checkpoint_for(populated_journal(2))

    with pytest.raises(ValueError, match="extension count"):
        CheckpointVerification(
            checkpoint=checkpoint,
            chain_record_count=3,
            chain_head_digest="a" * 64,
            additional_records=0,
        )


def test_verification_model_rejects_invalid_chain_head():
    checkpoint = checkpoint_for(populated_journal(1))

    with pytest.raises(ValueError, match="chain digest"):
        CheckpointVerification(
            checkpoint=checkpoint,
            chain_record_count=1,
            chain_head_digest="invalid",
            additional_records=0,
        )


def test_verification_model_rejects_exact_digest_mismatch():
    checkpoint = checkpoint_for(populated_journal(2))

    with pytest.raises(ValueError, match="checkpoint digest"):
        CheckpointVerification(
            checkpoint=checkpoint,
            chain_record_count=checkpoint.record_count,
            chain_head_digest="f" * 64,
            additional_records=0,
        )

    valid = CheckpointVerification(
        checkpoint=checkpoint,
        chain_record_count=checkpoint.record_count,
        chain_head_digest=checkpoint.head_digest,
        additional_records=0,
    )
    with pytest.raises(ValueError, match="checkpoint digest"):
        replace(valid, chain_head_digest="f" * 64)


def test_snapshot_checkpoint_during_concurrent_appends():
    journal = create_audit_journal()
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []

    def writer():
        try:
            for _ in range(30):
                barrier.wait(timeout=5.0)
                journal.append(event=event())
                barrier.wait(timeout=5.0)
        except BaseException as exc:  # noqa: BLE001 - surface thread failures
            failures.append(exc)

    thread = threading.Thread(target=writer)
    thread.start()
    checkpoints = []

    try:
        for _ in range(30):
            barrier.wait(timeout=5.0)
            checkpoints.append(checkpoint_for(journal))
            barrier.wait(timeout=5.0)
    finally:
        thread.join(timeout=5.0)

    assert not thread.is_alive()
    assert not failures
    assert len(checkpoints) == 30

    records = journal.snapshot()
    for checkpoint in checkpoints:
        verified = verify_audit_checkpoint(
            records=records,
            checkpoint=checkpoint,
            allow_extensions=True,
        )
        assert verified.additional_records == 30 - checkpoint.record_count
