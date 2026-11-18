"""Tests for monotonic trust in Ed25519 signed audit checkpoints."""

import threading
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from vintar.checks.sqli import time_evidence_freshness as freshness_module
from vintar.checks.sqli.time_evidence_audit import (
    GENESIS_DIGEST,
    AuditEvent,
    AuditEventType,
    AuditIntegrityError,
    create_audit_journal,
)
from vintar.checks.sqli.time_evidence_checkpoint import (
    AuditCheckpointError,
    checkpoint_from_journal,
)
from vintar.checks.sqli.time_evidence_freshness import (
    CheckpointFreshnessError,
    FreshnessAcceptance,
    TrustedCheckpointState,
    create_signed_checkpoint_tracker,
)
from vintar.checks.sqli.time_evidence_governor import GovernorUsage
from vintar.checks.sqli.time_evidence_signature import (
    SignedCheckpointError,
    sign_audit_checkpoint,
)

_JOURNAL = "a" * 32
_OTHER_JOURNAL = "b" * 32
_RUN_A = "c" * 32
_RUN_B = "d" * 32
_KEY_ID = "trusted-key"
_OTHER_KEY_ID = "another-key"


@pytest.fixture
def private_key():
    return Ed25519PrivateKey.generate()


def make_event(run_id=_RUN_A):
    return AuditEvent(
        event_type=AuditEventType.REGISTERED,
        usage=GovernorUsage(
            files_used=0,
            bytes_used=0,
            slots_in_use=0,
            unknown_slots=0,
            halted=False,
        ),
        run_id=run_id,
    )


def make_journal(count=0, *, first_run=_RUN_A):
    journal = create_audit_journal()

    for index in range(count):
        run_id = first_run if index == 0 else _RUN_A
        journal.append(event=make_event(run_id))

    return journal


def make_envelope(
    journal,
    private_key,
    *,
    journal_id=_JOURNAL,
    key_id=_KEY_ID,
):
    checkpoint = checkpoint_from_journal(
        journal=journal,
        journal_id=journal_id,
    )

    return sign_audit_checkpoint(
        checkpoint=checkpoint,
        private_key=private_key,
        key_id=key_id,
    )


def make_tracker(private_key):
    return create_signed_checkpoint_tracker(
        journal_id=_JOURNAL,
        key_id=_KEY_ID,
        public_key=private_key.public_key(),
    )


def accept_journal(tracker, journal, private_key):
    return tracker.accept(
        records=journal.snapshot(),
        envelope=make_envelope(journal, private_key),
    )


def test_initial_state_is_unanchored(private_key):
    tracker = make_tracker(private_key)

    assert tracker.snapshot() is None
    assert tracker.journal_id == _JOURNAL
    assert tracker.key_id == _KEY_ID


def test_first_checkpoint_establishes_baseline(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(3)

    result = accept_journal(tracker, journal, private_key)

    assert type(result) is FreshnessAcceptance
    assert result.advanced
    assert result.state.record_count == 3
    assert result.state.head_digest == journal.head_digest
    assert tracker.snapshot() == result.state


def test_empty_checkpoint_can_initialize_tracker(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal()

    result = accept_journal(tracker, journal, private_key)

    assert result.advanced
    assert result.state.record_count == 0
    assert result.state.head_digest == GENESIS_DIGEST


def test_append_only_extension_advances_state(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(3)
    before = accept_journal(tracker, journal, private_key)

    journal.append(event=make_event())
    journal.append(event=make_event(_RUN_B))

    after = accept_journal(tracker, journal, private_key)

    assert after.advanced
    assert before.state.record_count == 3
    assert after.state.record_count == 5
    assert tracker.snapshot() == after.state


def test_same_checkpoint_is_idempotent(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(3)
    first = accept_journal(tracker, journal, private_key)

    second = accept_journal(tracker, journal, private_key)

    assert first.advanced
    assert not second.advanced
    assert second.state is first.state
    assert tracker.snapshot() is first.state


def test_older_signed_checkpoint_is_rejected(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(2)
    old_records = journal.snapshot()
    old_envelope = make_envelope(journal, private_key)

    for _ in range(3):
        journal.append(event=make_event())

    current = accept_journal(tracker, journal, private_key)

    with pytest.raises(CheckpointFreshnessError, match="rolls back"):
        tracker.accept(
            records=old_records,
            envelope=old_envelope,
        )

    assert tracker.snapshot() is current.state


def test_same_count_different_digest_is_rejected(private_key):
    tracker = make_tracker(private_key)
    original = make_journal(3)
    first = accept_journal(tracker, original, private_key)

    divergent = make_journal(3, first_run=_RUN_B)

    with pytest.raises(CheckpointFreshnessError, match="diverges"):
        accept_journal(tracker, divergent, private_key)

    assert tracker.snapshot() is first.state


def test_larger_divergent_chain_is_rejected(private_key):
    tracker = make_tracker(private_key)
    original = make_journal(3)
    first = accept_journal(tracker, original, private_key)

    divergent = make_journal(5, first_run=_RUN_B)

    with pytest.raises(CheckpointFreshnessError, match="diverges"):
        accept_journal(tracker, divergent, private_key)

    assert tracker.snapshot() is first.state


def test_divergence_is_checked_at_previous_position(private_key):
    tracker = make_tracker(private_key)
    original = make_journal(2)
    accept_journal(tracker, original, private_key)

    alternative = create_audit_journal()
    alternative.append(event=make_event())
    alternative.append(event=make_event(_RUN_B))
    alternative.append(event=make_event())

    with pytest.raises(CheckpointFreshnessError, match="diverges"):
        accept_journal(tracker, alternative, private_key)


def test_invalid_signature_does_not_update_state(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(2)
    first = accept_journal(tracker, journal, private_key)

    journal.append(event=make_event())
    envelope = make_envelope(journal, private_key)
    invalid = replace(envelope, signature_hex="0" * 128)

    with pytest.raises(SignedCheckpointError, match="signature"):
        tracker.accept(
            records=journal.snapshot(),
            envelope=invalid,
        )

    assert tracker.snapshot() is first.state


def test_attacker_signed_checkpoint_is_rejected(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(3)

    attacker_key = Ed25519PrivateKey.generate()
    attacker_envelope = make_envelope(journal, attacker_key)

    with pytest.raises(SignedCheckpointError, match="signature"):
        tracker.accept(
            records=journal.snapshot(),
            envelope=attacker_envelope,
        )

    assert tracker.snapshot() is None


def test_untrusted_key_id_is_rejected(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(2)
    envelope = make_envelope(
        journal,
        private_key,
        key_id=_OTHER_KEY_ID,
    )

    with pytest.raises(SignedCheckpointError, match="key identifier"):
        tracker.accept(
            records=journal.snapshot(),
            envelope=envelope,
        )

    assert tracker.snapshot() is None


def test_wrong_journal_id_is_rejected(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(2)
    envelope = make_envelope(
        journal,
        private_key,
        journal_id=_OTHER_JOURNAL,
    )

    with pytest.raises(AuditCheckpointError, match="journal identifier"):
        tracker.accept(
            records=journal.snapshot(),
            envelope=envelope,
        )


def test_corrupted_chain_does_not_update_state(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(3)
    records = journal.snapshot()
    envelope = make_envelope(journal, private_key)

    corrupted = (
        records[0],
        replace(records[1], digest="f" * 64),
        records[2],
    )

    with pytest.raises(AuditIntegrityError, match="digest mismatch"):
        tracker.accept(
            records=corrupted,
            envelope=envelope,
        )

    assert tracker.snapshot() is None


def test_signed_checkpoint_must_cover_entire_supplied_chain(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(2)
    envelope = make_envelope(journal, private_key)

    journal.append(event=make_event())

    with pytest.raises(AuditCheckpointError, match="record count"):
        tracker.accept(
            records=journal.snapshot(),
            envelope=envelope,
        )

    assert tracker.snapshot() is None


def test_historical_signature_cannot_advance_to_unsigned_extension(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(100)
    checkpoint_at_100 = make_envelope(journal, private_key)
    initial = tracker.accept(
        records=journal.snapshot(),
        envelope=checkpoint_at_100,
    )

    for _ in range(20):
        journal.append(event=make_event())

    with pytest.raises(AuditCheckpointError, match="record count"):
        tracker.accept(
            records=journal.snapshot(),
            envelope=checkpoint_at_100,
        )

    assert tracker.snapshot() is initial.state
    assert tracker.snapshot().record_count == 100


def test_same_count_with_invalid_signature_is_not_idempotent(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(2)
    first = accept_journal(tracker, journal, private_key)

    envelope = make_envelope(journal, private_key)
    forged = replace(envelope, signature_hex="0" * 128)

    with pytest.raises(SignedCheckpointError, match="signature"):
        tracker.accept(
            records=journal.snapshot(),
            envelope=forged,
        )

    assert tracker.snapshot() is first.state


def test_previous_state_is_immutable(private_key):
    tracker = make_tracker(private_key)
    first = accept_journal(tracker, make_journal(1), private_key)

    with pytest.raises(AttributeError):
        first.state.record_count = 100


def test_state_constructor_reuses_checkpoint_invariants():
    with pytest.raises(ValueError, match="record count"):
        TrustedCheckpointState(
            journal_id=_JOURNAL,
            key_id=_KEY_ID,
            record_count=-1,
            head_digest=GENESIS_DIGEST,
        )


def test_state_rejects_invalid_key_id():
    with pytest.raises(ValueError, match="key identifier"):
        TrustedCheckpointState(
            journal_id=_JOURNAL,
            key_id="invalid key",
            record_count=0,
            head_digest=GENESIS_DIGEST,
        )


def test_state_rejects_non_genesis_empty_head():
    with pytest.raises(ValueError, match="genesis"):
        TrustedCheckpointState(
            journal_id=_JOURNAL,
            key_id=_KEY_ID,
            record_count=0,
            head_digest="f" * 64,
        )


def test_state_replace_revalidates_invariants():
    state = TrustedCheckpointState(
        journal_id=_JOURNAL,
        key_id=_KEY_ID,
        record_count=0,
        head_digest=GENESIS_DIGEST,
    )

    with pytest.raises(ValueError, match="record count"):
        replace(state, record_count=-1)


def test_acceptance_model_rejects_invalid_state():
    with pytest.raises(TypeError, match="trust state"):
        FreshnessAcceptance(
            state=object(),
            advanced=True,
        )


def test_acceptance_model_rejects_bool_like_integer():
    state = TrustedCheckpointState(
        journal_id=_JOURNAL,
        key_id=_KEY_ID,
        record_count=0,
        head_digest=GENESIS_DIGEST,
    )

    with pytest.raises(TypeError, match="advancement"):
        FreshnessAcceptance(
            state=state,
            advanced=1,
        )


@pytest.mark.parametrize(
    "journal_id",
    ("", "A" * 32, "invalid", True, None),
)
def test_tracker_rejects_invalid_journal_id(private_key, journal_id):
    with pytest.raises(ValueError, match="journal identifier"):
        create_signed_checkpoint_tracker(
            journal_id=journal_id,
            key_id=_KEY_ID,
            public_key=private_key.public_key(),
        )


@pytest.mark.parametrize(
    "key_id",
    ("", "invalid key", "x" * 65, True, None),
)
def test_tracker_rejects_invalid_key_id(private_key, key_id):
    with pytest.raises(ValueError, match="key identifier"):
        create_signed_checkpoint_tracker(
            journal_id=_JOURNAL,
            key_id=key_id,
            public_key=private_key.public_key(),
        )


def test_tracker_rejects_untrusted_key_type():
    with pytest.raises(TypeError, match="public key"):
        create_signed_checkpoint_tracker(
            journal_id=_JOURNAL,
            key_id=_KEY_ID,
            public_key=object(),
        )


class SimulatedVerificationAbort(BaseException):
    """Non-Exception failure used to verify atomic state updates."""


def test_verification_base_exception_does_not_update_state(
    private_key,
    monkeypatch,
):
    tracker = make_tracker(private_key)
    journal = make_journal(2)

    def abort_verification(**kwargs):
        raise SimulatedVerificationAbort

    monkeypatch.setattr(
        freshness_module,
        "verify_signed_audit_chain",
        abort_verification,
    )

    with pytest.raises(SimulatedVerificationAbort):
        accept_journal(tracker, journal, private_key)

    assert tracker.snapshot() is None


def test_acceptance_construction_failure_does_not_update_state(
    private_key,
    monkeypatch,
):
    tracker = make_tracker(private_key)
    journal = make_journal(2)

    def abort_acceptance(**kwargs):
        raise SimulatedVerificationAbort

    monkeypatch.setattr(
        freshness_module,
        "FreshnessAcceptance",
        abort_acceptance,
    )

    with pytest.raises(SimulatedVerificationAbort):
        accept_journal(tracker, journal, private_key)

    assert tracker.snapshot() is None


def test_concurrent_identical_checkpoint_acceptance(private_key, worker_pool):
    tracker = make_tracker(private_key)
    journal = make_journal(3)
    envelope = make_envelope(journal, private_key)
    records = journal.snapshot()

    barrier = threading.Barrier(8)

    def worker():
        barrier.wait(timeout=5.0)
        return tracker.accept(records=records, envelope=envelope)

    futures = [worker_pool.submit(worker) for _ in range(8)]
    results = [future.result(timeout=5.0) for future in futures]
    assert len(results) == 8
    assert sum(result.advanced for result in results) == 1
    assert tracker.snapshot().record_count == 3


def test_concurrent_old_and_new_checkpoints_never_roll_back(private_key):
    tracker = make_tracker(private_key)
    journal = make_journal(2)

    older_records = journal.snapshot()
    older_envelope = make_envelope(journal, private_key)

    for _ in range(3):
        journal.append(event=make_event())

    newer_records = journal.snapshot()
    newer_envelope = make_envelope(journal, private_key)

    barrier = threading.Barrier(2)
    accepted = []
    rejected = []
    lock = threading.Lock()

    def worker(records, envelope):
        try:
            barrier.wait(timeout=5.0)
            result = tracker.accept(
                records=records,
                envelope=envelope,
            )
            with lock:
                accepted.append(result)
        except CheckpointFreshnessError as exc:
            with lock:
                rejected.append(exc)

    threads = [
        threading.Thread(
            target=worker,
            args=(older_records, older_envelope),
        ),
        threading.Thread(
            target=worker,
            args=(newer_records, newer_envelope),
        ),
    ]

    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5.0)

    assert all(not thread.is_alive() for thread in threads)
    assert len(accepted) in (1, 2)
    assert len(accepted) + len(rejected) == 2
    assert tracker.snapshot().record_count == 5


def test_distinct_trackers_are_independent(private_key):
    first = make_tracker(private_key)
    second = make_tracker(private_key)

    accept_journal(first, make_journal(3), private_key)

    assert first.snapshot().record_count == 3
    assert second.snapshot() is None


def test_recreated_tracker_does_not_inherit_state(private_key):
    first = make_tracker(private_key)
    accept_journal(first, make_journal(5), private_key)

    second = make_tracker(private_key)

    assert second.snapshot() is None

    older = make_journal(2)
    accepted = accept_journal(second, older, private_key)

    # No persisted trusted floor exists across tracker lifetimes.
    assert accepted.advanced
    assert accepted.state.record_count == 2
