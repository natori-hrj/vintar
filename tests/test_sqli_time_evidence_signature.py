"""Tests for Ed25519 signed evidence audit checkpoints."""

import json
from dataclasses import replace

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from vintar.checks.sqli.time_evidence_audit import (
    AuditEvent,
    AuditEventType,
    AuditIntegrityError,
    create_audit_journal,
)
from vintar.checks.sqli.time_evidence_checkpoint import (
    AuditCheckpointError,
    checkpoint_from_journal,
)
from vintar.checks.sqli.time_evidence_governor import GovernorUsage
from vintar.checks.sqli.time_evidence_signature import (
    MAX_SIGNED_CHECKPOINT_JSON_BYTES,
    SIGNATURE_ALGORITHM,
    SIGNED_CHECKPOINT_VERSION,
    SignedCheckpointError,
    sign_audit_checkpoint,
    signed_checkpoint_from_json,
    verify_signed_audit_chain,
    verify_signed_checkpoint,
)

_JOURNAL = "a" * 32
_OTHER_JOURNAL = "b" * 32
_RUN_A = "c" * 32
_RUN_B = "d" * 32
_KEY_ID = "research-key-1"


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


def make_journal(count=3):
    journal = create_audit_journal()
    for index in range(count):
        journal.append(event=make_event(_RUN_A if index % 2 == 0 else _RUN_B))
    return journal


def make_envelope(private_key, count=3):
    journal = make_journal(count)
    checkpoint = checkpoint_from_journal(
        journal=journal,
        journal_id=_JOURNAL,
    )
    envelope = sign_audit_checkpoint(
        checkpoint=checkpoint,
        private_key=private_key,
        key_id=_KEY_ID,
    )
    return journal, envelope


def test_valid_signature_round_trip(private_key):
    journal, envelope = make_envelope(private_key)

    restored = signed_checkpoint_from_json(payload=envelope.to_json())

    assert restored == envelope
    assert restored.to_json() == envelope.to_json()
    assert restored.version == SIGNED_CHECKPOINT_VERSION
    assert restored.algorithm == SIGNATURE_ALGORITHM

    checkpoint = verify_signed_checkpoint(
        envelope=restored,
        public_key=private_key.public_key(),
        expected_key_id=_KEY_ID,
    )

    assert checkpoint == envelope.checkpoint
    assert checkpoint.record_count == len(journal.snapshot())


def test_full_signed_chain_verification(private_key):
    journal, envelope = make_envelope(private_key)

    result = verify_signed_audit_chain(
        records=journal.snapshot(),
        envelope=envelope,
        public_key=private_key.public_key(),
        expected_key_id=_KEY_ID,
        expected_journal_id=_JOURNAL,
    )

    assert result.additional_records == 0
    assert result.chain_record_count == 3
    assert result.chain_head_digest == envelope.checkpoint.head_digest


def test_signing_is_deterministic_for_same_key_and_message(private_key):
    _, envelope = make_envelope(private_key)

    duplicate = sign_audit_checkpoint(
        checkpoint=envelope.checkpoint,
        private_key=private_key,
        key_id=_KEY_ID,
    )

    assert duplicate == envelope
    assert duplicate.signature_hex == envelope.signature_hex


def test_signature_matches_cryptography_primitive(private_key):
    _, envelope = make_envelope(private_key)

    message = b"vintar.audit.checkpoint.ed25519.v1\x00" + json.dumps(
        {
            "version": 1,
            "algorithm": "Ed25519",
            "key_id": _KEY_ID,
            "checkpoint": json.loads(envelope.checkpoint.to_json()),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")

    # Verification by the external primitive proves the encoding
    # is interoperable with the documented signing construction.
    private_key.public_key().verify(
        bytes.fromhex(envelope.signature_hex),
        message,
    )


def test_wrong_public_key_is_rejected(private_key):
    _, envelope = make_envelope(private_key)
    wrong_key = Ed25519PrivateKey.generate().public_key()

    with pytest.raises(SignedCheckpointError, match="signature"):
        verify_signed_checkpoint(
            envelope=envelope,
            public_key=wrong_key,
            expected_key_id=_KEY_ID,
        )


def test_wrong_trusted_key_id_is_rejected(private_key):
    _, envelope = make_envelope(private_key)

    with pytest.raises(SignedCheckpointError, match="key identifier"):
        verify_signed_checkpoint(
            envelope=envelope,
            public_key=private_key.public_key(),
            expected_key_id="another-key",
        )


def test_modified_key_id_invalidates_signature(private_key):
    _, envelope = make_envelope(private_key)
    modified = replace(envelope, key_id="another-key")

    with pytest.raises(SignedCheckpointError, match="signature"):
        verify_signed_checkpoint(
            envelope=modified,
            public_key=private_key.public_key(),
            expected_key_id="another-key",
        )


def test_modified_checkpoint_invalidates_signature(private_key):
    _, envelope = make_envelope(private_key)
    modified_checkpoint = replace(
        envelope.checkpoint,
        journal_id=_OTHER_JOURNAL,
    )
    modified = replace(
        envelope,
        checkpoint=modified_checkpoint,
    )

    with pytest.raises(SignedCheckpointError, match="signature"):
        verify_signed_checkpoint(
            envelope=modified,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
        )


def test_replacing_checkpoint_with_another_valid_checkpoint_fails(private_key):
    _, envelope = make_envelope(private_key, count=3)
    other_journal = make_journal(count=2)
    other_checkpoint = checkpoint_from_journal(
        journal=other_journal,
        journal_id=_JOURNAL,
    )
    modified = replace(envelope, checkpoint=other_checkpoint)

    with pytest.raises(SignedCheckpointError, match="signature"):
        verify_signed_checkpoint(
            envelope=modified,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
        )


def test_modified_signature_is_rejected(private_key):
    _, envelope = make_envelope(private_key)
    replacement = "0" if envelope.signature_hex[0] != "0" else "1"
    modified = replace(
        envelope,
        signature_hex=replacement + envelope.signature_hex[1:],
    )

    with pytest.raises(SignedCheckpointError, match="signature"):
        verify_signed_checkpoint(
            envelope=modified,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
        )


def test_modified_chain_is_rejected_even_with_valid_signature(private_key):
    journal, envelope = make_envelope(private_key)
    records = journal.snapshot()
    modified = (
        records[0],
        replace(records[1], digest="f" * 64),
        records[2],
    )

    with pytest.raises(AuditIntegrityError, match="digest mismatch"):
        verify_signed_audit_chain(
            records=modified,
            envelope=envelope,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
            expected_journal_id=_JOURNAL,
        )


def test_signed_checkpoint_rejects_rollback(private_key):
    journal, envelope = make_envelope(private_key)

    with pytest.raises(AuditCheckpointError, match="shorter"):
        verify_signed_audit_chain(
            records=journal.snapshot()[:2],
            envelope=envelope,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
            expected_journal_id=_JOURNAL,
            allow_extensions=True,
        )


def test_signed_checkpoint_accepts_valid_extension(private_key):
    journal, envelope = make_envelope(private_key)
    journal.append(event=make_event())
    journal.append(event=make_event(_RUN_B))

    result = verify_signed_audit_chain(
        records=journal.snapshot(),
        envelope=envelope,
        public_key=private_key.public_key(),
        expected_key_id=_KEY_ID,
        expected_journal_id=_JOURNAL,
        allow_extensions=True,
    )

    assert result.chain_record_count == 5
    assert result.additional_records == 2


def test_signed_checkpoint_rejects_unexpected_extension(private_key):
    journal, envelope = make_envelope(private_key)
    journal.append(event=make_event())

    with pytest.raises(AuditCheckpointError, match="record count"):
        verify_signed_audit_chain(
            records=journal.snapshot(),
            envelope=envelope,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
            expected_journal_id=_JOURNAL,
        )


def test_signed_checkpoint_rejects_wrong_journal_identity(private_key):
    journal, envelope = make_envelope(private_key)

    with pytest.raises(AuditCheckpointError, match="journal identifier"):
        verify_signed_audit_chain(
            records=journal.snapshot(),
            envelope=envelope,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
            expected_journal_id=_OTHER_JOURNAL,
        )


def test_empty_checkpoint_can_be_signed(private_key):
    journal, envelope = make_envelope(private_key, count=0)

    result = verify_signed_audit_chain(
        records=journal.snapshot(),
        envelope=envelope,
        public_key=private_key.public_key(),
        expected_key_id=_KEY_ID,
        expected_journal_id=_JOURNAL,
    )

    assert result.chain_record_count == 0


@pytest.mark.parametrize(
    "version",
    (0, 2, True, 1.0, "1", None),
)
def test_invalid_envelope_version(private_key, version):
    _, envelope = make_envelope(private_key)

    with pytest.raises(ValueError, match="version"):
        replace(envelope, version=version)


@pytest.mark.parametrize(
    "algorithm",
    ("ed25519", "RSA", "", 1, True, None),
)
def test_invalid_algorithm(private_key, algorithm):
    _, envelope = make_envelope(private_key)

    with pytest.raises(ValueError, match="algorithm"):
        replace(envelope, algorithm=algorithm)


@pytest.mark.parametrize(
    "key_id",
    ("", "has spaces", "../key", "é", "a" * 65, 1, True, None),
)
def test_invalid_key_identifier(private_key, key_id):
    _, envelope = make_envelope(private_key)

    with pytest.raises(ValueError, match="key identifier"):
        replace(envelope, key_id=key_id)


@pytest.mark.parametrize(
    "signature",
    ("", "A" * 128, "z" * 128, "a" * 127, "a" * 129, 1, True, None),
)
def test_invalid_signature_model(private_key, signature):
    _, envelope = make_envelope(private_key)

    with pytest.raises(ValueError, match="signature"):
        replace(envelope, signature_hex=signature)


def test_invalid_nested_checkpoint_model(private_key):
    _, envelope = make_envelope(private_key)

    with pytest.raises(TypeError, match="signed checkpoint"):
        replace(envelope, checkpoint=object())


def test_private_key_type_is_checked(private_key):
    _, envelope = make_envelope(private_key)

    with pytest.raises(TypeError, match="private key"):
        sign_audit_checkpoint(
            checkpoint=envelope.checkpoint,
            private_key=object(),
            key_id=_KEY_ID,
        )


def test_public_key_type_is_checked(private_key):
    _, envelope = make_envelope(private_key)

    with pytest.raises(TypeError, match="public key"):
        verify_signed_checkpoint(
            envelope=envelope,
            public_key=object(),
            expected_key_id=_KEY_ID,
        )


def test_wrong_envelope_type_is_rejected(private_key):
    with pytest.raises(TypeError, match="envelope"):
        verify_signed_checkpoint(
            envelope=object(),
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
        )


def test_wrong_checkpoint_type_is_rejected(private_key):
    with pytest.raises(TypeError, match="checkpoint"):
        sign_audit_checkpoint(
            checkpoint=object(),
            private_key=private_key,
            key_id=_KEY_ID,
        )


def test_signed_json_is_deterministic_and_compact(private_key):
    _, envelope = make_envelope(private_key)
    payload = envelope.to_json()

    assert payload.startswith('{"algorithm":"Ed25519"')
    assert " " not in payload
    assert signed_checkpoint_from_json(payload=payload) == envelope


def test_json_unknown_field_is_rejected(private_key):
    _, envelope = make_envelope(private_key)
    document = json.loads(envelope.to_json())
    document["other"] = 1

    with pytest.raises(ValueError, match="fields"):
        signed_checkpoint_from_json(payload=json.dumps(document))


def test_json_missing_field_is_rejected(private_key):
    _, envelope = make_envelope(private_key)
    document = json.loads(envelope.to_json())
    del document["signature_hex"]

    with pytest.raises(ValueError, match="fields"):
        signed_checkpoint_from_json(payload=json.dumps(document))


def test_json_duplicate_outer_key_is_rejected(private_key):
    _, envelope = make_envelope(private_key)
    payload = envelope.to_json()
    payload = payload.replace(
        '"algorithm":"Ed25519",',
        '"algorithm":"Ed25519","algorithm":"Ed25519",',
        1,
    )

    with pytest.raises(ValueError, match="Invalid signed checkpoint JSON"):
        signed_checkpoint_from_json(payload=payload)


def test_json_duplicate_nested_key_is_rejected(private_key):
    _, envelope = make_envelope(private_key)
    payload = envelope.to_json()
    payload = payload.replace(
        '"record_count":3,',
        '"record_count":3,"record_count":3,',
        1,
    )

    with pytest.raises(ValueError, match="Invalid signed checkpoint JSON"):
        signed_checkpoint_from_json(payload=payload)


@pytest.mark.parametrize(
    "payload",
    ("", "[]", "null", "not-json", "あ", '{"x":NaN}'),
)
def test_invalid_json_is_rejected(payload):
    with pytest.raises(ValueError):
        signed_checkpoint_from_json(payload=payload)


def test_oversized_json_is_rejected():
    with pytest.raises(ValueError, match="length"):
        signed_checkpoint_from_json(
            payload=" " * (MAX_SIGNED_CHECKPOINT_JSON_BYTES + 1)
        )


def test_json_non_string_is_rejected():
    with pytest.raises(TypeError, match="string"):
        signed_checkpoint_from_json(payload=b"{}")


def test_json_rejects_boolean_version(private_key):
    _, envelope = make_envelope(private_key)
    document = json.loads(envelope.to_json())
    document["version"] = True

    with pytest.raises(ValueError, match="version"):
        signed_checkpoint_from_json(payload=json.dumps(document))


def test_json_rejects_invalid_nested_checkpoint(private_key):
    _, envelope = make_envelope(private_key)
    document = json.loads(envelope.to_json())
    document["checkpoint"]["record_count"] = True

    with pytest.raises(ValueError, match="record count"):
        signed_checkpoint_from_json(payload=json.dumps(document))


def test_json_decoding_does_not_authenticate_signature(private_key):
    _, envelope = make_envelope(private_key)
    document = json.loads(envelope.to_json())
    document["signature_hex"] = "0" * 128

    decoded = signed_checkpoint_from_json(payload=json.dumps(document))

    with pytest.raises(SignedCheckpointError, match="signature"):
        verify_signed_checkpoint(
            envelope=decoded,
            public_key=private_key.public_key(),
            expected_key_id=_KEY_ID,
        )


def test_signature_is_not_a_trust_anchor_by_itself():
    attacker_key = Ed25519PrivateKey.generate()
    _, envelope = make_envelope(attacker_key)

    # Anyone can produce a mathematically valid signature with
    # their own key. The verifier must trust the public key separately.
    with pytest.raises(SignedCheckpointError, match="signature"):
        verify_signed_checkpoint(
            envelope=envelope,
            public_key=Ed25519PrivateKey.generate().public_key(),
            expected_key_id=_KEY_ID,
        )


def test_external_primitive_rejects_tampered_message(private_key):
    _, envelope = make_envelope(private_key)
    signature = bytes.fromhex(envelope.signature_hex)

    with pytest.raises(InvalidSignature):
        private_key.public_key().verify(
            signature,
            b"unrelated message",
        )
