"""Ed25519 signatures for evidence audit checkpoints.

A signature authenticates checkpoint bytes under a caller-trusted
public key. It does not establish journal completeness, freshness,
issuer identity, or trusted key distribution.
"""

import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vintar.checks.sqli.time_evidence_audit import AuditRecord
from vintar.checks.sqli.time_evidence_checkpoint import (
    AuditCheckpoint,
    CheckpointVerification,
    checkpoint_from_json,
    verify_audit_checkpoint,
)

SIGNATURE_ALGORITHM = "Ed25519"
SIGNED_CHECKPOINT_VERSION = 1
MAX_SIGNED_CHECKPOINT_JSON_BYTES = 1024

_DOMAIN = b"vintar.audit.checkpoint.ed25519.v1\x00"
_HEX = frozenset("0123456789abcdef")
_KEY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_ENVELOPE_FIELDS = frozenset(
    {
        "version",
        "algorithm",
        "key_id",
        "checkpoint",
        "signature_hex",
    }
)


class SignedCheckpointError(ValueError):
    """A signed checkpoint failed an authentication requirement."""


def _valid_key_id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 64
        and all(character in _KEY_CHARS for character in value)
    )


def _valid_signature(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 128
        and all(character in _HEX for character in value)
    )


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate keys at every JSON object level."""
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate signed checkpoint JSON field.")
        result[key] = value

    return result


def _invalid_constant(value: str) -> object:
    raise ValueError(f"Invalid JSON numeric constant: {value}.")


def _checkpoint_object(checkpoint: AuditCheckpoint) -> dict[str, object]:
    return {
        "version": checkpoint.version,
        "journal_id": checkpoint.journal_id,
        "record_count": checkpoint.record_count,
        "head_digest": checkpoint.head_digest,
    }


def _canonical_json(document: dict[str, object]) -> str:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _signed_message(
    *,
    checkpoint: AuditCheckpoint,
    key_id: str,
) -> bytes:
    """Bind context, signature algorithm, key identifier and checkpoint."""
    document: dict[str, object] = {
        "version": SIGNED_CHECKPOINT_VERSION,
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "checkpoint": _checkpoint_object(checkpoint),
    }
    return _DOMAIN + _canonical_json(document).encode("ascii")


@dataclass(frozen=True, slots=True)
class SignedAuditCheckpoint:
    """Immutable signature envelope with strictly validated fields."""

    version: int
    algorithm: str
    key_id: str
    checkpoint: AuditCheckpoint
    signature_hex: str

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != SIGNED_CHECKPOINT_VERSION:
            raise ValueError("Unsupported signed checkpoint version.")

        if type(self.algorithm) is not str or self.algorithm != SIGNATURE_ALGORITHM:
            raise ValueError("Unsupported checkpoint signature algorithm.")

        if not _valid_key_id(self.key_id):
            raise ValueError("Invalid checkpoint key identifier.")

        if type(self.checkpoint) is not AuditCheckpoint:
            raise TypeError("Invalid signed checkpoint.")

        if not _valid_signature(self.signature_hex):
            raise ValueError("Invalid checkpoint signature.")

    def to_json(self) -> str:
        """Serialize the fixed signed envelope deterministically."""
        return _canonical_json(
            {
                "version": self.version,
                "algorithm": self.algorithm,
                "key_id": self.key_id,
                "checkpoint": _checkpoint_object(self.checkpoint),
                "signature_hex": self.signature_hex,
            }
        )


def sign_audit_checkpoint(
    *,
    checkpoint: AuditCheckpoint,
    private_key: Ed25519PrivateKey,
    key_id: str,
) -> SignedAuditCheckpoint:
    """Sign a checkpoint using an externally managed Ed25519 private key."""
    if type(checkpoint) is not AuditCheckpoint:
        raise TypeError("Invalid audit checkpoint.")

    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("Invalid Ed25519 private key.")

    if not _valid_key_id(key_id):
        raise ValueError("Invalid checkpoint key identifier.")

    signature = private_key.sign(
        _signed_message(
            checkpoint=checkpoint,
            key_id=key_id,
        )
    )

    return SignedAuditCheckpoint(
        version=SIGNED_CHECKPOINT_VERSION,
        algorithm=SIGNATURE_ALGORITHM,
        key_id=key_id,
        checkpoint=checkpoint,
        signature_hex=signature.hex(),
    )


def signed_checkpoint_from_json(
    *,
    payload: str,
) -> SignedAuditCheckpoint:
    """Decode a bounded JSON envelope with no duplicate or unknown fields."""
    if type(payload) is not str:
        raise TypeError("Signed checkpoint JSON must be a string.")

    try:
        encoded = payload.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Signed checkpoint JSON must be ASCII.") from exc

    if not 1 <= len(encoded) <= MAX_SIGNED_CHECKPOINT_JSON_BYTES:
        raise ValueError("Invalid signed checkpoint JSON length.")

    try:
        document = json.loads(
            payload,
            object_pairs_hook=_unique_pairs,
            parse_constant=_invalid_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Invalid signed checkpoint JSON.") from exc

    if type(document) is not dict or document.keys() != _ENVELOPE_FIELDS:
        raise ValueError("Invalid signed checkpoint JSON fields.")

    checkpoint_document = document["checkpoint"]
    if type(checkpoint_document) is not dict:
        raise ValueError("Invalid nested checkpoint object.")

    # Reuse the existing checkpoint decoder and all its schema checks.
    checkpoint = checkpoint_from_json(payload=_canonical_json(checkpoint_document))

    return SignedAuditCheckpoint(
        version=document["version"],
        algorithm=document["algorithm"],
        key_id=document["key_id"],
        checkpoint=checkpoint,
        signature_hex=document["signature_hex"],
    )


def verify_signed_checkpoint(
    *,
    envelope: SignedAuditCheckpoint,
    public_key: Ed25519PublicKey,
    expected_key_id: str,
) -> AuditCheckpoint:
    """Verify a signature using a separately trusted Ed25519 public key.

    The caller must bind expected_key_id to the supplied public key
    through an independent trust policy. Neither the ID nor the
    envelope's contents constitute a trust anchor by themselves.
    """
    if type(envelope) is not SignedAuditCheckpoint:
        raise TypeError("Invalid signed checkpoint envelope.")

    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("Invalid Ed25519 public key.")

    if not _valid_key_id(expected_key_id):
        raise ValueError("Invalid expected checkpoint key identifier.")

    if envelope.key_id != expected_key_id:
        raise SignedCheckpointError("Checkpoint key identifier mismatch.")

    message = _signed_message(
        checkpoint=envelope.checkpoint,
        key_id=envelope.key_id,
    )

    try:
        public_key.verify(
            bytes.fromhex(envelope.signature_hex),
            message,
        )
    except InvalidSignature as exc:
        raise SignedCheckpointError(
            "Checkpoint Ed25519 signature verification failed."
        ) from exc

    return envelope.checkpoint


def verify_signed_audit_chain(
    *,
    records: tuple[AuditRecord, ...],
    envelope: SignedAuditCheckpoint,
    public_key: Ed25519PublicKey,
    expected_key_id: str,
    expected_journal_id: str,
    allow_extensions: bool = False,
) -> CheckpointVerification:
    """Verify the trusted-key signature and the complete audit chain.

    A valid signature authenticates one historical checkpoint, not
    its freshness or the completeness of later journal operations.
    """
    checkpoint = verify_signed_checkpoint(
        envelope=envelope,
        public_key=public_key,
        expected_key_id=expected_key_id,
    )

    return verify_audit_checkpoint(
        records=records,
        checkpoint=checkpoint,
        expected_journal_id=expected_journal_id,
        allow_extensions=allow_extensions,
    )
