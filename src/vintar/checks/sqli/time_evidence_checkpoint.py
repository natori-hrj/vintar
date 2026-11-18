"""Portable checkpoints for deterministic evidence audit chains.

Checkpoints bind a declared journal identifier to a record count and
hash-chain head. Independent trust in a checkpoint is required for
rollback detection. No persistence, signing, or external I/O occurs.
"""

import hmac
import json
import uuid
from dataclasses import dataclass

from vintar.checks.sqli.time_evidence_audit import (
    GENESIS_DIGEST,
    MAX_AUDIT_RECORDS,
    AcquisitionAuditJournal,
    AuditIntegrityError,
    AuditRecord,
    verify_audit_chain,
)

CHECKPOINT_VERSION = 1
MAX_CHECKPOINT_JSON_BYTES = 512

_HEX = frozenset("0123456789abcdef")
_CHECKPOINT_FIELDS = frozenset({"version", "journal_id", "record_count", "head_digest"})


class AuditCheckpointError(AuditIntegrityError):
    """An audit chain disagrees with the required checkpoint."""


def _valid_hex(value: object, length: int) -> bool:
    return (
        type(value) is str
        and len(value) == length
        and all(character in _HEX for character in value)
    )


@dataclass(frozen=True, slots=True)
class AuditCheckpoint:
    """A versioned, self-declared anchor for one chain position.

    The identifier associates checkpoints with a logical journal but
    does not authenticate the journal or the checkpoint issuer.
    """

    version: int
    journal_id: str
    record_count: int
    head_digest: str

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != CHECKPOINT_VERSION:
            raise ValueError("Unsupported audit checkpoint version.")

        if not _valid_hex(self.journal_id, 32):
            raise ValueError("Invalid checkpoint journal identifier.")

        if (
            type(self.record_count) is not int
            or not 0 <= self.record_count <= MAX_AUDIT_RECORDS
        ):
            raise ValueError("Invalid checkpoint record count.")

        if not _valid_hex(self.head_digest, 64):
            raise ValueError("Invalid checkpoint head digest.")

        if self.record_count == 0 and self.head_digest != GENESIS_DIGEST:
            raise ValueError("Empty checkpoint requires genesis digest.")

    def to_json(self) -> str:
        """Encode the fixed schema deterministically, without external I/O."""
        return json.dumps(
            {
                "version": self.version,
                "journal_id": self.journal_id,
                "record_count": self.record_count,
                "head_digest": self.head_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )


@dataclass(frozen=True, slots=True)
class CheckpointVerification:
    """Result of checking one anchor against a full supplied audit chain."""

    checkpoint: AuditCheckpoint
    chain_record_count: int
    chain_head_digest: str
    additional_records: int

    def __post_init__(self) -> None:
        if type(self.checkpoint) is not AuditCheckpoint:
            raise TypeError("Invalid checkpoint verification anchor.")

        if (
            type(self.chain_record_count) is not int
            or not 0 <= self.chain_record_count <= MAX_AUDIT_RECORDS
        ):
            raise ValueError("Invalid verification chain count.")

        if not _valid_hex(self.chain_head_digest, 64):
            raise ValueError("Invalid verification chain digest.")

        if (
            type(self.additional_records) is not int
            or self.additional_records < 0
            or self.chain_record_count - self.checkpoint.record_count
            != self.additional_records
        ):
            raise ValueError("Invalid checkpoint extension count.")

        if self.chain_record_count == 0 and self.chain_head_digest != GENESIS_DIGEST:
            raise ValueError("Empty chain requires genesis digest.")

        if self.additional_records == 0 and not hmac.compare_digest(
            self.chain_head_digest,
            self.checkpoint.head_digest,
        ):
            raise ValueError("Exact verification requires checkpoint digest.")


def create_audit_checkpoint(
    *,
    records: tuple[AuditRecord, ...],
    journal_id: str,
) -> AuditCheckpoint:
    """Validate a supplied chain before creating its declared anchor."""
    if not _valid_hex(journal_id, 32):
        raise ValueError("Invalid checkpoint journal identifier.")

    verified = verify_audit_chain(records=records)

    return AuditCheckpoint(
        version=CHECKPOINT_VERSION,
        journal_id=journal_id,
        record_count=verified.record_count,
        head_digest=verified.head_digest,
    )


def checkpoint_from_journal(
    *,
    journal: AcquisitionAuditJournal,
    journal_id: str,
) -> AuditCheckpoint:
    """Capture one immutable snapshot of a trusted caller's journal."""
    if type(journal) is not AcquisitionAuditJournal:
        raise TypeError("Invalid acquisition audit journal.")

    return create_audit_checkpoint(
        records=journal.snapshot(),
        journal_id=journal_id,
    )


def create_journal_id() -> str:
    """Create a random logical journal identifier; not authentication."""
    return uuid.uuid4().hex


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys rather than accepting the last value."""
    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate checkpoint JSON field.")
        result[key] = value

    return result


def checkpoint_from_json(*, payload: str) -> AuditCheckpoint:
    """Strictly decode the bounded, versioned checkpoint schema."""
    if type(payload) is not str:
        raise TypeError("Checkpoint JSON must be a string.")

    try:
        encoded = payload.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Checkpoint JSON must be ASCII.") from exc

    if not 1 <= len(encoded) <= MAX_CHECKPOINT_JSON_BYTES:
        raise ValueError("Invalid checkpoint JSON length.")

    try:
        document = json.loads(
            payload,
            object_pairs_hook=_unique_pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("Invalid JSON numeric constant.")
            ),
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Invalid checkpoint JSON.") from exc

    if type(document) is not dict or document.keys() != _CHECKPOINT_FIELDS:
        raise ValueError("Invalid checkpoint JSON fields.")

    return AuditCheckpoint(
        version=document["version"],
        journal_id=document["journal_id"],
        record_count=document["record_count"],
        head_digest=document["head_digest"],
    )


def verify_audit_checkpoint(
    *,
    records: tuple[AuditRecord, ...],
    checkpoint: AuditCheckpoint,
    expected_journal_id: str | None = None,
    allow_extensions: bool = False,
) -> CheckpointVerification:
    """Verify the complete chain and its checkpoint at a fixed position.

    expected_journal_id is meaningful only when obtained from an
    independently trusted source. allow_extensions verifies an
    authentic prefix while accepting later append-only records.
    """
    if type(checkpoint) is not AuditCheckpoint:
        raise TypeError("Invalid audit checkpoint.")

    if type(allow_extensions) is not bool:
        raise TypeError("Invalid checkpoint extension mode.")

    if expected_journal_id is not None and not _valid_hex(expected_journal_id, 32):
        raise ValueError("Invalid expected journal identifier.")

    if expected_journal_id is not None and not hmac.compare_digest(
        checkpoint.journal_id, expected_journal_id
    ):
        raise AuditCheckpointError("Checkpoint journal identifier mismatch.")

    # Verify all supplied records, including extensions. A correct
    # checkpoint prefix must not bless a corrupted later suffix.
    full = verify_audit_chain(records=records)

    if full.record_count < checkpoint.record_count:
        raise AuditCheckpointError("Audit chain is shorter than its checkpoint.")

    if not allow_extensions and full.record_count != checkpoint.record_count:
        raise AuditCheckpointError("Audit checkpoint record count mismatch.")

    anchored_digest = (
        GENESIS_DIGEST
        if checkpoint.record_count == 0
        else records[checkpoint.record_count - 1].digest
    )

    if not hmac.compare_digest(
        anchored_digest,
        checkpoint.head_digest,
    ):
        raise AuditCheckpointError("Audit checkpoint head digest mismatch.")

    return CheckpointVerification(
        checkpoint=checkpoint,
        chain_record_count=full.record_count,
        chain_head_digest=full.head_digest,
        additional_records=full.record_count - checkpoint.record_count,
    )
