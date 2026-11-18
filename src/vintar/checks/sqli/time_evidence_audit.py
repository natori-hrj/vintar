"""Deterministic hash-chained audit declarations for evidence acquisition.

The journal records caller-supplied events, not authenticated execution.
It performs no filesystem, network, or acquisition I/O.
"""

import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from enum import Enum

from vintar.checks.sqli.time_evidence import (
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_RECORDS,
)
from vintar.checks.sqli.time_evidence_governor import GovernorUsage
from vintar.checks.sqli.time_evidence_process import ProcessAcquisitionStatus

GENESIS_DIGEST = "0" * 64
MAX_AUDIT_RECORDS = 10_000
_DOMAIN = b"vintar.evidence.audit.v1\x00"
_HEX = frozenset("0123456789abcdef")
_ID_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)
_MAX_AUDIT_FILES = MAX_EVIDENCE_RECORDS**2
_MAX_AUDIT_BYTES = MAX_EVIDENCE_BYTES * MAX_EVIDENCE_RECORDS**2
_MAX_AUDIT_WORKERS = 64


class AuditEventType(str, Enum):
    REGISTERED = "registered"
    RESERVED = "reserved"
    SETTLED = "settled"
    INVALIDATED = "invalidated"
    TERMINATED = "terminated"
    HALTED = "halted"


class AuditIntegrityError(ValueError):
    """A supplied audit chain failed structural or digest verification."""


def _valid_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _valid_run_id(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 32
        and all(character in _HEX for character in value)
    )


def _valid_evidence_id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 100
        and all(character in _ID_CHARS for character in value)
    )


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """A bounded, typed declaration about an acquisition operation.

    Usage is the declared post-event governor state. This model does
    not independently verify that an operation actually occurred.
    """

    event_type: AuditEventType
    usage: GovernorUsage
    run_id: str | None = None
    evidence_id: str | None = None
    process_status: ProcessAcquisitionStatus | None = None

    def __post_init__(self) -> None:
        if type(self.event_type) is not AuditEventType:
            raise TypeError("Invalid audit event type.")

        if type(self.usage) is not GovernorUsage:
            raise TypeError("Invalid audit usage.")

        if (
            self.usage.files_used > _MAX_AUDIT_FILES
            or self.usage.bytes_used > _MAX_AUDIT_BYTES
            or self.usage.slots_in_use > _MAX_AUDIT_WORKERS
            or self.usage.unknown_slots > _MAX_AUDIT_WORKERS
        ):
            raise ValueError("Audit usage exceeds schema limits.")

        if self.run_id is not None and not _valid_run_id(self.run_id):
            raise ValueError("Invalid audit run identifier.")

        if self.evidence_id is not None and not _valid_evidence_id(self.evidence_id):
            raise ValueError("Invalid audit evidence identifier.")

        if (
            self.process_status is not None
            and type(self.process_status) is not ProcessAcquisitionStatus
        ):
            raise TypeError("Invalid audit process status.")

        if self.event_type is AuditEventType.HALTED:
            if not self.usage.halted:
                raise ValueError("Halted audit event requires halted usage.")
            if self.evidence_id is not None:
                raise ValueError("Unexpected halted evidence identifier.")
            if self.process_status not in (
                None,
                ProcessAcquisitionStatus.WORKER_FAILED,
                ProcessAcquisitionStatus.UNREAPED,
            ):
                raise ValueError("Invalid halted process status.")
            if (
                self.process_status
                in (
                    ProcessAcquisitionStatus.WORKER_FAILED,
                    ProcessAcquisitionStatus.UNREAPED,
                )
                and self.usage.unknown_slots == 0
            ):
                raise ValueError("Halted worker requires unknown usage.")
            return

        if self.run_id is None:
            raise ValueError("Audit event requires a run identifier.")

        if self.event_type in (
            AuditEventType.RESERVED,
            AuditEventType.SETTLED,
        ):
            if self.evidence_id is None:
                raise ValueError("Audit event requires an evidence identifier.")
        elif (
            self.event_type
            in (
                AuditEventType.REGISTERED,
                AuditEventType.TERMINATED,
            )
            and self.evidence_id is not None
        ):
            raise ValueError("Unexpected audit evidence identifier.")

        if self.event_type is AuditEventType.SETTLED:
            if self.process_status not in (
                ProcessAcquisitionStatus.COMPLETED,
                ProcessAcquisitionStatus.TIMED_OUT,
            ):
                raise ValueError("Invalid settled process status.")
        elif self.event_type is AuditEventType.INVALIDATED:
            if self.process_status is ProcessAcquisitionStatus.COMPLETED:
                raise ValueError("Invalid invalidation process status.")
        elif self.process_status is not None:
            raise ValueError("Unexpected audit process status.")


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One numbered event linked to the preceding record digest."""

    sequence: int
    previous_digest: str
    event: AuditEvent
    digest: str

    def __post_init__(self) -> None:
        if type(self.sequence) is not int or not (
            1 <= self.sequence <= MAX_AUDIT_RECORDS
        ):
            raise ValueError("Invalid audit sequence.")

        if not _valid_digest(self.previous_digest):
            raise ValueError("Invalid previous audit digest.")

        if type(self.event) is not AuditEvent:
            raise TypeError("Invalid audit record event.")

        if not _valid_digest(self.digest):
            raise ValueError("Invalid audit record digest.")


@dataclass(frozen=True, slots=True)
class AuditVerification:
    """Verified chain metadata; not evidence authenticity."""

    record_count: int
    head_digest: str

    def __post_init__(self) -> None:
        if (
            type(self.record_count) is not int
            or not 0 <= self.record_count <= MAX_AUDIT_RECORDS
        ):
            raise ValueError("Invalid verified record count.")

        if not _valid_digest(self.head_digest):
            raise ValueError("Invalid verified audit digest.")

        if self.record_count == 0 and self.head_digest != GENESIS_DIGEST:
            raise ValueError("Empty verification requires genesis digest.")


def _canonical_payload(
    *,
    sequence: int,
    previous_digest: str,
    event: AuditEvent,
) -> bytes:
    """Encode an explicitly versioned, fixed-field JSON representation."""
    usage = event.usage

    document = {
        "version": 1,
        "sequence": sequence,
        "previous_digest": previous_digest,
        "event": {
            "event_type": event.event_type.value,
            "run_id": event.run_id,
            "evidence_id": event.evidence_id,
            "process_status": (
                event.process_status.value if event.process_status is not None else None
            ),
            "usage": {
                "files_used": usage.files_used,
                "bytes_used": usage.bytes_used,
                "slots_in_use": usage.slots_in_use,
                "unknown_slots": usage.unknown_slots,
                "halted": usage.halted,
            },
        },
    }

    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _record_digest(
    *,
    sequence: int,
    previous_digest: str,
    event: AuditEvent,
) -> str:
    return hashlib.sha256(
        _DOMAIN
        + _canonical_payload(
            sequence=sequence,
            previous_digest=previous_digest,
            event=event,
        )
    ).hexdigest()


def verify_audit_chain(
    *,
    records: tuple[AuditRecord, ...],
    expected_head: str | None = None,
    expected_count: int | None = None,
) -> AuditVerification:
    """Verify ordered linkage, canonical digests and optional anchors.

    Without an independently trusted expected head and record count,
    truncation or complete replacement can remain undetectable.
    """
    if type(records) is not tuple:
        raise TypeError("Audit records must be a tuple.")

    if len(records) > MAX_AUDIT_RECORDS:
        raise AuditIntegrityError("Audit record limit exceeded.")

    if expected_head is not None and not _valid_digest(expected_head):
        raise ValueError("Invalid expected audit head.")

    if expected_count is not None and (
        type(expected_count) is not int or not 0 <= expected_count <= MAX_AUDIT_RECORDS
    ):
        raise ValueError("Invalid expected audit count.")

    previous = GENESIS_DIGEST

    for sequence, record in enumerate(records, start=1):
        if type(record) is not AuditRecord:
            raise AuditIntegrityError("Invalid audit record type.")

        if record.sequence != sequence:
            raise AuditIntegrityError("Audit sequence is not contiguous.")

        if not hmac.compare_digest(record.previous_digest, previous):
            raise AuditIntegrityError("Audit predecessor digest mismatch.")

        calculated = _record_digest(
            sequence=record.sequence,
            previous_digest=record.previous_digest,
            event=record.event,
        )

        if not hmac.compare_digest(record.digest, calculated):
            raise AuditIntegrityError("Audit record digest mismatch.")

        previous = calculated

    if expected_count is not None and expected_count != len(records):
        raise AuditIntegrityError("Audit record count does not match anchor.")

    if expected_head is not None and not hmac.compare_digest(expected_head, previous):
        raise AuditIntegrityError("Audit head does not match anchor.")

    return AuditVerification(
        record_count=len(records),
        head_digest=previous,
    )


class AcquisitionAuditJournal:
    """Append-only in-memory journal for trusted callers.

    Appends are serialized. No mutation or deletion method is exposed.
    Python code capable of changing private attributes is not isolated.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: tuple[AuditRecord, ...] = ()
        self._head = GENESIS_DIGEST

    @property
    def record_count(self) -> int:
        with self._lock:
            return len(self._records)

    @property
    def head_digest(self) -> str:
        with self._lock:
            return self._head

    def snapshot(self) -> tuple[AuditRecord, ...]:
        """Return an immutable snapshot in append order."""
        with self._lock:
            return self._records

    def append(self, *, event: AuditEvent) -> AuditRecord:
        """Atomically append a checked event and advance the head."""
        if type(event) is not AuditEvent:
            raise TypeError("Invalid audit event.")

        with self._lock:
            if len(self._records) >= MAX_AUDIT_RECORDS:
                raise ValueError("Audit journal record limit exceeded.")

            sequence = len(self._records) + 1
            previous = self._head
            digest = _record_digest(
                sequence=sequence,
                previous_digest=previous,
                event=event,
            )

            record = AuditRecord(
                sequence=sequence,
                previous_digest=previous,
                event=event,
                digest=digest,
            )

            self._records = (*self._records, record)
            self._head = digest
            return record

    def verify(self) -> AuditVerification:
        """Validate a snapshot against the journal's current head."""
        with self._lock:
            return verify_audit_chain(
                records=self._records,
                expected_head=self._head,
                expected_count=len(self._records),
            )


def create_audit_journal() -> AcquisitionAuditJournal:
    """Create an empty, in-memory evidence acquisition audit journal."""
    return AcquisitionAuditJournal()
