"""Budgeted streaming acquisition of local timing research evidence.

The adapter shares a POSIX acquisition boundary with the full-file
loader. Deadlines are cooperative, not hard I/O cancellation.
"""

import hashlib
import math
import os
import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from vintar.checks.sqli._time_evidence_posix import (
    MAX_CHUNK_SIZE,
    EvidenceAcquisitionError,
    open_confined_evidence,
    relative_components,
    root_components,
    validate_after_read,
)
from vintar.checks.sqli._time_evidence_posix import (
    require_posix as _require_posix,
)
from vintar.checks.sqli.time_evidence import (
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_RECORDS,
    EvidenceBinding,
)
from vintar.checks.sqli.time_evidence_session import (
    EvidenceCheckStatus,
    EvidenceObservation,
    VerificationSession,
    add_evidence_observation,
)

_MAX_TOTAL_BYTES = MAX_EVIDENCE_BYTES * MAX_EVIDENCE_RECORDS


class AcquisitionOutcome(StrEnum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"
    ACQUISITION_FAILED = "acquisition_failed"
    BUDGET_EXCEEDED = "budget_exceeded"


@dataclass(frozen=True, slots=True)
class AcquisitionPolicy:
    """Upper bounds for one sequential local acquisition run."""

    max_files: int = MAX_EVIDENCE_RECORDS
    max_total_bytes: int = _MAX_TOTAL_BYTES
    max_elapsed_seconds: float = 60.0

    def __post_init__(self) -> None:
        if type(self.max_files) is not int or not (
            1 <= self.max_files <= MAX_EVIDENCE_RECORDS
        ):
            raise ValueError("Invalid acquisition file budget.")
        if type(self.max_total_bytes) is not int or not (
            1 <= self.max_total_bytes <= _MAX_TOTAL_BYTES
        ):
            raise ValueError("Invalid acquisition byte budget.")
        if (
            type(self.max_elapsed_seconds) is not float
            or not math.isfinite(self.max_elapsed_seconds)
            or not 0 < self.max_elapsed_seconds <= 3600.0
        ):
            raise ValueError("Invalid acquisition time budget.")


@dataclass(frozen=True, slots=True, repr=False)
class AcquisitionAttempt:
    """One attempted acquisition and its consumed bytes."""

    evidence_id: str
    outcome: AcquisitionOutcome
    bytes_read: int

    def __post_init__(self) -> None:
        if (
            type(self.evidence_id) is not str
            or not 1 <= len(self.evidence_id) <= 100
            or not all(
                character.isascii() and (character.isalnum() or character in "_-")
                for character in self.evidence_id
            )
        ):
            raise ValueError("Invalid acquisition evidence identifier.")
        if type(self.outcome) is not AcquisitionOutcome:
            raise TypeError("Invalid acquisition outcome.")
        if type(self.bytes_read) is not int or not (
            0 <= self.bytes_read <= MAX_EVIDENCE_BYTES
        ):
            raise ValueError("Invalid acquired byte count.")
        if (
            self.outcome in (AcquisitionOutcome.MATCHED, AcquisitionOutcome.MISMATCHED)
            and self.bytes_read == 0
        ):
            raise ValueError("Invalid acquired byte count.")


@dataclass(frozen=True, slots=True, repr=False)
class AcquisitionRun:
    """Immutable accounting for a sequential verification run."""

    binding: EvidenceBinding = field(repr=False)
    session: VerificationSession = field(repr=False)
    policy: AcquisitionPolicy
    started_at: float = field(repr=False)
    attempts: tuple[AcquisitionAttempt, ...] = field(default=(), repr=False)

    def __post_init__(self) -> None:
        if type(self.binding) is not EvidenceBinding:
            raise TypeError("Invalid acquisition binding.")
        if type(self.session) is not VerificationSession:
            raise TypeError("Invalid acquisition session.")
        if self.session.binding is not self.binding:
            raise ValueError("Acquisition session does not match binding.")
        if type(self.policy) is not AcquisitionPolicy:
            raise TypeError("Invalid acquisition policy.")
        if (
            type(self.started_at) is not float
            or not math.isfinite(self.started_at)
            or self.started_at < 0
        ):
            raise ValueError("Invalid acquisition clock origin.")
        if type(self.attempts) is not tuple:
            raise TypeError("Invalid acquisition attempts.")
        if len(self.attempts) > self.policy.max_files:
            raise ValueError("Acquisition file budget exceeded.")
        if any(type(item) is not AcquisitionAttempt for item in self.attempts):
            raise TypeError("Invalid acquisition attempt.")
        identifiers = tuple(item.evidence_id for item in self.attempts)
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("Duplicate acquisition attempt.")
        if any(
            self.session.binding.index.get(identifier) is None
            for identifier in identifiers
        ):
            raise ValueError("Acquisition evidence is not bound.")
        if self.total_bytes > self.policy.max_total_bytes:
            raise ValueError("Acquisition byte budget exceeded.")
        successful_attempts = {
            item.evidence_id: item
            for item in self.attempts
            if item.outcome
            in (AcquisitionOutcome.MATCHED, AcquisitionOutcome.MISMATCHED)
        }
        session_observations = {
            observation.evidence_id: observation
            for observation in self.session.observations
        }
        if set(successful_attempts) != set(session_observations):
            raise ValueError("Inconsistent acquisition session.")
        for identifier, attempt in successful_attempts.items():
            observation = session_observations[identifier]
            expected = (
                EvidenceCheckStatus.MATCHED
                if attempt.outcome is AcquisitionOutcome.MATCHED
                else EvidenceCheckStatus.MISMATCHED
            )
            if (
                observation.status is not expected
                or observation.observed_size != attempt.bytes_read
            ):
                raise ValueError("Inconsistent acquisition outcome.")

    @property
    def attempted_files(self) -> int:
        return len(self.attempts)

    @property
    def total_bytes(self) -> int:
        return sum(item.bytes_read for item in self.attempts)

    @property
    def failed_attempts(self) -> int:
        return sum(
            item.outcome
            in (
                AcquisitionOutcome.ACQUISITION_FAILED,
                AcquisitionOutcome.BUDGET_EXCEEDED,
            )
            for item in self.attempts
        )

    @property
    def remaining_files(self) -> int:
        return self.policy.max_files - self.attempted_files

    @property
    def remaining_bytes(self) -> int:
        return self.policy.max_total_bytes - self.total_bytes


class _ReadFailure(Exception):
    """Internal read failure with bounded resource accounting."""

    def __init__(self, outcome: AcquisitionOutcome, bytes_read: int) -> None:
        super().__init__("Evidence acquisition did not complete.")
        self.outcome = outcome
        self.bytes_read = bytes_read


def _check_deadline(deadline: float, bytes_read: int) -> None:
    if time.monotonic() >= deadline:
        raise _ReadFailure(AcquisitionOutcome.BUDGET_EXCEEDED, bytes_read)


def _stream_digest(
    *,
    root: str | Path,
    relative_path: str,
    byte_limit: int,
    deadline: float,
) -> tuple[str, int]:
    """Hash a confined regular file without retaining its full contents."""
    received = 0

    def checkpoint() -> None:
        _check_deadline(deadline, received)

    def pre_open_check(metadata: os.stat_result) -> None:
        if metadata.st_size > byte_limit:
            raise _ReadFailure(AcquisitionOutcome.BUDGET_EXCEEDED, received)

    try:
        checkpoint()
        _require_posix()
        with open_confined_evidence(
            root=root,
            relative_path=relative_path,
            checkpoint=checkpoint,
            pre_open_check=pre_open_check,
        ) as (file_fd, before):
            digest = hashlib.sha256()
            while received < before.st_size:
                checkpoint()
                request_size = min(
                    MAX_CHUNK_SIZE,
                    before.st_size - received,
                    byte_limit - received,
                )
                if request_size <= 0:
                    raise _ReadFailure(AcquisitionOutcome.BUDGET_EXCEEDED, received)
                chunk = os.read(file_fd, request_size)
                if not chunk:
                    raise EvidenceAcquisitionError(
                        "Evidence length changed during acquisition."
                    )
                received += len(chunk)
                if received > byte_limit or received > MAX_EVIDENCE_BYTES:
                    raise _ReadFailure(
                        AcquisitionOutcome.BUDGET_EXCEEDED,
                        min(received, byte_limit),
                    )
                digest.update(chunk)
                checkpoint()
            validate_after_read(file_fd=file_fd, before=before, received=received)
            checkpoint()
            return digest.hexdigest(), received
    except _ReadFailure:
        raise
    except (OSError, EvidenceAcquisitionError):
        raise _ReadFailure(AcquisitionOutcome.ACQUISITION_FAILED, received) from None


def start_acquisition_run(
    *, session: VerificationSession, policy: AcquisitionPolicy
) -> AcquisitionRun:
    """Start accounting against an initially unchecked evidence session."""
    if type(session) is not VerificationSession:
        raise TypeError("Invalid acquisition session.")
    if type(policy) is not AcquisitionPolicy:
        raise TypeError("Invalid acquisition policy.")
    if session.checked_count:
        raise ValueError("Acquisition requires an initially empty session.")
    return AcquisitionRun(
        binding=session.binding,
        session=session,
        policy=policy,
        started_at=float(time.monotonic()),
    )


def acquire_evidence_stream(
    *,
    run: AcquisitionRun,
    evidence_id: str,
    root: str | Path,
    relative_path: str,
) -> AcquisitionRun:
    """Attempt one confined read and return an accounted immutable run."""
    if type(run) is not AcquisitionRun:
        raise TypeError("Invalid acquisition run.")
    record = run.session.binding.index.get(evidence_id)
    if record is None:
        raise ValueError("Evidence identifier is not bound.")
    if any(attempt.evidence_id == evidence_id for attempt in run.attempts):
        raise ValueError("Evidence already attempted in this run.")
    if not run.remaining_files:
        raise ValueError("Acquisition file budget exhausted.")
    root_components(root)
    relative_components(relative_path)
    deadline = run.started_at + run.policy.max_elapsed_seconds
    session = run.session
    if run.remaining_bytes == 0:
        outcome = AcquisitionOutcome.BUDGET_EXCEEDED
        consumed = 0
    else:
        try:
            observed_sha256, consumed = _stream_digest(
                root=root,
                relative_path=relative_path,
                byte_limit=min(run.remaining_bytes, MAX_EVIDENCE_BYTES),
                deadline=deadline,
            )
        except _ReadFailure as failure:
            outcome = failure.outcome
            consumed = failure.bytes_read
        else:
            observation = EvidenceObservation(
                binding=session.binding,
                evidence_id=evidence_id,
                observed_sha256=observed_sha256,
                observed_size=consumed,
            )
            outcome = (
                AcquisitionOutcome.MATCHED
                if observation.status is EvidenceCheckStatus.MATCHED
                else AcquisitionOutcome.MISMATCHED
            )
            session = add_evidence_observation(session=session, observation=observation)
    return AcquisitionRun(
        binding=run.binding,
        session=session,
        policy=run.policy,
        started_at=run.started_at,
        attempts=(
            *run.attempts,
            AcquisitionAttempt(
                evidence_id=evidence_id, outcome=outcome, bytes_read=consumed
            ),
        ),
    )
