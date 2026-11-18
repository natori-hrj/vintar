"""Track byte-integrity checks performed during one evidence session.

Session results describe supplied bytes only. They do not establish
trusted acquisition, artifact authenticity, or ground-truth validity.
No filesystem or network I/O is performed.
"""

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import StrEnum

from vintar.checks.sqli.time_evidence import (
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_RECORDS,
    EvidenceBinding,
    EvidenceRecord,
)


class EvidenceCheckStatus(StrEnum):
    MATCHED = "matched"
    MISMATCHED = "mismatched"
    UNCHECKED = "unchecked"


class SessionStatus(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceObservation:
    """Digest of explicitly supplied bytes for an expected record.

    This record does not retain the original bytes.
    Its source is a declaration, not an authenticated event.
    """

    binding: EvidenceBinding = field(repr=False)
    evidence_id: str
    observed_sha256: str
    observed_size: int

    def __post_init__(self) -> None:
        if type(self.binding) is not EvidenceBinding:
            raise TypeError("Invalid observed evidence binding.")

        if self.binding.index.get(self.evidence_id) is None:
            raise ValueError("Observed evidence identifier is not bound.")

        if (
            type(self.observed_sha256) is not str
            or len(self.observed_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in self.observed_sha256
            )
        ):
            raise ValueError("Invalid observed SHA-256 digest.")

        if type(self.observed_size) is not int:
            raise TypeError("Invalid observed evidence size.")

        if not 1 <= self.observed_size <= MAX_EVIDENCE_BYTES:
            raise ValueError("Invalid observed evidence size.")

    @property
    def record(self) -> EvidenceRecord:
        record = self.binding.index.get(self.evidence_id)
        if record is None:  # pragma: no cover - enforced during construction
            raise RuntimeError("Observed evidence identifier is not bound.")
        return record

    @property
    def status(self) -> EvidenceCheckStatus:
        if self.observed_size == self.record.size_bytes and hmac.compare_digest(
            self.observed_sha256,
            self.record.sha256,
        ):
            return EvidenceCheckStatus.MATCHED

        return EvidenceCheckStatus.MISMATCHED


def observe_evidence_bytes(
    *,
    binding: EvidenceBinding,
    evidence_id: str,
    content: bytes,
) -> EvidenceObservation:
    """Digest one supplied byte string without retaining its contents."""
    if type(binding) is not EvidenceBinding:
        raise TypeError("Invalid evidence binding.")

    if binding.index.get(evidence_id) is None:
        raise ValueError("Evidence identifier is not bound.")

    if type(content) is not bytes:
        raise TypeError("Evidence content must be bytes.")

    if not 1 <= len(content) <= MAX_EVIDENCE_BYTES:
        raise ValueError("Invalid evidence content size.")

    return EvidenceObservation(
        binding=binding,
        evidence_id=evidence_id,
        observed_sha256=hashlib.sha256(content).hexdigest(),
        observed_size=len(content),
    )


@dataclass(frozen=True, slots=True, repr=False)
class VerificationSession:
    """Immutable, possibly partial record of evidence byte checks."""

    binding: EvidenceBinding = field(repr=False)
    observations: tuple[EvidenceObservation, ...] = field(
        default=(),
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self.binding) is not EvidenceBinding:
            raise TypeError("Invalid evidence binding.")

        if type(self.observations) is not tuple:
            raise TypeError("Invalid verification observations.")

        if len(self.observations) > MAX_EVIDENCE_RECORDS:
            raise ValueError("Too many verification observations.")

        if any(
            type(observation) is not EvidenceObservation
            for observation in self.observations
        ):
            raise TypeError("Invalid verification observation.")

        identifiers = tuple(
            observation.evidence_id for observation in self.observations
        )

        if identifiers != tuple(sorted(set(identifiers))):
            raise ValueError("Invalid verification observation ordering.")

        if any(
            observation.binding is not self.binding for observation in self.observations
        ):
            raise ValueError("Observation does not match bound evidence.")

    @property
    def evidence_count(self) -> int:
        return self.binding.evidence_count

    @property
    def checked_count(self) -> int:
        return len(self.observations)

    @property
    def matched_count(self) -> int:
        return len(self.matched_ids)

    @property
    def mismatched_count(self) -> int:
        return len(self.mismatched_ids)

    @property
    def unchecked_count(self) -> int:
        return len(self.unchecked_ids)

    @property
    def matched_ids(self) -> tuple[str, ...]:
        return tuple(
            observation.evidence_id
            for observation in self.observations
            if observation.status is EvidenceCheckStatus.MATCHED
        )

    @property
    def mismatched_ids(self) -> tuple[str, ...]:
        return tuple(
            observation.evidence_id
            for observation in self.observations
            if observation.status is EvidenceCheckStatus.MISMATCHED
        )

    @property
    def unchecked_ids(self) -> tuple[str, ...]:
        checked = {observation.evidence_id for observation in self.observations}
        return tuple(
            record.evidence_id
            for record in self.binding.index.records
            if record.evidence_id not in checked
        )

    @property
    def status(self) -> SessionStatus:
        if self.mismatched_ids:
            return SessionStatus.FAILED

        if self.unchecked_ids:
            return SessionStatus.INCOMPLETE

        return SessionStatus.COMPLETE

    @property
    def is_complete(self) -> bool:
        return self.status is SessionStatus.COMPLETE

    def evidence_status(self, evidence_id: str) -> EvidenceCheckStatus:
        """Return the status of a known evidence identifier."""
        record = self.binding.index.get(evidence_id)

        if record is None:
            raise ValueError("Evidence identifier is not bound.")

        for observation in self.observations:
            if observation.evidence_id == evidence_id:
                return observation.status

        return EvidenceCheckStatus.UNCHECKED


def create_verification_session(
    *,
    binding: EvidenceBinding,
) -> VerificationSession:
    """Start an empty session; no content has been checked yet."""
    return VerificationSession(binding=binding)


def add_evidence_observation(
    *,
    session: VerificationSession,
    observation: EvidenceObservation,
) -> VerificationSession:
    """Append one independently supplied observation.

    An evidence ID cannot be checked twice in one session.
    Create a new session to repeat verification.
    """
    if type(session) is not VerificationSession:
        raise TypeError("Invalid verification session.")

    if type(observation) is not EvidenceObservation:
        raise TypeError("Invalid evidence observation.")

    if any(
        current.evidence_id == observation.evidence_id
        for current in session.observations
    ):
        raise ValueError("Evidence already checked in this session.")

    observations = tuple(
        sorted(
            (*session.observations, observation),
            key=lambda item: item.evidence_id,
        )
    )

    return VerificationSession(
        binding=session.binding,
        observations=observations,
    )


def check_evidence_in_session(
    *,
    session: VerificationSession,
    evidence_id: str,
    content: bytes,
) -> VerificationSession:
    """Check supplied bytes and return a new validated session."""
    if type(session) is not VerificationSession:
        raise TypeError("Invalid verification session.")

    record = session.binding.index.get(evidence_id)

    if record is None:
        raise ValueError("Evidence identifier is not bound.")

    observation = observe_evidence_bytes(
        binding=session.binding,
        evidence_id=record.evidence_id,
        content=content,
    )

    return add_evidence_observation(
        session=session,
        observation=observation,
    )
