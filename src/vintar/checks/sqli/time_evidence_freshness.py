"""Monotonic in-process trust state for signed audit checkpoints.

Only checkpoints verified against a fixed, caller-trusted Ed25519
public key and a complete audit chain can advance the state.

This module offers no persistence, clock-based freshness, key
rotation, or protection from mutation of private Python attributes.
"""

import hmac
import threading
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vintar.checks.sqli.time_evidence_audit import (
    GENESIS_DIGEST,
    AuditRecord,
)
from vintar.checks.sqli.time_evidence_checkpoint import (
    CHECKPOINT_VERSION,
    AuditCheckpoint,
)
from vintar.checks.sqli.time_evidence_signature import (
    SignedAuditCheckpoint,
    verify_signed_audit_chain,
)

_KEY_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
)


class CheckpointFreshnessError(ValueError):
    """A checkpoint violates an already accepted trust state."""


def _valid_key_id(value: object) -> bool:
    return (
        type(value) is str
        and 1 <= len(value) <= 64
        and all(character in _KEY_CHARS for character in value)
    )


@dataclass(frozen=True, slots=True)
class TrustedCheckpointState:
    """Latest accepted checkpoint position for one configured journal."""

    journal_id: str
    key_id: str
    record_count: int
    head_digest: str

    def __post_init__(self) -> None:
        # Reuse the existing checkpoint model's strict field bounds.
        AuditCheckpoint(
            version=CHECKPOINT_VERSION,
            journal_id=self.journal_id,
            record_count=self.record_count,
            head_digest=self.head_digest,
        )

        if not _valid_key_id(self.key_id):
            raise ValueError("Invalid trusted checkpoint key identifier.")


@dataclass(frozen=True, slots=True)
class FreshnessAcceptance:
    """Result of an accepted, authenticated checkpoint observation."""

    state: TrustedCheckpointState
    advanced: bool

    def __post_init__(self) -> None:
        if type(self.state) is not TrustedCheckpointState:
            raise TypeError("Invalid accepted trust state.")

        if type(self.advanced) is not bool:
            raise TypeError("Invalid advancement flag.")


class SignedCheckpointTrustTracker:
    """Track a monotonic, authenticated audit-chain position.

    One tracker is permanently bound to one journal identifier,
    key identifier, and trusted public key for its lifetime.

    The initial state is unanchored. The first authentic checkpoint
    establishes a baseline but cannot prove that it is the latest
    checkpoint ever issued.
    """

    def __init__(
        self,
        *,
        journal_id: str,
        key_id: str,
        public_key: Ed25519PublicKey,
    ) -> None:
        AuditCheckpoint(
            version=CHECKPOINT_VERSION,
            journal_id=journal_id,
            record_count=0,
            head_digest=GENESIS_DIGEST,
        )

        if not _valid_key_id(key_id):
            raise ValueError("Invalid trusted checkpoint key identifier.")

        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("Invalid trusted Ed25519 public key.")

        self._journal_id = journal_id
        self._key_id = key_id
        self._public_key = public_key
        self._lock = threading.RLock()
        self._state: TrustedCheckpointState | None = None

    @property
    def journal_id(self) -> str:
        return self._journal_id

    @property
    def key_id(self) -> str:
        return self._key_id

    def snapshot(self) -> TrustedCheckpointState | None:
        """Return the immutable latest state, or None before first trust."""
        with self._lock:
            return self._state

    def accept(
        self,
        *,
        records: tuple[AuditRecord, ...],
        envelope: SignedAuditCheckpoint,
    ) -> FreshnessAcceptance:
        """Verify a signed checkpoint, then advance state if monotonic.

        Both verification and state update are serialized under one lock.
        The supplied chain must end at the submitted checkpoint; the
        accepted head is never inferred from unsigned later records.
        """
        with self._lock:
            verified = verify_signed_audit_chain(
                records=records,
                envelope=envelope,
                public_key=self._public_key,
                expected_key_id=self._key_id,
                expected_journal_id=self._journal_id,
                allow_extensions=False,
            )

            checkpoint = verified.checkpoint
            previous = self._state

            if previous is not None:
                if checkpoint.record_count < previous.record_count:
                    raise CheckpointFreshnessError(
                        "Signed checkpoint rolls back the accepted record count."
                    )

                if previous.record_count:
                    previous_digest = records[previous.record_count - 1].digest
                else:
                    previous_digest = GENESIS_DIGEST

                if not hmac.compare_digest(
                    previous_digest,
                    previous.head_digest,
                ):
                    raise CheckpointFreshnessError(
                        "Signed checkpoint diverges from trusted history."
                    )

                if checkpoint.record_count == previous.record_count:
                    # Prior-prefix comparison above also proves the
                    # current checkpoint's digest matches previous.
                    return FreshnessAcceptance(
                        state=previous,
                        advanced=False,
                    )

            accepted = TrustedCheckpointState(
                journal_id=self._journal_id,
                key_id=self._key_id,
                record_count=checkpoint.record_count,
                head_digest=checkpoint.head_digest,
            )

            result = FreshnessAcceptance(
                state=accepted,
                advanced=True,
            )
            self._state = accepted
            return result


def create_signed_checkpoint_tracker(
    *,
    journal_id: str,
    key_id: str,
    public_key: Ed25519PublicKey,
) -> SignedCheckpointTrustTracker:
    """Create an unanchored tracker with immutable trust configuration."""
    return SignedCheckpointTrustTracker(
        journal_id=journal_id,
        key_id=key_id,
        public_key=public_key,
    )
