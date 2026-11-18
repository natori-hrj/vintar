
# Signed Audit Checkpoint Freshness

## Purpose

This module maintains a monotonic, in-process trust state for
Ed25519-signed evidence audit checkpoints.

A tracker accepts only checkpoints that:

- Have valid Ed25519 signatures under its configured public key
- Match its configured Key ID
- Match its configured Journal ID
- Correspond exactly to a valid supplied audit chain
- Do not roll back its previously accepted record count
- Preserve its previously accepted chain history

The module does not provide persistent anti-rollback state,
trusted timestamps, key management, or external anchoring.

## Trust configuration

Each SignedCheckpointTrustTracker is bound at construction to:

- One logical Journal ID
- One Key ID
- One trusted Ed25519 public key

These values are not changed through the public API.

The caller must establish the trusted relationship between
the Journal ID, Key ID, public key and authorized signer.

The tracker does not discover or fetch public keys.

The tracker does not trust a public key carried inside a
SignedAuditCheckpoint.

## Initial state

A newly created tracker has no accepted checkpoint.

```python
tracker = create_signed_checkpoint_tracker(
    journal_id=trusted_journal_id,
    key_id="trusted-key",
    public_key=trusted_public_key,
)

assert tracker.snapshot() is None
```

The first valid signed checkpoint establishes the initial
trusted position.

It does not prove that the checkpoint is the newest one
ever issued.

For example, an attacker can replay an older valid
checkpoint to a newly initialized tracker if the attacker
can select which checkpoint is presented.

External trusted initialization is not implemented.

## Accepted state

TrustedCheckpointState contains:

- journal_id
- key_id
- record_count
- head_digest

The state is an immutable frozen dataclass.

The existing AuditCheckpoint model validates the journal
identifier, count and digest bounds.

The Key ID is additionally validated.

The state is not a digital signature or a durable record.

The snapshot() API returns the latest accepted state or
None when the tracker has not accepted any checkpoint.

## Acceptance

```python
result = tracker.accept(
    records=records,
    envelope=signed_envelope,
)
```

The operation runs under the tracker's RLock.

It first calls verify_signed_audit_chain() with:

```text
allow_extensions = False
```

Therefore the signed checkpoint must describe the full
supplied audit chain.

A historical signed checkpoint cannot advance the tracker
to a later unsigned chain head.

To advance from 100 records to 120 records, the caller
must present a valid signed checkpoint for record 120.

The tracker validates the complete supplied chain
before updating its state.

## Monotonic rules

### First acceptance

If no state exists, a valid signed checkpoint establishes
the initial state.

The returned FreshnessAcceptance has:

```text
advanced = True
```

This includes a valid empty-chain checkpoint.

### Greater record count

If the incoming count is greater than the accepted count,
the tracker verifies that the new chain contains the
previously accepted head at its original position.

For a previously accepted checkpoint at record 100, a
new 120-record checkpoint must preserve the exact digest
at record 100.

If the old history matches, the state advances to 120.

If the history differs, the operation fails.

This prevents accepting a longer, divergent chain merely
because its record count is larger.

### Smaller record count

A valid signed checkpoint with a smaller record count
is rejected.

The tracker raises CheckpointFreshnessError.

The previous state remains unchanged.

### Equal record count

When the count is unchanged, the signature and complete
chain are verified again.

If the digest agrees with the accepted state, the
submission is treated as idempotent:

```text
advanced = False
```

A different digest is rejected.

The tracker does not implement one-time-use nonces or
reject repeated presentations of an identical checkpoint.

Therefore this is monotonic state management, not a
general-purpose replay prevention protocol.

## Historical continuity

The previous accepted Head Digest is compared with the
digest at the same position in the newly supplied chain.

For a previous count of zero, the Genesis Digest is used.

The comparison uses hmac.compare_digest().

This check is separate from signature validation.

A cryptographically valid signature can still correspond
to a divergent chain.

Such a chain is rejected when it conflicts with the
tracker's already accepted history.

This assumes the accepted state itself has remained
trustworthy inside the process.

## Chain verification

The existing signed-checkpoint verifier performs:

1. Envelope type checks
2. Key ID comparison
3. Ed25519 signature verification
4. Journal ID comparison
5. Complete audit-chain integrity verification
6. Exact checkpoint position and Head Digest comparison

The tracker then performs monotonic and historical
continuity checks.

Only after these checks succeed does it update the
accepted state.

A rejected update must not change the previous state.
The immutable acceptance result is also constructed before
the tracker replaces its state, so result-construction failure
does not leave a partially committed update.

## Concurrency

The tracker uses threading.RLock.

Signature verification, chain verification, comparison
with the previous trust state and state update all happen
within the same critical section.

This provides a single serialized acceptance order for
threads sharing the same tracker instance.

If two threads submit checkpoints at record counts
100 and 120, the resulting state cannot finish at 100
after 120 has already been accepted.

The 100-record submission may succeed if it is processed
before the 120-record submission.

It must fail if processed after acceptance of 120.

A duplicate valid checkpoint is accepted idempotently
without advancing the state.

Separate tracker instances do not coordinate.

The implementation provides no cross-process locking.

## Error behavior

CheckpointFreshnessError indicates a violation of
previously accepted trust state.

Examples:

- Smaller record count
- Divergent history at the previously accepted position
- Same record count with a different digest

Invalid Ed25519 signatures are rejected by the existing
SignedCheckpointError.

Malformed audit chains are rejected by the existing
audit integrity verification logic.

Checkpoint mismatch and incorrect Journal ID are rejected
by the existing checkpoint validation API.

A failed verification leaves the tracker state unchanged.

## Security boundary

The tracker does not prove:

- Checkpoint creation time
- Checkpoint publication time
- The newest globally issued checkpoint
- Real-world signer identity or authorization
- Trusted public-key distribution
- Private-key security
- Key revocation or rotation
- Evidence authenticity
- Complete recording of actual acquisition events
- Host or process identity
- Durable audit history
- Persistent anti-rollback guarantees

It also does not protect against trusted Python code
directly modifying private attributes.

## Restart and replay limitations

The tracker stores trust state only in process memory.

When the process terminates, the state is lost.

A newly created tracker accepts its first valid signed
checkpoint as its baseline, even if that checkpoint is
historically older than a checkpoint accepted by a prior
process.

This means process restarts can reset the rollback floor.

An attacker who can replace both the tracker state and
the trusted configuration can also defeat the intended
continuity checks.

Persistent anti-rollback requires an independent durable
trust boundary.

That is not implemented here.

## Trust configuration limitations

A tracker is configured with one trusted public key.

The module does not provide:

- Public-key registries
- Certificate chains
- Key rotation
- Key revocation
- Multiple accepted signing keys
- Recovery from signing-key compromise
- Secure transfer of state between tracker instances

Changing keys should be designed with explicit trust
migration rules rather than silently replacing a key
inside an existing tracker.

## Resource limitations

The existing Audit Journal and Checkpoint models limit
the maximum chain size to 10,000 records.

Verification is performed on the complete supplied chain.

The tracker's RLock is held during verification.

Consequently, large chains can block concurrent
acceptance operations until verification finishes.

This design prioritizes a simple atomic in-process
trust transition over parallel signature verification.

It is not optimized for high-throughput audit services.

## Compatibility

No changes are required to:

- AcquisitionAuditJournal
- AuditCheckpoint
- SignedAuditCheckpoint
- AcquisitionResourceGovernor
- AcquisitionSupervisor
- AcquisitionRun
- VerificationSession
- SQLi Analyzer
- HTTP Runner
- CLI
- Schema
- CI
- Vulnerability Verdict

The module does not perform Evidence acquisition.

It does not change Governor accounting or audit-event
emission.

It does not promote research CANDIDATE results to
Verdict.VULNERABLE.

## Validation

```bash
uv run pytest tests/test_sqli_time_evidence_freshness.py -v
uv run pytest tests/test_sqli_time_evidence_signature.py -v
uv run pytest tests/test_sqli_time_evidence_checkpoint.py -v
uv run pytest tests/test_sqli_time_evidence_audit.py -v

uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

## Future work

Potential next stages include:

- Durable trusted state
- Trusted monotonic counters
- Independent state anchoring
- Authenticated recovery snapshots
- Key rotation and revocation
- Anti-rollback across process restarts
- Distributed checkpoint coordination
- Signed checkpoint issuance policies
- Trusted timestamp and freshness validation
- Tamper-evident state archival

The current mechanism is a bounded, thread-safe,
in-memory monotonic trust tracker.
