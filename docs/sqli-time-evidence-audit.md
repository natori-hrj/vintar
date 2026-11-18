
# Evidence Acquisition Audit Journal

## Purpose

This module provides a deterministic, in-memory audit journal
for declared evidence acquisition events.

It supports:

- Structured audit event models
- Contiguous sequence numbers
- Canonical JSON serialization
- SHA-256 hash chaining
- Immutable event snapshots
- Thread-safe event appending
- Independent chain verification
- Optional externally trusted verification anchors

The journal does not automatically observe acquisition operations.

It accepts events explicitly supplied by trusted callers.

## Architecture

```text
Caller-supplied AuditEvent
          |
          v
AcquisitionAuditJournal.append()
          |
          +-- Validate event model
          +-- Allocate sequence number
          +-- Include previous digest
          +-- Canonical JSON encoding
          +-- Calculate SHA-256 digest
          |
          v
       AuditRecord
          |
          v
    Immutable snapshot
          |
          v
   verify_audit_chain()
```

The module performs no filesystem or network I/O.

It does not modify evidence files or acquisition results.

## Event types

The following event types are supported:

| Event | Declared meaning |
| --- | --- |
| REGISTERED | A supervisor was registered |
| RESERVED | Resources were reserved for an attempt |
| SETTLED | A completed or timed-out attempt was accounted for |
| INVALIDATED | A supervised run was invalidated |
| TERMINATED | A supervised run was explicitly terminated |
| HALTED | Governor admissions were halted |

These names describe caller declarations.

The journal does not independently verify that the declared
operation happened.

## Audit event fields

Each AuditEvent contains:

- event_type
- run_id
- evidence_id
- process_status
- usage

Usage is a GovernorUsage snapshot representing the declared
state after the event.

The usage model validates non-negative accounting values,
unknown worker counts, and halted-state consistency.

The audit schema additionally bounds declared usage to the maximum values
representable by the current Governor policy model. This prevents an
arbitrarily large caller-supplied integer from expanding canonical JSON and
consuming unbounded serialization resources.

### Run identifiers

Most event types require a run identifier.

A run identifier is exactly 32 lowercase hexadecimal
characters.

HALTED may omit the run identifier when the halt is
governor-wide rather than attributable to one run.

### Evidence identifiers

RESERVED and SETTLED require an Evidence ID.

Evidence identifiers follow the existing bounded
ASCII identifier convention.

Other event types do not require an Evidence ID.

REGISTERED and TERMINATED reject an Evidence ID.

### Process status

SETTLED accepts:

- COMPLETED
- TIMED_OUT

INVALIDATED may carry a terminal process status
or omit it for explicit invalidation.

HALTED may carry:

- WORKER_FAILED
- UNREAPED

or omit a process status when the cause is not represented
by those statuses.

A HALTED declaration attributed to WORKER_FAILED or UNREAPED requires at
least one unknown worker slot. HALTED does not accept an Evidence ID.

The event schema intentionally does not encode every
possible causal relationship between Governor operations.

## Canonical serialization

Each digest is calculated from a fixed JSON structure.

The structure contains:

```json
{
  "version": 1,
  "sequence": 1,
  "previous_digest": "<64 lowercase hexadecimal characters>",
  "event": {
    "event_type": "registered",
    "run_id": "<32 lowercase hexadecimal characters>",
    "evidence_id": null,
    "process_status": null,
    "usage": {
      "files_used": 0,
      "bytes_used": 0,
      "slots_in_use": 0,
      "unknown_slots": 0,
      "halted": false
    }
  }
}
```

The actual canonical encoding uses:

- Lexicographically sorted JSON keys
- Compact separators
- ASCII escaping
- No NaN or Infinity
- UTF-8-compatible ASCII bytes
- A fixed schema version

The serializer uses explicit fields rather than Python
repr(), object identity, or dictionary insertion order.

Timestamps are not included.

Two identical ordered event sequences produce identical
hash chains.

The journal does not automatically include execution time,
host identity, process ID, or acquisition-source identity.

## Hash calculation

Each record includes:

- sequence
- previous_digest
- event
- digest

The genesis digest is 64 hexadecimal zero characters.

For every event:

```text
payload = canonical_json(
    version,
    sequence,
    previous_digest,
    event
)

digest = SHA256(
    domain_separator || payload
)
```

The domain separator is:

```text
vintar.evidence.audit.v1 followed by a NUL byte
```

Domain separation distinguishes this digest construction
from ordinary content hashes elsewhere in Vintar.

It does not provide authentication.

## Verification

verify_audit_chain() checks:

1. Records are a bounded tuple.
2. Each record has the expected type.
3. Sequence numbers begin at one and are contiguous.
4. The first record references the genesis digest.
5. Every subsequent record references the previous digest.
6. Every record digest matches its canonical payload.
7. Optional expected record count matches.
8. Optional expected head digest matches.

The function returns AuditVerification containing:

- record_count
- head_digest

An invalid chain raises AuditIntegrityError.

The verifier does not silently repair or reorder records.

## Trusted anchors

A valid internal chain does not prove that it is complete.

For example, a valid three-record chain can be truncated
to its first two records.

The remaining two records form a valid prefix.

Without an external reference, the verifier cannot know
that the third record previously existed.

Callers may supply:

- expected_head
- expected_count

These are meaningful only if acquired from an independent,
trusted source.

An attacker who can rewrite the entire journal and its
expected anchors can construct a new internally valid chain.

The current module does not provide an external anchor store.

## Append-only behavior

The public journal API exposes:

- append()
- snapshot()
- verify()
- record_count
- head_digest

It does not provide event deletion or modification methods.

Snapshots are immutable tuples of frozen AuditRecord objects.

This is an API-level append-only convention.

It is not protection against code with direct access to
the journal's private Python attributes or process memory.

The journal uses a fixed maximum of 10,000 records.

Its immutable tuple representation favors simple snapshot
semantics over high-throughput append performance.

Appending copies the existing tuple and is not intended
for large-volume production audit logging.

## Concurrency

A per-journal RLock serializes event addition.

The sequence number, previous digest, new record and new
head are calculated and stored while the lock is held.

Two concurrent append operations cannot receive the same
sequence number through the public API.

The observed order is the order in which the journal lock
is acquired.

That order does not independently establish the
chronological order of external acquisition operations.

No cross-process locking is provided.

## Integration boundary

This module is intentionally independent from the
existing acquisition execution path.

It does not automatically emit events from:

- AcquisitionResourceGovernor.register()
- AcquisitionResourceGovernor.acquire()
- AcquisitionResourceGovernor.terminate()
- AcquisitionResourceGovernor.invalidate()
- AcquisitionSupervisor
- Process-isolated acquisition workers

Applications may explicitly create AuditEvent instances
based on observed results, but doing so does not establish
a trusted acquisition or complete audit history.

A future integration stage must define failure handling
when an audit append cannot be completed.

The choice between fail-open and fail-closed acquisition
behavior must be explicit before the audit journal becomes
part of the execution path.

## Security limitations

The audit journal does not prove:

- The event actually occurred
- Every relevant event was recorded
- Events were recorded at the correct time
- The recorded GovernorUsage was the true usage
- The event was produced by an authorized caller
- The originating process or host identity
- Evidence authenticity
- Ground Truth correctness
- Independent verification
- Protection against whole-chain regeneration
- Protection against chain deletion without a trusted anchor
- Persistence across process restarts

SHA-256 protects internal consistency against accidental
changes and detects tampering when an authentic chain
reference is available.

It is not an authentication mechanism.

## Compatibility

This module does not change:

- AcquisitionResourceGovernor
- AcquisitionSupervisor
- AcquisitionRun
- AcquisitionPolicy
- Process-isolated acquisition
- Streaming Evidence Loader
- POSIX acquisition primitive
- EvidenceBinding
- VerificationSession
- SQLi Analyzer
- HTTP Runner
- Ground Truth
- CLI
- Schema
- CI
- Production Verdict

It does not promote a research CANDIDATE to
Verdict.VULNERABLE.

## Validation

Run the journal-specific tests:

```bash
uv run pytest tests/test_sqli_time_evidence_audit.py -v
```

Run the acquisition regressions:

```bash
uv run pytest tests/test_sqli_time_evidence_governor.py -v
uv run pytest tests/test_sqli_time_evidence_lifecycle.py -v
uv run pytest tests/test_sqli_time_evidence_process.py -v
```

Run the complete regression suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

## Future work

Potential follow-up stages include:

- Explicit Governor-to-journal event emission
- Audited reservation and settlement transactions
- Failure policy for audit append errors
- Stable event schema migration
- External immutable audit storage
- Independently anchored chain heads
- Signed checkpoints
- Cross-process audit coordination
- Operational timestamps and trusted clock sources
- Auditor identity and authorization

The current implementation establishes a bounded
deterministic audit data model.

It does not yet establish an authenticated acquisition log.
