
# Evidence Audit Checkpoints

## Purpose

This module provides portable checkpoints for the existing
hash-chained evidence acquisition audit journal.

A checkpoint identifies one declared position in an audit
chain by:

- Schema version
- Logical journal identifier
- Record count
- Head digest at that record count

The module supports creating, serializing, decoding and
verifying checkpoints without filesystem or network I/O.

It does not sign, persist or externally anchor checkpoints.

## Architecture

```text
AcquisitionAuditJournal
          |
          v
    Immutable snapshot
          |
          v
  verify_audit_chain()
          |
          v
    AuditCheckpoint
          |
          +-- version
          +-- journal_id
          +-- record_count
          +-- head_digest
          |
          v
    Portable JSON
          |
          v
Independent trusted storage
    (not implemented)
```

Independent verification compares a supplied full audit
chain with a checkpoint.

The caller must establish whether the checkpoint can be
trusted.

## Checkpoint schema

AuditCheckpoint contains four fields.

### version

The schema version is exactly integer 1.

Boolean values, strings, unsupported versions and
floating-point values are rejected.

The version describes the checkpoint schema, not a
version of the evidence itself.

### journal_id

A 32-character lowercase hexadecimal identifier.

The create_journal_id() helper generates a random UUID4
identifier encoded as lowercase hexadecimal.

The ID is a correlation value, not authentication.

The existing AcquisitionAuditJournal does not have a
persistent journal identifier.

Callers are responsible for assigning and consistently
using a logical identifier.

A different journal may claim the same identifier.

### record_count

The number of records represented by the checkpoint.

The value is a strict non-negative integer bounded by
MAX_AUDIT_RECORDS.

The existing journal limit is 10,000 records.

### head_digest

A lowercase hexadecimal SHA-256 digest with 64 characters.

For record_count = 0, the digest must equal GENESIS_DIGEST.

For nonempty chains, it represents the digest of the
record at the checkpoint position.

## Creating a checkpoint

Given an immutable record tuple:

```python
checkpoint = create_audit_checkpoint(
    records=records,
    journal_id=journal_id,
)
```

The function verifies the entire supplied audit chain
before constructing the checkpoint.

An invalid chain is rejected.

Given an AcquisitionAuditJournal:

```python
checkpoint = checkpoint_from_journal(
    journal=journal,
    journal_id=journal_id,
)
```

The helper obtains one immutable snapshot and verifies it.

It does not rely on separately reading the journal's
record count and head digest, which could represent
different moments during concurrent updates.

Checkpoint creation does not make the source journal
trustworthy.

## JSON representation

Checkpoints use deterministic JSON encoding.

For an empty journal, the representation has this shape:

```json
{
  "head_digest": "0000000000000000000000000000000000000000000000000000000000000000",
  "journal_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "record_count": 0,
  "version": 1
}
```

The actual serialized form uses compact separators and
lexicographically sorted keys.

Use:

```python
payload = checkpoint.to_json()
```

To decode:

```python
checkpoint = checkpoint_from_json(
    payload=payload,
)
```

The decoder rejects:

- Non-string inputs
- Empty inputs
- Inputs exceeding 512 ASCII bytes
- Non-ASCII input
- Invalid JSON
- Duplicate JSON keys
- Missing fields
- Unexpected fields
- Unsupported versions
- Invalid identifiers
- Invalid digest strings
- Invalid record counts
- Boolean values in integer fields
- Non-genesis digests for empty checkpoints

JSON transport is supported only as in-memory strings.

The module does not write or read checkpoint files.

## Exact verification

Exact verification requires the supplied chain to match
the checkpoint at its final position.

```python
result = verify_audit_checkpoint(
    records=records,
    checkpoint=checkpoint,
    expected_journal_id=trusted_journal_id,
)
```

The verifier:

1. Validates checkpoint and argument types.
2. Checks the optional expected journal identifier.
3. Verifies the complete supplied audit chain.
4. Rejects chains shorter than the checkpoint.
5. Rejects chains longer than the checkpoint.
6. Compares the checkpoint's head digest.
7. Returns a CheckpointVerification result.

Exact verification is appropriate for checking a
historical export against its expected checkpoint.

## Prefix verification

A historical checkpoint can remain valid after additional
records are appended.

Set allow_extensions=True:

```python
result = verify_audit_checkpoint(
    records=current_records,
    checkpoint=trusted_checkpoint,
    expected_journal_id=trusted_journal_id,
    allow_extensions=True,
)
```

The verifier:

1. Verifies the complete supplied chain.
2. Requires at least checkpoint.record_count records.
3. Compares the digest at the checkpoint position.
4. Permits later records only if the whole chain remains valid.

A checkpoint at 100 records can therefore verify a
120-record chain if the first 100 records are unchanged.

The result includes:

- checkpoint
- chain_record_count
- chain_head_digest
- additional_records

It does not imply that all expected real-world operations
were recorded.

`CheckpointVerification` also enforces that a result with
zero additional records has the same chain head as its checkpoint.
This invariant applies to direct construction and
`dataclasses.replace()` as well as verifier-created results.

## Rollback detection

Consider a trusted checkpoint with:

```text
record_count = 100
head_digest  = H100
```

If a supplied chain has 90 records, verification fails.

If it has 100 records but the last digest differs from
H100, verification fails.

If it has 120 records and allow_extensions=True, the
verifier checks that record 100 has digest H100 and
validates the remaining 20 records.

These checks detect divergence relative to the supplied
checkpoint.

They do not prove that the checkpoint represents the
latest known state.

A checkpoint from 80 records cannot by itself prove
that a journal previously contained 100 records.

For meaningful rollback detection, the caller needs a
fresh, independently trusted checkpoint.

## Journal identity limitations

Journal IDs are caller-assigned correlation identifiers.

They are not embedded into the existing audit-record
hash calculation.

As a result:

- Identical record sequences have identical chain digests.
- The same records can be declared under another journal ID.
- A forged checkpoint can claim an arbitrary journal ID.
- A journal ID alone does not prove chain provenance.

expected_journal_id is useful only when the expected
identifier was independently established.

The module does not prevent journal identity spoofing.

## Threat model

This checkpoint mechanism can detect:

- Truncation below a trusted checkpoint count
- Historical prefix replacement
- Different content at the checkpoint position
- Corruption of supplied extension records
- Invalid or malformed chains
- Checkpoint schema inconsistencies

It cannot prevent or independently detect:

- Replacement of both journal and checkpoint
- Modification of a checkpoint in untrusted storage
- Missing acquisition events never recorded
- False caller-supplied audit events
- Direct access to private Python attributes
- Journal deletion
- Process crashes
- Loss of in-memory data
- Journal identity spoofing
- Unauthenticated checkpoint creation
- Rollback beyond the newest trusted checkpoint

The current checkpoint format contains no signature,
message authentication code, or trusted timestamp.

## External anchoring boundary

An external anchor is a checkpoint stored or attested
outside the system that produces the journal, under an
independent trust boundary.

This release defines the portable checkpoint model and
verification API only.

No external storage backend is implemented.

No signing keys are generated or managed.

A checkpoint stored alongside a modifiable journal
does not provide meaningful independent rollback
protection when an attacker can replace both.

Future anchoring must address storage permissions,
freshness, identity, integrity, retention and recovery.

## Integration with Resource Governor

The audited Resource Governor currently exposes:

```python
records = governor.audit_snapshot()
verification = governor.audit_verify()
```

An application can create a checkpoint from the snapshot:

```python
checkpoint = create_audit_checkpoint(
    records=governor.audit_snapshot(),
    journal_id=journal_id,
)
```

The checkpoint module does not change Governor behavior.

It does not register journal IDs inside the Governor.

It does not automatically publish or persist checkpoints.

It does not modify acquisition budgets or Worker state.

## Concurrency

The journal snapshot is an immutable tuple.

Checkpoint creation works from one supplied snapshot.

If the journal receives additional events afterward, the
checkpoint remains a valid anchor for the earlier prefix.

Prefix verification can check that earlier position in
the newer complete chain.

The implementation does not synchronize with an external
storage system or across processes.

## Resource limits

The checkpoint model accepts record counts between zero
and MAX_AUDIT_RECORDS.

Serialized checkpoint input is limited to 512 ASCII bytes.

Verification uses the existing bounded
verify_audit_chain() implementation.

Prefix verification validates the entire supplied chain,
including records after the checkpoint position.

These limits do not prevent resource exhaustion by
arbitrary trusted Python code outside the API boundary.

## Compatibility

No changes are made to:

- AcquisitionAuditJournal
- AcquisitionResourceGovernor
- GovernorPolicy
- AcquisitionSupervisor
- AcquisitionRun
- VerificationSession
- Process-isolated acquisition
- Streaming Evidence Loader
- POSIX acquisition primitive
- SQLi Analyzer
- HTTP Runner
- Ground Truth
- CLI
- Schema
- CI
- Vulnerability Verdict

The checkpoint mechanism does not promote CANDIDATE to
Verdict.VULNERABLE.

## Validation

```bash
uv run pytest tests/test_sqli_time_evidence_checkpoint.py -v
uv run pytest tests/test_sqli_time_evidence_audit.py -v
uv run pytest tests/test_sqli_time_evidence_governor_audit.py -v
uv run pytest tests/test_sqli_time_evidence_governor.py -v

uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

## Future work

Potential extensions include:

- Trusted external checkpoint storage
- Signed checkpoint envelopes
- Key rotation and issuer identity
- Monotonic checkpoint sequence tracking
- Secure publication of checkpoint heads
- Durable audit records
- Crash recovery
- Journal identity binding in record hashing
- Cross-process journal coordination
- Trusted timestamps and freshness policies

The current module provides independently verifiable
checkpoint data, not an authenticated anchoring service.
