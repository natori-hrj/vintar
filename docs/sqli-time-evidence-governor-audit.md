
# Governed Evidence Acquisition Audit Integration

## Purpose

This module integrates the in-memory Evidence Acquisition Audit
Journal with the shared Acquisition Resource Governor.

Audited mode records selected governor operations automatically.

The journal uses deterministic JSON encoding and a SHA-256
hash chain.

The integration is intended for trusted in-process research
workflows.

It does not provide durable or authenticated audit logging.

## Compatibility

The governor constructor accepts an optional flag:

```python
governor = AcquisitionResourceGovernor(
    policy=policy,
    audited=True,
)
```

The factory accepts the same option:

```python
governor = create_resource_governor(
    policy=policy,
    audited=True,
)
```

By default, audited is False.

The existing constructor and factory usages remain valid.

The following APIs are added:

- audit_enabled
- audit_snapshot()
- audit_verify()

The existing accounting, supervision and acquisition APIs
remain available.

## Journal ownership

An audited governor constructs and owns its own
AcquisitionAuditJournal.

The journal is not accepted as an externally supplied object.

This prevents ordinary callers from using the public API
to append unrelated events into the governor's reserved
audit capacity.

The governor exposes immutable snapshots and verification,
not a public journal mutation interface.

Trusted Python code with direct access to private attributes
can still modify the journal.

## Event emission

The following mappings are implemented:

| Governor operation | Audit event |
| --- | --- |
| Successful register | REGISTERED |
| Successful resource reservation | RESERVED |
| Completed acquisition | SETTLED |
| Reaped timeout | SETTLED, INVALIDATED |
| Worker failure | INVALIDATED, HALTED |
| Unreaped worker | INVALIDATED, HALTED |
| Unexpected post-reservation exception | HALTED |
| Explicit terminate | TERMINATED |
| Explicit invalidate | INVALIDATED |

A rejected acquisition request does not emit RESERVED.

A failed reservation append prevents the acquisition
from reaching the worker.

A SETTLED event records the accounting snapshot after
the acquisition has been settled.

A RESERVED event records the projected state that will
become authoritative before the worker starts.

## Resource accounting

The governor continues to apply the existing budgets:

- Cumulative admitted file count
- Worst-case reserved byte count
- Concurrent worker-slot count

The reservation amount is:

```text
min(16 MiB, remaining AcquisitionRun byte budget)
```

After a completed acquisition:

```text
refund = reserved bytes - reported bytes_read
```

The resulting GovernorUsage is included in the SETTLED
audit event.

File attempts remain charged.

Normal acquisition failure and budget exhaustion can both
produce SETTLED events with process status COMPLETED.

## Lock ordering

The governor holds its RLock while:

- Validating admission
- Appending a reservation event
- Updating resource counters
- Updating registry and handle state
- Settling completed operations
- Appending settlement and terminal events

The journal maintains its own RLock.

The normal lock acquisition order is:

```text
Governor RLock -> Journal RLock
```

Journal code does not call back into the governor.

The governor lock is released during the potentially
blocking subprocess operation.

This allows independent supervisors to perform acquisitions
concurrently within the shared worker and byte budgets.

## Audit record capacity

The journal has a maximum of 10,000 records.

Audited mode accounts for journal capacity in admission.

A new supervised acquisition requires capacity for:

- One RESERVED event
- Up to two terminal events

Two record positions are reserved in the governor's
in-memory capacity accounting while the worker is in flight.

Other registrations and acquisitions must leave these
outstanding positions available.

When capacity cannot be reserved, admission is rejected
without consuming acquisition resources.

The governor does not automatically reset the journal.

## Registration behavior

REGISTERED is appended before the new supervisor entry
becomes visible through the governor.

If the append fails, registration does not succeed.

The governor halts further admissions.

An attempted HALTED record is best-effort.

If the audit subsystem itself is failing, the HALTED
record may also be missing.

## Reservation behavior

Before dispatching a worker, the governor:

1. Validates the current handle.
2. Validates Evidence ID and acquisition arguments.
3. Checks shared resource limits.
4. Checks audit record capacity.
5. Constructs projected GovernorUsage.
6. Appends RESERVED.
7. Applies the corresponding resource reservation.
8. Releases the governor lock.
9. Calls the existing supervised acquisition API.

If RESERVED cannot be appended, the worker is not started.

This is an in-process ordering guarantee, not a durable
transaction.

## Settlement behavior

After a completed acquisition, the governor:

1. Validates LifecycleAcquisitionResult.
2. Validates Run and handle continuity.
3. Calculates actual reported consumption.
4. Refunds unused reserved bytes.
5. Releases the worker slot.
6. Rotates the governor handle.
7. Appends SETTLED with the updated usage.
8. Returns the result.

If SETTLED append fails after accounting is updated,
the operation does not return a successful result.

The governor transitions to halted state, revokes
continuation through its own API, and attempts to record
HALTED.

Already completed worker activity cannot be undone.

The settled resource counters are not rolled back.

## Timeout handling

A TIMED_OUT result from the existing process adapter
indicates that worker termination was confirmed.

The governor:

- Retains the full byte reservation
- Charges the attempted file
- Releases the worker slot
- Revokes the continuation handle
- Appends SETTLED
- Appends INVALIDATED

Other supervisors may continue if the governor remains
active and has sufficient resources.

## Uncertain worker handling

WORKER_FAILED and UNREAPED are handled conservatively.

The governor:

- Retains the full byte reservation
- Retains the worker slot
- Increments unknown_slots
- Revokes the continuation handle
- Halts new admissions
- Appends INVALIDATED
- Appends HALTED

These records do not establish that an unreaped worker
actually terminated.

An unexpected exception after reservation also causes
the governor to halt.

If worker state is uncertain, the reservation remains
charged and the slot remains held.

## Audit append failure

A required audit append failure, including a `BaseException`, halts
new admissions. Registration and reservation append failures are
reported as `AcquisitionAuditError` with the original failure chained
as their cause.

The integration cannot guarantee that a HALTED record
will be written when the journal itself is failing.

It therefore prioritizes preserving the authoritative
halted state over producing a complete audit history.

A caller must not interpret a valid remaining journal
as proof that every event was recorded.

No automatic recovery or reset operation is provided.

## Concurrency and ordering

All journal appends initiated by the governor occur
while its RLock is held.

Therefore concurrent operations on the same governor
receive one serialized audit-record order.

Different workers may finish in either order.

The recorded order is the governor's transition order,
not an independent timestamp ordering of physical I/O.

The journal does not record timestamps.

Separate governor instances have separate journals.

## Audit verification

The API:

```python
verification = governor.audit_verify()
```

checks the current journal against its current in-memory
head and record count.

The API:

```python
records = governor.audit_snapshot()
```

returns an immutable snapshot.

A caller may independently verify those records using:

```python
verify_audit_chain(
    records=records,
    expected_head=trusted_head,
    expected_count=trusted_count,
)
```

The expected head and count must be obtained from an
independent trusted source to detect truncation or
whole-chain replacement.

The governor does not export or persist trusted anchors.

## Atomicity limitations

The implementation coordinates operations through Python
locks and synchronous in-memory calls.

It is not a filesystem transaction, database transaction,
or write-ahead log.

It does not protect against:

- Interpreter termination between steps
- Process crash during event emission
- Power loss
- Direct mutation of private Python attributes
- Deliberate modification by trusted-code execution
- Missing events caused by execution outside the governor
- Failure of the audit subsystem itself

The journal can remain internally consistent despite
missing an event.

No claim of globally atomic audit-and-resource commits
is made.

## Security boundary

The integrated journal does not prove:

- The underlying Evidence is authentic
- The Ground Truth is correct
- The Worker ran under a trusted security identity
- All acquisition operations used this governor
- Every actual filesystem read was logged
- Audit records were durably persisted
- The audit chain is protected from total replacement
- Events occurred at a trustworthy wall-clock time

The audit chain supports deterministic internal integrity
verification for records produced by this governor.

It does not provide digital signatures or externally
anchored authenticity.

## Non-audited mode

When audited=False:

- No journal is allocated
- No audit records are emitted
- Existing resource accounting is retained
- Existing lifecycle behavior is retained
- audit_snapshot() and audit_verify() are unavailable

The feature is opt-in for compatibility.

## Validation

Run integration tests:

```bash
uv run pytest tests/test_sqli_time_evidence_governor_audit.py -v
```

Run related regressions:

```bash
uv run pytest tests/test_sqli_time_evidence_audit.py -v
uv run pytest tests/test_sqli_time_evidence_governor.py -v
uv run pytest tests/test_sqli_time_evidence_lifecycle.py -v
uv run pytest tests/test_sqli_time_evidence_process.py -v
```

Run the complete suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

## Future work

Potential next stages include:

- Immutable external audit storage
- Durable reservation and settlement journals
- Signed audit checkpoints
- Trusted head and count anchoring
- Cross-process audit coordination
- Recovery after interrupted transactions
- Verified worker reaping evidence
- Trusted acquisition identity
- Schema migration and archival
- Bounded-memory audit storage

The current integration is an in-process audit
consistency mechanism, not a production audit service.
