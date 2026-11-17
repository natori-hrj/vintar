
# Acquisition Run Lifecycle Management

## Purpose

This module manages the lifecycle of process-isolated evidence
acquisition runs.

It prevents stale handles from continuing a run through the
same trusted AcquisitionSupervisor instance.

It does not turn Python objects into security capabilities
against malicious code executing in the same interpreter.

## Architecture

```text
AcquisitionSupervisor
    |
    +-- Authoritative AcquisitionRun
    |
    +-- Run ID
    |
    +-- Current generation handle
    |
    +-- Lifecycle status
    |
    +-- Serialized acquisition operations
            |
            v
    acquire_evidence_isolated()
            |
            v
    ProcessAcquisitionResult
```

The supervisor owns the current AcquisitionRun.

Callers provide the current AcquisitionHandle rather than
submitting their own AcquisitionRun for each operation.

The supervisor controls which run is passed to the
process-isolated acquisition function.

## Lifecycle states

Three lifecycle states are defined.

### ACTIVE

The supervisor accepts the currently issued handle.

A completed acquisition produces a new AcquisitionRun
and a new generation-specific handle.

The previous handle becomes stale.

### TERMINATED

The caller has explicitly ended the run.

The supervisor discards its active run reference and handle.

Further acquisition operations are rejected.

This state does not indicate a worker failure.

### INVALIDATED

The run can no longer be continued through the supervisor.

Invalidation occurs following:

- Process timeout
- Worker failure
- Unreaped worker
- Unexpected acquisition exception
- Inconsistent acquisition result
- Explicit invalidation

The supervisor discards its active run reference and handle.

A new supervisor must be created for a new independent run.

## Run identifiers

Each supervisor generates one UUID4-based identifier.

The identifier is represented as 32 lowercase hexadecimal
characters without separators.

This is a correlation identifier, not proof of ownership.

Knowledge of a Run ID does not authorize acquisition.

## Generation handles

The first handle starts at generation zero.

A completed acquisition increments the generation.

A handle is accepted only if it is the exact Python object
currently held by the supervisor.

A new object with identical fields is rejected.

dataclasses.replace() does not recreate a valid handle.

Handles are intentionally compared by object identity.

This protects against accidental replay of older handles
through the same supervisor instance.

## Acquisition sequence

1. The caller obtains the initial handle.
2. The caller requests acquisition through the supervisor.
3. The supervisor checks the current lifecycle state.
4. The supervisor checks handle identity.
5. The supervisor acquires its lock.
6. The supervisor passes its authoritative AcquisitionRun
   to the process-isolated acquisition adapter.
7. On completion, the supervisor validates the returned
   run's binding, policy, clock origin, attempt prefix,
   and attempted Evidence ID.
8. The supervisor stores the updated run.
9. The supervisor issues the next generation handle.

Only the latest handle can be used for the next acquisition.

## Thread safety

Each supervisor uses an RLock.

All lifecycle-mutating operations on one supervisor are serialized.

Two threads submitting the same handle cannot both complete
an acquisition successfully.

Once the first acquisition completes, the second thread's
handle is stale.

The lock is held while waiting for the process acquisition.

Consequently, another thread cannot terminate or invalidate
that supervisor until the ongoing operation releases the lock.

If acquisition obtains the lock first and rotates the handle, a concurrent
terminate or invalidate call using the old handle is rejected as stale after
it acquires the lock. If the terminal operation obtains the lock first, the
later acquisition is rejected because the supervisor is no longer ACTIVE.

This is intentional serialization, not asynchronous cancellation.

## Failure behavior

If the process-isolated adapter reports:

- TIMED_OUT
- WORKER_FAILED
- UNREAPED

the supervisor transitions to INVALIDATED.

The result does not contain a resumable AcquisitionRun
or a continuation handle.

If the adapter raises unexpectedly during acquisition,
the supervisor invalidates the run before propagating
the exception.

The same fail-closed rule applies after the adapter returns: an invalid
result type, malformed completed result, inconsistent run, or exception
while validating or constructing the next handle invalidates the
supervisor before the error is propagated. A malformed return must never
leave the previous run ACTIVE.

This conservatively handles operations whose worker
activity or byte consumption may be unknown.

## Immutable snapshots

The snapshot() operation exposes the current immutable
AcquisitionRun to a caller with a valid handle.

The caller may inspect that snapshot.

However, the caller cannot submit an arbitrary snapshot
back into the supervisor.

The supervisor exclusively controls which run is used
for subsequent managed acquisitions.

The caller may still use the legacy acquisition functions
outside the supervisor. Such calls are not governed by
this lifecycle contract.

## Security boundary

The supervisor prevents stale handles only when:

- The same supervisor instance remains authoritative
- Callers route operations through its public methods
- Python code accessing its internals is trusted
- The supervisor is not replaced with a new independent one

It does not provide:

- Cross-process locking
- Persistent revocation
- An external capability service
- Authorization against malicious in-process code
- Globally unique enforced run ownership
- Cryptographically authenticated handles
- Protection from direct calls to the underlying APIs
- Resource limits shared by independent supervisors

A malicious caller with arbitrary Python execution could
access private attributes or invoke lower-level acquisition
functions directly.

These limitations are fundamental to this in-process design.

## Process termination

The supervisor delegates worker lifecycle handling to
the process-isolated evidence adapter.

It does not introduce new termination signals.

The process adapter remains responsible for:

- Spawn
- Deadline monitoring
- Terminate
- Kill escalation
- Reaping
- IPC validation
- Acquisition byte accounting

The supervisor cannot guarantee that an unreaped worker
has stopped running.

An UNREAPED result invalidates the run but does not
establish that the underlying process has terminated.

## Evidence integrity

Successful acquisitions retain the existing SHA-256 and
size comparison contract.

A MATCHED result indicates metadata consistency.

It does not prove:

- Evidence authenticity
- Trusted publisher identity
- Trusted timestamps
- Independent evidence acquisition
- Correct Ground Truth

The supervisor does not change EvidenceBinding or
VerificationSession semantics.

## Compatibility

No changes are made to:

- Existing AcquisitionRun
- Existing AcquisitionPolicy
- Existing process acquisition API
- Local Evidence Loader
- Streaming Evidence Loader
- POSIX acquisition primitive
- SQLi Analyzer
- HTTP Runner
- Ground Truth
- CLI
- Schema
- CI
- Production Verdict

The supervisor is an optional higher-level API.

## Tests

Run lifecycle tests:

```bash
uv run pytest tests/test_sqli_time_evidence_lifecycle.py -v
```

Run process and streaming acquisition regressions:

```bash
uv run pytest tests/test_sqli_time_evidence_process.py -v
uv run pytest tests/test_sqli_time_evidence_stream.py -v
```

Run the complete test suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

## Future work

Potential extensions include:

- A persistent run registry
- Cross-process run ownership
- Revocation tokens
- Controlled worker credentials
- Supervisor-managed process groups
- Administrative cancellation during blocking acquisition
- Global resource budgets
- Trusted verification logs
- Signed evidence manifests

The current implementation provides in-process lifecycle
coordination for controlled research workflows.
