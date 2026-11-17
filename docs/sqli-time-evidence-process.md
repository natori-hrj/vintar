
# Process-isolated Evidence Acquisition

## Purpose

This module runs Vintar's local streaming evidence acquisition in a
separate Python process.

The parent process monitors elapsed time and attempts to terminate
a child that exceeds the configured deadline.

This is a research-only process isolation adapter, not a complete
operating-system sandbox.

## Architecture

```text
Parent process
    |
    | Evidence ID, root, relative path, byte limit, deadline
    v
Spawned acquisition worker
    |
    | Confined POSIX file access
    | Streaming SHA-256
    |
    | Digest metadata or failure metadata
    v
Parent validation
    |
    | Reconstruct immutable AcquisitionRun
    v
VerificationSession
```

The child does not receive the complete EvidenceBinding,
ProvenanceManifest, or VerificationSession.

It receives only acquisition parameters.

The worker never sends raw evidence bytes through IPC.

## Spawn isolation

The implementation requests the multiprocessing "spawn" context.

The spawned worker starts a new Python interpreter rather than
using fork-based inheritance of the parent's memory.

This reduces inherited process-state coupling.

It does not imply:

- A separate security identity
- A container
- A filesystem sandbox
- Restricted permissions
- A seccomp profile
- An independent trust domain

The worker executes with the operating-system permissions
available to the parent.

## Worker protocol

A successful worker reports:

- A success marker
- Observed SHA-256
- Observed byte count

A normally failed acquisition reports:

- A failure marker
- Acquisition failure or budget-exceeded outcome
- Bytes consumed before the failure

The parent validates the received message before accepting it.

The protocol carries no raw file contents.

The IPC channel is intended for the child created by this module.
It is not cryptographically authenticated against a compromised
child process.

## Process results

ProcessAcquisitionResult reports one of four states.

### COMPLETED

The worker finished normally and provided an acceptable result.

The result contains a new immutable AcquisitionRun.

It may contain an acquisition attempt whose outcome is:

- MATCHED
- MISMATCHED
- ACQUISITION_FAILED
- BUDGET_EXCEEDED

A completed process acquisition does not necessarily mean the
evidence content matched.

### TIMED_OUT

The deadline expired.

The parent attempted to terminate and reap the worker.

No resumable AcquisitionRun is returned.

### WORKER_FAILED

The worker crashed, failed to start, exited abnormally, or
provided an invalid or missing result.

No resumable AcquisitionRun is returned.

### UNREAPED

The parent could not confirm that the worker had terminated
and been reaped.

No resumable AcquisitionRun is returned.

This result requires operational attention before another
acquisition is attempted.

## Unknown byte consumption

A process may be terminated while reading a file.

After forced termination, the parent cannot reliably establish
the exact number of bytes already consumed.

Therefore timeout and worker-failure results do not fabricate
a zero-byte acquisition attempt.

The result deliberately contains no resumable AcquisitionRun.

The caller must not reuse the original Run to continue an
acquisition sequence after a terminal outcome.

This is an API contract, not an operating-system-enforced
prohibition on reusing a previously retained Python object.

A stronger capability-based or persisted state manager would
be required to enforce that rule across untrusted callers.

## Deadline semantics

The effective deadline is the earlier of:

- The per-acquisition timeout
- The existing AcquisitionRun elapsed-time deadline

The parent waits for completion up to the remaining deadline.

The parent checks the effective deadline again immediately before
`Process.start()`. If process-object preparation has already exhausted
the deadline, the child is not started and the result is `TIMED_OUT`.

If the worker is still running, the parent attempts:

1. Process termination
2. A bounded grace period
3. Process kill
4. A second bounded grace period

These termination steps can add time beyond the requested
acquisition deadline.

Process creation itself is also not guaranteed to be
completed within the configured timeout.

Failure from `Process.start()`, including the restriction that a
daemonic parent cannot create children, is reported as `WORKER_FAILED`.
Both Pipe endpoints and the unstarted process handle are then closed.

A task stuck in an uninterruptible kernel I/O state might
not terminate promptly even after a kill request.

Therefore this is a parent-enforced termination mechanism,
not a universal strict wall-clock execution guarantee.

## Existing budget semantics

The existing AcquisitionPolicy remains unchanged.

The child uses the available byte budget for one file.

Successful acquisitions produce verified observations only
after the parent receives and validates the worker result.

Acquisition failure and budget exhaustion without a process
timeout retain their ordinary accounting semantics.

The caller must not conflate:

- A completed acquisition
- A matched artifact
- A reaped worker
- Evidence authenticity

These are separate properties.

## Filesystem safety

The worker reuses the existing streaming acquisition code.

Its file-opening contract includes:

- Validated absolute root
- Validated relative path
- Directory-relative traversal
- O_NOFOLLOW
- O_NONBLOCK
- Regular-file validation
- Hard-link rejection
- 16 MiB per-file limit
- Streaming SHA-256
- Before/after metadata comparisons

The shared POSIX primitive remains responsible for these checks.

## Failure isolation

A malformed worker reply is rejected.

A worker that fails to report a result does not create
an EvidenceObservation.

The parent does not add an observation based solely on
a successful operating-system exit code.

The operating-system exit status and worker protocol must
both indicate successful completion.

## Remaining risks

The adapter does not protect against:

- Privileged attackers
- Hostile filesystems
- Compromised kernels
- Compromised child-process code
- Maliciously modified trusted modules
- Inherited credentials or filesystem permissions
- Exhaustion by concurrent independent acquisition runs
- A worker that cannot be reaped
- Process creation delays
- Platform-specific multiprocessing behavior

The module does not implement a global process supervisor.

## Authenticity boundary

MATCHED means that the observed SHA-256 and file size agree
with the expected EvidenceRecord.

It does not establish:

- Evidence authenticity
- Trusted publisher identity
- Trusted acquisition identity
- Trusted timestamps
- Ground Truth correctness
- Independent verification execution

No production vulnerability Verdict is changed.

## Tests

Run the isolated acquisition tests:

```bash
uv run pytest tests/test_sqli_time_evidence_process.py -v
```

Run existing evidence acquisition tests:

```bash
uv run pytest tests/test_sqli_time_evidence_posix.py -v
uv run pytest tests/test_sqli_time_evidence_loader.py -v
uv run pytest tests/test_sqli_time_evidence_stream.py -v
```

Run the full regression suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

Actual subprocess tests require an environment that supports
Python multiprocessing with the "spawn" start method.

No Docker or external HTTP service is required.

## Release boundary

This module does not modify:

- SQLi Analyzer
- SQLi HTTP Runner
- Boolean/Time-based confirmation
- Cross-Phase Guard
- EvidenceBinding
- VerificationSession
- Existing AcquisitionRun
- Application and Cluster evaluation
- Ground Truth
- CLI
- Schema
- CI
- Production Verdict

The adapter must never promote CANDIDATE to Verdict.VULNERABLE.

## Future work

Possible next stages include:

- Stronger worker lifecycle supervision
- Linux-specific sandboxing and resource limits
- Controlled worker credentials
- Trusted acquisition logs
- Persistent run identities
- Globally coordinated budgets
- Signed evidence manifests

A dedicated process is an operational isolation measure,
not proof of evidence authenticity.
