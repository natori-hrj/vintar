
# Shared Evidence Acquisition Resource Governance

## Purpose

This module coordinates resource consumption across multiple
AcquisitionSupervisor instances in one Python process.

It provides shared admission limits for:

- Attempted evidence files
- Reserved and consumed evidence bytes
- Concurrent supervised acquisition operations

The governor does not replace the per-run AcquisitionPolicy.

Both limits apply independently.

## Architecture

```text
AcquisitionResourceGovernor
    |
    +-- Shared file budget
    +-- Shared byte budget
    +-- Shared worker-slot budget
    +-- Supervisor registry
    +-- Admission and settlement lock
    |
    +-- AcquisitionSupervisor A
    +-- AcquisitionSupervisor B
    +-- AcquisitionSupervisor C
            |
            v
       Process-isolated
       Evidence Acquisition
```

All registered supervisors are created and owned by the governor.

Callers receive GovernorHandle objects rather than direct access
to the underlying supervisor.

The governor controls admission to supervised acquisitions
performed through its own public methods.

## Policy

GovernorPolicy defines three shared limits.

### max_files

Maximum cumulative admitted acquisition attempts.

The count includes completed, failed, and timed-out attempts.

Rejected requests do not consume a file slot.

The count is not reduced after completion.

### max_total_bytes

Maximum cumulative bytes charged to the governor.

The governor reserves the maximum amount that the underlying
AcquisitionRun could read in one attempt.

A normal completed acquisition refunds the unused reservation.

An acquisition with unknown byte consumption retains its full
reservation permanently for this governor instance.

### max_workers

Maximum number of concurrently reserved worker slots.

A slot is reserved before invoking the process acquisition API.

A slot is released only when a completed acquisition or a
reaped timeout has been reported.

Unknown worker state causes conservative retention.

## Worst-case byte reservation

The existing process acquisition API does not accept a separate
governor-wide byte limit for an individual operation.

The maximum possible byte consumption of one attempt is:

```text
min(16 MiB, remaining bytes in the AcquisitionRun)
```

The governor reserves this entire amount before dispatch.

This can reject a request even when the actual file is small.

For example, if the global remaining budget is 5 MiB but the
underlying Run can still read 16 MiB, the governor rejects
the request.

It does not pre-read file contents or bypass existing
file safety checks to obtain a smaller reservation.

This is intentional conservative admission control.

## Atomic admission

All admission decisions occur under the governor RLock.

One admitted request atomically increments:

- files_used by one
- bytes_used by the reserved maximum
- slots_in_use by one

The governor also marks the selected supervisor busy.

Once admission succeeds, the governor releases the lock and
executes the potentially blocking acquisition.

Another supervisor can be admitted concurrently if sufficient
global resources remain.

The same supervisor cannot acquire twice simultaneously.

## Completed acquisition settlement

The governor accepts a successful result only after validating:

- Exact LifecycleAcquisitionResult type
- Completed process status
- EvidenceBinding object identity
- AcquisitionPolicy object identity
- Run clock origin
- Attempt prefix
- Exactly one new Attempt
- Requested Evidence ID
- Generation progression
- Current Supervisor snapshot identity
- Consumed bytes not exceeding the reservation

The AcquisitionRun model provides its additional integrity
checks for Session Observation and Attempt accounting.

After validation:

```text
actual_consumed = new_attempt.bytes_read

refund = reserved_bytes - actual_consumed
```

The governor subtracts the refund from shared usage.

It releases the worker slot.

The file attempt remains charged.

The caller receives a new governor handle.

## Completed acquisition failure

A normal ACQUISITION_FAILED or BUDGET_EXCEEDED attempt can
still have a completed process lifecycle.

When the process returns an accepted new AcquisitionRun,
the governor charges its reported bytes_read and releases
the worker slot.

The corresponding Evidence ID remains attempted, even if
its VerificationSession status is UNCHECKED.

The caller may continue with another Evidence ID while the
supervisor and governor are active.

## Timeout accounting

For a TIMED_OUT process result, the process isolation adapter
reports that the worker was successfully reaped.

However, the exact number of bytes it read may be unknown.

The governor:

- Charges one attempted file
- Retains the entire reserved byte amount
- Releases the worker slot
- Revokes the supervisor's continuation handle

Other supervisors may continue if resources remain.

No bytes are refunded merely because the worker was reaped.

## Worker failures and unreaped workers

WORKER_FAILED does not universally establish that every
possible worker lifecycle was reaped successfully.

UNREAPED explicitly reports an unconfirmed worker exit.

In either case, the governor:

- Retains the full byte reservation
- Retains the worker slot
- Records one unknown slot
- Revokes the failed supervisor's continuation handle
- Halts all further admissions

An unexpected exception or malformed supervised result
also halts admissions and retains the reservation.

The governor provides no automatic reset operation.

## Governor halt

When halted, the governor rejects:

- New supervisor registration
- New acquisition admission
- Snapshot acquisition through its public interface
- Additional explicit lifecycle changes

This is a conservative operational state.

The governor's usage snapshot remains readable.

An operator must investigate the uncertain worker state
before creating a fresh independent governor.

Creating a new governor is technically possible, but
it does not prove any previous worker has terminated.

## Concurrency

The governor releases its lock during a potentially blocking
supervised acquisition.

Consequently, different supervisors can perform acquisitions
concurrently up to max_workers.

The supervisor itself continues to serialize operations
within one AcquisitionSupervisor instance.

A second request against a busy supervisor is rejected.

Terminate and invalidate cannot interrupt that supervisor's
in-flight acquisition through the governor.

This version does not provide asynchronous cancellation.

## File and byte accounting

The governor usage counters mean:

| Counter | Meaning |
| --- | --- |
| files_used | Cumulative admitted attempts |
| bytes_used | Final charged bytes plus active reservations |
| slots_in_use | Active or conservatively held worker slots |
| unknown_slots | Worker slots retained for uncertain outcomes |
| halted | Whether new operations are disabled |

The counters are in-memory accounting values.

They do not provide a cryptographically signed audit trail.

`GovernorUsage.can_admit` means only that admissions have not been
administratively halted. A specific request can still be rejected by the
remaining file, byte, or worker limits. Usage snapshots reject negative,
boolean, and internally inconsistent counters when directly constructed.

## Resource boundaries

The governor is not an operating-system-wide budget.

The shared policy applies only to supervisors registered
with the same governor object.

The following remain outside its control:

- Separate governor instances
- Other Python interpreter processes
- Direct calls to lower-level acquisition APIs
- Other programs reading the same evidence files
- Malicious code mutating private Python attributes
- Global CPU or resident-memory limits
- Process-wide file descriptor limits
- Persistent accounting across restarts

The governor assumes trusted in-process callers.

## Evidence integrity

Successful evidence acquisition continues to use:

- The common POSIX file boundary
- Streaming SHA-256
- EvidenceRecord size and digest comparison
- VerificationSession Observation tracking
- Existing per-run acquisition budgets

A MATCHED result only establishes correspondence with the
registered digest and size.

It does not establish artifact authenticity, publisher
identity, Ground Truth correctness, or independent verification.

## Compatibility

No changes are made to:

- AcquisitionRun
- AcquisitionPolicy
- AcquisitionSupervisor
- Process-isolated Evidence Acquisition
- Streaming Evidence Loader
- POSIX primitive
- Analyzer
- HTTP Runner
- Ground Truth
- CLI
- Schema
- CI
- Vulnerability Verdict

The governor is an optional, higher-level coordination API.

It does not promote CANDIDATE to Verdict.VULNERABLE.

## Validation

```bash
uv run pytest tests/test_sqli_time_evidence_governor.py -v
uv run pytest tests/test_sqli_time_evidence_lifecycle.py -v
uv run pytest tests/test_sqli_time_evidence_process.py -v
uv run pytest tests/test_sqli_time_evidence_stream.py -v

uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The tests use temporary local evidence files.

Real process acquisition tests require a working Python
multiprocessing spawn environment.

No external HTTP service or Docker container is required.

## Future research

Potential extensions include:

- Explicit confirmed worker-reap acknowledgements
- A global resource registry shared across processes
- Persistent reservation and settlement journals
- Administrative recovery from uncertain worker state
- Admission-time byte ceilings passed into worker IPC
- Process-level CPU and memory resource limits
- Supervisor-managed cancellation
- Trusted evidence verification logs

This implementation favors conservative resource accounting
over maximum throughput or admission efficiency.
