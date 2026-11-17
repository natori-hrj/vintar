
# Time-based SQLi Evidence Acquisition Budget and Streaming

## Purpose

This document defines a budgeted streaming adapter for local evidence
acquisition in Vintar's experimental time-based SQLi research system.

The adapter hashes evidence incrementally and records resource
consumption, including partially failed acquisitions.

It does not authenticate the evidence source or establish a trusted
verification event.

## Architecture

The implementation uses the following separation:

```text
EvidenceBinding
       |
VerificationSession
       |
AcquisitionRun
       |
POSIX local acquisition
       |
Streaming SHA-256
       |
EvidenceObservation
```

The existing VerificationSession remains immutable.

The adapter uses the confined POSIX loader's validation helpers,
file-opening policy, and descriptor management.

The existing full-file loader is unchanged.

## Acquisition Policy

AcquisitionPolicy limits one sequential acquisition run.

Supported limits:

- max_files
- max_total_bytes
- max_elapsed_seconds

Defaults:

| Budget | Default |
| --- | --- |
| Files attempted | 301 |
| Total bytes read | 301 × 16 MiB |
| Elapsed seconds | 60.0 |

The allowed range is:

- max_files: 1 to 301
- max_total_bytes: 1 to 301 × 16 MiB
- max_elapsed_seconds: greater than 0, up to 3600.0

An individual file retains the existing 16 MiB size limit.

The default aggregate byte budget is a maximum configuration
bound, not a recommendation to acquire that much data.

For small experiments, callers should choose smaller budgets.

## Streaming SHA-256

Evidence bytes are read using bounded chunks of at most 64 KiB.

The SHA-256 digest is updated incrementally.

The full file content is not concatenated into one bytes object.

The implementation retains only the current chunk,
the incremental hash state, and acquisition metadata.

Python still temporarily allocates each returned chunk.

The adapter cannot guarantee secure erasure of transient bytes.

## File Safety

The adapter reuses the existing POSIX loader's policies:

- Absolute, constrained root
- Validated relative path
- Directory-relative opening
- O_NOFOLLOW
- O_DIRECTORY
- O_CLOEXEC
- O_NONBLOCK
- Regular-file validation
- Single hard-link policy
- Pre-open stat
- Post-open fstat
- Post-read fstat
- File metadata stability checks
- Automatic file-descriptor cleanup

The adapter imports these helpers from the existing loader.

These are currently internal integration points, not a
publicly versioned loader API.

If the loader's security contract changes, both acquisition
paths must be reviewed together.

## Acquisition Outcomes

Every attempted evidence acquisition produces one outcome.

### MATCHED

The file was read successfully, and the observed SHA-256
digest and size match its expected EvidenceRecord.

The VerificationSession records a MATCHED observation.

### MISMATCHED

The file was read successfully, but its content does not
match the expected digest or size.

The VerificationSession records MISMATCHED.

### ACQUISITION_FAILED

The file could not be acquired under the local safety policy,
or a read failed before completion.

This includes violating the fixed per-file safety limit of 16 MiB.

No EvidenceObservation is added.

Bytes read before failure remain charged to the budget.

### BUDGET_EXCEEDED

The operation encountered a configured byte or time limit.

This refers to the run's remaining aggregate budget. It is distinct
from rejecting a file that violates the fixed per-file safety policy.

No EvidenceObservation is added.

Bytes already read remain charged to the budget.

## Attempt Accounting

The AcquisitionRun is immutable.

A new run object is returned after every attempted acquisition.

The run records:

- Number of attempted files
- Total bytes actually read
- Remaining file budget
- Remaining byte budget
- Number of failed attempts
- Each attempted evidence identifier
- Each attempt's outcome and consumed bytes

Failed attempts consume one file slot.

A failed attempt with five bytes already read consumes
five bytes from the total byte budget.

A failed attempt with no bytes read consumes zero bytes.

The same evidence ID cannot be attempted twice within
one AcquisitionRun.

The file budget is checked before a new acquisition starts.

When the file budget is exhausted, further calls are rejected
without starting an additional attempt.

## Session Accounting

Only successful complete file reads produce observations.

A successful read can produce MATCHED or MISMATCHED.

Acquisition failure and budget exhaustion leave the
VerificationSession unchanged.

A run with failed acquisitions may therefore have more
attempted files than checked evidence.

The model validates consistency between successful
acquisition attempts and Session observations.

Each successful attempt must have the same observed byte count and
MATCHED or MISMATCHED state as its Session observation. AcquisitionRun
also retains the exact in-memory EvidenceBinding used to start the run,
so replacing the current Session with one from another Binding is rejected.

The caller must distinguish:

- Acquisition attempt count
- Bytes consumed
- Successful completed reads
- VerificationSession checked evidence
- VerificationSession matched evidence

These quantities are not interchangeable.

## Deadline Semantics

The adapter uses time.monotonic() and a configured
elapsed-time budget.

It checks the deadline before and between filesystem
operations, during reading, and after the final read.

The deadline is cooperative.

It does not interrupt an os.open(), os.stat(),
os.fstat(), or os.read() call that blocks.

A blocking filesystem call may cause the actual
elapsed time to exceed max_elapsed_seconds.

Consequently, the configured deadline is not a
strict wall-clock execution bound.

Enforcing a hard bound requires a separately
designed isolation and cancellation mechanism.

## Error Handling

Invalid model types, unbound evidence identifiers,
duplicate attempts, and exhausted file slots are
rejected before acquisition.

Malformed root and relative paths are also rejected before filesystem
access and do not create an AcquisitionAttempt.

Filesystem acquisition failures are represented as
ACQUISITION_FAILED.

Budget exhaustion during an acquisition is represented
as BUDGET_EXCEEDED.

Failure records do not retain raw paths or evidence bytes.

The caller must independently record operational
failures if additional audit detail is required.

This research model is not a trusted audit log.

Frozen dataclasses and validation reject structurally inconsistent
direct construction and replacement. They do not prevent trusted
in-process Python code from constructing an entirely new, internally
consistent run with a different policy or clock origin.

## Integrity and Authenticity

Matching an expected SHA-256 digest establishes
consistency with the expected metadata.

It does not establish:

- Evidence authorship
- Trusted creation time
- Evidence publication integrity
- Ground Truth validity
- Application independence
- Independent verifier execution
- A signed acquisition event

An attacker who can replace both evidence content
and the expected digest can defeat this comparison.

## Security Limitations

The adapter does not provide:

- Atomic filesystem snapshots
- Guaranteed read deadlines
- Global process memory limits
- Global CPU limits
- Trusted evidence storage
- Digital signatures
- Trusted timestamps
- Tamper-proof verification logs
- Cross-process acquisition coordination

The file and byte budgets apply only to one
sequential AcquisitionRun.

They are not global limits shared across multiple runs.

The implementation does not permit retried evidence IDs
within the same run.

A new run may repeat verification, subject to a new
independently configured budget.

## Ground Truth Boundary

This adapter does not modify:

- Application Ground Truth
- Analyzer classifications
- Timing thresholds
- Time-based HTTP Runner
- Confirmation or Cross-Phase Guard
- Cluster quality estimates
- Vulnerability Verdict
- CLI, Schema, or CI

CANDIDATE is not promoted to Verdict.VULNERABLE.

## Reproduction

Run the streaming adapter tests:

```bash
uv run pytest tests/test_sqli_time_evidence_stream.py -v
```

Run the existing acquisition and session tests:

```bash
uv run pytest tests/test_sqli_time_evidence_loader.py -v
uv run pytest tests/test_sqli_time_evidence_session.py -v
uv run pytest tests/test_sqli_time_evidence.py -v
```

Run the entire project regression suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The unit tests use local temporary files.

No Docker or external HTTP service is required.

## Next Research Topics

Potential future work includes:

- A shared, independently enforced global resource budget
- Streaming acquisition with trusted artifact repositories
- Persisted content-addressed verification logs
- Signed Evidence manifests
- Trusted verification identities
- Reliable process-level I/O cancellation
- Explicit hostile-filesystem threat models

This adapter provides bounded resource accounting and
incremental hashing, not a trusted evidence store.
