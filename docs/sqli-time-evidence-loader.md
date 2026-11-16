
# Time-based SQLi Local Evidence Acquisition

## Purpose

This document describes the local, read-only evidence acquisition
boundary used by Vintar's experimental timing evaluation.

The loader retrieves evidence bytes from a restricted local
filesystem tree and passes them to an existing VerificationSession.

It does not authenticate the evidence publisher or create
a trusted filesystem snapshot.

## Scope

The initial implementation is designed for Linux/POSIX.

It uses:

- Directory-relative file opening
- O_NOFOLLOW
- O_DIRECTORY
- O_CLOEXEC
- O_NONBLOCK
- fstat
- Bounded read operations
- Immutable VerificationSession updates

It performs no network access.

No write operations are performed by the loader.

## Trusted Root

The caller supplies an absolute root directory as a string or concrete
`pathlib.Path` instance such as `PosixPath`.

The root must not be the filesystem root.

The configured root is limited to 4096 characters, 64 components,
and 255 characters per component to bound parsing and descriptor use.

The loader opens the root path from the filesystem root
one component at a time.

Each component must be a directory and must not be
a symbolic link.

This includes the root itself and every parent component between
the filesystem root and the configured root.

The caller is responsible for configuring an appropriate
root with suitable ownership and permissions.

The loader does not establish an independent
operating-system sandbox.

## Relative Paths

Evidence paths must be relative to the trusted root.

Absolute paths, empty elements, dot elements, parent
directory traversal, backslashes, and unsupported
characters are rejected.

The maximum relative path depth is 16 components.

The maximum relative path length is 1024 characters.

Each component may contain ASCII letters, digits,
underscores, hyphens, and periods.

Each component is limited to 100 characters.

A valid relative path does not by itself establish
that the file is safe.

## Symlink Handling

All directory components and the final file are
opened with O_NOFOLLOW.

This prevents symbolic-link following for the
opened path components on supported filesystems.

The loader does not use path resolution followed
by an ordinary file open.

The design holds directory file descriptors
while opening each successive component.

Symlink policy is enforced during opening.

## Regular Files

Only regular files are accepted.

FIFO, sockets, devices, and directories are rejected.

The final path is first inspected with a directory-relative `stat`
that does not follow symbolic links. Recognized special files are
rejected before the loader opens them. The opened descriptor is then
checked with `fstat` and must match the pre-open metadata.

O_NONBLOCK is applied when opening the final file
so a FIFO cannot block the process while being opened.

The file must have a link count of exactly one.

This is a conservative policy intended to reject
hard-linked evidence files.

It does not verify the file's original publisher.

## Size Limits

Accepted evidence size:

```text
1 byte <= file size <= 16 MiB
```

The file size is checked before reading.

Reads are performed in bounded chunks.

The cumulative byte count is checked during reading.

The total bytes received must equal the original
size recorded by fstat.

The limit applies to an individual evidence file,
not to an entire verification session.

The caller must control concurrent sessions and
aggregate resource consumption.

The returned byte string and the internal chunk collection can coexist
briefly, so peak process memory can exceed the 16 MiB file limit.

## Concurrent Modification

The loader records fstat metadata before and
after reading.

It compares:

- Device
- Inode
- File mode
- Link count
- File size
- Modification time
- Change time

A detected change causes acquisition failure.

This is a best-effort race detection strategy.

It does not prevent all concurrent modifications,
nor does it create an atomic snapshot.

An attacker with sufficient control of the
filesystem may evade metadata-based checks.

There remains a race between the pre-open metadata check and `open`.
`O_NOFOLLOW`, `O_NONBLOCK`, and the post-open `fstat` check limit this
window, but they cannot guarantee that opening a maliciously replaced
special file has no operating-system or device-specific side effect.

Expected SHA-256 content verification remains
necessary.

For higher assurance, use an independently
controlled, immutable evidence repository.

## VerificationSession Integration

The loader accepts:

- VerificationSession
- Evidence ID
- Trusted root
- Relative file path

The Evidence ID must already be present in the
session's EvidenceBinding.

One successful acquisition creates one new
EvidenceObservation.

The previous VerificationSession remains unchanged.

The evidence ID and file path are supplied separately.

Neither is interpreted as an arbitrary URL.

## Acquisition Failure

Acquisition failures raise EvidenceAcquisitionError.

These include:

- File not found
- Permission denied
- Symlink rejection
- Unsupported file type
- Unsupported hard-link count
- Empty or oversized files
- Detected concurrent modification
- Other operating-system read failures

Acquisition failure does not create an observation.

The original session remains unchanged.

All directory and file descriptors owned by the loader are closed on
successful return and on every handled failure path.

Invalid API arguments may raise TypeError or ValueError.

## Digest Mismatch

A readable, structurally valid file may not match
the expected EvidenceRecord digest or size.

This is different from acquisition failure.

Such a file produces an EvidenceObservation
with status MISMATCHED.

The resulting session status becomes FAILED.

The loader must never replace the expected digest
with a newly calculated value to make a mismatch pass.

## Trust Limitations

A successful local read does not establish:

- Evidence authenticity
- Trusted file ownership
- Trusted creation timestamps
- Registration precedence
- Source-code correctness
- Ground Truth correctness
- Statistical independence
- Tamper-proof verification history

The loader reads bytes.

The existing VerificationSession records whether
those bytes match the expected metadata.

A MATCHED observation is not an authenticated
verification attestation.

## Remaining Filesystem Risks

The following are not fully addressed:

- Malicious concurrent writers
- Filesystem snapshot consistency
- Hostile kernel or filesystem behavior
- Bind mounts and mount namespace changes
- Shared mutable storage
- File-descriptor exhaustion by other code
- Total CPU and memory across many evidence files
- Blocking or slow reads from network, FUSE, or hostile filesystems
- Trusted ownership and permission enforcement
- Signed evidence publication
- Persistent audit logs

The loader should only be used in a controlled
research environment until these boundaries
have been independently reviewed.

`O_NONBLOCK` prevents the normal FIFO-open blocking case but does not
provide a wall-clock deadline for regular-file reads. The loader has no
aggregate byte budget or acquisition timeout.

## Data Minimization

The loader temporarily holds file bytes in memory.

Those bytes are not stored in EvidenceRecord
or VerificationSession.

Python byte strings cannot be guaranteed to be
securely erased from process memory after use.

The acquisition error messages should not contain
sensitive paths or evidence contents.

The loader does not log raw evidence bytes.

## Testing

Run the local loader tests:

```bash
uv run pytest tests/test_sqli_time_evidence_loader.py -v
```

Run the supporting evidence tests:

```bash
uv run pytest tests/test_sqli_time_evidence_session.py -v
uv run pytest tests/test_sqli_time_evidence.py -v
uv run pytest tests/test_sqli_time_provenance.py -v
```

Run the complete regression suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

Tests use temporary directories and local files.

No Docker or network service is required.

## Release Boundary

This adapter does not change:

- Time-based Probe Plan
- Timing Analyzer
- HTTP Runner
- Boolean SQLi
- Confirmation
- Cross-Phase Guard
- Application evaluation
- Cluster evaluation
- Provenance
- Evidence metadata
- Existing VerificationSession semantics
- CLI
- Schema
- CI security gates
- Production vulnerability Verdict

Local evidence acquisition does not promote
CANDIDATE to Verdict.VULNERABLE.

## Future Work

Potential extensions include:

- Streaming digests without materializing full bytes
- Aggregate I/O and CPU budgets
- Controlled execution identity
- Immutable evidence repository integration
- Independent publisher signature verification
- Trusted registration timestamps
- Tamper-evident verification logs
- Platform-specific security reviews

The current implementation is a local acquisition
boundary, not a trusted evidence store.
