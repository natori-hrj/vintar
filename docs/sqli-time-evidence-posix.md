# Shared POSIX Evidence Acquisition Boundary

## Purpose

The full-file evidence loader and streaming evidence loader share one internal
POSIX acquisition primitive. This reduces the risk that file-opening security
checks diverge between acquisition modes.

## Module responsibilities

- `_time_evidence_posix.py`: path policy, descriptor-relative traversal,
  regular-file checks, pre/post metadata checks, and FD lifecycle.
- `time_evidence_loader.py`: legacy bounded full-file reading, returning bytes
  to the existing `VerificationSession` byte-check API.
- `time_evidence_stream.py`: incremental SHA-256, per-run file/byte budgets,
  cooperative deadline checks, and immutable attempt accounting.

The full-file loader and streaming loader retain their existing public APIs.
Their different read strategies and error-accounting contracts are intentional.

## Acquisition sequence

1. The caller checks POSIX feature support.
2. Validate the absolute root and relative path before filesystem access.
3. Open `/` and each root/intermediate directory with `O_DIRECTORY`,
   `O_NOFOLLOW`, and `O_CLOEXEC`, retaining directory FDs.
4. Inspect the final path with directory-relative `stat(follow_symlinks=False)`.
5. Reject symlinks, non-regular files, hard links, empty files, and files
   larger than 16 MiB **before** the final file is opened.
6. Optionally enforce a streaming byte budget before opening.
7. Open the final file with `O_NOFOLLOW`, `O_NONBLOCK`, and `O_CLOEXEC`.
8. Compare the post-open `fstat()` result with the pre-open metadata.
9. Read in at most 64 KiB requests; the caller retains its own read strategy.
10. Check post-read metadata stability and the exact byte count.
11. Close all owned descriptors, including on failure.

The shared context manager owns the final FD and all directory FDs. Callers
must not close or retain it beyond the context manager's lifetime.
Callback exceptions propagate to the caller only after all descriptors already
owned by the context manager have been closed. The optional metadata callback
runs once before the final open and once after the post-open metadata match.

The context manager does not automatically perform the final metadata check:
internal callers must call `validate_after_read()` before leaving its scope.
Both acquisition adapters do so. This primitive remains internal partly so a
new caller cannot accidentally treat opening the FD as a completed acquisition.

## Streaming deadline

The streaming adapter passes a checkpoint callback to the shared primitive.
It is invoked before descriptor opening and other major filesystem operations.
The streaming adapter also checks the deadline before and after reads.

This is **cooperative**: an individual blocking syscall can exceed the
configured deadline. Neither POSIX flags nor `fstat` checks provide hard
wall-clock cancellation. This module is not a process isolation boundary.

## Race and trust limitations

Pre-open `stat`, post-open `fstat`, and post-read `fstat` reduce common
TOCTOU risks but do not provide an atomic filesystem snapshot. Privileged
attackers, mutable mount namespaces, hostile filesystems, and malicious
concurrent writers are outside the guarantees of this implementation.

A `MATCHED` observation indicates digest-and-size consistency only. It does
not establish provenance, publisher authenticity, a trusted verification
identity, a trusted timestamp, or correct Ground Truth.

The full-file loader still temporarily retains the file bytes and may have
a peak memory footprint larger than 16 MiB. The streaming adapter retains
only its current chunk and hash state, but its byte and time budgets apply
only to one sequential `AcquisitionRun`, not to the whole process.

## Compatibility

- `read_local_evidence`: retains `bytes` return value and acquisition errors.
- `check_local_evidence_in_session`: retains immutable Session updates.
- `acquire_evidence_stream`: retains per-attempt accounting, partial-byte
  charging, `MATCHED`/`MISMATCHED`, and error outcomes.
- Invalid paths and unknown Evidence IDs are rejected before attempts.
- Analyzer, Runner, Ground Truth, Verdict, CLI, Schema, and CI are unchanged.
- No network access, artifact writing, or verdict promotion is introduced.

The primitive is an internal implementation detail, not a public stable API.
Any future change to its path policy or metadata contract requires reviewing
both acquisition adapters and their regression tests together.

## Validation

```bash
uv run pytest tests/test_sqli_time_evidence_posix.py -v
uv run pytest tests/test_sqli_time_evidence_loader.py -v
uv run pytest tests/test_sqli_time_evidence_stream.py -v
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The local unit tests do not require Docker or external services.
