"""Process-isolated local evidence acquisition for timing research.

A spawned child performs streaming acquisition. The parent supervises
its lifecycle. Timeout or worker failure makes byte accounting
indeterminate, so no resumable AcquisitionRun is returned.
"""

import math
import multiprocessing
import time
from dataclasses import dataclass, field
from enum import StrEnum
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from pathlib import Path

from vintar.checks.sqli._time_evidence_posix import (
    relative_components,
    require_posix,
    root_components,
)
from vintar.checks.sqli.time_evidence import MAX_EVIDENCE_BYTES
from vintar.checks.sqli.time_evidence_session import (
    EvidenceCheckStatus,
    EvidenceObservation,
    add_evidence_observation,
)
from vintar.checks.sqli.time_evidence_stream import (
    AcquisitionAttempt,
    AcquisitionOutcome,
    AcquisitionRun,
    _ReadFailure,
    _stream_digest,
)

_TERMINATION_GRACE_SECONDS = 0.2
_MAX_TIMEOUT_SECONDS = 3600.0


class ProcessAcquisitionStatus(StrEnum):
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    WORKER_FAILED = "worker_failed"
    UNREAPED = "unreaped"


@dataclass(frozen=True, slots=True, repr=False)
class ProcessAcquisitionResult:
    """Only a completed acquisition provides a resumable run."""

    status: ProcessAcquisitionStatus
    run: AcquisitionRun | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.status) is not ProcessAcquisitionStatus:
            raise TypeError("Invalid process acquisition status.")
        if self.status is ProcessAcquisitionStatus.COMPLETED:
            if type(self.run) is not AcquisitionRun:
                raise ValueError("Completed acquisition requires a run.")
        elif self.run is not None:
            raise ValueError("Terminal acquisition must not expose a run.")

    @property
    def can_continue(self) -> bool:
        return self.status is ProcessAcquisitionStatus.COMPLETED


def _worker(
    connection: Connection,
    root: str,
    relative_path: str,
    byte_limit: int,
    deadline: float,
) -> None:
    """Return digest metadata or a bounded acquisition failure."""
    try:
        try:
            digest, consumed = _stream_digest(
                root=root,
                relative_path=relative_path,
                byte_limit=byte_limit,
                deadline=deadline,
            )
        except _ReadFailure as failure:
            message = (
                "failure",
                failure.outcome.value,
                failure.bytes_read,
            )
        else:
            message = ("success", digest, consumed)

        connection.send(message)
    finally:
        connection.close()


def _stop_worker(process: BaseProcess) -> bool:
    """Attempt termination, escalation, and child reaping."""
    try:
        if not process.is_alive():
            process.join(timeout=0)
            return process.exitcode is not None

        process.terminate()
        process.join(timeout=_TERMINATION_GRACE_SECONDS)

        if process.is_alive():
            process.kill()
            process.join(timeout=_TERMINATION_GRACE_SECONDS)
    except (AssertionError, OSError, RuntimeError, ValueError):
        return False

    return not process.is_alive() and process.exitcode is not None


def _validate_message(
    message: object,
    *,
    byte_limit: int,
) -> tuple[AcquisitionOutcome, str | None, int] | None:
    """Reject malformed, oversized, or unsupported worker replies."""
    if type(byte_limit) is not int or not 1 <= byte_limit <= MAX_EVIDENCE_BYTES:
        return None

    if type(message) is not tuple or len(message) != 3:
        return None

    marker, value, consumed = message

    if (
        type(marker) is not str
        or type(consumed) is not int
        or not 0 <= consumed <= byte_limit
        or consumed > MAX_EVIDENCE_BYTES
    ):
        return None

    if marker == "success":
        if (
            consumed == 0
            or type(value) is not str
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
        ):
            return None
        return AcquisitionOutcome.MATCHED, value, consumed

    if marker == "failure" and type(value) is str:
        if value == AcquisitionOutcome.ACQUISITION_FAILED.value:
            return AcquisitionOutcome.ACQUISITION_FAILED, None, consumed
        if value == AcquisitionOutcome.BUDGET_EXCEEDED.value:
            return AcquisitionOutcome.BUDGET_EXCEEDED, None, consumed

    return None


def _append_attempt(
    *,
    run: AcquisitionRun,
    evidence_id: str,
    outcome: AcquisitionOutcome,
    consumed: int,
    digest: str | None = None,
) -> AcquisitionRun:
    """Reconstruct existing immutable accounting in the parent."""
    session = run.session

    if digest is not None:
        observation = EvidenceObservation(
            binding=run.binding,
            evidence_id=evidence_id,
            observed_sha256=digest,
            observed_size=consumed,
        )
        outcome = (
            AcquisitionOutcome.MATCHED
            if observation.status is EvidenceCheckStatus.MATCHED
            else AcquisitionOutcome.MISMATCHED
        )
        session = add_evidence_observation(
            session=session,
            observation=observation,
        )

    return AcquisitionRun(
        binding=run.binding,
        session=session,
        policy=run.policy,
        started_at=run.started_at,
        attempts=(
            *run.attempts,
            AcquisitionAttempt(
                evidence_id=evidence_id,
                outcome=outcome,
                bytes_read=consumed,
            ),
        ),
    )


def _terminal(status: ProcessAcquisitionStatus) -> ProcessAcquisitionResult:
    return ProcessAcquisitionResult(status=status)


def acquire_evidence_isolated(
    *,
    run: AcquisitionRun,
    evidence_id: str,
    root: str | Path,
    relative_path: str,
    timeout_seconds: float = 5.0,
) -> ProcessAcquisitionResult:
    """Acquire one artifact in a spawned child and supervise its deadline.

    A clean response preserves AcquisitionRun accounting. Timeout,
    worker crash, or invalid IPC produces no resumable Run.

    Startup and worker termination cannot be strictly time-bounded.
    """
    if type(run) is not AcquisitionRun:
        raise TypeError("Invalid acquisition run.")

    record = run.binding.index.get(evidence_id)
    if record is None:
        raise ValueError("Evidence identifier is not bound.")

    if any(item.evidence_id == evidence_id for item in run.attempts):
        raise ValueError("Evidence already attempted in this run.")

    if not run.remaining_files:
        raise ValueError("Acquisition file budget exhausted.")

    if (
        type(timeout_seconds) is not float
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= _MAX_TIMEOUT_SECONDS
    ):
        raise ValueError("Invalid process acquisition timeout.")

    roots = root_components(root)
    parts = relative_components(relative_path)
    require_posix()

    if run.remaining_bytes == 0:
        return ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
            run=_append_attempt(
                run=run,
                evidence_id=evidence_id,
                outcome=AcquisitionOutcome.BUDGET_EXCEEDED,
                consumed=0,
            ),
        )

    started = time.monotonic()
    deadline = min(
        started + timeout_seconds,
        run.started_at + run.policy.max_elapsed_seconds,
    )

    if started >= deadline:
        return ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
            run=_append_attempt(
                run=run,
                evidence_id=evidence_id,
                outcome=AcquisitionOutcome.BUDGET_EXCEEDED,
                consumed=0,
            ),
        )

    byte_limit = min(run.remaining_bytes, MAX_EVIDENCE_BYTES)

    try:
        context = multiprocessing.get_context("spawn")
        parent_conn, child_conn = context.Pipe(duplex=False)
    except (OSError, RuntimeError, ValueError):
        return _terminal(ProcessAcquisitionStatus.WORKER_FAILED)

    try:
        process = context.Process(
            target=_worker,
            args=(
                child_conn,
                "/" + "/".join(roots),
                "/".join(parts),
                byte_limit,
                deadline,
            ),
            daemon=True,
        )
    except (OSError, RuntimeError, ValueError):
        parent_conn.close()
        child_conn.close()
        return _terminal(ProcessAcquisitionStatus.WORKER_FAILED)

    started_process = False

    try:
        if time.monotonic() >= deadline:
            child_conn.close()
            return _terminal(ProcessAcquisitionStatus.TIMED_OUT)

        try:
            process.start()
            started_process = True
        except (AssertionError, OSError, RuntimeError):
            started_process = process.pid is not None
            return _terminal(ProcessAcquisitionStatus.WORKER_FAILED)
        finally:
            child_conn.close()

        process.join(timeout=max(0.0, deadline - time.monotonic()))

        if process.is_alive() or time.monotonic() >= deadline:
            reaped = _stop_worker(process)
            return _terminal(
                ProcessAcquisitionStatus.TIMED_OUT
                if reaped
                else ProcessAcquisitionStatus.UNREAPED
            )

        if process.exitcode != 0 or not parent_conn.poll(0):
            return _terminal(ProcessAcquisitionStatus.WORKER_FAILED)

        try:
            message = parent_conn.recv()
        except (EOFError, OSError, ValueError):
            return _terminal(ProcessAcquisitionStatus.WORKER_FAILED)

        parsed = _validate_message(message, byte_limit=byte_limit)
        if parsed is None:
            return _terminal(ProcessAcquisitionStatus.WORKER_FAILED)

        outcome, digest, consumed = parsed
        return ProcessAcquisitionResult(
            status=ProcessAcquisitionStatus.COMPLETED,
            run=_append_attempt(
                run=run,
                evidence_id=evidence_id,
                outcome=outcome,
                consumed=consumed,
                digest=digest,
            ),
        )
    finally:
        parent_conn.close()
        if started_process:
            if process.is_alive():
                _stop_worker(process)
            if not process.is_alive():
                process.close()
        else:
            process.close()
