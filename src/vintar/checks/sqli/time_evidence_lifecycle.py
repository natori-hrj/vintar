"""In-process lifecycle supervision for isolated evidence acquisition.

A supervisor owns the authoritative AcquisitionRun and issues
single-generation handles. This is an in-process coordination boundary,
not an authentication or operating-system security boundary.
"""

import threading
import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

from vintar.checks.sqli.time_evidence_process import (
    ProcessAcquisitionResult,
    ProcessAcquisitionStatus,
    acquire_evidence_isolated,
)
from vintar.checks.sqli.time_evidence_session import VerificationSession
from vintar.checks.sqli.time_evidence_stream import (
    AcquisitionPolicy,
    AcquisitionRun,
    start_acquisition_run,
)


class AcquisitionLifecycleStatus(StrEnum):
    ACTIVE = "active"
    TERMINATED = "terminated"
    INVALIDATED = "invalidated"


class AcquisitionLifecycleError(RuntimeError):
    """A lifecycle operation is not authorized by the current state."""


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class AcquisitionHandle:
    """A generation-specific capability issued by one supervisor."""

    run_id: str
    generation: int

    def __post_init__(self) -> None:
        if (
            type(self.run_id) is not str
            or len(self.run_id) != 32
            or any(character not in "0123456789abcdef" for character in self.run_id)
        ):
            raise ValueError("Invalid acquisition run identifier.")

        if type(self.generation) is not int or self.generation < 0:
            raise ValueError("Invalid acquisition generation.")


@dataclass(frozen=True, slots=True, repr=False)
class LifecycleAcquisitionResult:
    """Return a continuation handle only for an active supervised run."""

    status: AcquisitionLifecycleStatus
    process_status: ProcessAcquisitionStatus | None
    handle: AcquisitionHandle | None = field(default=None, repr=False)
    run: AcquisitionRun | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.status) is not AcquisitionLifecycleStatus:
            raise TypeError("Invalid lifecycle status.")

        if (
            self.process_status is not None
            and type(self.process_status) is not ProcessAcquisitionStatus
        ):
            raise TypeError("Invalid process status.")

        if self.status is AcquisitionLifecycleStatus.ACTIVE:
            if (
                self.process_status is not ProcessAcquisitionStatus.COMPLETED
                or type(self.handle) is not AcquisitionHandle
                or type(self.run) is not AcquisitionRun
            ):
                raise ValueError("Active result requires completed acquisition.")
        elif self.handle is not None or self.run is not None:
            raise ValueError("Terminal result must not expose a continuation.")

        if (
            self.status is AcquisitionLifecycleStatus.TERMINATED
            and self.process_status is not None
        ):
            raise ValueError("Termination must not report a worker result.")

        if (
            self.status is AcquisitionLifecycleStatus.INVALIDATED
            and self.process_status is ProcessAcquisitionStatus.COMPLETED
        ):
            raise ValueError("Invalidated result cannot be completed.")

    @property
    def can_continue(self) -> bool:
        return self.status is AcquisitionLifecycleStatus.ACTIVE


class AcquisitionSupervisor:
    """Own a single sequential acquisition run and its current handle.

    All operations on one supervisor are serialized by an RLock.
    Its state is authoritative only for calls routed through this object.
    """

    def __init__(
        self,
        *,
        session: VerificationSession,
        policy: AcquisitionPolicy,
    ) -> None:
        if type(session) is not VerificationSession:
            raise TypeError("Invalid acquisition session.")

        if type(policy) is not AcquisitionPolicy:
            raise TypeError("Invalid acquisition policy.")

        run = start_acquisition_run(session=session, policy=policy)
        run_id = uuid.uuid4().hex

        self._lock = threading.RLock()
        self._run_id = run_id
        self._run: AcquisitionRun | None = run
        self._handle: AcquisitionHandle | None = AcquisitionHandle(
            run_id=run_id,
            generation=0,
        )
        self._status = AcquisitionLifecycleStatus.ACTIVE
        self._last_process_status: ProcessAcquisitionStatus | None = None

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def status(self) -> AcquisitionLifecycleStatus:
        with self._lock:
            return self._status

    @property
    def last_process_status(self) -> ProcessAcquisitionStatus | None:
        with self._lock:
            return self._last_process_status

    @property
    def can_continue(self) -> bool:
        with self._lock:
            return self._status is AcquisitionLifecycleStatus.ACTIVE

    def initial_handle(self) -> AcquisitionHandle:
        """Return the first capability before any acquisition is performed."""
        with self._lock:
            if self._status is not AcquisitionLifecycleStatus.ACTIVE:
                raise AcquisitionLifecycleError("Acquisition run is not active.")

            if self._handle is None:
                raise AcquisitionLifecycleError("No active acquisition handle.")

            return self._handle

    def snapshot(self, *, handle: AcquisitionHandle) -> AcquisitionRun:
        """Return the current immutable model for a valid active handle."""
        with self._lock:
            self._require_handle(handle)
            if self._run is None:
                raise AcquisitionLifecycleError("No active acquisition run.")
            return self._run

    def _require_handle(self, handle: AcquisitionHandle) -> None:
        if type(handle) is not AcquisitionHandle:
            raise TypeError("Invalid acquisition handle.")

        if self._status is not AcquisitionLifecycleStatus.ACTIVE:
            raise AcquisitionLifecycleError("Acquisition run is not active.")

        if handle is not self._handle or handle.run_id != self._run_id:
            raise AcquisitionLifecycleError("Stale or foreign acquisition handle.")

    def acquire(
        self,
        *,
        handle: AcquisitionHandle,
        evidence_id: str,
        root: str | Path,
        relative_path: str,
        timeout_seconds: float = 5.0,
    ) -> LifecycleAcquisitionResult:
        """Execute one supervised acquisition and rotate its handle.

        Any exception after entering the supervised operation invalidates
        the run conservatively, because worker activity may be unknown.
        """
        with self._lock:
            self._require_handle(handle)

            run = self._run
            if run is None:
                raise AcquisitionLifecycleError("No active acquisition run.")

            try:
                result = acquire_evidence_isolated(
                    run=run,
                    evidence_id=evidence_id,
                    root=root,
                    relative_path=relative_path,
                    timeout_seconds=timeout_seconds,
                )
                if type(result) is not ProcessAcquisitionResult:
                    raise AcquisitionLifecycleError("Invalid worker process result.")

                if type(result.status) is not ProcessAcquisitionStatus:
                    raise AcquisitionLifecycleError("Invalid worker process status.")

                self._last_process_status = result.status

                if result.status is not ProcessAcquisitionStatus.COMPLETED:
                    self._invalidate()
                    return LifecycleAcquisitionResult(
                        status=AcquisitionLifecycleStatus.INVALIDATED,
                        process_status=result.status,
                    )

                next_run = result.run
                if (
                    type(next_run) is not AcquisitionRun
                    or next_run.binding is not run.binding
                    or next_run.policy is not run.policy
                    or next_run.started_at != run.started_at
                    or len(next_run.attempts) != len(run.attempts) + 1
                    or next_run.attempts[:-1] != run.attempts
                    or next_run.attempts[-1].evidence_id != evidence_id
                ):
                    raise AcquisitionLifecycleError(
                        "Inconsistent supervised acquisition result."
                    )

                next_handle = AcquisitionHandle(
                    run_id=self._run_id,
                    generation=handle.generation + 1,
                )
                lifecycle_result = LifecycleAcquisitionResult(
                    status=AcquisitionLifecycleStatus.ACTIVE,
                    process_status=ProcessAcquisitionStatus.COMPLETED,
                    handle=next_handle,
                    run=next_run,
                )
            except BaseException:
                self._invalidate()
                raise

            self._run = next_run
            self._handle = next_handle
            return lifecycle_result

    def terminate(self, *, handle: AcquisitionHandle) -> None:
        """Explicitly end an active run without starting another worker."""
        with self._lock:
            self._require_handle(handle)
            self._run = None
            self._handle = None
            self._status = AcquisitionLifecycleStatus.TERMINATED

    def invalidate(self, *, handle: AcquisitionHandle) -> None:
        """Explicitly revoke the current handle and run."""
        with self._lock:
            self._require_handle(handle)
            self._invalidate()

    def _invalidate(self) -> None:
        self._run = None
        self._handle = None
        self._status = AcquisitionLifecycleStatus.INVALIDATED


def create_acquisition_supervisor(
    *,
    session: VerificationSession,
    policy: AcquisitionPolicy,
) -> AcquisitionSupervisor:
    """Create a supervisor owning a fresh, initially unchecked run."""
    return AcquisitionSupervisor(session=session, policy=policy)
