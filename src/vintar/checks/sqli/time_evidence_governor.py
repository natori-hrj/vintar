"""Shared in-process resource governance for evidence acquisition.

The governor owns supervised runs, reserves worst-case resources before
dispatch, and settles them only from verified completed results.
Unknown worker outcomes halt new admissions conservatively.
"""

import math
import threading
from dataclasses import dataclass
from pathlib import Path

from vintar.checks.sqli._time_evidence_posix import (
    relative_components,
    require_posix,
    root_components,
)
from vintar.checks.sqli.time_evidence import (
    MAX_EVIDENCE_BYTES,
    MAX_EVIDENCE_RECORDS,
)
from vintar.checks.sqli.time_evidence_lifecycle import (
    AcquisitionHandle,
    AcquisitionLifecycleStatus,
    AcquisitionSupervisor,
    LifecycleAcquisitionResult,
)
from vintar.checks.sqli.time_evidence_process import ProcessAcquisitionStatus
from vintar.checks.sqli.time_evidence_session import VerificationSession
from vintar.checks.sqli.time_evidence_stream import (
    AcquisitionPolicy,
    AcquisitionRun,
)


class AcquisitionGovernanceError(RuntimeError):
    """The requested operation violates the governor's state."""


class ResourceBudgetError(AcquisitionGovernanceError):
    """A shared resource reservation cannot be admitted."""


@dataclass(frozen=True, slots=True)
class GovernorPolicy:
    """Limits shared across runs registered to one governor."""

    max_files: int = MAX_EVIDENCE_RECORDS
    max_total_bytes: int = MAX_EVIDENCE_BYTES * MAX_EVIDENCE_RECORDS
    max_workers: int = 2

    def __post_init__(self) -> None:
        if (
            type(self.max_files) is not int
            or not 1 <= self.max_files <= MAX_EVIDENCE_RECORDS**2
        ):
            raise ValueError("Invalid governor file budget.")

        if (
            type(self.max_total_bytes) is not int
            or not 1
            <= self.max_total_bytes
            <= MAX_EVIDENCE_BYTES * MAX_EVIDENCE_RECORDS**2
        ):
            raise ValueError("Invalid governor byte budget.")

        if type(self.max_workers) is not int or not 1 <= self.max_workers <= 64:
            raise ValueError("Invalid governor worker limit.")


@dataclass(frozen=True, slots=True, eq=False, repr=False)
class GovernorHandle:
    """Generation-specific handle issued by one governor."""

    run_id: str
    generation: int

    def __post_init__(self) -> None:
        if (
            type(self.run_id) is not str
            or len(self.run_id) != 32
            or any(char not in "0123456789abcdef" for char in self.run_id)
        ):
            raise ValueError("Invalid governor run identifier.")

        if type(self.generation) is not int or self.generation < 0:
            raise ValueError("Invalid governor generation.")


@dataclass(frozen=True, slots=True)
class GovernorUsage:
    """An immutable accounting snapshot, not a trusted audit record."""

    files_used: int
    bytes_used: int
    slots_in_use: int
    unknown_slots: int
    halted: bool

    def __post_init__(self) -> None:
        counters = (
            self.files_used,
            self.bytes_used,
            self.slots_in_use,
            self.unknown_slots,
        )
        if any(type(value) is not int or value < 0 for value in counters):
            raise ValueError("Invalid governor usage counter.")

        if self.unknown_slots > self.slots_in_use:
            raise ValueError("Invalid governor unknown worker count.")

        if type(self.halted) is not bool:
            raise TypeError("Invalid governor halt state.")

        if self.unknown_slots and not self.halted:
            raise ValueError("Unknown workers require halted admissions.")

    @property
    def can_admit(self) -> bool:
        """Return whether admissions are not administratively halted.

        A true value does not guarantee that a particular reservation fits.
        """
        return not self.halted


@dataclass(frozen=True, slots=True, repr=False)
class GovernedAcquisitionResult:
    """A supervised result with an optional next governor handle."""

    lifecycle: LifecycleAcquisitionResult
    handle: GovernorHandle | None = None

    def __post_init__(self) -> None:
        if type(self.lifecycle) is not LifecycleAcquisitionResult:
            raise TypeError("Invalid governed lifecycle result.")

        if self.lifecycle.can_continue:
            if type(self.handle) is not GovernorHandle:
                raise ValueError("Active result requires a governor handle.")
            if (
                self.lifecycle.handle is None
                or self.handle.run_id != self.lifecycle.handle.run_id
                or self.handle.generation != self.lifecycle.handle.generation
            ):
                raise ValueError("Governed handle does not match lifecycle.")
        elif self.handle is not None:
            raise ValueError("Terminal result cannot expose a handle.")

    @property
    def can_continue(self) -> bool:
        return self.lifecycle.can_continue

    @property
    def run(self) -> AcquisitionRun | None:
        return self.lifecycle.run


@dataclass(slots=True)
class _Entry:
    supervisor: AcquisitionSupervisor
    lifecycle_handle: AcquisitionHandle | None
    handle: GovernorHandle | None
    busy: bool = False


class AcquisitionResourceGovernor:
    """Coordinate multiple owned supervisors within one Python process.

    The governor lock covers admission and settlement, but not the
    blocking acquisition itself. One supervisor can be in flight only
    once, and reservations cannot overcommit the shared policy.
    """

    def __init__(self, *, policy: GovernorPolicy) -> None:
        if type(policy) is not GovernorPolicy:
            raise TypeError("Invalid governor policy.")

        self._policy = policy
        self._lock = threading.RLock()
        self._entries: dict[str, _Entry] = {}
        self._files_used = 0
        self._bytes_used = 0
        self._slots_in_use = 0
        self._unknown_slots = 0
        self._halted = False

    @property
    def policy(self) -> GovernorPolicy:
        return self._policy

    def usage(self) -> GovernorUsage:
        with self._lock:
            return GovernorUsage(
                files_used=self._files_used,
                bytes_used=self._bytes_used,
                slots_in_use=self._slots_in_use,
                unknown_slots=self._unknown_slots,
                halted=self._halted,
            )

    def register(
        self,
        *,
        session: VerificationSession,
        policy: AcquisitionPolicy,
    ) -> GovernorHandle:
        """Register a new supervisor owned exclusively by this governor."""
        with self._lock:
            self._require_running()

            if len(self._entries) >= MAX_EVIDENCE_RECORDS:
                raise ResourceBudgetError("Governor registration limit reached.")

            supervisor = AcquisitionSupervisor(
                session=session,
                policy=policy,
            )
            lifecycle_handle = supervisor.initial_handle()
            run_id = supervisor.run_id

            if run_id in self._entries:
                raise AcquisitionGovernanceError("Duplicate supervisor identifier.")

            handle = GovernorHandle(run_id=run_id, generation=0)
            self._entries[run_id] = _Entry(
                supervisor=supervisor,
                lifecycle_handle=lifecycle_handle,
                handle=handle,
            )
            return handle

    def _require_running(self) -> None:
        if self._halted:
            raise AcquisitionGovernanceError("Governor admissions are halted.")

    def _require_entry(self, handle: GovernorHandle) -> _Entry:
        if type(handle) is not GovernorHandle:
            raise TypeError("Invalid governor handle.")

        entry = self._entries.get(handle.run_id)

        if entry is None or handle is not entry.handle:
            raise AcquisitionGovernanceError("Stale or foreign governor handle.")

        if entry.busy:
            raise AcquisitionGovernanceError("Acquisition already in progress.")

        if entry.lifecycle_handle is None:
            raise AcquisitionGovernanceError("Acquisition run is not active.")

        return entry

    def snapshot(self, *, handle: GovernorHandle) -> AcquisitionRun:
        """Inspect the current run without allowing caller-driven updates."""
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)
            assert entry.lifecycle_handle is not None
            return entry.supervisor.snapshot(handle=entry.lifecycle_handle)

    def acquire(
        self,
        *,
        handle: GovernorHandle,
        evidence_id: str,
        root: str | Path,
        relative_path: str,
        timeout_seconds: float = 5.0,
    ) -> GovernedAcquisitionResult:
        """Reserve, execute, and settle one supervised acquisition.

        Rejected admission consumes no resources. After reservation,
        an unexpected exception retains the entire reservation and
        halts admissions because worker state may be unknown.
        """
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)

            assert entry.lifecycle_handle is not None
            old_run = entry.supervisor.snapshot(
                handle=entry.lifecycle_handle,
            )

            # Reject invalid calls before consuming any global budget.
            if old_run.binding.index.get(evidence_id) is None:
                raise ValueError("Evidence identifier is not bound.")

            if any(attempt.evidence_id == evidence_id for attempt in old_run.attempts):
                raise ValueError("Evidence already attempted in this run.")

            if not old_run.remaining_files:
                raise ValueError("Acquisition file budget exhausted.")

            if (
                type(timeout_seconds) is not float
                or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 3600.0
            ):
                raise ValueError("Invalid process acquisition timeout.")

            root_components(root)
            relative_components(relative_path)
            require_posix()

            reservation = min(
                MAX_EVIDENCE_BYTES,
                old_run.remaining_bytes,
            )

            if self._files_used >= self._policy.max_files:
                raise ResourceBudgetError("Governor file budget exhausted.")

            if self._slots_in_use >= self._policy.max_workers:
                raise ResourceBudgetError("Governor worker limit reached.")

            if self._bytes_used + reservation > self._policy.max_total_bytes:
                raise ResourceBudgetError("Governor byte budget insufficient.")

            self._files_used += 1
            self._bytes_used += reservation
            self._slots_in_use += 1
            entry.busy = True

            lifecycle_handle = entry.lifecycle_handle

        # Never hold the governor lock across subprocess execution.
        # The entry remains busy, preventing concurrent reuse.
        try:
            lifecycle = entry.supervisor.acquire(
                handle=lifecycle_handle,
                evidence_id=evidence_id,
                root=root,
                relative_path=relative_path,
                timeout_seconds=timeout_seconds,
            )

            with self._lock:
                if type(lifecycle) is not LifecycleAcquisitionResult:
                    raise AcquisitionGovernanceError(
                        "Invalid supervised acquisition result."
                    )

                if lifecycle.status is AcquisitionLifecycleStatus.ACTIVE:
                    if (
                        lifecycle.process_status
                        is not ProcessAcquisitionStatus.COMPLETED
                        or lifecycle.handle is None
                        or lifecycle.run is None
                    ):
                        raise AcquisitionGovernanceError(
                            "Inconsistent completed acquisition."
                        )

                    new_run = lifecycle.run

                    if (
                        new_run.binding is not old_run.binding
                        or new_run.policy is not old_run.policy
                        or new_run.started_at != old_run.started_at
                        or len(new_run.attempts) != len(old_run.attempts) + 1
                        or new_run.attempts[:-1] != old_run.attempts
                        or new_run.attempts[-1].evidence_id != evidence_id
                        or lifecycle.handle.generation
                        != lifecycle_handle.generation + 1
                        or lifecycle.handle.run_id != handle.run_id
                        or entry.supervisor.snapshot(handle=lifecycle.handle)
                        is not new_run
                    ):
                        raise AcquisitionGovernanceError("Inconsistent supervised run.")

                    consumed = new_run.attempts[-1].bytes_read

                    if not 0 <= consumed <= reservation:
                        raise AcquisitionGovernanceError(
                            "Acquisition exceeded reserved bytes."
                        )

                    new_handle = GovernorHandle(
                        run_id=handle.run_id,
                        generation=handle.generation + 1,
                    )
                    result = GovernedAcquisitionResult(
                        lifecycle=lifecycle,
                        handle=new_handle,
                    )

                    self._bytes_used -= reservation - consumed
                    self._slots_in_use -= 1
                    entry.lifecycle_handle = lifecycle.handle
                    entry.handle = new_handle
                    entry.busy = False
                    return result

                if (
                    lifecycle.status is not AcquisitionLifecycleStatus.INVALIDATED
                    or lifecycle.handle is not None
                    or lifecycle.run is not None
                ):
                    raise AcquisitionGovernanceError(
                        "Inconsistent terminal acquisition."
                    )

                status = lifecycle.process_status

                if status not in (
                    ProcessAcquisitionStatus.TIMED_OUT,
                    ProcessAcquisitionStatus.WORKER_FAILED,
                    ProcessAcquisitionStatus.UNREAPED,
                ):
                    raise AcquisitionGovernanceError(
                        "Invalid terminal process outcome."
                    )

                result = GovernedAcquisitionResult(lifecycle=lifecycle)

                # The full byte reservation remains charged.
                entry.lifecycle_handle = None
                entry.handle = None
                entry.busy = False

                if status is ProcessAcquisitionStatus.TIMED_OUT:
                    # The existing process adapter reports this only
                    # when the worker has been confirmed reaped.
                    self._slots_in_use -= 1
                else:
                    # Without a reliable reap acknowledgement, retain
                    # the slot and refuse all further admissions.
                    self._unknown_slots += 1
                    self._halted = True

                return result

        except BaseException:
            with self._lock:
                # No reliable accounting may be available. Preserve
                # the reservation and held worker slot, and halt.
                self._halted = True
                self._unknown_slots += 1
                entry.lifecycle_handle = None
                entry.handle = None
                entry.busy = False
            raise

    def terminate(self, *, handle: GovernorHandle) -> None:
        """End one active supervisor, without refunding past usage."""
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)
            assert entry.lifecycle_handle is not None

            try:
                entry.supervisor.terminate(handle=entry.lifecycle_handle)
            except BaseException:
                self._halted = True
                raise

            entry.lifecycle_handle = None
            entry.handle = None

    def invalidate(self, *, handle: GovernorHandle) -> None:
        """Revoke one active supervisor, without refunding past usage."""
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)
            assert entry.lifecycle_handle is not None

            try:
                entry.supervisor.invalidate(handle=entry.lifecycle_handle)
            except BaseException:
                self._halted = True
                raise

            entry.lifecycle_handle = None
            entry.handle = None


def create_resource_governor(
    *,
    policy: GovernorPolicy,
) -> AcquisitionResourceGovernor:
    """Create one coordinator with a shared in-process budget."""
    return AcquisitionResourceGovernor(policy=policy)
