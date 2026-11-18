"""Shared resource governance with optional in-memory audit integration.

Audited mode serializes accounting transitions and hash-chained audit
appends under the governor lock. An audit failure halts admissions.
This is not durable or cryptographically authenticated audit logging.
"""

import math
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

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

if TYPE_CHECKING:
    from vintar.checks.sqli.time_evidence_audit import (
        AcquisitionAuditJournal,
        AuditRecord,
        AuditVerification,
    )


class AcquisitionGovernanceError(RuntimeError):
    """The requested operation violates the governor's state."""


class ResourceBudgetError(AcquisitionGovernanceError):
    """A shared resource reservation cannot be admitted."""


class AcquisitionAuditError(AcquisitionGovernanceError):
    """Required audit recording failed and admissions were halted."""


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
    """Immutable accounting snapshot, not a trusted audit record."""

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
        """Not administratively halted; individual admission may still fail."""
        return not self.halted


@dataclass(frozen=True, slots=True, repr=False)
class GovernedAcquisitionResult:
    """Supervised result with an optional next governor handle."""

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
    """Own supervised runs and shared in-process acquisition budgets.

    In audited mode, the journal is owned by this governor. All journal
    appends and resource-state transitions occur under the governor lock.
    Blocking acquisitions execute without holding that lock.
    """

    def __init__(
        self,
        *,
        policy: GovernorPolicy,
        audited: bool = False,
    ) -> None:
        if type(policy) is not GovernorPolicy:
            raise TypeError("Invalid governor policy.")
        if type(audited) is not bool:
            raise TypeError("Invalid audited mode.")

        self._policy = policy
        self._lock = threading.RLock()
        self._entries: dict[str, _Entry] = {}
        self._files_used = 0
        self._bytes_used = 0
        self._slots_in_use = 0
        self._unknown_slots = 0
        self._halted = False
        self._audit_pending = 0

        self._journal: AcquisitionAuditJournal | None = None
        if audited:
            # Local import avoids the AuditEvent -> GovernorUsage cycle.
            from vintar.checks.sqli.time_evidence_audit import (
                AcquisitionAuditJournal as AuditJournal,
            )

            self._journal = AuditJournal()

    @property
    def policy(self) -> GovernorPolicy:
        return self._policy

    @property
    def audit_enabled(self) -> bool:
        return self._journal is not None

    def _usage_unlocked(self) -> GovernorUsage:
        return GovernorUsage(
            files_used=self._files_used,
            bytes_used=self._bytes_used,
            slots_in_use=self._slots_in_use,
            unknown_slots=self._unknown_slots,
            halted=self._halted,
        )

    def usage(self) -> GovernorUsage:
        with self._lock:
            return self._usage_unlocked()

    def audit_snapshot(self) -> tuple["AuditRecord", ...]:
        """Return the owned journal's immutable record snapshot."""
        with self._lock:
            if self._journal is None:
                raise AcquisitionGovernanceError("Audit mode is disabled.")
            return self._journal.snapshot()

    def audit_verify(self) -> "AuditVerification":
        """Verify the current in-memory chain against its current head."""
        with self._lock:
            if self._journal is None:
                raise AcquisitionGovernanceError("Audit mode is disabled.")
            return self._journal.verify()

    def _audit_capacity(self, additional: int) -> None:
        """Reserve room for outstanding completion events."""
        if self._journal is None:
            return

        from vintar.checks.sqli.time_evidence_audit import MAX_AUDIT_RECORDS

        if (
            self._journal.record_count + self._audit_pending + additional
            > MAX_AUDIT_RECORDS
        ):
            raise ResourceBudgetError("Governor audit capacity exhausted.")

    def _emit(
        self,
        event_type: str,
        *,
        usage: GovernorUsage,
        run_id: str | None = None,
        evidence_id: str | None = None,
        process_status: ProcessAcquisitionStatus | None = None,
    ) -> None:
        if self._journal is None:
            return

        from vintar.checks.sqli.time_evidence_audit import (
            AuditEvent,
            AuditEventType,
        )

        self._journal.append(
            event=AuditEvent(
                event_type=AuditEventType(event_type),
                usage=usage,
                run_id=run_id,
                evidence_id=evidence_id,
                process_status=process_status,
            )
        )

    def _best_effort_halt_event(
        self,
        *,
        run_id: str | None,
        process_status: ProcessAcquisitionStatus | None = None,
    ) -> None:
        """A failed journal must never prevent the governor from halting."""
        try:
            self._emit(
                "halted",
                usage=self._usage_unlocked(),
                run_id=run_id,
                process_status=process_status,
            )
        except BaseException:  # noqa: BLE001 - halt recording is best-effort
            return

    def _audit_failure(
        self,
        *,
        run_id: str | None,
        cause: BaseException,
    ) -> None:
        self._halted = True
        self._best_effort_halt_event(run_id=run_id)
        raise AcquisitionAuditError(
            "Acquisition audit recording failed; admissions halted."
        ) from cause

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

    def register(
        self,
        *,
        session: VerificationSession,
        policy: AcquisitionPolicy,
    ) -> GovernorHandle:
        with self._lock:
            self._require_running()

            if len(self._entries) >= MAX_EVIDENCE_RECORDS:
                raise ResourceBudgetError("Governor registration limit reached.")

            self._audit_capacity(1)

            supervisor = AcquisitionSupervisor(
                session=session,
                policy=policy,
            )
            lifecycle_handle = supervisor.initial_handle()
            run_id = supervisor.run_id

            if run_id in self._entries:
                raise AcquisitionGovernanceError("Duplicate supervisor identifier.")

            handle = GovernorHandle(run_id=run_id, generation=0)

            try:
                self._emit(
                    "registered",
                    usage=self._usage_unlocked(),
                    run_id=run_id,
                )
            except BaseException as exc:  # noqa: BLE001 - fail closed on aborts
                self._audit_failure(run_id=run_id, cause=exc)

            self._entries[run_id] = _Entry(
                supervisor=supervisor,
                lifecycle_handle=lifecycle_handle,
                handle=handle,
            )
            return handle

    def snapshot(self, *, handle: GovernorHandle) -> AcquisitionRun:
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)
            assert entry.lifecycle_handle is not None
            return entry.supervisor.snapshot(handle=entry.lifecycle_handle)

    def _validate_request(
        self,
        *,
        run: AcquisitionRun,
        evidence_id: str,
        root: str | Path,
        relative_path: str,
        timeout_seconds: float,
    ) -> int:
        if run.binding.index.get(evidence_id) is None:
            raise ValueError("Evidence identifier is not bound.")

        if any(item.evidence_id == evidence_id for item in run.attempts):
            raise ValueError("Evidence already attempted in this run.")

        if not run.remaining_files:
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

        return min(MAX_EVIDENCE_BYTES, run.remaining_bytes)

    def _validate_completed(
        self,
        *,
        lifecycle: LifecycleAcquisitionResult,
        old_run: AcquisitionRun,
        lifecycle_handle: AcquisitionHandle,
        handle: GovernorHandle,
        evidence_id: str,
        reservation: int,
        entry: _Entry,
    ) -> tuple[AcquisitionRun, GovernorHandle]:
        if (
            lifecycle.process_status is not ProcessAcquisitionStatus.COMPLETED
            or lifecycle.handle is None
            or lifecycle.run is None
        ):
            raise AcquisitionGovernanceError("Inconsistent completed acquisition.")

        new_run = lifecycle.run

        if (
            type(new_run) is not AcquisitionRun
            or new_run.binding is not old_run.binding
            or new_run.policy is not old_run.policy
            or new_run.started_at != old_run.started_at
            or len(new_run.attempts) != len(old_run.attempts) + 1
            or new_run.attempts[:-1] != old_run.attempts
            or new_run.attempts[-1].evidence_id != evidence_id
            or lifecycle.handle.generation != lifecycle_handle.generation + 1
            or lifecycle.handle.run_id != handle.run_id
            or entry.supervisor.snapshot(handle=lifecycle.handle) is not new_run
        ):
            raise AcquisitionGovernanceError("Inconsistent supervised run.")

        consumed = new_run.attempts[-1].bytes_read
        if not 0 <= consumed <= reservation:
            raise AcquisitionGovernanceError("Acquisition exceeded reserved bytes.")

        next_handle = GovernorHandle(
            run_id=handle.run_id,
            generation=handle.generation + 1,
        )
        return new_run, next_handle

    def _freeze_after_exception(
        self,
        *,
        entry: _Entry,
        run_id: str,
        was_busy: bool,
    ) -> None:
        """Halt and retain uncertain reservations without double counting."""
        with self._lock:
            self._halted = True

            if was_busy and entry.busy:
                self._unknown_slots += 1
                self._audit_pending -= 2
                entry.busy = False

            entry.lifecycle_handle = None
            entry.handle = None
            self._best_effort_halt_event(run_id=run_id)

    def acquire(
        self,
        *,
        handle: GovernorHandle,
        evidence_id: str,
        root: str | Path,
        relative_path: str,
        timeout_seconds: float = 5.0,
    ) -> GovernedAcquisitionResult:
        """Reserve and account for one supervised acquisition.

        Audit appends and accounting transitions are serialized under
        the governor lock. A failed required append halts admissions.
        """
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)
            assert entry.lifecycle_handle is not None

            old_run = entry.supervisor.snapshot(handle=entry.lifecycle_handle)
            reservation = self._validate_request(
                run=old_run,
                evidence_id=evidence_id,
                root=root,
                relative_path=relative_path,
                timeout_seconds=timeout_seconds,
            )

            if self._files_used >= self._policy.max_files:
                raise ResourceBudgetError("Governor file budget exhausted.")

            if self._slots_in_use >= self._policy.max_workers:
                raise ResourceBudgetError("Governor worker limit reached.")

            if self._bytes_used + reservation > self._policy.max_total_bytes:
                raise ResourceBudgetError("Governor byte budget insufficient.")

            # One RESERVED plus two potential terminal records.
            self._audit_capacity(3)

            projected = GovernorUsage(
                files_used=self._files_used + 1,
                bytes_used=self._bytes_used + reservation,
                slots_in_use=self._slots_in_use + 1,
                unknown_slots=self._unknown_slots,
                halted=self._halted,
            )

            try:
                self._emit(
                    "reserved",
                    usage=projected,
                    run_id=handle.run_id,
                    evidence_id=evidence_id,
                )
            except BaseException as exc:  # noqa: BLE001 - fail closed on aborts
                self._audit_failure(run_id=handle.run_id, cause=exc)

            self._files_used += 1
            self._bytes_used += reservation
            self._slots_in_use += 1
            self._audit_pending += 2
            entry.busy = True
            lifecycle_handle = entry.lifecycle_handle

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
                    new_run, next_handle = self._validate_completed(
                        lifecycle=lifecycle,
                        old_run=old_run,
                        lifecycle_handle=lifecycle_handle,
                        handle=handle,
                        evidence_id=evidence_id,
                        reservation=reservation,
                        entry=entry,
                    )
                    result = GovernedAcquisitionResult(
                        lifecycle=lifecycle,
                        handle=next_handle,
                    )

                    self._bytes_used -= reservation - new_run.attempts[-1].bytes_read
                    self._slots_in_use -= 1
                    self._audit_pending -= 2
                    entry.lifecycle_handle = lifecycle.handle
                    entry.handle = next_handle
                    entry.busy = False

                    self._emit(
                        "settled",
                        usage=self._usage_unlocked(),
                        run_id=handle.run_id,
                        evidence_id=evidence_id,
                        process_status=ProcessAcquisitionStatus.COMPLETED,
                    )
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

                entry.lifecycle_handle = None
                entry.handle = None
                entry.busy = False
                self._audit_pending -= 2

                if status is ProcessAcquisitionStatus.TIMED_OUT:
                    self._slots_in_use -= 1
                    self._emit(
                        "settled",
                        usage=self._usage_unlocked(),
                        run_id=handle.run_id,
                        evidence_id=evidence_id,
                        process_status=status,
                    )
                    self._emit(
                        "invalidated",
                        usage=self._usage_unlocked(),
                        run_id=handle.run_id,
                        evidence_id=evidence_id,
                        process_status=status,
                    )
                else:
                    self._unknown_slots += 1
                    self._halted = True
                    self._emit(
                        "invalidated",
                        usage=self._usage_unlocked(),
                        run_id=handle.run_id,
                        evidence_id=evidence_id,
                        process_status=status,
                    )
                    self._emit(
                        "halted",
                        usage=self._usage_unlocked(),
                        run_id=handle.run_id,
                        process_status=status,
                    )

                return result

        except BaseException:
            self._freeze_after_exception(
                entry=entry,
                run_id=handle.run_id,
                was_busy=True,
            )
            raise

    def terminate(self, *, handle: GovernorHandle) -> None:
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)
            assert entry.lifecycle_handle is not None
            self._audit_capacity(1)

            try:
                entry.supervisor.terminate(handle=entry.lifecycle_handle)
                entry.lifecycle_handle = None
                entry.handle = None
                self._emit(
                    "terminated",
                    usage=self._usage_unlocked(),
                    run_id=handle.run_id,
                )
            except BaseException:
                self._halted = True
                entry.lifecycle_handle = None
                entry.handle = None
                self._best_effort_halt_event(run_id=handle.run_id)
                raise

    def invalidate(self, *, handle: GovernorHandle) -> None:
        with self._lock:
            self._require_running()
            entry = self._require_entry(handle)
            assert entry.lifecycle_handle is not None
            self._audit_capacity(1)

            try:
                entry.supervisor.invalidate(handle=entry.lifecycle_handle)
                entry.lifecycle_handle = None
                entry.handle = None
                self._emit(
                    "invalidated",
                    usage=self._usage_unlocked(),
                    run_id=handle.run_id,
                )
            except BaseException:
                self._halted = True
                entry.lifecycle_handle = None
                entry.handle = None
                self._best_effort_halt_event(run_id=handle.run_id)
                raise


def create_resource_governor(
    *,
    policy: GovernorPolicy,
    audited: bool = False,
) -> AcquisitionResourceGovernor:
    """Create a shared governor with optional owned audit journal."""
    return AcquisitionResourceGovernor(
        policy=policy,
        audited=audited,
    )
