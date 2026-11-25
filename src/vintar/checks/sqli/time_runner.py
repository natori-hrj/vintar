"""Execute experimental time-based SQLi probes through a scoped context.

The runner owns plan construction and all observations for one run.
It does not prove SQL execution and is not connected to production
findings, CLI commands, or CI security gates.

The deadline is cooperative: no new dispatch is permitted after
expiry, but active synchronous I/O cannot be forcibly interrupted.
"""

import hashlib
import math
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field, replace

import httpx

from vintar.checks.sqli._errors import redact_runtime_errors
from vintar.checks.sqli.decision_facts import (
    OperationalCondition,
    TimeOperationalCondition,
    response_operational_condition,
)
from vintar.checks.sqli.observation_sink import (
    AttemptOutcome,
    SqliObservationSink,
    emit_attempt_stop,
    emit_observation,
)
from vintar.checks.sqli.time_analyzer import (
    TimeAnalysis,
    TimeAnalysisStatus,
    TimeObservation,
    TimeProbeOutcome,
    analyze_time_probes,
    time_operational_decision_facts,
    time_response_signature,
)
from vintar.checks.sqli.time_plan import (
    TIME_PROBE_ORDER,
    TIME_REQUESTS,
    TimePayloads,
    TimeProbeKind,
    prepare_time_plan,
)
from vintar.core.budget import RequestBudgetExceededError
from vintar.core.executor import ExecutionContext
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimitInterruptedError
from vintar.core.request import InjectionPoint, RequestTemplate
from vintar.core.transport import ExecutionDeadlineExceededError

MAX_TOTAL_SECONDS = 120.0


@dataclass(frozen=True, slots=True, repr=False)
class TimeRunReport:
    """Sanitized accounting for one experimental execution.

    Budget usage may exceed transport dispatches because the budget
    is consumed before rate-limiter acquisition and dispatch.
    """

    analysis: TimeAnalysis = field(repr=False)
    budget_used: int
    transport_attempts: int
    total_elapsed_seconds: float
    deadline_exceeded: bool

    def __post_init__(self) -> None:
        if type(self.analysis) is not TimeAnalysis:
            raise TypeError("Invalid time run analysis.")

        if type(self.budget_used) is not int:
            raise TypeError("Invalid time run budget usage.")

        if type(self.transport_attempts) is not int:
            raise TypeError("Invalid time run dispatch count.")

        if not (0 <= self.transport_attempts <= self.budget_used <= TIME_REQUESTS):
            raise ValueError("Invalid time run request accounting.")

        if self.budget_used != self.analysis.request_count:
            raise ValueError("Invalid time run observation count.")

        if self.budget_used - self.transport_attempts > 1:
            raise ValueError("Invalid time run dispatch count.")

        if (
            self.transport_attempts < self.budget_used
            and self.analysis.reason_code != "probe_interrupted"
        ):
            raise ValueError("Invalid time run dispatch outcome.")

        elapsed = self.total_elapsed_seconds

        if type(elapsed) is not int and type(elapsed) is not float:
            raise TypeError("Invalid time run duration.")

        if not 0 <= elapsed <= 1_000_000 or not math.isfinite(elapsed):
            raise ValueError("Invalid time run duration.")

        if type(self.deadline_exceeded) is not bool:
            raise TypeError("Invalid time run deadline flag.")

        if self.deadline_exceeded and (
            self.analysis.status is not TimeAnalysisStatus.INCONCLUSIVE
            or self.analysis.reason_code
            not in {"incomplete_probes", "probe_interrupted"}
        ):
            raise ValueError("Invalid time run deadline outcome.")


def _validate_total_seconds(value: object) -> float:
    if type(value) is not int and type(value) is not float:
        raise TypeError("Invalid total time limit.")

    if not 0 < value <= MAX_TOTAL_SECONDS or not math.isfinite(value):
        raise ValueError("Invalid total time limit.")

    return float(value)


def _read_clock(clock: Callable[[], float]) -> float:
    value = clock()
    if (
        (type(value) is not int and type(value) is not float)
        or not -sys.float_info.max <= value <= sys.float_info.max
        or not math.isfinite(value)
    ):
        raise RuntimeError("Time verification clock failed.")
    return float(value)


def verify_time_based_sqli(
    *,
    template: RequestTemplate,
    point: InjectionPoint,
    payloads: TimePayloads,
    expected_delay_seconds: float,
    context: ExecutionContext,
    max_total_seconds: float = 45.0,
    transport: httpx.BaseTransport | None = None,
    clock: Callable[[], float] = time.monotonic,
    observation_sink: SqliObservationSink | None = None,
) -> TimeRunReport:
    """Run one bounded experimental timing verification.

    All nine requests are preflighted before any HTTP I/O.

    The caller must authorize the target and use an isolated,
    single-threaded ExecutionContext with nine unused budget slots.

    A transport supplied by the caller is a trusted test dependency.
    """
    total_limit = _validate_total_seconds(max_total_seconds)

    if type(context) is not ExecutionContext:
        raise TypeError("Invalid time execution context.")

    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError("Invalid time execution transport.")

    if not callable(clock):
        raise TypeError("Invalid time execution clock.")

    started = _read_clock(clock)

    budget_is_fresh = (
        context.budget.max_requests == TIME_REQUESTS
        and context.budget.used_requests == 0
        and context.budget.remaining == TIME_REQUESTS
    )
    if not budget_is_fresh:
        emit_attempt_stop(
            observation_sink,
            family="time",
            sequence=1,
            kind=TimeProbeKind.BASELINE.value,
            outcome=AttemptOutcome.NOT_DISPATCHED,
            failure=OperationalCondition.BUDGET_UNAVAILABLE,
        )
    try:
        plan = prepare_time_plan(
            template=template,
            point=point,
            payloads=payloads,
            expected_delay_seconds=expected_delay_seconds,
            context=context,
        )
    except (TypeError, ValueError):
        if budget_is_fresh:
            emit_attempt_stop(
                observation_sink,
                family="time",
                sequence=1,
                kind=TimeProbeKind.BASELINE.value,
                outcome=AttemptOutcome.NOT_DISPATCHED,
                failure=OperationalCondition.PREFLIGHT_FAILED,
            )
        raise

    deadline = started + total_limit
    if not math.isfinite(deadline):
        raise RuntimeError("Time verification clock failed.")
    observations: list[TimeObservation] = []
    transport_attempts = 0
    deadline_exceeded = False

    def finish() -> TimeRunReport:
        with redact_runtime_errors("Time verification analysis failed."):
            finished = _read_clock(clock)
            if finished < started:
                raise RuntimeError("Time verification clock failed.")

            analysis = analyze_time_probes(
                plan=plan,
                observations=tuple(observations),
            )
            if deadline_exceeded:
                if analysis.reason_code == "incomplete_probes":
                    sequence = len(observations) + 1
                    probe_kind = TIME_PROBE_ORDER[sequence - 1]
                else:
                    stopping = observations[-1]
                    sequence = stopping.sequence
                    probe_kind = stopping.kind
                analysis = replace(
                    analysis,
                    decision_facts=time_operational_decision_facts(
                        reason_code=analysis.reason_code,
                        sequence=sequence,
                        probe_kind=probe_kind,
                        deadline=True,
                    ),
                )

            report = TimeRunReport(
                analysis=analysis,
                budget_used=context.budget.used_requests,
                transport_attempts=transport_attempts,
                total_elapsed_seconds=max(0.0, finished - started),
                deadline_exceeded=deadline_exceeded,
            )

        return report

    for sequence, step in enumerate(plan.steps, start=1):
        remaining = deadline - _read_clock(clock)

        if remaining <= 0:
            deadline_exceeded = True
            emit_attempt_stop(
                observation_sink,
                family="time",
                sequence=sequence,
                kind=step.kind.value,
                outcome=AttemptOutcome.NOT_DISPATCHED,
                failure=TimeOperationalCondition.DEADLINE,
            )
            return finish()

        if context.budget.remaining <= 0:
            raise RuntimeError("Time verification request budget exhausted.")

        rate_wait_seconds = 0.0

        def observe_rate_wait(value: float) -> None:
            nonlocal rate_wait_seconds
            rate_wait_seconds = value

        def observe_dispatch() -> None:
            nonlocal transport_attempts
            transport_attempts += 1

        outcome: TimeProbeOutcome | None = None
        response: HttpResult | None = None
        budget_before = context.budget.used_requests

        try:
            with redact_runtime_errors(
                "Time verification execution failed.",
                passthrough=(
                    ExecutionDeadlineExceededError,
                    RateLimitInterruptedError,
                    httpx.RequestError,
                    RequestBudgetExceededError,
                ),
            ):
                response = context.execute(
                    step.template,
                    transport=transport,
                    request_timeout=min(
                        float(context.timeout),
                        remaining,
                    ),
                    deadline=deadline,
                    on_rate_wait=observe_rate_wait,
                    on_dispatch=observe_dispatch,
                    clock=clock,
                )

        except ExecutionDeadlineExceededError:
            deadline_exceeded = True
            if context.budget.used_requests == budget_before:
                emit_attempt_stop(
                    observation_sink,
                    family="time",
                    sequence=sequence,
                    kind=step.kind.value,
                    outcome=AttemptOutcome.NOT_DISPATCHED,
                    failure=TimeOperationalCondition.DEADLINE,
                )
                return finish()
            outcome = TimeProbeOutcome.INTERRUPTED

        except RateLimitInterruptedError:
            outcome = TimeProbeOutcome.INTERRUPTED

        except httpx.TimeoutException:
            outcome = TimeProbeOutcome.TIMEOUT

        except httpx.RequestError:
            outcome = TimeProbeOutcome.REQUEST_FAILED

        except RequestBudgetExceededError:
            raise RuntimeError("Time verification request budget exhausted.") from None

        if response is not None:
            if type(response) is not HttpResult:
                raise RuntimeError("Time verification execution failed.")

            if _read_clock(clock) >= deadline:
                # A response completed after the run deadline is not
                # eligible for a timing classification.
                deadline_exceeded = True
                outcome = TimeProbeOutcome.INTERRUPTED

            else:
                # HttpResult.elapsed begins before ScopedTransport
                # acquires the limiter. Remove the measured acquire
                # duration from the response observation.
                elapsed = response.elapsed - rate_wait_seconds
                if elapsed < -1e-6:
                    raise RuntimeError("Time verification timing failed.")
                elapsed = max(0.0, elapsed)

                try:
                    observation = TimeObservation(
                        kind=step.kind,
                        sequence=sequence,
                        outcome=TimeProbeOutcome.COMPLETED,
                        elapsed_seconds=elapsed,
                        status_code=response.status_code,
                        truncated=response.truncated,
                        rate_wait_seconds=rate_wait_seconds,
                    )
                    observations.append(observation)
                    emit_observation(
                        observation_sink,
                        family="time",
                        sequence=sequence,
                        kind=step.kind.value,
                        observation=time_response_signature(
                            observation,
                            body_size=response.size,
                            body_digest=hashlib.sha256(response.body).hexdigest(),
                        ),
                    )
                except (TypeError, ValueError, OverflowError):
                    raise RuntimeError(
                        "Time verification observation failed."
                    ) from None

                if (
                    response_operational_condition(
                        response.status_code, truncated=response.truncated
                    )
                    is not None
                ):
                    return finish()

                continue

        if outcome is None:
            raise RuntimeError("Time verification execution failed.")

        try:
            observation = TimeObservation(
                kind=step.kind,
                sequence=sequence,
                outcome=outcome,
                rate_wait_seconds=rate_wait_seconds,
            )
            observations.append(observation)
            emit_attempt_stop(
                observation_sink,
                family="time",
                sequence=sequence,
                kind=step.kind.value,
                outcome=AttemptOutcome.NO_RESPONSE,
                failure=(
                    TimeOperationalCondition.DEADLINE if deadline_exceeded else outcome
                ),
            )
        except (TypeError, ValueError, OverflowError):
            raise RuntimeError("Time verification observation failed.") from None

        return finish()

    return finish()
