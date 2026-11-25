"""Execute the fixed four-request error-based SQLi plan through trusted context."""

from dataclasses import dataclass, field

import httpx

from vintar.checks.sqli.decision_facts import (
    OperationalCondition,
    OperationalDecisionFacts,
)
from vintar.checks.sqli.error_analyzer import (
    ERROR_PROBE_ORDER,
    ErrorAnalysis,
    ErrorObservation,
    ErrorProbeFailure,
    ErrorProbeKind,
    analyze_error_responses,
    error_observation,
    error_operational_decision_facts,
    error_probe_failure_reason,
    operational_stop_reason,
    validate_error_probe_payload,
)
from vintar.checks.sqli.error_contract import ErrorAnalysisStatus
from vintar.checks.sqli.models import ProbeError
from vintar.checks.sqli.observation_sink import (
    AttemptOutcome,
    SqliObservationSink,
    emit_attempt_stop,
    emit_observation,
)
from vintar.checks.sqli.orchestrator import classify_probe_error
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimitInterruptedError
from vintar.core.request import InjectionPoint, RequestTemplate
from vintar.core.scope import validate_scope
from vintar.core.template import validate_template

ERROR_REQUESTS = 4


@dataclass(frozen=True, slots=True, repr=False)
class ErrorRunReport:
    """Sanitized analysis and exact request/transport accounting."""

    analysis: ErrorAnalysis = field(repr=False)
    budget_used: int
    transport_attempts: int

    def __post_init__(self) -> None:
        if type(self.analysis) is not ErrorAnalysis:
            raise TypeError(
                "Invalid error run analysis. Supply an ErrorAnalysis produced by the analyzer or bounded runner."
            )
        if (
            type(self.budget_used) is not int
            or type(self.transport_attempts) is not int
        ):
            raise TypeError(
                "Invalid error run request accounting. Supply integer budget and transport-attempt counts."
            )
        if not 0 <= self.transport_attempts <= self.budget_used <= ERROR_REQUESTS:
            raise ValueError(
                "Invalid error run request accounting. Use counts from zero through the four-request budget, with transport attempts no greater than reserved requests."
            )
        if self.budget_used != self.analysis.request_count:
            raise ValueError(
                "Error run budget usage must equal recorded attempts. Use the ExecutionContext budget delta for this run."
            )
        if self.budget_used - self.transport_attempts > 1:
            raise ValueError(
                "Invalid error run dispatch accounting. Record at most one terminal attempt that stopped before transport dispatch."
            )


def _operational_analysis(
    observations: list[ErrorObservation],
    failures: list[ErrorProbeFailure],
    reason_code: str,
    decision_facts: OperationalDecisionFacts,
) -> ErrorAnalysis:
    return ErrorAnalysis(
        status=ErrorAnalysisStatus.INCONCLUSIVE,
        reason_code=reason_code,
        observations=tuple(observations),
        failures=tuple(failures),
        decision_facts=decision_facts,
    )


def verify_error_based_sqli(
    *,
    template: RequestTemplate,
    point: InjectionPoint,
    error_payload: str,
    context: ExecutionContext,
    transport: httpx.BaseTransport | None = None,
    observation_sink: SqliObservationSink | None = None,
) -> ErrorRunReport:
    """Run baseline, probe, baseline, probe with no retries."""
    if type(template) is not RequestTemplate:
        raise TypeError(
            "Invalid error verification template. Supply a validated RequestTemplate."
        )
    if type(point) is not InjectionPoint:
        raise TypeError(
            "Invalid error injection point. Supply a validated query InjectionPoint."
        )
    if type(context) is not ExecutionContext:
        raise TypeError(
            "Invalid error execution context. Supply an ExecutionContext with trusted scope and budget."
        )
    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError(
            "Invalid error execution transport. Supply an httpx BaseTransport or omit it."
        )
    try:
        payload = validate_error_probe_payload(error_payload)
        probe = inject(template, point, payload)
        if probe == template:
            raise ValueError(
                "Error probe matches the baseline. Check the query injection target, occurrence, mode, and explicit payload."
            )
        for planned in (template, probe):
            validate_template(planned)
            validate_scope(planned.url, context.scope)
    except (TypeError, ValueError):
        emit_attempt_stop(
            observation_sink,
            family="error",
            sequence=1,
            kind=ErrorProbeKind.BASELINE.value,
            outcome=AttemptOutcome.NOT_DISPATCHED,
            failure=OperationalCondition.PREFLIGHT_FAILED,
        )
        raise
    if context.budget.remaining < ERROR_REQUESTS:
        emit_attempt_stop(
            observation_sink,
            family="error",
            sequence=1,
            kind=ErrorProbeKind.BASELINE.value,
            outcome=AttemptOutcome.NOT_DISPATCHED,
            failure=OperationalCondition.BUDGET_UNAVAILABLE,
        )
        raise ValueError(
            "Error SQLi requires four unused request slots. Supply a fresh four-request budget."
        )
    starting_budget_used = context.budget.used_requests

    plan = tuple(
        (kind, template if kind is ErrorProbeKind.BASELINE else probe)
        for kind in ERROR_PROBE_ORDER
    )
    observations: list[ErrorObservation] = []
    failures: list[ErrorProbeFailure] = []
    responses: dict[ErrorProbeKind, list[HttpResult]] = {
        kind: [] for kind in ErrorProbeKind
    }
    transport_attempts = 0

    def finish(analysis: ErrorAnalysis) -> ErrorRunReport:
        return ErrorRunReport(
            analysis=analysis,
            budget_used=context.budget.used_requests - starting_budget_used,
            transport_attempts=transport_attempts,
        )

    def finish_operational(
        reason_code: str,
        *,
        sequence: int,
        kind: ErrorProbeKind,
        condition: ProbeError | OperationalCondition,
        status_code: int | None = None,
    ) -> ErrorRunReport:
        return finish(
            _operational_analysis(
                observations,
                failures,
                reason_code,
                error_operational_decision_facts(
                    reason_code=reason_code,
                    sequence=sequence,
                    kind=kind,
                    condition=condition,
                    status_code=status_code,
                ),
            )
        )

    for sequence, (kind, planned) in enumerate(plan, start=1):

        def observe_dispatch() -> None:
            nonlocal transport_attempts
            transport_attempts += 1

        try:
            response = context.execute(
                planned,
                transport=transport,
                on_dispatch=observe_dispatch,
            )
        except RateLimitInterruptedError:
            failure_reason = error_probe_failure_reason(ProbeError.RATE_LIMIT)
            failure = ErrorProbeFailure(kind, sequence, failure_reason)
            failures.append(failure)
            emit_attempt_stop(
                observation_sink,
                family="error",
                sequence=sequence,
                kind=kind.value,
                outcome=AttemptOutcome.NO_RESPONSE,
                failure=ProbeError.RATE_LIMIT,
            )
            return finish_operational(
                operational_stop_reason(failure),
                sequence=sequence,
                kind=kind,
                condition=ProbeError.RATE_LIMIT,
            )
        except httpx.TimeoutException:
            failure_reason = error_probe_failure_reason(ProbeError.TIMEOUT)
            failure = ErrorProbeFailure(kind, sequence, failure_reason)
            failures.append(failure)
            emit_attempt_stop(
                observation_sink,
                family="error",
                sequence=sequence,
                kind=kind.value,
                outcome=AttemptOutcome.NO_RESPONSE,
                failure=ProbeError.TIMEOUT,
            )
            return finish_operational(
                operational_stop_reason(failure),
                sequence=sequence,
                kind=kind,
                condition=ProbeError.TIMEOUT,
            )
        except httpx.RequestError as exc:
            condition = classify_probe_error(exc)
            failure_reason = error_probe_failure_reason(condition)
            failure = ErrorProbeFailure(kind, sequence, failure_reason)
            failures.append(failure)
            emit_attempt_stop(
                observation_sink,
                family="error",
                sequence=sequence,
                kind=kind.value,
                outcome=AttemptOutcome.NO_RESPONSE,
                failure=condition,
            )
            return finish_operational(
                operational_stop_reason(failure),
                sequence=sequence,
                kind=kind,
                condition=condition,
            )

        observation = error_observation(kind, sequence, response)
        observations.append(observation)
        emit_observation(
            observation_sink,
            family="error",
            sequence=sequence,
            kind=kind.value,
            observation=observation,
        )
        responses[kind].append(response)
        stop_reason = operational_stop_reason(observation)
        if stop_reason is not None:
            response_condition = (
                OperationalCondition.RATE_LIMITED
                if stop_reason == "rate_limited"
                else OperationalCondition.TRUNCATED
            )
            return finish_operational(
                stop_reason,
                sequence=sequence,
                kind=kind,
                condition=response_condition,
                status_code=observation.status_code,
            )

    analysis = analyze_error_responses(
        (
            responses[ErrorProbeKind.BASELINE][0],
            responses[ErrorProbeKind.BASELINE][1],
        ),
        (
            responses[ErrorProbeKind.PROBE][0],
            responses[ErrorProbeKind.PROBE][1],
        ),
        probe_payload=payload,
    )
    return finish(analysis)
