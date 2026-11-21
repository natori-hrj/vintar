"""Execute the fixed four-request error-based SQLi plan through trusted context."""

from dataclasses import dataclass, field

import httpx

from vintar.checks.sqli.error_analyzer import (
    ERROR_PROBE_ORDER,
    ErrorAnalysis,
    ErrorObservation,
    ErrorProbeFailure,
    ErrorProbeKind,
    analyze_error_responses,
    error_observation,
    operational_stop_reason,
    validate_error_probe_payload,
)
from vintar.checks.sqli.error_contract import ErrorAnalysisStatus
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
) -> ErrorAnalysis:
    return ErrorAnalysis(
        status=ErrorAnalysisStatus.INCONCLUSIVE,
        reason_code=reason_code,
        observations=tuple(observations),
        failures=tuple(failures),
    )


def verify_error_based_sqli(
    *,
    template: RequestTemplate,
    point: InjectionPoint,
    error_payload: str,
    context: ExecutionContext,
    transport: httpx.BaseTransport | None = None,
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
    payload = validate_error_probe_payload(error_payload)
    probe = inject(template, point, payload)
    if probe == template:
        raise ValueError(
            "Error probe matches the baseline. Check the query injection target, occurrence, mode, and explicit payload."
        )
    for planned in (template, probe):
        validate_template(planned)
        validate_scope(planned.url, context.scope)
    if context.budget.remaining < ERROR_REQUESTS:
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

    def finish_operational(reason_code: str) -> ErrorRunReport:
        return finish(_operational_analysis(observations, failures, reason_code))

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
            failure = ErrorProbeFailure(kind, sequence, "probe_interrupted")
            failures.append(failure)
            return finish_operational(operational_stop_reason(failure))
        except httpx.TimeoutException:
            failure = ErrorProbeFailure(kind, sequence, "probe_timeout")
            failures.append(failure)
            return finish_operational(operational_stop_reason(failure))
        except httpx.RequestError:
            failure = ErrorProbeFailure(kind, sequence, "probe_failed")
            failures.append(failure)
            return finish_operational(operational_stop_reason(failure))

        observation = error_observation(kind, sequence, response)
        observations.append(observation)
        responses[kind].append(response)
        stop_reason = operational_stop_reason(observation)
        if stop_reason is not None:
            return finish_operational(stop_reason)

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
