import hashlib

import httpx

from vintar.checks.sqli.analyzer import analyze_boolean_responses
from vintar.checks.sqli.models import (
    Observation,
    ProbeError,
    ProbeFailure,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.checks.sqli.observation_sink import (
    SqliObservationSink,
    emit_observation,
)
from vintar.core.budget import RequestBudgetExceededError
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimitInterruptedError
from vintar.core.request import InjectionPoint, RequestTemplate
from vintar.core.scope import validate_scope
from vintar.core.template import validate_template

BOOLEAN_PROBE_ORDER = (
    ProbeKind.BASELINE,
    ProbeKind.TRUE,
    ProbeKind.FALSE,
    ProbeKind.BASELINE,
    ProbeKind.FALSE,
    ProbeKind.TRUE,
)


def _observation(
    kind: ProbeKind,
    response: HttpResult,
) -> Observation:
    return Observation(
        kind=kind,
        status_code=response.status_code,
        body_size=response.size,
        elapsed=response.elapsed,
        body_digest=hashlib.sha256(response.body).hexdigest(),
        truncated=response.truncated,
    )


def _probe_error(exc: httpx.RequestError) -> ProbeError:
    if isinstance(exc, httpx.TimeoutException):
        return ProbeError.TIMEOUT
    if isinstance(exc, httpx.ConnectError):
        return ProbeError.CONNECTION
    if isinstance(
        exc,
        (httpx.ReadError, httpx.RemoteProtocolError, httpx.DecodingError),
    ):
        return ProbeError.RESPONSE_READ
    return ProbeError.UNKNOWN


def query_value_at_point(template: RequestTemplate, point: InjectionPoint) -> str:
    occurrence = 0
    for name, value in template.params:
        if name != point.name:
            continue
        if occurrence == point.occurrence:
            return value
        occurrence += 1
    raise ValueError(
        "The Boolean injection target disappeared after preflight. Check the "
        "request template and injection occurrence instead of executing probes."
    )


def _emit_in_request_order(
    sink: SqliObservationSink | None,
    plan: tuple[tuple[ProbeKind, RequestTemplate], ...],
    observations: tuple[Observation, ...],
) -> None:
    by_kind = {
        kind: [item for item in observations if item.kind is kind] for kind in ProbeKind
    }
    offsets = {kind: 0 for kind in ProbeKind}
    for sequence, (kind, _) in enumerate(plan, start=1):
        index = offsets[kind]
        if index >= len(by_kind[kind]):
            break
        emit_observation(
            sink,
            family="boolean",
            sequence=sequence,
            kind=kind.value,
            observation=by_kind[kind][index],
        )
        offsets[kind] += 1


def verify_boolean_sqli(
    *,
    check_id: str,
    template: RequestTemplate,
    point: InjectionPoint,
    true_payload: str,
    false_payload: str,
    context: ExecutionContext,
    transport: httpx.BaseTransport | None = None,
    observation_sink: SqliObservationSink | None = None,
) -> VerificationResult:
    """Run six bounded Boolean probes through ExecutionContext.

    Only use against explicitly authorized origins.

    Custom transports are trusted test dependencies only.
    Never expose them to untrusted configuration.
    """
    if type(check_id) is not str:
        raise TypeError("check_id must be a string.")
    if not check_id.strip():
        raise ValueError("check_id cannot be empty.")

    if not isinstance(template, RequestTemplate):
        raise TypeError("template must be a RequestTemplate.")
    if not isinstance(point, InjectionPoint):
        raise TypeError("point must be an InjectionPoint.")
    if not isinstance(context, ExecutionContext):
        raise TypeError("context must be an ExecutionContext.")
    if transport is not None and not isinstance(transport, httpx.BaseTransport):
        raise TypeError("transport must be an httpx.BaseTransport or None.")

    if type(true_payload) is not str or type(false_payload) is not str:
        raise TypeError("Probe payloads must be strings.")

    if not true_payload or not false_payload:
        raise ValueError("Probe payloads cannot be empty.")

    if true_payload == false_payload:
        raise ValueError("TRUE and FALSE payloads must differ.")

    true_template = inject(template, point, true_payload)
    false_template = inject(template, point, false_payload)

    if true_template == template or false_template == template:
        raise ValueError("Injected probe templates must differ from the baseline.")

    # Validate the entire plan before the first HTTP request.
    planned_templates = (
        template,
        true_template,
        false_template,
    )
    for item in planned_templates:
        validate_template(item)
        validate_scope(item.url, context.scope)

    requests = {
        ProbeKind.BASELINE: template,
        ProbeKind.TRUE: true_template,
        ProbeKind.FALSE: false_template,
    }
    plan = tuple((kind, requests[kind]) for kind in BOOLEAN_PROBE_ORDER)

    if context.budget.remaining < len(plan):
        return VerificationResult(
            check_id=check_id,
            verdict=Verdict.INCONCLUSIVE,
            observations=(),
            failures=(),
            request_count=0,
            reason_code="budget_unavailable",
            reason="Insufficient request budget for six probes.",
        )

    observations: list[Observation] = []
    failures: list[ProbeFailure] = []
    responses: dict[ProbeKind, list[HttpResult]] = {kind: [] for kind in ProbeKind}

    for kind, request_template in plan:
        try:
            response = context.execute(
                request_template,
                transport=transport,
            )
        except RequestBudgetExceededError:
            failures.append(
                ProbeFailure(
                    kind=kind,
                    error=ProbeError.BUDGET_EXCEEDED,
                )
            )
            break
        except RateLimitInterruptedError:
            failures.append(
                ProbeFailure(
                    kind=kind,
                    error=ProbeError.RATE_LIMIT,
                )
            )
            break
        except httpx.RequestError as exc:
            failures.append(
                ProbeFailure(
                    kind=kind,
                    error=_probe_error(exc),
                )
            )
            break

        observation = _observation(kind, response)
        observations.append(observation)
        responses[kind].append(response)

        if response.status_code == 429:
            _emit_in_request_order(observation_sink, plan, tuple(observations))
            return VerificationResult(
                check_id=check_id,
                verdict=Verdict.INCONCLUSIVE,
                observations=tuple(observations),
                failures=tuple(failures),
                request_count=len(observations) + len(failures),
                reason_code="rate_limited",
                reason=(
                    "The target returned HTTP 429. Remaining probes were not sent."
                ),
            )

    if failures:
        _emit_in_request_order(observation_sink, plan, tuple(observations))
        return VerificationResult(
            check_id=check_id,
            verdict=Verdict.INCONCLUSIVE,
            observations=tuple(observations),
            failures=tuple(failures),
            request_count=len(observations) + len(failures),
            reason_code="probe_failed",
            reason="A probe failed before verification completed.",
        )

    result = analyze_boolean_responses(
        check_id=check_id,
        baseline=(responses[ProbeKind.BASELINE][0], responses[ProbeKind.BASELINE][1]),
        true_responses=(responses[ProbeKind.TRUE][0], responses[ProbeKind.TRUE][1]),
        false_responses=(responses[ProbeKind.FALSE][0], responses[ProbeKind.FALSE][1]),
        echo_values=(
            query_value_at_point(template, point),
            query_value_at_point(true_template, point),
            query_value_at_point(false_template, point),
        ),
    )
    _emit_in_request_order(observation_sink, plan, result.observations)
    return result
