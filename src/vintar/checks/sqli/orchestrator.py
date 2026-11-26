import hashlib

import httpx

from vintar.checks.sqli.analyzer import (
    analyze_boolean_responses,
    boolean_response_signature,
)
from vintar.checks.sqli.decision_facts import (
    DecisionStage,
    OperationalCondition,
    OperationalDecisionFacts,
    response_operational_condition,
)
from vintar.checks.sqli.models import (
    BOOLEAN_PROBE_ORDER,
    Observation,
    ProbeError,
    ProbeFailure,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.checks.sqli.observation_sink import (
    AttemptOutcome,
    SqliObservationSink,
    emit_attempt_stop,
    emit_observation,
)
from vintar.core.budget import RequestBudgetExceededError
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject, value_at_injection_point
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimitInterruptedError
from vintar.core.request import InjectionPoint, RequestTemplate
from vintar.core.scope import validate_scope
from vintar.core.template import validate_template


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


def classify_probe_error(exc: httpx.RequestError) -> ProbeError:
    """Classify a bounded probe failure without retaining exception details."""
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
    """Return the selected value for legacy callers and generalized injection."""
    return value_at_injection_point(template, point)


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
            observation=boolean_response_signature(kind, by_kind[kind][index]),
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

    try:
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
    except (TypeError, ValueError):
        emit_attempt_stop(
            observation_sink,
            family="boolean",
            sequence=1,
            kind=ProbeKind.BASELINE.value,
            outcome=AttemptOutcome.NOT_DISPATCHED,
            failure=OperationalCondition.PREFLIGHT_FAILED,
        )
        raise

    requests = {
        ProbeKind.BASELINE: template,
        ProbeKind.TRUE: true_template,
        ProbeKind.FALSE: false_template,
    }
    plan = tuple((kind, requests[kind]) for kind in BOOLEAN_PROBE_ORDER)

    if context.budget.remaining < len(plan):
        emit_attempt_stop(
            observation_sink,
            family="boolean",
            sequence=1,
            kind=ProbeKind.BASELINE.value,
            outcome=AttemptOutcome.NOT_DISPATCHED,
            failure=OperationalCondition.BUDGET_UNAVAILABLE,
        )
        return VerificationResult(
            check_id=check_id,
            verdict=Verdict.INCONCLUSIVE,
            observations=(),
            failures=(),
            request_count=0,
            reason_code="budget_unavailable",
            reason="Insufficient request budget for six probes.",
            decision_facts=OperationalDecisionFacts(
                reason_code="budget_unavailable",
                stage=DecisionStage.INITIAL,
                sequence=1,
                probe_kind=ProbeKind.BASELINE,
                condition=OperationalCondition.BUDGET_UNAVAILABLE,
            ),
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
                    error=classify_probe_error(exc),
                )
            )
            break

        observation = _observation(kind, response)
        observations.append(observation)
        responses[kind].append(response)

        if (
            response_operational_condition(
                response.status_code, truncated=response.truncated
            )
            is OperationalCondition.RATE_LIMITED
        ):
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
                decision_facts=OperationalDecisionFacts(
                    reason_code="rate_limited",
                    stage=DecisionStage.INITIAL,
                    sequence=len(observations),
                    probe_kind=kind,
                    condition=OperationalCondition.RATE_LIMITED,
                    status_code=response.status_code,
                ),
            )

    if failures:
        _emit_in_request_order(observation_sink, plan, tuple(observations))
        failure = failures[-1]
        emit_attempt_stop(
            observation_sink,
            family="boolean",
            sequence=len(observations) + len(failures),
            kind=failure.kind.value,
            outcome=AttemptOutcome.NO_RESPONSE,
            failure=failure.error,
        )
        return VerificationResult(
            check_id=check_id,
            verdict=Verdict.INCONCLUSIVE,
            observations=tuple(observations),
            failures=tuple(failures),
            request_count=len(observations) + len(failures),
            reason_code="probe_failed",
            reason="A probe failed before verification completed.",
            decision_facts=OperationalDecisionFacts(
                reason_code="probe_failed",
                stage=DecisionStage.INITIAL,
                sequence=len(observations) + len(failures),
                probe_kind=failures[-1].kind,
                condition=failures[-1].error,
            ),
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
