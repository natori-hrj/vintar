"""Bounded operational behavior of the Error SQLi request runner."""

from dataclasses import replace

import httpx
import pytest

from vintar.checks.sqli.error_analyzer import ErrorAnalysis
from vintar.checks.sqli.error_contract import ErrorAnalysisStatus
from vintar.checks.sqli.error_runner import ErrorRunReport, verify_error_based_sqli
from vintar.checks.sqli.observation_sink import RecordedSqliObservation
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy


def context(
    *,
    max_response_size: int = 1_048_576,
    rate_limiter: RateLimiter | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "example.test", 80)})
        ),
        budget=RequestBudget(4),
        timeout=1.0,
        max_response_size=max_response_size,
        rate_limiter=rate_limiter or RateLimiter(100.0, _sleep=lambda _: None),
    )


def run(
    handler,
    *,
    execution_context: ExecutionContext | None = None,
    observation_sink=None,
):
    return verify_error_based_sqli(
        template=RequestTemplate(
            method="GET",
            url="http://example.test/search",
            params=(("q", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="q",
            occurrence=0,
            mode=InjectionMode.APPEND,
        ),
        error_payload="'",
        context=execution_context or context(),
        transport=httpx.MockTransport(handler),
        observation_sink=observation_sink,
    )


def test_trusted_sink_receives_error_observations_in_request_order():
    recorded: list[RecordedSqliObservation] = []

    run(
        lambda request: httpx.Response(200, content=b"stable"),
        observation_sink=recorded.append,
    )

    assert [item.sequence for item in recorded] == [1, 2, 3, 4]
    assert [item.kind for item in recorded] == [
        "baseline",
        "probe",
        "baseline",
        "probe",
    ]
    assert all(item.family == "error" for item in recorded)


def verification_inputs() -> dict[str, object]:
    return {
        "template": RequestTemplate(
            method="GET",
            url="http://example.test/search",
            params=(("q", "Pets"),),
        ),
        "point": InjectionPoint(
            location=InjectionLocation.QUERY,
            name="q",
            occurrence=0,
            mode=InjectionMode.APPEND,
        ),
        "error_payload": "'",
        "context": context(),
        "transport": httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"stable")
        ),
    }


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("template", object(), r"verification template"),
        ("point", object(), r"injection point"),
        ("context", object(), r"execution context"),
        ("transport", object(), r"execution transport"),
    ],
)
def test_runner_rejects_invalid_dependencies_before_http(field, value, message):
    inputs = verification_inputs()
    inputs[field] = value

    with pytest.raises(TypeError, match=message):
        verify_error_based_sqli(**inputs)


def test_runner_rejects_probe_identical_to_baseline():
    inputs = verification_inputs()
    inputs["point"] = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="q",
        occurrence=0,
        mode=InjectionMode.REPLACE,
    )
    inputs["error_payload"] = "Pets"

    with pytest.raises(
        ValueError,
        match=r"probe matches the baseline.*injection target.*explicit payload",
    ):
        verify_error_based_sqli(**inputs)


def test_runner_rejects_less_than_four_unused_requests():
    inputs = verification_inputs()
    inputs["context"] = ExecutionContext(
        scope=context().scope,
        budget=RequestBudget(3),
        timeout=1.0,
        rate_limiter=RateLimiter(100.0, _sleep=lambda _: None),
    )

    with pytest.raises(
        ValueError,
        match=r"four unused request slots.*fresh four-request budget",
    ):
        verify_error_based_sqli(**inputs)


def test_error_run_report_rejects_invalid_accounting():
    valid = run(lambda request: httpx.Response(200, content=b"stable"))
    invalid = (
        ({"analysis": object()}, TypeError, r"run analysis"),
        ({"budget_used": True}, TypeError, r"request accounting"),
        ({"transport_attempts": True}, TypeError, r"request accounting"),
        ({"budget_used": 5}, ValueError, r"request accounting"),
        ({"transport_attempts": 2}, ValueError, r"dispatch accounting"),
    )
    for changes, error, message in invalid:
        with pytest.raises(error, match=message):
            replace(valid, **changes)

    attempts = 0

    def fail_third(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 3:
            raise httpx.ReadTimeout("bounded timeout")
        return httpx.Response(200, content=b"stable")

    partial = run(fail_third)
    with pytest.raises(ValueError, match=r"budget usage.*recorded attempts"):
        replace(partial, budget_used=4)

    assert isinstance(valid, ErrorRunReport)


@pytest.mark.parametrize(
    ("exception", "reason"),
    [
        (httpx.ReadTimeout("bounded timeout"), "probe_timeout"),
        (httpx.ConnectError("bounded failure"), "probe_failed"),
    ],
)
def test_transport_failure_stops_after_one_attempt(exception, reason):
    def handler(request: httpx.Request) -> httpx.Response:
        raise exception

    report = run(handler)

    assert report.analysis.reason_code == reason
    assert report.analysis.request_count == 1
    assert report.budget_used == 1
    assert report.transport_attempts == 1


def test_http_rate_limit_stops_after_one_completed_attempt():
    report = run(lambda request: httpx.Response(429, content=b"limited"))

    assert report.analysis.reason_code == "rate_limited"
    assert report.analysis.request_count == 1
    assert report.budget_used == 1
    assert report.transport_attempts == 1


def test_truncation_stops_after_one_completed_attempt():
    report = run(
        lambda request: httpx.Response(200, content=b"too long"),
        execution_context=context(max_response_size=4),
    )

    assert report.analysis.reason_code == "truncated_response"
    assert report.analysis.request_count == 1
    assert report.budget_used == 1
    assert report.transport_attempts == 1


def test_interrupted_rate_wait_stops_before_second_transport_dispatch():
    clock_values = iter((0.0, 0.0, 0.0, 0.0))

    def clock() -> float:
        return next(clock_values)

    def interrupted_sleep(delay: float) -> None:
        raise RuntimeError("simulated operator interruption")

    limiter = RateLimiter(1.0, _clock=clock, _sleep=interrupted_sleep)
    report = run(
        lambda request: httpx.Response(200, content=b"ok"),
        execution_context=context(rate_limiter=limiter),
    )

    assert report.analysis.reason_code == "probe_interrupted"
    assert report.analysis.request_count == 2
    assert report.budget_used == 2
    assert report.transport_attempts == 1


def test_fourth_http_rate_limit_is_a_four_attempt_operational_result():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(429 if calls == 4 else 200, content=b"response")

    report = run(handler)

    assert report.analysis.reason_code == "rate_limited"
    assert report.analysis.request_count == 4
    assert report.budget_used == 4
    assert report.transport_attempts == 4


@pytest.mark.parametrize(
    "reason",
    (
        "rate_limited",
        "truncated_response",
        "probe_timeout",
        "probe_failed",
        "probe_interrupted",
    ),
)
@pytest.mark.parametrize("position", (1, 2, 3, 4))
def test_each_operational_reason_is_valid_at_every_attempt(reason, position):
    dispatches = 0
    execution_context = context(max_response_size=4)

    if reason == "probe_interrupted":
        waits = 0

        def interrupted_sleep(delay: float) -> None:
            nonlocal waits
            waits += 1
            if waits == position:
                raise RuntimeError("simulated operator interruption")

        limiter = RateLimiter(1.0, _clock=lambda: 0.0, _sleep=interrupted_sleep)
        limiter.acquire()
        execution_context = context(max_response_size=4, rate_limiter=limiter)

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatches
        dispatches += 1
        if dispatches == position:
            if reason == "probe_timeout":
                raise httpx.ReadTimeout("bounded timeout")
            if reason == "probe_failed":
                raise httpx.ConnectError("bounded failure")
            if reason == "rate_limited":
                return httpx.Response(429, content=b"stop")
            if reason == "truncated_response":
                return httpx.Response(200, content=b"too long")
        return httpx.Response(200, content=b"ok")

    report = run(handler, execution_context=execution_context)

    assert report.analysis.reason_code == reason
    assert report.analysis.request_count == position
    assert report.budget_used == position
    assert report.transport_attempts == (
        position - 1 if reason == "probe_interrupted" else position
    )


@pytest.mark.parametrize("position", (1, 2, 3, 4))
def test_rate_limit_precedes_truncation_at_every_attempt(position):
    dispatches = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal dispatches
        dispatches += 1
        if dispatches == position:
            return httpx.Response(429, content=b"too long")
        return httpx.Response(200, content=b"ok")

    report = run(handler, execution_context=context(max_response_size=4))

    assert report.analysis.reason_code == "rate_limited"
    assert report.analysis.request_count == position
    terminal = report.analysis.observations[-1]
    assert terminal.status_code == 429
    assert terminal.truncated
    with pytest.raises(
        ValueError,
        match=(
            r"implies rate_limited.*429 takes precedence over truncation.*"
            r"batch stops on rate limits"
        ),
    ):
        ErrorAnalysis(
            status=ErrorAnalysisStatus.INCONCLUSIVE,
            reason_code="truncated_response",
            observations=report.analysis.observations,
        )


@pytest.mark.parametrize(
    ("co_occurring_reasons", "expected_reason"),
    [
        (("rate_limited", "truncated_response"), "rate_limited"),
    ],
)
def test_each_co_occurring_operational_pair_has_one_reason(
    co_occurring_reasons, expected_reason
):
    report = run(
        lambda request: httpx.Response(429, content=b"too long"),
        execution_context=context(max_response_size=4),
    )
    accepted = []
    for reason in co_occurring_reasons:
        try:
            ErrorAnalysis(
                status=ErrorAnalysisStatus.INCONCLUSIVE,
                reason_code=reason,
                observations=report.analysis.observations,
            )
        except ValueError:
            continue
        accepted.append(reason)

    assert report.analysis.reason_code == expected_reason
    assert accepted == [expected_reason]
