"""Bounded operational behavior of the Error SQLi request runner."""

import httpx
import pytest

from vintar.checks.sqli.error_runner import verify_error_based_sqli
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
    )


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
