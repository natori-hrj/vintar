"""Tests for scoped experimental time-based SQLi execution."""

import time
from dataclasses import replace

import httpx
import pytest

from vintar.checks.sqli.observation_sink import RecordedSqliObservation
from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_plan import (
    TimePayloads,
    TimeProbeKind,
)
from vintar.checks.sqli.time_runner import (
    TimeRunReport,
    verify_time_based_sqli,
)
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy

ORIGIN = "http://127.0.0.1:18084"


class FakeClock:
    def __init__(self, value=0.0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def make_context(
    *,
    timeout: float = 2.0,
    rate: float = 100.0,
    requests: int = 9,
    rate_limiter: RateLimiter | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset(
                {
                    AllowedOrigin(
                        "http",
                        "127.0.0.1",
                        18084,
                    )
                }
            )
        ),
        budget=RequestBudget(requests),
        timeout=timeout,
        rate_limiter=rate_limiter or RateLimiter(requests_per_second=rate),
    )


def make_template() -> RequestTemplate:
    return RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        params=(("category", "Pets"),),
    )


def make_point() -> InjectionPoint:
    return InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        mode=InjectionMode.APPEND,
    )


def make_payloads() -> TimePayloads:
    return TimePayloads(
        delay="_delayed",
        control="_control",
    )


def run_with_transport(
    handler,
    *,
    context=None,
    expected_delay=0.25,
    total_seconds=5.0,
    clock=None,
    observation_sink=None,
):
    context = context or make_context()

    report = verify_time_based_sqli(
        template=make_template(),
        point=make_point(),
        payloads=make_payloads(),
        expected_delay_seconds=expected_delay,
        context=context,
        max_total_seconds=total_seconds,
        transport=httpx.MockTransport(handler),
        clock=clock or time.monotonic,
        observation_sink=observation_sink,
    )

    return report, context


def test_nine_successful_requests_are_accounted_for():
    received = []

    def handler(request):
        received.append(request.url.params.get("category"))
        return httpx.Response(200, text="ok")

    report, context = run_with_transport(handler)

    assert report.analysis.status is TimeAnalysisStatus.NOT_CONFIRMED
    assert report.analysis.request_count == 9
    assert report.budget_used == 9
    assert report.transport_attempts == 9
    assert context.budget.used_requests == 9

    assert received == [
        "Pets",
        "Pets_control",
        "Pets_delayed",
        "Pets_control",
        "Pets_delayed",
        "Pets",
        "Pets_delayed",
        "Pets",
        "Pets_control",
    ]


def test_trusted_sink_receives_time_observations_in_request_order():
    recorded: list[RecordedSqliObservation] = []

    run_with_transport(
        lambda request: httpx.Response(200, text="ok"),
        observation_sink=recorded.append,
    )

    assert [item.sequence for item in recorded] == list(range(1, 10))
    assert [item.kind for item in recorded] == [
        "baseline",
        "control",
        "delay",
        "control",
        "delay",
        "baseline",
        "delay",
        "baseline",
        "control",
    ]
    assert all(item.family == "time" for item in recorded)


def test_controlled_delay_produces_experimental_candidate(monkeypatch):
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=100.0,
        _clock=clock,
        _sleep=clock.advance,
    )
    context = make_context(rate_limiter=limiter)
    monkeypatch.setattr("vintar.core.http.time.perf_counter", clock)

    def handler(request):
        if request.url.params.get("category") == "Pets_delayed":
            clock.advance(0.28)

        return httpx.Response(200, text="ok")

    report, _ = run_with_transport(
        handler,
        context=context,
        total_seconds=5.0,
        clock=clock,
    )

    assert report.analysis.status is TimeAnalysisStatus.CANDIDATE
    assert report.analysis.reason_code == "timing_pattern_matched"


def test_no_delay_is_not_confirmed():
    report, _ = run_with_transport(
        lambda request: httpx.Response(
            200,
            text="ok",
        )
    )

    assert report.analysis.status is TimeAnalysisStatus.NOT_CONFIRMED


@pytest.mark.parametrize(
    ("status", "reason"),
    [
        (429, "rate_limited"),
        (403, "non_success_status"),
        (302, "non_success_status"),
        (500, "non_success_status"),
    ],
)
def test_unsafe_status_stops_immediately(status, reason):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(status)

    report, context = run_with_transport(handler)

    assert report.analysis.status is TimeAnalysisStatus.INCONCLUSIVE
    assert report.analysis.reason_code == reason
    assert report.analysis.request_count == 1
    assert report.transport_attempts == 1
    assert report.budget_used == 1
    assert context.budget.used_requests == 1
    assert len(calls) == 1


def test_timeout_does_not_become_candidate():
    def handler(request):
        raise httpx.ReadTimeout("simulated timeout")

    report, context = run_with_transport(handler)

    assert report.analysis.status is TimeAnalysisStatus.INCONCLUSIVE
    assert report.analysis.reason_code == "probe_timeout"
    assert report.analysis.evidence is None
    assert report.analysis.request_count == 1
    assert report.transport_attempts == 1
    assert context.budget.used_requests == 1


def test_request_failure_does_not_become_candidate():
    def handler(request):
        raise httpx.ConnectError("simulated connection")

    report, _ = run_with_transport(handler)

    assert report.analysis.status is TimeAnalysisStatus.INCONCLUSIVE
    assert report.analysis.reason_code == "probe_failed"
    assert report.analysis.evidence is None


def test_truncated_response_stops_immediately():
    context = replace(
        make_context(),
        max_response_size=3,
    )
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, content=b"long-response")

    report, _ = run_with_transport(
        handler,
        context=context,
    )

    assert report.analysis.status is TimeAnalysisStatus.INCONCLUSIVE
    assert report.analysis.reason_code == "truncated_response"
    assert report.transport_attempts == 1
    assert len(calls) == 1


def test_exhausted_deadline_prevents_subsequent_dispatch():
    clock = FakeClock()
    calls = []

    def handler(request):
        calls.append(request)
        clock.advance(0.04)
        return httpx.Response(200, text="ok")

    report, context = run_with_transport(
        handler,
        total_seconds=0.02,
        clock=clock,
    )

    assert report.deadline_exceeded
    assert report.analysis.status is TimeAnalysisStatus.INCONCLUSIVE
    assert report.analysis.reason_code in {
        "probe_interrupted",
        "incomplete_probes",
    }
    assert report.transport_attempts <= 1
    assert context.budget.used_requests <= 1
    assert len(calls) <= 1


def test_deadline_during_rate_wait_prevents_dispatch():
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=10.0,
        _clock=clock,
        _sleep=clock.advance,
    )
    context = make_context(rate_limiter=limiter)
    calls = []

    report, _ = run_with_transport(
        lambda request: calls.append(request) or httpx.Response(200),
        context=context,
        total_seconds=0.05,
        clock=clock,
    )

    assert report.deadline_exceeded
    assert report.analysis.reason_code == "probe_interrupted"
    assert report.analysis.request_count == 2
    assert report.budget_used == 2
    assert report.transport_attempts == 1
    assert len(calls) == 1


def test_timeout_is_recapped_after_rate_wait():
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=25.0,
        _clock=clock,
        _sleep=clock.advance,
    )
    limiter.acquire()
    context = make_context(rate_limiter=limiter)
    timeout_extensions = []

    def handler(request):
        timeout_extensions.append(request.extensions["timeout"])
        return httpx.Response(429)

    report, _ = run_with_transport(
        handler,
        context=context,
        total_seconds=0.05,
        clock=clock,
    )

    assert report.analysis.reason_code == "rate_limited"
    assert len(timeout_extensions) == 1
    assert all(0 < value <= 0.010000001 for value in timeout_extensions[0].values())


def test_deadline_before_budget_reservation_records_no_attempt():
    class TickingClock(FakeClock):
        def __call__(self):
            current = self.value
            self.value += 0.01
            return current

    clock = TickingClock()
    calls = []

    report, context = run_with_transport(
        lambda request: calls.append(request) or httpx.Response(200),
        total_seconds=0.015,
        clock=clock,
    )

    assert report.deadline_exceeded
    assert report.analysis.reason_code == "incomplete_probes"
    assert report.analysis.request_count == 0
    assert report.budget_used == 0
    assert report.transport_attempts == 0
    assert context.budget.used_requests == 0
    assert not calls


def test_rate_limiter_interruption_records_budget_without_dispatch():
    clock = FakeClock()

    def interrupt_sleep(seconds):
        clock.advance(seconds / 2)
        raise RuntimeError("interrupted")

    limiter = RateLimiter(
        requests_per_second=10.0,
        _clock=clock,
        _sleep=interrupt_sleep,
    )
    limiter.acquire()
    context = make_context(rate_limiter=limiter)
    calls = []

    report, _ = run_with_transport(
        lambda request: calls.append(request) or httpx.Response(200),
        context=context,
        clock=clock,
    )

    assert report.analysis.reason_code == "probe_interrupted"
    assert report.analysis.request_count == 1
    assert report.budget_used == 1
    assert report.transport_attempts == 0
    assert report.analysis.observations[0].rate_wait_seconds >= 0
    assert not calls


def test_response_completed_after_deadline_is_not_timing_evidence():
    clock = FakeClock()

    def handler(request):
        clock.advance(0.1)
        return httpx.Response(200)

    report, context = run_with_transport(
        handler,
        total_seconds=0.05,
        clock=clock,
    )

    assert report.deadline_exceeded
    assert report.analysis.reason_code == "probe_interrupted"
    assert report.analysis.evidence is None
    assert report.budget_used == 1
    assert report.transport_attempts == 1
    assert context.budget.used_requests == 1


def test_invalid_budget_rejected_before_http():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200)

    context = make_context(requests=8)

    with pytest.raises(ValueError, match="budget"):
        run_with_transport(
            handler,
            context=context,
        )

    assert context.budget.used_requests == 0
    assert not calls


def test_secrets_are_not_retained():
    secret = "time-run-secret"
    context = make_context()

    template = replace(
        make_template(),
        headers=(("Authorization", "Bearer " + secret),),
        cookies=(("session", secret),),
    )

    report = verify_time_based_sqli(
        template=template,
        point=make_point(),
        payloads=make_payloads(),
        expected_delay_seconds=0.25,
        context=context,
        transport=httpx.MockTransport(lambda request: httpx.Response(200)),
    )

    assert secret not in repr(report)
    assert secret not in repr(report.analysis)
    assert "_delayed" not in repr(report)
    assert "_control" not in repr(report)


def test_rate_wait_is_separate_from_response_elapsed():
    context = make_context(rate=10.0)

    report, _ = run_with_transport(
        lambda request: httpx.Response(200, text="ok"),
        context=context,
    )

    observations = report.analysis.observations

    assert len(observations) == 9
    assert observations[0].kind is TimeProbeKind.BASELINE

    assert any(item.rate_wait_seconds > 0.05 for item in observations[1:])

    assert all(item.elapsed_seconds >= 0 for item in observations)

    assert report.analysis.status is TimeAnalysisStatus.NOT_CONFIRMED


@pytest.mark.parametrize(
    "total_seconds",
    [
        0,
        -1,
        True,
        float("nan"),
        float("inf"),
        10**1000,
        121,
    ],
)
def test_invalid_total_deadline_rejected(total_seconds):
    with pytest.raises((TypeError, ValueError)):
        run_with_transport(
            lambda request: httpx.Response(200),
            total_seconds=total_seconds,
        )


def test_negative_net_transport_elapsed_is_execution_error(monkeypatch):
    def fake_execute(self, template, **kwargs):
        self.budget.consume()
        kwargs["on_rate_wait"](0.2)
        kwargs["on_dispatch"]()
        return HttpResult(
            status_code=200,
            elapsed=0.1,
            body=b"",
            headers={},
        )

    monkeypatch.setattr(ExecutionContext, "execute", fake_execute)

    with pytest.raises(RuntimeError, match="timing failed"):
        run_with_transport(lambda request: httpx.Response(200))


def test_report_rejects_inconsistent_direct_construction():
    report, _ = run_with_transport(lambda request: httpx.Response(200))

    invalid = (
        {"budget_used": 8},
        {"transport_attempts": 8},
        {"deadline_exceeded": True},
    )

    assert type(report) is TimeRunReport
    for changes in invalid:
        with pytest.raises(ValueError):
            replace(report, **changes)


def test_huge_per_request_timeout_is_rejected_before_dispatch():
    context = make_context()
    calls = []

    with pytest.raises(ValueError, match="per-request timeout"):
        context.execute(
            make_template(),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
            request_timeout=10**1000,
        )

    assert context.budget.used_requests == 0
    assert not calls
