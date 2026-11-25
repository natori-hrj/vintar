import httpx
import pytest

from vintar.checks.sqli.models import ProbeError, ProbeKind, Verdict
from vintar.checks.sqli.observation_sink import (
    AttemptOutcome,
    RecordedSqliObservation,
)
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy


def make_context(
    max_requests: int = 6,
    *,
    rate_limiter: RateLimiter | None = None,
    max_response_size: int = 1_048_576,
) -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        budget=RequestBudget(max_requests),
        rate_limiter=rate_limiter or RateLimiter(requests_per_second=100),
        max_response_size=max_response_size,
    )


def make_template() -> RequestTemplate:
    return RequestTemplate(
        method="GET",
        url="http://localhost:8000/items",
        params=(("id", "1"),),
    )


def verify(context, transport, **overrides):
    values = {
        "check_id": "items-sqli",
        "template": make_template(),
        "point": InjectionPoint(
            location=InjectionLocation.QUERY,
            name="id",
        ),
        "true_payload": "true-probe",
        "false_payload": "false-probe",
        "context": context,
        "transport": transport,
    }
    values.update(overrides)
    return verify_boolean_sqli(**values)


def test_sends_six_probes_in_order():
    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params["id"]
        received.append(value)

        body = b"B" if value == "false-probe" else b"A"
        return httpx.Response(200, content=body)

    context = make_context()
    result = verify(context, httpx.MockTransport(handler))

    assert received == [
        "1",
        "true-probe",
        "false-probe",
        "1",
        "false-probe",
        "true-probe",
    ]
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "boolean_candidate"
    assert result.request_count == 6
    assert context.budget.used_requests == 6
    assert [item.kind for item in result.observations] == [
        ProbeKind.BASELINE,
        ProbeKind.BASELINE,
        ProbeKind.TRUE,
        ProbeKind.TRUE,
        ProbeKind.FALSE,
        ProbeKind.FALSE,
    ]


def test_trusted_sink_receives_boolean_observations_in_request_order():
    recorded: list[RecordedSqliObservation] = []
    verify(
        make_context(),
        httpx.MockTransport(lambda request: httpx.Response(200, content=b"same")),
        observation_sink=recorded.append,
    )

    assert [item.sequence for item in recorded] == list(range(1, 7))
    assert [item.kind for item in recorded] == [
        "baseline",
        "true",
        "false",
        "baseline",
        "false",
        "true",
    ]
    assert all(item.family == "boolean" for item in recorded)
    assert all(item.observation.status_code == 200 for item in recorded)
    assert all(not hasattr(item.observation, "elapsed") for item in recorded)
    assert all(not hasattr(item.observation, "body") for item in recorded)


def test_identical_responses_are_not_detected():
    context = make_context()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"same")
    )

    result = verify(context, transport)

    assert result.verdict is Verdict.NOT_DETECTED
    assert result.request_count == 6


def test_insufficient_budget_sends_nothing():
    calls: list[httpx.Request] = []
    context = make_context(max_requests=5)

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    recorded: list[RecordedSqliObservation] = []
    result = verify(
        context,
        httpx.MockTransport(handler),
        observation_sink=recorded.append,
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "budget_unavailable"
    assert result.request_count == 0
    assert context.budget.used_requests == 0
    assert calls == []
    assert len(recorded) == 1
    assert recorded[0].outcome is AttemptOutcome.NOT_DISPATCHED
    assert recorded[0].sequence == 1


def test_scope_rejection_occurs_before_http():
    calls: list[httpx.Request] = []
    context = make_context()

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    invalid = RequestTemplate(
        method="GET",
        url="http://example.com:8000/items",
        params=(("id", "1"),),
    )

    recorded: list[RecordedSqliObservation] = []
    with pytest.raises(ValueError, match="outside the allowed scope"):
        verify(
            context,
            httpx.MockTransport(handler),
            template=invalid,
            observation_sink=recorded.append,
        )

    assert calls == []
    assert context.budget.used_requests == 0
    assert len(recorded) == 1
    assert recorded[0].outcome is AttemptOutcome.NOT_DISPATCHED


def test_timeout_stops_remaining_probes():
    received: list[str] = []
    context = make_context()

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request.url.params["id"])

        if len(received) == 2:
            raise httpx.ReadTimeout("Timed out.", request=request)

        return httpx.Response(200, content=b"ok")

    recorded: list[RecordedSqliObservation] = []
    result = verify(
        context,
        httpx.MockTransport(handler),
        observation_sink=recorded.append,
    )

    assert received == ["1", "true-probe"]
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "probe_failed"
    assert result.request_count == 2
    assert len(result.observations) == 1
    assert len(result.failures) == 1
    assert result.failures[0].kind is ProbeKind.TRUE
    assert result.failures[0].error is ProbeError.TIMEOUT
    assert context.budget.used_requests == 2
    assert [(item.sequence, item.outcome) for item in recorded] == [
        (1, AttemptOutcome.RESPONSE),
        (2, AttemptOutcome.NO_RESPONSE),
    ]
    assert recorded[-1].failure is ProbeError.TIMEOUT


@pytest.mark.parametrize(
    ("failure_position", "expected_kind"),
    [
        (1, ProbeKind.BASELINE),
        (2, ProbeKind.TRUE),
        (3, ProbeKind.FALSE),
        (4, ProbeKind.BASELINE),
        (5, ProbeKind.FALSE),
        (6, ProbeKind.TRUE),
    ],
)
def test_failure_kind_matches_reordered_probe_plan(
    failure_position,
    expected_kind,
):
    context = make_context()
    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request.url.params["id"])
        if len(received) == failure_position:
            raise httpx.ReadError("Probe failed.", request=request)
        return httpx.Response(200, content=b"ok")

    result = verify(context, httpx.MockTransport(handler))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.request_count == failure_position
    assert len(result.observations) == failure_position - 1
    assert result.failures[0].kind is expected_kind
    assert result.failures[0].error is ProbeError.RESPONSE_READ
    assert context.budget.used_requests == failure_position


@pytest.mark.parametrize(
    ("error_type", "expected"),
    [
        (httpx.ConnectError, ProbeError.CONNECTION),
        (httpx.ReadError, ProbeError.RESPONSE_READ),
        (httpx.RemoteProtocolError, ProbeError.RESPONSE_READ),
        (httpx.DecodingError, ProbeError.RESPONSE_READ),
        (httpx.WriteError, ProbeError.UNKNOWN),
    ],
)
def test_httpx_request_error_is_classified(error_type, expected):
    context = make_context()

    def handler(request: httpx.Request) -> httpx.Response:
        raise error_type("Probe failed.", request=request)

    result = verify(context, httpx.MockTransport(handler))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.request_count == 1
    assert result.observations == ()
    assert result.failures[0].kind is ProbeKind.BASELINE
    assert result.failures[0].error is expected
    assert context.budget.used_requests == 1


def test_invalid_payloads_do_not_send_requests():
    context = make_context()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(ValueError, match="must differ"):
        verify(
            context,
            httpx.MockTransport(handler),
            true_payload="same",
            false_payload="same",
        )

    assert calls == []
    assert context.budget.used_requests == 0


@pytest.mark.parametrize(
    ("invalid", "error"),
    [("", ValueError), ("   ", ValueError), (None, TypeError), (123, TypeError)],
)
def test_invalid_check_id_does_not_send_requests(invalid, error):
    context = make_context()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(error, match="check_id"):
        verify(
            context,
            httpx.MockTransport(handler),
            check_id=invalid,
        )

    assert calls == []
    assert context.budget.used_requests == 0


def test_invalid_template_fields_are_rejected_before_http():
    context = make_context()
    calls: list[httpx.Request] = []
    invalid = RequestTemplate(
        method="GET",
        url="http://localhost:8000/items",
        headers=(("X-Test", "unsafe\nvalue"),),
        params=(("id", "1"),),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(ValueError, match="header value"):
        verify(
            context,
            httpx.MockTransport(handler),
            template=invalid,
        )

    assert calls == []
    assert context.budget.used_requests == 0


def test_host_header_cannot_bypass_scope():
    context = make_context()
    calls: list[httpx.Request] = []
    invalid = RequestTemplate(
        method="GET",
        url="http://localhost:8000/items",
        headers=(("Host", "example.com"),),
        params=(("id", "1"),),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(ValueError, match="Host header"):
        verify(
            context,
            httpx.MockTransport(handler),
            template=invalid,
        )

    assert calls == []
    assert context.budget.used_requests == 0


def test_probe_template_identical_to_baseline_is_rejected_before_http():
    context = make_context()
    calls: list[httpx.Request] = []
    template = make_template()
    template = RequestTemplate(
        method=template.method,
        url=template.url,
        params=(("id", "true-probe"),),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(ValueError, match="differ from the baseline"):
        verify(
            context,
            httpx.MockTransport(handler),
            template=template,
        )

    assert calls == []
    assert context.budget.used_requests == 0


def test_rate_limit_interruption_stops_remaining_probes():
    class InterruptedClock:
        def monotonic(self) -> float:
            return 0.0

        def sleep(self, seconds: float) -> None:
            raise RuntimeError(f"Interrupted after {seconds} seconds.")

    clock = InterruptedClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )
    context = make_context(rate_limiter=limiter)
    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request.url.params["id"])
        return httpx.Response(200, content=b"ok")

    result = verify(context, httpx.MockTransport(handler))

    assert received == ["1"]
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "probe_failed"
    assert result.request_count == 2
    assert len(result.observations) == 1
    assert result.failures[0].kind is ProbeKind.TRUE
    assert result.failures[0].error is ProbeError.RATE_LIMIT
    assert context.budget.used_requests == 2


def test_mid_run_budget_exhaustion_stops_before_next_http_request():
    context = make_context()
    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request.url.params["id"])
        while context.budget.remaining:
            context.budget.consume()
        return httpx.Response(200, content=b"ok")

    result = verify(context, httpx.MockTransport(handler))

    assert received == ["1"]
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.request_count == 2
    assert len(result.observations) == 1
    assert result.failures[0].kind is ProbeKind.TRUE
    assert result.failures[0].error is ProbeError.BUDGET_EXCEEDED
    assert context.budget.used_requests == 6


def test_same_context_preserves_budget_and_rate_limit_state():
    class AdvancingClock:
        def __init__(self) -> None:
            self.now = 0.0
            self.delays: list[float] = []

        def monotonic(self) -> float:
            return self.now

        def sleep(self, seconds: float) -> None:
            self.delays.append(seconds)
            self.now += seconds

    clock = AdvancingClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )
    context = make_context(max_requests=12, rate_limiter=limiter)
    calls: list[httpx.Request] = []
    transport = httpx.MockTransport(
        lambda request: calls.append(request) or httpx.Response(200, content=b"same")
    )

    first = verify(context, transport)
    second = verify(context, transport)

    assert first.verdict is Verdict.NOT_DETECTED
    assert second.verdict is Verdict.NOT_DETECTED
    assert len(calls) == 12
    assert context.budget.used_requests == 12
    assert clock.delays == [0.5] * 11


def test_redirect_response_is_not_followed():
    context = make_context()
    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(str(request.url))
        return httpx.Response(
            302,
            headers={"Location": "http://example.com/out-of-scope"},
        )

    result = verify(context, httpx.MockTransport(handler))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "non_success_status"
    assert len(received) == 6
    assert all(url.startswith("http://localhost:8000/") for url in received)
    assert context.budget.used_requests == 6


def test_truncated_responses_are_inconclusive():
    context = make_context(max_response_size=1)
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=b"too large")
    )

    result = verify(context, transport)

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "truncated_response"
    assert result.request_count == 6
    assert all(observation.truncated for observation in result.observations)
    assert context.budget.used_requests == 6


def test_second_round_reverses_true_false_order():
    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params["id"]
        received.append(value)
        return httpx.Response(200, content=b"same")

    context = make_context()
    result = verify(context, httpx.MockTransport(handler))

    assert received[:3] == [
        "1",
        "true-probe",
        "false-probe",
    ]

    assert received[3:] == [
        "1",
        "false-probe",
        "true-probe",
    ]

    assert result.request_count == 6
    assert result.verdict is Verdict.NOT_DETECTED
    assert context.budget.used_requests == 6


@pytest.mark.parametrize(
    ("position", "expected_kind"),
    [
        (1, ProbeKind.BASELINE),
        (2, ProbeKind.TRUE),
        (3, ProbeKind.FALSE),
        (4, ProbeKind.BASELINE),
        (5, ProbeKind.FALSE),
        (6, ProbeKind.TRUE),
    ],
)
def test_http_429_stops_remaining_probes(
    position: int,
    expected_kind: ProbeKind,
):
    received: list[str] = []
    context = make_context()

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request.url.params["id"])

        if len(received) == position:
            return httpx.Response(
                429,
                headers={"Retry-After": "120"},
                content=b"Too Many Requests",
            )

        return httpx.Response(200, content=b"ok")

    result = verify(context, httpx.MockTransport(handler))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "rate_limited"
    assert result.request_count == position
    assert len(result.observations) == position
    assert result.failures == ()
    assert result.evidence is None
    assert result.confidence is None

    assert result.observations[-1].kind is expected_kind
    assert result.observations[-1].status_code == 429
    assert result.observations[-1].truncated is True

    assert len(received) == position
    assert context.budget.used_requests == position
    assert context.budget.remaining == 6 - position


@pytest.mark.parametrize(
    "retry_after",
    [
        pytest.param("120", id="seconds"),
        pytest.param("0", id="zero"),
        pytest.param("-1", id="negative"),
        pytest.param("invalid", id="invalid"),
        pytest.param("9" * 10_000, id="extreme"),
        pytest.param("Wed, 21 Oct 2099 07:28:00 GMT", id="http-date"),
    ],
)
def test_retry_after_does_not_trigger_retry(retry_after: str):
    calls = 0
    context = make_context()

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1

        return httpx.Response(
            429,
            headers={"Retry-After": retry_after},
        )

    result = verify(context, httpx.MockTransport(handler))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "rate_limited"
    assert result.request_count == 1
    assert context.budget.used_requests == 1
    assert calls == 1


def test_http_503_does_not_use_rate_limited_reason():
    context = make_context()
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, content=b"unavailable")

    result = verify(context, httpx.MockTransport(handler))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "non_success_status"
    assert result.request_count == 6
    assert calls == 6


def test_429_response_is_not_a_probe_failure():
    context = make_context()
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            429,
            content=b"rate limited",
        )
    )

    result = verify(context, transport)

    assert result.request_count == 1
    assert len(result.observations) == 1
    assert result.observations[0].status_code == 429
    assert result.observations[0].body_size == 0
    assert result.observations[0].truncated is True
    assert not hasattr(result.observations[0], "body")
    assert not hasattr(result.observations[0], "headers")
    assert "rate limited" not in repr(result)
    assert result.failures == ()


def test_context_can_be_reused_after_rate_limited_result():
    context = make_context(max_requests=8)
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 2:
            return httpx.Response(429, content=b"slow down")
        return httpx.Response(200, content=b"same")

    transport = httpx.MockTransport(handler)

    first = verify(context, transport)
    second = verify(context, transport)

    assert first.reason_code == "rate_limited"
    assert first.request_count == 2
    assert second.verdict is Verdict.NOT_DETECTED
    assert second.request_count == 6
    assert calls == 8
    assert context.budget.used_requests == 8
    assert context.budget.remaining == 0
