from dataclasses import FrozenInstanceError

import httpx
import pytest

from vintar.core.budget import (
    RequestBudget,
    RequestBudgetExceededError,
)
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter, RateLimitInterruptedError
from vintar.core.request import RequestTemplate
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.core.transport import ScopedTransport


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.delays: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.delays.append(seconds)
        self.now += seconds


def make_context(max_requests: int = 2) -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset(
                {
                    AllowedOrigin("http", "localhost", 8000),
                }
            )
        ),
        budget=RequestBudget(max_requests=max_requests),
    )


def test_allowed_request():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200, text="ok")

    context = make_context()
    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )

    result = context.execute(
        template,
        transport=httpx.MockTransport(handler),
    )

    assert result.status_code == 200
    assert result.body == b"ok"
    assert requests == ["http://localhost:8000/"]
    assert context.budget.used_requests == 1


def test_out_of_scope_request_is_not_sent():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200)

    context = make_context()
    template = RequestTemplate(
        method="GET",
        url="http://example.com:8000/",
    )

    with pytest.raises(ValueError, match="outside the allowed scope"):
        context.execute(template, transport=httpx.MockTransport(handler))

    assert requests == []
    assert context.budget.used_requests == 0


def test_budget_exceeded_request_is_not_sent():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200)

    context = make_context(max_requests=1)
    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )
    transport = httpx.MockTransport(handler)

    context.execute(template, transport=transport)

    with pytest.raises(RequestBudgetExceededError):
        context.execute(template, transport=transport)

    assert len(requests) == 1
    assert context.budget.used_requests == 1


def test_failed_request_still_consumes_budget():
    clock = FakeClock()
    request_times: list[float] = []

    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        request_times.append(clock.now)

        if len(request_times) == 1:
            raise httpx.ConnectError("Connection failed", request=request)

        return httpx.Response(200)

    context = ExecutionContext(
        scope=make_context().scope,
        budget=RequestBudget(max_requests=2),
        rate_limiter=limiter,
    )
    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )
    transport = httpx.MockTransport(handler)

    with pytest.raises(httpx.ConnectError):
        context.execute(
            template,
            transport=transport,
        )

    context.execute(template, transport=transport)

    assert request_times == [0.0, 0.5]
    assert clock.delays == [0.5]
    assert context.budget.used_requests == 2


def test_request_hook_cannot_bypass_scope():
    requests = []
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )
    context = ExecutionContext(
        scope=make_context().scope,
        budget=RequestBudget(max_requests=2),
        rate_limiter=limiter,
    )

    def rewrite(request: httpx.Request) -> None:
        request.url = httpx.URL("http://example.com:8000/rewritten")

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200)

    guarded = ScopedTransport(
        transport=httpx.MockTransport(handler),
        scope=context.scope,
        budget=context.budget,
        rate_limiter=context.rate_limiter,
    )

    with (
        httpx.Client(
            transport=guarded,
            event_hooks={"request": [rewrite]},
            trust_env=False,
        ) as client,
        pytest.raises(ValueError, match="outside the allowed scope"),
    ):
        client.get("http://localhost:8000/")

    valid = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )
    context.execute(valid, transport=httpx.MockTransport(handler))

    assert requests == ["http://localhost:8000/"]
    assert clock.delays == []
    assert context.budget.used_requests == 1


def test_context_configuration_is_immutable():
    context = make_context()

    with pytest.raises(FrozenInstanceError):
        context.scope = context.scope

    with pytest.raises(FrozenInstanceError):
        context.budget = RequestBudget(100)

    with pytest.raises(FrozenInstanceError):
        context.timeout = 60

    with pytest.raises(FrozenInstanceError):
        context.max_response_size = 999_999_999

    with pytest.raises(FrozenInstanceError):
        context.rate_limiter = RateLimiter(100)


@pytest.mark.parametrize(
    "url,headers,cookies",
    [
        ("http://localhost:8000/?id=1", (), ()),
        (
            "http://localhost:8000/",
            (("X-Test", "one"), ("x-test", "two")),
            (),
        ),
        (
            "http://localhost:8000/",
            (("Cookie", "session=one"),),
            (("session", "two"),),
        ),
    ],
)
def test_invalid_template_does_not_consume_budget(url, headers, cookies):
    context = make_context()
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200)

    template = RequestTemplate(
        method="GET",
        url=url,
        headers=headers,
        cookies=cookies,
    )

    with pytest.raises(ValueError):
        context.execute(template, transport=httpx.MockTransport(handler))

    assert requests == []
    assert context.budget.used_requests == 0


@pytest.mark.parametrize(
    "timeout,max_response_size",
    [
        (0.0, 1024),
        (61.0, 1024),
        (10.0, 0),
        (10.0, -1),
    ],
)
def test_invalid_context_settings(timeout, max_response_size):
    with pytest.raises(ValueError):
        ExecutionContext(
            scope=make_context().scope,
            budget=RequestBudget(1),
            timeout=timeout,
            max_response_size=max_response_size,
        )


def test_caller_owned_transport_can_be_reused():
    class TrackingTransport(httpx.BaseTransport):
        def __init__(self):
            self.requests = 0
            self.close_calls = 0
            self.closed = False

        def handle_request(self, request):
            if self.closed:
                raise RuntimeError("Transport already closed.")

            self.requests += 1
            return httpx.Response(200, text="ok")

        def close(self):
            self.close_calls += 1
            self.closed = True

    transport = TrackingTransport()
    context = make_context(max_requests=2)

    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )

    try:
        first = context.execute(template, transport=transport)
        second = context.execute(template, transport=transport)

        assert first.status_code == 200
        assert second.status_code == 200
        assert transport.requests == 2
        assert transport.close_calls == 0
        assert context.budget.used_requests == 2

        with pytest.raises(RequestBudgetExceededError):
            context.execute(template, transport=transport)

        assert transport.requests == 2
        assert transport.close_calls == 0
    finally:
        transport.close()

    assert transport.close_calls == 1


def test_out_of_scope_does_not_close_caller_transport():
    class TrackingTransport(httpx.BaseTransport):
        def __init__(self):
            self.close_calls = 0
            self.requests = 0

        def handle_request(self, request):
            self.requests += 1
            return httpx.Response(200)

        def close(self):
            self.close_calls += 1

    transport = TrackingTransport()
    context = make_context()

    template = RequestTemplate(
        method="GET",
        url="http://example.com:8000/",
    )

    with pytest.raises(ValueError, match="outside the allowed scope"):
        context.execute(template, transport=transport)

    assert transport.requests == 0
    assert transport.close_calls == 0
    assert context.budget.used_requests == 0

    transport.close()
    assert transport.close_calls == 1


@pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
def test_context_does_not_follow_redirects(status_code: int):
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))

        return httpx.Response(
            status_code,
            headers={"Location": "http://example.com/"},
        )

    context = make_context(max_requests=2)

    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )

    result = context.execute(
        template,
        transport=httpx.MockTransport(handler),
    )

    assert result.status_code == status_code
    assert result.headers["location"] == "http://example.com/"
    assert requested_urls == ["http://localhost:8000/"]
    assert context.budget.used_requests == 1


def test_owned_transport_is_closed():
    class TrackingTransport(httpx.BaseTransport):
        def __init__(self):
            self.close_calls = 0

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            return httpx.Response(200)

        def close(self) -> None:
            self.close_calls += 1

    transport = TrackingTransport()
    context = make_context()

    guarded = ScopedTransport(
        transport=transport,
        scope=context.scope,
        budget=context.budget,
        close_underlying=True,
        rate_limiter=context.rate_limiter,
    )

    with httpx.Client(transport=guarded, trust_env=False) as client:
        response = client.get("http://localhost:8000/")
        assert response.status_code == 200
        assert transport.close_calls == 0

    assert transport.close_calls == 1
    assert context.budget.used_requests == 1


def test_execution_context_enforces_rate_limit():
    clock = FakeClock()
    request_times: list[float] = []

    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        request_times.append(clock.now)
        return httpx.Response(200, text="ok")

    context = ExecutionContext(
        scope=make_context().scope,
        budget=RequestBudget(max_requests=3),
        rate_limiter=limiter,
    )

    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )

    transport = httpx.MockTransport(handler)

    for _ in range(3):
        context.execute(template, transport=transport)

    assert request_times == [0.0, 0.5, 1.0]
    assert clock.delays == [0.5, 0.5]
    assert context.budget.used_requests == 3


def test_budget_exceeded_does_not_wait():
    clock = FakeClock()
    requests: list[str] = []

    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    context = ExecutionContext(
        scope=make_context().scope,
        budget=RequestBudget(max_requests=1),
        rate_limiter=limiter,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200)

    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )

    transport = httpx.MockTransport(handler)

    context.execute(template, transport=transport)

    with pytest.raises(RequestBudgetExceededError):
        context.execute(template, transport=transport)

    assert len(requests) == 1
    assert clock.delays == []
    assert context.budget.used_requests == 1


def test_out_of_scope_does_not_acquire_rate_limit():
    clock = FakeClock()
    request_times: list[float] = []

    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    context = ExecutionContext(
        scope=make_context().scope,
        budget=RequestBudget(max_requests=2),
        rate_limiter=limiter,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        request_times.append(clock.now)
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)

    invalid = RequestTemplate(
        method="GET",
        url="http://example.com:8000/",
    )

    valid = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )

    with pytest.raises(ValueError, match="outside the allowed scope"):
        context.execute(invalid, transport=transport)

    context.execute(valid, transport=transport)

    assert request_times == [0.0]
    assert clock.delays == []
    assert context.budget.used_requests == 1


def test_failed_rate_limit_wait_preserves_budget():
    clock = FakeClock()
    requests: list[str] = []

    def interrupted_sleep(seconds: float) -> None:
        raise RuntimeError("Sleep interrupted.")

    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=interrupted_sleep,
    )

    context = ExecutionContext(
        scope=make_context().scope,
        budget=RequestBudget(max_requests=2),
        rate_limiter=limiter,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(200)

    template = RequestTemplate(
        method="GET",
        url="http://localhost:8000/",
    )

    transport = httpx.MockTransport(handler)

    context.execute(template, transport=transport)

    with pytest.raises(RateLimitInterruptedError) as exc_info:
        context.execute(template, transport=transport)

    assert isinstance(exc_info.value.__cause__, RuntimeError)
    assert str(exc_info.value.__cause__) == "Sleep interrupted."

    assert len(requests) == 1
    assert context.budget.used_requests == 2
    assert context.budget.remaining == 0


@pytest.mark.parametrize("invalid_limiter", [None, "disabled", 123])
def test_context_rejects_invalid_rate_limiter(invalid_limiter):
    with pytest.raises(TypeError, match="rate_limiter must be a RateLimiter"):
        ExecutionContext(
            scope=make_context().scope,
            budget=RequestBudget(2),
            rate_limiter=invalid_limiter,
        )


def test_scoped_transport_rejects_missing_rate_limiter():
    context = make_context()

    with pytest.raises(TypeError, match="rate_limiter must be a RateLimiter"):
        ScopedTransport(
            transport=httpx.MockTransport(lambda request: httpx.Response(200)),
            scope=context.scope,
            budget=context.budget,
            rate_limiter=None,
        )
