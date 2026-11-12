"""Tests for aggregate regression execution limits."""

from dataclasses import FrozenInstanceError

import httpx
import pytest

from vintar.checks.sqli.models import Verdict
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression import batch as batch_module
from vintar.regression.batch import (
    RegressionBatchResult,
    run_regression_batch,
)
from vintar.regression.cases import parse_regression_case
from vintar.regression.runner import RegressionStatus, TrustedExecutionPolicy

CASE_SOURCE = """
version = 1
id = "case-one"
type = "sqli.boolean"
expected_verdict = "not_detected"

[target]
url = "http://localhost:8000/products"
allowed_origin = "http://localhost:8000"

[[target.params]]
name = "category"
value = "Pets"

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 2.0
timeout_seconds = 10.0
"""


def make_case(
    case_id: str,
    *,
    url: str = "http://localhost:8000/products",
    origin: str = "http://localhost:8000",
    expected: str = "not_detected",
    rps: float = 2.0,
):
    source = (
        CASE_SOURCE.replace('id = "case-one"', f'id = "{case_id}"')
        .replace(
            'url = "http://localhost:8000/products"',
            f'url = "{url}"',
        )
        .replace(
            'allowed_origin = "http://localhost:8000"',
            f'allowed_origin = "{origin}"',
        )
        .replace(
            'expected_verdict = "not_detected"',
            f'expected_verdict = "{expected}"',
        )
        .replace(
            "requests_per_second = 2.0",
            f"requests_per_second = {rps}",
        )
    )
    return parse_regression_case(source)


def make_policy(
    *,
    requests: int = 12,
    rps: float = 2.0,
    host: str = "localhost",
):
    return TrustedExecutionPolicy(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", host, 8000)})
        ),
        max_requests=requests,
        max_requests_per_second=rps,
    )


@pytest.fixture(autouse=True)
def virtual_time(monkeypatch):
    """Make rate limiting deterministic without real delays."""
    clock = [0.0]
    starts = []

    def sleep(seconds: float):
        clock[0] += seconds

    def factory(*, requests_per_second: float):
        limiter = RateLimiter(
            requests_per_second=requests_per_second,
            _clock=lambda: clock[0],
            _sleep=sleep,
        )
        starts.append(limiter)
        return limiter

    monkeypatch.setattr(batch_module, "RateLimiter", factory)
    return clock, starts


def test_two_cases_share_one_request_budget(virtual_time):
    cases = [make_case("case-one"), make_case("case-two")]
    received = []

    def handler(request):
        received.append(request)
        return httpx.Response(200, content=b"same")

    result = run_regression_batch(
        cases,
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert len(result.outcomes) == 2
    assert len(received) == 12
    assert result.requests_used == 12
    assert result.status is RegressionStatus.PASS
    assert all(outcome.status is RegressionStatus.PASS for outcome in result.outcomes)

    # One shared RateLimiter instance is created for the batch.
    _, created = virtual_time
    assert len(created) == 1


def test_insufficient_total_budget_sends_nothing():
    calls = []

    with pytest.raises(ValueError, match="budget"):
        run_regression_batch(
            [make_case("one"), make_case("two")],
            policy=make_policy(requests=11),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_later_case_outside_scope_sends_nothing():
    first = make_case("one")
    second = make_case(
        "two",
        url="http://example.com:8000/products",
        origin="http://example.com:8000",
    )
    calls = []

    with pytest.raises(ValueError, match="trusted execution scope"):
        run_regression_batch(
            [first, second],
            policy=make_policy(),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_duplicate_case_ids_rejected_without_http():
    case = make_case("same")
    calls = []

    with pytest.raises(ValueError, match="Duplicate"):
        run_regression_batch(
            [case, case],
            policy=make_policy(),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_global_rate_limit_applies_across_case_boundary(
    virtual_time,
):
    cases = [make_case("one"), make_case("two")]
    clock, _ = virtual_time
    dispatch_times = []

    def handler(request):
        dispatch_times.append(clock[0])
        return httpx.Response(200, content=b"same")

    run_regression_batch(
        cases,
        policy=make_policy(rps=1.0),
        transport=httpx.MockTransport(handler),
    )

    assert len(dispatch_times) == 12
    assert dispatch_times == pytest.approx([float(i) for i in range(12)])


def test_slowest_case_rate_cannot_be_relaxed_by_policy(virtual_time):
    cases = [make_case("one"), make_case("two", rps=0.5)]
    clock, _ = virtual_time
    dispatch_times = []

    run_regression_batch(
        cases,
        policy=make_policy(rps=10.0),
        transport=httpx.MockTransport(
            lambda request: (
                dispatch_times.append(clock[0]) or httpx.Response(200, content=b"same")
            )
        ),
    )

    assert dispatch_times == pytest.approx([float(i * 2) for i in range(12)])


def test_first_case_429_stops_remaining_cases():
    cases = [make_case("one"), make_case("two")]
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(429)
        return httpx.Response(200, content=b"same")

    result = run_regression_batch(
        cases,
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert len(calls) == 1
    assert result.requests_used == 1
    assert result.planned_case_ids == ("one", "two")
    assert result.complete is False
    assert len(result.outcomes) == 1
    assert result.outcomes[0].status is RegressionStatus.INCONCLUSIVE
    assert result.status is RegressionStatus.INCONCLUSIVE


def test_429_batch_never_reaches_later_case():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(429)

    result = run_regression_batch(
        [make_case("one"), make_case("two")],
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert len(calls) == 1
    assert result.requests_used == 1
    assert result.complete is False
    assert result.status is RegressionStatus.INCONCLUSIVE


def test_connection_failure_is_recorded_and_stops_batch():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            raise httpx.ConnectError("private target detail", request=request)
        return httpx.Response(200, content=b"same")

    result = run_regression_batch(
        [make_case("one"), make_case("two")],
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert len(calls) == 1
    assert result.requests_used == 1
    assert result.complete is False
    assert len(result.outcomes) == 1
    assert result.outcomes[0].status is RegressionStatus.INCONCLUSIVE
    assert result.status is RegressionStatus.INCONCLUSIVE


def test_local_rate_limit_interruption_stops_batch(monkeypatch):
    now = [0.0]

    def interrupted_sleep(delay):
        raise RuntimeError("interrupted")

    monkeypatch.setattr(
        batch_module,
        "RateLimiter",
        lambda *, requests_per_second: RateLimiter(
            requests_per_second=requests_per_second,
            _clock=lambda: now[0],
            _sleep=interrupted_sleep,
        ),
    )
    calls = []

    result = run_regression_batch(
        [make_case("one"), make_case("two")],
        policy=make_policy(),
        transport=httpx.MockTransport(
            lambda request: (
                calls.append(request) or httpx.Response(200, content=b"same")
            )
        ),
    )

    assert len(calls) == 1
    assert result.requests_used == 2
    assert result.requests_used == sum(
        outcome.verification.request_count for outcome in result.outcomes
    )
    assert result.complete is False
    assert result.status is RegressionStatus.INCONCLUSIVE


def test_fail_status_precedes_incomplete_batch():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 7:
            return httpx.Response(429)
        return httpx.Response(200, content=b"same")

    result = run_regression_batch(
        [
            make_case("expected-vulnerable", expected="vulnerable"),
            make_case("rate-limited"),
            make_case("not-run"),
        ],
        policy=make_policy(requests=18),
        transport=httpx.MockTransport(handler),
    )

    assert len(calls) == 7
    assert len(result.outcomes) == 2
    assert result.outcomes[0].verification.verdict is Verdict.NOT_DETECTED
    assert result.outcomes[0].expectation_match is False
    assert result.complete is False
    assert result.status is RegressionStatus.FAIL


def test_keyboard_interrupt_aborts_without_running_later_cases():
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 7:
            raise KeyboardInterrupt
        return httpx.Response(200, content=b"same")

    with pytest.raises(KeyboardInterrupt):
        run_regression_batch(
            [make_case("one"), make_case("two"), make_case("three")],
            policy=make_policy(requests=18),
            transport=httpx.MockTransport(handler),
        )

    assert len(calls) == 7


@pytest.mark.parametrize(
    "invalid",
    [[], (), "case", {}, None],
)
def test_invalid_batch_input_rejected(invalid):
    with pytest.raises((TypeError, ValueError)):
        run_regression_batch(
            invalid,
            policy=make_policy(),
        )


def test_duplicate_case_is_rejected():
    case = make_case("same")

    with pytest.raises(ValueError, match="Duplicate"):
        run_regression_batch(
            [case, case],
            policy=make_policy(),
        )


def test_batch_size_limit():
    cases = [make_case(f"case-{i}") for i in range(129)]

    with pytest.raises(ValueError, match="batch size"):
        run_regression_batch(
            cases,
            policy=make_policy(requests=774),
        )


def test_batch_result_does_not_expose_payloads():
    result = run_regression_batch(
        [make_case("one")],
        policy=make_policy(requests=6),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"same")
        ),
    )

    rendered = repr(result)
    assert "true-probe" not in rendered
    assert "false-probe" not in rendered
    assert "localhost" not in rendered

    with pytest.raises(FrozenInstanceError):
        result.status = RegressionStatus.FAIL


def test_result_model_rejects_invalid_planned_case_id():
    result = run_regression_batch(
        [make_case("one")],
        policy=make_policy(requests=6),
        transport=httpx.MockTransport(lambda request: httpx.Response(429)),
    )

    with pytest.raises(ValueError, match="case identifier"):
        RegressionBatchResult(
            planned_case_ids=("invalid identifier",),
            outcomes=result.outcomes,
            status=result.status,
            requests_used=result.requests_used,
        )


def test_result_model_rejects_inconsistent_status():
    result = run_regression_batch(
        [make_case("one")],
        policy=make_policy(requests=6),
        transport=httpx.MockTransport(lambda request: httpx.Response(429)),
    )

    with pytest.raises(ValueError, match="batch status"):
        RegressionBatchResult(
            planned_case_ids=result.planned_case_ids,
            outcomes=result.outcomes,
            status=RegressionStatus.PASS,
            requests_used=result.requests_used,
        )


@pytest.mark.parametrize("delta", [-1, 1])
def test_result_model_requires_exact_request_accounting(delta):
    result = run_regression_batch(
        [make_case("one")],
        policy=make_policy(requests=6),
        transport=httpx.MockTransport(lambda request: httpx.Response(429)),
    )

    with pytest.raises(ValueError, match="request count"):
        RegressionBatchResult(
            planned_case_ids=result.planned_case_ids,
            outcomes=result.outcomes,
            status=result.status,
            requests_used=result.requests_used + delta,
        )


def test_result_model_rejects_unplanned_or_reordered_outcomes():
    result = run_regression_batch(
        [make_case("one"), make_case("two")],
        policy=make_policy(),
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"same")
        ),
    )

    with pytest.raises(ValueError, match="planned case order"):
        RegressionBatchResult(
            planned_case_ids=("two", "one"),
            outcomes=result.outcomes,
            status=result.status,
            requests_used=result.requests_used,
        )
