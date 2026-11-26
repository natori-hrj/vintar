"""Error-case single-run and mixed-batch accounting contracts."""

import httpx
import pytest
from test_regression_batch import make_case
from test_regression_error_http import error_case
from test_regression_time_http import time_case

from vintar.core.budget import RequestBudget
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression import batch as batch_module
from vintar.regression import runner as runner_module
from vintar.regression.batch import run_regression_batch
from vintar.regression.errors import BatchRequestBudgetError
from vintar.regression.report import regression_batch_report_dict
from vintar.regression.runner import (
    ErrorRegressionOutcome,
    RegressionOutcome,
    TimeRegressionOutcome,
    TrustedExecutionPolicy,
)


def policy(requests: int) -> TrustedExecutionPolicy:
    return TrustedExecutionPolicy(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        max_requests=requests,
        max_requests_per_second=10.0,
        max_timeout_seconds=3.0,
        max_time_execution_seconds=31.5,
    )


def test_error_case_batch_preflight_counts_four_before_http():
    calls = []

    with pytest.raises(
        BatchRequestBudgetError,
        match=r"cannot cover every selected case.*Increase policy.max_requests",
    ):
        run_regression_batch(
            [error_case("http://localhost:8000", "safe", "not_detected")],
            policy=policy(3),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_error_case_requires_four_shared_requests_remaining():
    case = error_case("http://localhost:8000", "safe", "not_detected")
    shared_budget = RequestBudget(9)
    for _ in range(6):
        shared_budget.consume()
    calls = []

    with pytest.raises(
        BatchRequestBudgetError,
        match=r"fewer than four requests remaining.*Increase policy.max_requests",
    ):
        runner_module._run_with_resources(
            case,
            policy=policy(9),
            budget=shared_budget,
            rate_limiter=RateLimiter(10.0, _sleep=lambda _: None),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert shared_budget.used_requests == 6
    assert shared_budget.remaining == 3
    assert calls == []


def test_mixed_boolean_time_error_batch_uses_exact_shared_budget(monkeypatch):
    clock = [0.0]

    def limiter(*, requests_per_second: float) -> RateLimiter:
        return RateLimiter(
            requests_per_second,
            _clock=lambda: clock[0],
            _sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )

    monkeypatch.setattr(batch_module, "RateLimiter", limiter)
    received = []
    result = run_regression_batch(
        [
            make_case("boolean-case"),
            time_case("http://localhost:8000", "safe", "not_detected"),
            error_case("http://localhost:8000", "safe", "not_detected"),
        ],
        policy=policy(19),
        transport=httpx.MockTransport(
            lambda request: (
                received.append(request) or httpx.Response(200, content=b"stable")
            )
        ),
    )

    assert len(received) == 19
    assert result.requests_used == 19
    assert tuple(outcome.request_count for outcome in result.outcomes) == (6, 9, 4)
    assert isinstance(result.outcomes[0], RegressionOutcome)
    assert isinstance(result.outcomes[1], TimeRegressionOutcome)
    assert isinstance(result.outcomes[2], ErrorRegressionOutcome)


def test_mixed_boolean_time_error_batch_rejects_short_total_budget_before_http():
    calls = []

    with pytest.raises(
        BatchRequestBudgetError,
        match=r"cannot cover every selected case.*Increase policy.max_requests",
    ):
        run_regression_batch(
            [
                make_case("boolean-case"),
                time_case("http://localhost:8000", "safe", "not_detected"),
                error_case("http://localhost:8000", "safe", "not_detected"),
            ],
            policy=policy(18),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_error_analyzer_facts_flow_through_batch_report_writer():
    result = run_regression_batch(
        [error_case("http://localhost:8000", "safe", "inconclusive")],
        policy=policy(4),
        transport=httpx.MockTransport(lambda request: httpx.Response(503)),
    )

    outcome = regression_batch_report_dict(result)["outcomes"][0]
    assert outcome["actual_reason_code"] == "non_success_status"
    assert outcome["decision_facts"] == {
        "category": "operational",
        "stage": "error",
        "sequence": 1,
        "probe_kind": "baseline",
        "condition": "non_success_status",
        "status_code": 503,
    }
