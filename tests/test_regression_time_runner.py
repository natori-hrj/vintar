"""Unit tests for time-case policy preflight and batch accounting."""

import math

import httpx
import pytest
from test_regression_runner import make_case
from test_regression_time_http import time_case
from test_sqli_time_analyzer import run_analysis

from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.time_runner import TimeRunReport
from vintar.core.budget import RequestBudget
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression import batch as batch_module
from vintar.regression import runner as runner_module
from vintar.regression.batch import run_regression_batch
from vintar.regression.report import regression_batch_report_dict
from vintar.regression.runner import (
    TimeRequestBudgetError,
    TrustedExecutionPolicy,
    run_regression_case,
)


def policy(**changes) -> TrustedExecutionPolicy:
    values = {
        "scope": ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        "max_requests": 9,
        "max_requests_per_second": 10.0,
        "max_timeout_seconds": 3.0,
        "max_time_execution_seconds": 30.0,
    }
    values.update(changes)
    return TrustedExecutionPolicy(**values)


def test_time_case_rejects_short_trusted_timeout_before_http():
    calls = []
    with pytest.raises(
        ValueError,
        match=r"Trusted timeout is too short.*max_timeout_seconds",
    ):
        run_regression_case(
            time_case("http://localhost:8000", "safe", "not_detected"),
            policy=policy(max_timeout_seconds=0.5),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_time_case_rejects_impossible_deadline_before_http():
    calls = []
    with pytest.raises(
        ValueError,
        match=r"deadline cannot accommodate.*max_time_execution_seconds",
    ):
        run_regression_case(
            time_case("http://localhost:8000", "safe", "not_detected"),
            policy=policy(
                max_requests_per_second=0.1,
                max_time_execution_seconds=45.0,
            ),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_time_deadline_preflight_accepts_exact_worst_case_boundary():
    required = 9 * 3.0 + 8 / 10.0
    received = []

    outcome = run_regression_case(
        time_case("http://localhost:8000", "safe", "not_detected"),
        policy=policy(max_time_execution_seconds=required),
        transport=httpx.MockTransport(
            lambda request: (
                received.append(request) or httpx.Response(200, content=b"stable")
            )
        ),
    )

    assert len(received) == 9
    assert outcome.request_count == 9


def test_time_deadline_preflight_rejects_just_over_boundary_before_http():
    required = 9 * 3.0 + 8 / 10.0
    calls = []

    with pytest.raises(ValueError, match=r"deadline cannot accommodate"):
        run_regression_case(
            time_case("http://localhost:8000", "safe", "not_detected"),
            policy=policy(max_time_execution_seconds=math.nextafter(required, 0.0)),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


@pytest.mark.parametrize("value", [True, 0.0, 120.01, float("inf")])
def test_trusted_time_deadline_is_bounded_numeric(value):
    with pytest.raises(ValueError, match="Invalid trusted execution limit"):
        policy(max_time_execution_seconds=value)


@pytest.mark.parametrize(
    ("analysis", "expected", "verdict", "reason"),
    [
        (
            run_analysis(),
            "inconclusive",
            Verdict.INCONCLUSIVE,
            "timing_pattern_matched",
        ),
        (
            run_analysis(delay=(0.12, 0.13, 0.14)),
            "not_detected",
            Verdict.NOT_DETECTED,
            "timing_pattern_not_matched",
        ),
    ],
)
def test_time_single_case_uses_product_mapping_and_policy_deadline(
    monkeypatch, analysis, expected, verdict, reason
):
    captured = []

    def fake_verify(**kwargs):
        captured.append(kwargs)
        return TimeRunReport(
            analysis=analysis,
            budget_used=9,
            transport_attempts=9,
            total_elapsed_seconds=0.0,
            deadline_exceeded=False,
        )

    monkeypatch.setattr(runner_module, "verify_time_based_sqli", fake_verify)

    outcome = run_regression_case(
        time_case("http://localhost:8000", "safe", expected),
        policy=policy(max_time_execution_seconds=31.0),
    )

    assert outcome.final_verdict is verdict
    assert outcome.final_reason_code == reason
    assert outcome.request_count == 9
    assert outcome.expectation_match
    assert captured[0]["max_total_seconds"] == 31.0
    assert captured[0]["context"].budget.max_requests == 9


def test_time_case_batch_accounts_for_nine_requests(monkeypatch):
    clock = [0.0]

    def limiter(*, requests_per_second: float) -> RateLimiter:
        return RateLimiter(
            requests_per_second=requests_per_second,
            _clock=lambda: clock[0],
            _sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
        )

    monkeypatch.setattr(batch_module, "RateLimiter", limiter)
    received = []
    result = run_regression_batch(
        [time_case("http://localhost:8000", "safe", "not_detected")],
        policy=policy(),
        transport=httpx.MockTransport(
            lambda request: (
                received.append(request) or httpx.Response(200, content=b"stable")
            )
        ),
    )

    assert len(received) == 9
    assert result.requests_used == 9
    assert result.outcomes[0].request_count == 9
    report = regression_batch_report_dict(result)
    outcome = report["outcomes"][0]
    assert outcome["check_type"] == "sqli.time"
    assert outcome["actual_verdict"] == "not_detected"
    assert outcome["actual_reason_code"] == "timing_pattern_not_matched"
    assert outcome["request_count"] == 9
    assert outcome["timing"] == {
        "status": "not_confirmed",
        "reason_code": "timing_pattern_not_matched",
        "request_count": 9,
    }
    assert "verification" not in outcome
    assert "confirmation" not in outcome


def test_time_case_batch_emits_bounded_timing_decision_facts(monkeypatch):
    analysis = run_analysis(control=(0.10, 0.50, 0.12))

    def fake_verify(**kwargs):
        return TimeRunReport(
            analysis=analysis,
            budget_used=9,
            transport_attempts=9,
            total_elapsed_seconds=0.0,
            deadline_exceeded=False,
        )

    monkeypatch.setattr(runner_module, "verify_time_based_sqli", fake_verify)
    result = run_regression_batch(
        [time_case("http://localhost:8000", "safe", "inconclusive")],
        policy=policy(),
    )

    outcome = regression_batch_report_dict(result)["outcomes"][0]
    assert outcome["actual_reason_code"] == "unstable_timing"
    assert outcome["decision_facts"] == {
        "category": "timing_dynamics",
        "instability_causes": ["control_span"],
    }


def test_time_case_batch_budget_preflight_counts_nine_before_http():
    calls = []
    with pytest.raises(ValueError, match="budget"):
        run_regression_batch(
            [time_case("http://localhost:8000", "safe", "not_detected")],
            policy=policy(max_requests=8),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_mixed_batch_budget_preflight_rejects_eight_remaining_before_http():
    calls = []
    with pytest.raises(
        ValueError,
        match=r"cannot cover every selected case.*Increase policy.max_requests",
    ):
        run_regression_batch(
            [
                make_case(),
                time_case("http://localhost:8000", "safe", "not_detected"),
            ],
            policy=policy(max_requests=14, max_timeout_seconds=10.0),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_time_case_fresh_budget_requires_nine_shared_requests_remaining():
    case = time_case("http://localhost:8000", "safe", "not_detected")
    trusted_policy = policy(max_requests=14)
    shared_budget = RequestBudget(14)
    for _ in range(6):
        shared_budget.consume()
    calls = []

    with pytest.raises(
        TimeRequestBudgetError,
        match=r"fewer than nine requests remaining.*Increase policy.max_requests",
    ):
        runner_module._run_with_resources(
            case,
            policy=trusted_policy,
            budget=shared_budget,
            rate_limiter=RateLimiter(requests_per_second=10.0),
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert shared_budget.used_requests == 6
    assert shared_budget.remaining == 8
    assert calls == []
