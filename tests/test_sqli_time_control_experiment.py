"""Controlled experiments for independent time-based SQLi controls.

These use a simulated transport clock, not live socket networking.
Control outcomes do not establish that SQL was executed.
"""

import sqlite3
from contextlib import closing

import httpx
import pytest

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_plan import TimePayloads
from vintar.checks.sqli.time_research import (
    ControlAssessment,
    assess_independent_control,
)
from vintar.checks.sqli.time_runner import verify_time_based_sqli
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

ORIGIN = "http://127.0.0.1:18085"

PRIMARY_DELAY = "' AND vintar_delay(0.4)=1-- "
PRIMARY_CONTROL = "' AND vintar_delay(0)=1-- "
SHADOW_DELAY = "__shadow_delay"
SHADOW_CONTROL = "__shadow_control"


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def make_context(clock: FakeClock) -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", 18085)})
        ),
        budget=RequestBudget(9),
        timeout=3.0,
        rate_limiter=RateLimiter(
            requests_per_second=100.0,
            _clock=clock,
            _sleep=clock.advance,
        ),
    )


def sqlite_handler(
    category: str,
    clock: FakeClock,
    delay_calls: list[float],
) -> None:
    with closing(sqlite3.connect(":memory:")) as connection:

        def delay(seconds: float) -> int:
            delay_calls.append(seconds)
            clock.advance(seconds)
            return 1

        connection.create_function("vintar_delay", 1, delay)
        connection.execute("CREATE TABLE products (category TEXT)")
        connection.execute("INSERT INTO products VALUES ('Pets')")
        connection.execute(
            f"SELECT category FROM products WHERE category = '{category}'"
        ).fetchall()


def run_experiment(
    monkeypatch,
    *,
    mode: str,
    payloads: TimePayloads,
):
    clock = FakeClock()
    monkeypatch.setattr(
        "vintar.core.http.time.perf_counter",
        clock,
    )

    received = []
    sql_delay_calls: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "127.0.0.1"
        assert request.url.port == 18085

        category = request.url.params["category"]
        received.append(category)

        if mode == "sql":
            try:
                sqlite_handler(category, clock, sql_delay_calls)
            except sqlite3.Error:
                return httpx.Response(500, content=b"query-error")

        elif mode == "exact_mimic":
            if category == "Pets" + PRIMARY_DELAY:
                clock.advance(0.4)

        elif mode == "broad_mimic":
            if category in {
                "Pets" + PRIMARY_DELAY,
                "Pets" + SHADOW_DELAY,
            }:
                clock.advance(0.4)

        else:
            raise AssertionError("Invalid experiment mode.")

        return httpx.Response(200, content=b"ok")

    context = make_context(clock)

    report = verify_time_based_sqli(
        template=RequestTemplate(
            method="GET",
            url=ORIGIN + "/products",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=payloads,
        expected_delay_seconds=0.3,
        context=context,
        max_total_seconds=5.0,
        transport=httpx.MockTransport(handler),
        clock=clock,
    )

    assert report.budget_used == 9
    assert report.transport_attempts == 9
    assert report.analysis.request_count == 9
    assert len(received) == 9
    assert not report.deadline_exceeded

    return report, tuple(received), tuple(sql_delay_calls)


@pytest.mark.parametrize(
    ("mode", "expected_control"),
    [
        ("sql", TimeAnalysisStatus.NOT_CONFIRMED),
        ("exact_mimic", TimeAnalysisStatus.NOT_CONFIRMED),
        ("broad_mimic", TimeAnalysisStatus.CANDIDATE),
    ],
)
def test_independent_control_experiment(
    monkeypatch,
    mode,
    expected_control,
):
    primary, primary_received, primary_sql_calls = run_experiment(
        monkeypatch,
        mode=mode,
        payloads=TimePayloads(
            delay=PRIMARY_DELAY,
            control=PRIMARY_CONTROL,
        ),
    )

    independent, shadow_received, shadow_sql_calls = run_experiment(
        monkeypatch,
        mode=mode,
        payloads=TimePayloads(
            delay=SHADOW_DELAY,
            control=SHADOW_CONTROL,
        ),
    )

    assert primary.analysis.status is TimeAnalysisStatus.CANDIDATE
    assert independent.analysis.status is expected_control

    assert primary_received == (
        "Pets",
        "Pets" + PRIMARY_CONTROL,
        "Pets" + PRIMARY_DELAY,
        "Pets" + PRIMARY_CONTROL,
        "Pets" + PRIMARY_DELAY,
        "Pets",
        "Pets" + PRIMARY_DELAY,
        "Pets",
        "Pets" + PRIMARY_CONTROL,
    )
    assert shadow_received == (
        "Pets",
        "Pets" + SHADOW_CONTROL,
        "Pets" + SHADOW_DELAY,
        "Pets" + SHADOW_CONTROL,
        "Pets" + SHADOW_DELAY,
        "Pets",
        "Pets" + SHADOW_DELAY,
        "Pets",
        "Pets" + SHADOW_CONTROL,
    )

    if mode == "sql":
        assert primary_sql_calls == pytest.approx((0.0, 0.4, 0.0, 0.4, 0.4, 0.0))
        # Shadow values stay inside the SQL string literal and do not
        # invoke the registered SQLite delay function.
        assert shadow_sql_calls == ()
    else:
        assert primary_sql_calls == ()
        assert shadow_sql_calls == ()

    comparison = assess_independent_control(
        primary_case_id=mode,
        primary_status=primary.analysis.status,
        control_status=independent.analysis.status,
    )

    expected_assessment = (
        ControlAssessment.CONTROL_REACTIVE
        if expected_control is TimeAnalysisStatus.CANDIDATE
        else ControlAssessment.CONTROL_NOT_REACTIVE
    )

    assert comparison.assessment is expected_assessment


def test_sql_and_exact_non_sql_mimic_remain_indistinguishable(
    monkeypatch,
):
    primary_payloads = TimePayloads(
        delay=PRIMARY_DELAY,
        control=PRIMARY_CONTROL,
    )
    shadow_payloads = TimePayloads(
        delay=SHADOW_DELAY,
        control=SHADOW_CONTROL,
    )

    for mode in ("sql", "exact_mimic"):
        primary, _, _ = run_experiment(
            monkeypatch,
            mode=mode,
            payloads=primary_payloads,
        )
        shadow, _, _ = run_experiment(
            monkeypatch,
            mode=mode,
            payloads=shadow_payloads,
        )

        assert primary.analysis.status is TimeAnalysisStatus.CANDIDATE
        assert shadow.analysis.status is TimeAnalysisStatus.NOT_CONFIRMED

        assessment = assess_independent_control(
            primary_case_id=mode,
            primary_status=primary.analysis.status,
            control_status=shadow.analysis.status,
        )

        assert assessment.assessment is ControlAssessment.CONTROL_NOT_REACTIVE

    assert not hasattr(assessment, "verdict")


def test_sql_and_mimic_have_same_primary_timing_pattern(
    monkeypatch,
):
    payloads = TimePayloads(
        delay=PRIMARY_DELAY,
        control=PRIMARY_CONTROL,
    )

    sql, _, sql_delay_calls = run_experiment(
        monkeypatch,
        mode="sql",
        payloads=payloads,
    )
    mimic, _, mimic_delay_calls = run_experiment(
        monkeypatch,
        mode="exact_mimic",
        payloads=payloads,
    )

    assert sql.analysis.status is TimeAnalysisStatus.CANDIDATE
    assert mimic.analysis.status is TimeAnalysisStatus.CANDIDATE

    assert sql.analysis.evidence is not None
    assert mimic.analysis.evidence is not None

    assert sql.analysis.evidence.median_excess == pytest.approx(0.4)
    assert mimic.analysis.evidence.median_excess == pytest.approx(0.4)
    assert sql_delay_calls == pytest.approx((0.0, 0.4, 0.0, 0.4, 0.4, 0.0))
    assert mimic_delay_calls == ()
