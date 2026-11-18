"""Measure timing classification repeatability over loopback HTTP.

The deliberately vulnerable SQLite endpoint and non-SQL mimics
are isolated test fixtures. No external targets are used.
"""

import socket
import sqlite3
import threading
import time
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_plan import TimePayloads
from vintar.checks.sqli.time_quality import (
    GroundTruth,
    sample_from_report,
    summarize_quality,
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

DELAY_SECONDS = 0.35
EXPECTED_DELAY_SECONDS = 0.25
DELAY_PAYLOAD = "' AND vintar_delay(0.35)=1-- "
CONTROL_PAYLOAD = "' AND vintar_delay(0)=1-- "
REPETITIONS = 2

CASES = (
    ("vulnerable", GroundTruth.VULNERABLE),
    ("safe", GroundTruth.NON_VULNERABLE),
    ("mimic", GroundTruth.NON_VULNERABLE),
    ("auth", GroundTruth.NON_VULNERABLE),
    ("waf", GroundTruth.NON_VULNERABLE),
    ("cache", GroundTruth.NON_VULNERABLE),
    ("load", GroundTruth.NON_VULNERABLE),
)

EXPECTED = {
    "vulnerable": (
        TimeAnalysisStatus.CANDIDATE,
        "timing_pattern_matched",
        9,
    ),
    "safe": (
        TimeAnalysisStatus.NOT_CONFIRMED,
        "timing_pattern_not_matched",
        9,
    ),
    "mimic": (
        TimeAnalysisStatus.CANDIDATE,
        "timing_pattern_matched",
        9,
    ),
    "auth": (
        TimeAnalysisStatus.INCONCLUSIVE,
        "non_success_status",
        4,
    ),
    "waf": (
        TimeAnalysisStatus.INCONCLUSIVE,
        "non_success_status",
        2,
    ),
    "cache": (
        TimeAnalysisStatus.INCONCLUSIVE,
        "unstable_timing",
        9,
    ),
    "load": (
        TimeAnalysisStatus.INCONCLUSIVE,
        "unstable_timing",
        9,
    ),
}


@dataclass(repr=False)
class ServerState:
    count: int = 0
    received: list[str] = field(default_factory=list)
    sql_calls: int = 0
    delay_calls: int = 0
    delay_values: Counter = field(default_factory=Counter)
    lock: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
    )

    def reset(self) -> None:
        with self.lock:
            self.count = 0
            self.received.clear()
            self.sql_calls = 0
            self.delay_calls = 0
            self.delay_values.clear()

    def record(self, value: str) -> int:
        with self.lock:
            self.count += 1
            self.received.append(value)
            return self.count

    def record_sql(self) -> None:
        with self.lock:
            self.sql_calls += 1

    def record_delay(self, seconds: float) -> None:
        with self.lock:
            self.delay_calls += 1
            self.delay_values[seconds] += 1

    def snapshot(self) -> tuple[int, int, int]:
        with self.lock:
            return self.count, self.sql_calls, self.delay_calls

    def received_values(self) -> tuple[str, ...]:
        with self.lock:
            return tuple(self.received)

    def delay_value_count(self, seconds: float) -> int:
        with self.lock:
            return self.delay_values[seconds]


def execute_sql(
    category: str,
    *,
    vulnerable: bool,
    state: ServerState,
) -> None:
    with closing(sqlite3.connect(":memory:")) as connection:

        def delay_function(seconds: float) -> int:
            state.record_delay(seconds)
            time.sleep(seconds)
            return 1

        connection.create_function(
            "vintar_delay",
            1,
            delay_function,
        )
        connection.execute("CREATE TABLE products (category TEXT NOT NULL)")
        connection.execute(
            "INSERT INTO products VALUES (?)",
            ("Pets",),
        )

        state.record_sql()

        if vulnerable:
            # Only the local fixture interpolates untrusted SQL.
            connection.execute(
                f"SELECT category FROM products WHERE category = '{category}'"
            ).fetchall()
        else:
            connection.execute(
                "SELECT category FROM products WHERE category = ?",
                (category,),
            ).fetchall()


def create_app(state: ServerState) -> FastAPI:
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/reliability/{mode}")
    def endpoint(mode: str, request: Request) -> Response:
        if mode not in EXPECTED:
            return Response(status_code=404)

        values = request.query_params.getlist("category")

        if len(values) != 1:
            return Response(status_code=400)

        category = values[0]
        number = state.record(category)

        if mode == "auth" and number == 4:
            return Response(
                b"authentication-required",
                status_code=401,
            )

        if mode == "waf" and category == "Pets" + CONTROL_PAYLOAD:
            return Response(
                b"blocked",
                status_code=403,
            )

        if mode == "mimic":
            if category == "Pets" + DELAY_PAYLOAD:
                time.sleep(DELAY_SECONDS)

        elif mode == "cache":
            # Only the first injected delay request is uncached.
            if number == 3:
                time.sleep(DELAY_SECONDS)

        elif mode == "load":
            # A baseline request experiences unrelated server load.
            if number == 6:
                time.sleep(DELAY_SECONDS)

        elif mode in ("vulnerable", "safe"):
            try:
                execute_sql(
                    category,
                    vulnerable=(mode == "vulnerable"),
                    state=state,
                )
            except sqlite3.Error:
                return Response(
                    b"query-error",
                    status_code=500,
                )

        return Response(
            b"fixture-response",
            media_type="text/plain",
        )

    return app


@pytest.fixture(scope="module")
def reliability_server():
    state = ServerState()
    app = create_app(state)
    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    try:
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
        except OSError:
            pytest.skip("Loopback socket unavailable.")

        port = listener.getsockname()[1]

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            lifespan="off",
            access_log=False,
            log_level="critical",
            server_header=False,
        )

        server = uvicorn.Server(config)

        worker = threading.Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            daemon=True,
        )
        worker.start()

        try:
            deadline = time.monotonic() + 5.0

            while (
                not server.started and worker.is_alive() and time.monotonic() < deadline
            ):
                time.sleep(0.01)

            assert server.started
            assert worker.is_alive()

            yield state, f"http://127.0.0.1:{port}"

        finally:
            server.should_exit = True
            worker.join(timeout=5)

            if worker.is_alive():
                server.force_exit = True
                worker.join(timeout=5)

            assert not worker.is_alive()

    finally:
        listener.close()


def run_case(origin: str, mode: str):
    port = urlsplit(origin).port
    assert port is not None

    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset(
                {
                    AllowedOrigin(
                        "http",
                        "127.0.0.1",
                        port,
                    )
                }
            )
        ),
        budget=RequestBudget(9),
        timeout=3.0,
        rate_limiter=RateLimiter(
            requests_per_second=100.0,
        ),
    )

    report = verify_time_based_sqli(
        template=RequestTemplate(
            method="GET",
            url=f"{origin}/reliability/{mode}",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=TimePayloads(
            delay=DELAY_PAYLOAD,
            control=CONTROL_PAYLOAD,
        ),
        expected_delay_seconds=EXPECTED_DELAY_SECONDS,
        context=context,
        max_total_seconds=15.0,
    )

    assert report.budget_used == context.budget.used_requests
    return report


def expected_probe_values() -> tuple[str, ...]:
    return (
        "Pets",
        "Pets" + CONTROL_PAYLOAD,
        "Pets" + DELAY_PAYLOAD,
        "Pets" + CONTROL_PAYLOAD,
        "Pets" + DELAY_PAYLOAD,
        "Pets",
        "Pets" + DELAY_PAYLOAD,
        "Pets",
        "Pets" + CONTROL_PAYLOAD,
    )


@pytest.fixture(scope="module")
def measured_runs(reliability_server):
    state, origin = reliability_server
    samples = []

    for iteration in range(REPETITIONS):
        scheduled_cases = CASES if iteration == 0 else tuple(reversed(CASES))

        for mode, truth in scheduled_cases:
            state.reset()
            report = run_case(origin, mode)
            received, sql_calls, delay_calls = state.snapshot()

            expected_status, expected_reason, expected_count = EXPECTED[mode]

            assert report.analysis.status is expected_status, (
                mode,
                iteration,
                report.analysis.reason_code,
            )
            assert report.analysis.reason_code == expected_reason
            assert report.budget_used == expected_count
            assert report.transport_attempts == expected_count
            assert report.analysis.request_count == expected_count
            assert received == expected_count
            assert state.received_values() == expected_probe_values()[:expected_count]
            assert not report.deadline_exceeded

            if mode == "vulnerable":
                assert sql_calls == 9
                assert delay_calls == 6
                assert state.delay_value_count(DELAY_SECONDS) == 3
                assert state.delay_value_count(0.0) == 3
            elif mode == "safe":
                assert sql_calls == 9
                assert delay_calls == 0
                assert state.delay_value_count(DELAY_SECONDS) == 0
                assert state.delay_value_count(0.0) == 0
            else:
                assert sql_calls == 0
                assert delay_calls == 0

            samples.append(
                sample_from_report(
                    case_id=mode,
                    iteration=iteration,
                    ground_truth=truth,
                    report=report,
                    server_received=received,
                )
            )

    return tuple(samples)


def test_repeated_http_classifications(measured_runs):
    summary = summarize_quality(measured_runs)

    assert summary.total_cases == 7
    assert summary.repetitions == 2
    assert summary.total_runs == 14
    assert summary.vulnerable_runs == 2
    assert summary.non_vulnerable_runs == 12

    assert summary.true_candidates == 2
    assert summary.false_candidates == 2

    assert summary.candidates == 4
    assert summary.not_confirmed == 2
    assert summary.inconclusive == 8
    assert summary.execution_errors == 0

    assert summary.candidate_sensitivity == 1.0
    assert summary.false_candidate_rate == pytest.approx(2 / 12)
    assert summary.classification_coverage == pytest.approx(6 / 14)
    assert summary.abstention_rate == pytest.approx(8 / 14)
    assert summary.conditional_false_candidate_proportion == 0.5


def test_case_reliability_and_request_accounting(measured_runs):
    summary = summarize_quality(measured_runs)

    assert summary.flaky_case_rate == 0
    assert all(not case.flaky for case in summary.cases)

    expected_requests_per_round = sum(expected[2] for expected in EXPECTED.values())

    assert summary.budget_used == (expected_requests_per_round * REPETITIONS)
    assert summary.transport_attempts == summary.budget_used
    assert summary.server_received == summary.budget_used
    assert summary.observations == summary.budget_used
    assert summary.total_elapsed_seconds > 0


def test_non_sql_mimic_remains_a_false_candidate(measured_runs):
    summary = summarize_quality(measured_runs)
    cases = {case.case_id: case for case in summary.cases}

    assert cases["mimic"].ground_truth is GroundTruth.NON_VULNERABLE
    assert cases["mimic"].statuses == (
        "candidate",
        "candidate",
    )

    assert cases["vulnerable"].statuses == (
        "candidate",
        "candidate",
    )

    assert cases["auth"].statuses == (
        "inconclusive",
        "inconclusive",
    )
    assert cases["waf"].statuses == (
        "inconclusive",
        "inconclusive",
    )
