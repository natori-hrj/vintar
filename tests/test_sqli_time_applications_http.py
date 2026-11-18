"""Evaluate distinct local ASGI applications over loopback HTTP.

The deliberately unsafe SQL exists only in isolated SQLite fixtures.
Application independence is limited by shared runtime infrastructure.
"""

import socket
import sqlite3
import threading
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_application_quality import (
    ApplicationOutcome,
    ApplicationUnit,
    summarize_applications,
)
from vintar.checks.sqli.time_plan import TimePayloads
from vintar.checks.sqli.time_quality import (
    GroundTruth,
    sample_from_report,
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

DELAY_SECONDS = 0.4
EXPECTED_DELAY = 0.3

DELAY_PAYLOAD = "' AND vintar_delay(0.4)=1-- "
CONTROL_PAYLOAD = "' AND vintar_delay(0)=1-- "

CASES = (
    (
        "unsafe_sqlite",
        GroundTruth.VULNERABLE,
        "sqlite",
        "where",
        TimeAnalysisStatus.CANDIDATE,
    ),
    (
        "prepared_sqlite",
        GroundTruth.NON_VULNERABLE,
        "sqlite",
        "where",
        TimeAnalysisStatus.NOT_CONFIRMED,
    ),
    (
        "non_sql_mimic",
        GroundTruth.NON_VULNERABLE,
        "none",
        "none",
        TimeAnalysisStatus.CANDIDATE,
    ),
    (
        "non_sql_plain",
        GroundTruth.NON_VULNERABLE,
        "none",
        "none",
        TimeAnalysisStatus.NOT_CONFIRMED,
    ),
)


@dataclass(repr=False)
class ApplicationState:
    received: list[str] = field(default_factory=list)
    sql_executions: int = 0
    delay_values: list[float] = field(default_factory=list)
    lock: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
    )

    def record_request(self, category: str) -> None:
        with self.lock:
            self.received.append(category)

    def record_sql(self) -> None:
        with self.lock:
            self.sql_executions += 1

    def record_delay(self, seconds: float) -> None:
        with self.lock:
            self.delay_values.append(seconds)

    def snapshot(self):
        with self.lock:
            return (
                tuple(self.received),
                self.sql_executions,
                tuple(self.delay_values),
            )


def execute_sql(
    *,
    category: str,
    vulnerable: bool,
    state: ApplicationState,
) -> None:
    with closing(sqlite3.connect(":memory:")) as database:

        def sleep_function(seconds: float) -> int:
            state.record_delay(seconds)
            time.sleep(seconds)
            return 1

        database.create_function(
            "vintar_delay",
            1,
            sleep_function,
        )
        database.execute("CREATE TABLE products (category TEXT NOT NULL)")
        database.execute(
            "INSERT INTO products VALUES (?)",
            ("Pets",),
        )

        state.record_sql()

        if vulnerable:
            database.execute(
                f"SELECT category FROM products WHERE category = '{category}'"
            ).fetchall()
        else:
            database.execute(
                "SELECT category FROM products WHERE category = ?",
                (category,),
            ).fetchall()


def create_application(
    application_id: str,
    state: ApplicationState,
) -> FastAPI:
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/products")
    def products(request: Request) -> Response:
        values = request.query_params.getlist("category")

        if len(values) != 1:
            return Response(status_code=400)

        category = values[0]
        state.record_request(category)

        if application_id == "unsafe_sqlite":
            try:
                execute_sql(
                    category=category,
                    vulnerable=True,
                    state=state,
                )
            except sqlite3.Error:
                return Response(
                    b"query-error",
                    status_code=500,
                )

        elif application_id == "prepared_sqlite":
            try:
                execute_sql(
                    category=category,
                    vulnerable=False,
                    state=state,
                )
            except sqlite3.Error:
                return Response(
                    b"query-error",
                    status_code=500,
                )

        elif application_id == "non_sql_mimic":
            if category == "Pets" + DELAY_PAYLOAD:
                time.sleep(DELAY_SECONDS)

        elif application_id != "non_sql_plain":
            return Response(status_code=404)

        return Response(b"ok", media_type="text/plain")

    return app


@contextmanager
def running_application(application_id: str):
    state = ApplicationState()
    app = create_application(application_id, state)

    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)

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


def run_application(origin: str):
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
            url=origin + "/products",
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
        expected_delay_seconds=EXPECTED_DELAY,
        context=context,
        max_total_seconds=15.0,
    )

    assert context.budget.used_requests == report.budget_used
    return report


@pytest.fixture(scope="module")
def application_results():
    units = []

    for (
        application_id,
        truth,
        dbms,
        sql_context,
        expected,
    ) in CASES:
        with running_application(application_id) as (state, origin):
            samples = []

            for iteration in range(2):
                before_received, before_sql, before_delays = state.snapshot()

                report = run_application(origin)

                received, sql_count, delay_values = state.snapshot()

                new_requests = received[len(before_received) :]
                new_sql = sql_count - before_sql
                new_delays = delay_values[len(before_delays) :]

                assert report.analysis.status is expected
                assert report.budget_used == 9
                assert report.transport_attempts == 9
                assert report.analysis.request_count == 9
                assert len(new_requests) == 9
                assert not report.deadline_exceeded

                assert new_requests == (
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

                if application_id == "unsafe_sqlite":
                    assert new_sql == 9
                    assert new_delays.count(0.4) == 3
                    assert new_delays.count(0.0) == 3
                elif application_id == "prepared_sqlite":
                    assert new_sql == 9
                    assert not new_delays
                else:
                    assert new_sql == 0
                    assert not new_delays

                samples.append(
                    sample_from_report(
                        case_id=application_id,
                        iteration=iteration,
                        ground_truth=truth,
                        report=report,
                        server_received=len(new_requests),
                    )
                )

            units.append(
                ApplicationUnit(
                    application_id=application_id,
                    ground_truth=truth,
                    framework="fastapi",
                    dbms=dbms,
                    sql_context=sql_context,
                    samples=tuple(samples),
                )
            )

    return summarize_applications(tuple(units))


def test_application_level_http_quality(application_results):
    result = application_results

    assert result.application_count == 4
    assert result.run_count == 8
    assert result.vulnerable_count == 1
    assert result.non_vulnerable_count == 3
    assert result.true_candidates == 1
    assert result.false_candidates == 1

    assert result.candidate_sensitivity == 1
    assert result.false_candidate_rate == pytest.approx(1 / 3)
    assert result.classification_coverage == 1
    assert result.abstention_rate == 0
    assert result.mixed_case_rate == 0
    assert result.reason_flaky_rate == 0
    assert result.execution_error_run_count == 0

    assert result.request_count == 72
    assert result.dispatch_count == 72
    assert result.server_received == 72

    sensitivity = result.sensitivity_interval()
    false_candidates = result.false_candidate_interval()
    assert sensitivity is not None
    assert sensitivity.trials == 1
    assert false_candidates is not None
    assert false_candidates.trials == 3


def test_application_strata(application_results):
    groups = dict(application_results.strata("dbms"))

    assert groups["sqlite"].application_count == 2
    assert groups["none"].application_count == 2

    assert groups["sqlite"].candidate_sensitivity == 1
    assert groups["sqlite"].false_candidate_rate == 0

    assert groups["none"].candidate_sensitivity is None
    assert groups["none"].false_candidate_rate == 0.5


def test_application_outcomes_preserve_mimic(
    application_results,
):
    outcomes = {
        app.application_id: app.outcome for app in application_results.applications
    }

    assert outcomes == {
        "unsafe_sqlite": ApplicationOutcome.CANDIDATE,
        "prepared_sqlite": ApplicationOutcome.NOT_CONFIRMED,
        "non_sql_mimic": ApplicationOutcome.CANDIDATE,
        "non_sql_plain": ApplicationOutcome.NOT_CONFIRMED,
    }
