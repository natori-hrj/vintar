"""Evaluate experimental time-based SQLi through real loopback HTTP.

SQLite and non-SQL fixtures run by default. PostgreSQL and MySQL
require an explicitly enabled, isolated test database environment.

This corpus tests candidate classification, not vulnerability proof.
"""

import os
import socket
import sqlite3
import threading
import time
from collections import Counter
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import psycopg
import pymysql
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from vintar.checks.sqli.time_analyzer import (
    TimeAnalysisStatus,
    TimeObservation,
    TimeProbeOutcome,
    analyze_time_probes,
)
from vintar.checks.sqli.time_plan import (
    TIME_PROBE_ORDER,
    TimePayloads,
    prepare_time_plan,
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

EXPECTED_DELAY = 0.30
ACTUAL_DELAY = 0.40
SQLITE_DELAY = "' AND vintar_delay(0.4)=1-- "
SQLITE_CONTROL = "' AND vintar_delay(0)=1-- "
POSTGRES_DELAY = "' AND (SELECT COUNT(*) FROM pg_sleep(0.4))=1-- "
POSTGRES_CONTROL = "' AND (SELECT COUNT(*) FROM pg_sleep(0))=1-- "
MYSQL_DELAY = "' AND SLEEP(0.4)=0-- "
MYSQL_CONTROL = "' AND SLEEP(0)=0-- "
DATABASE_DELAY_EXPRESSIONS = {
    "postgres": "pg_sleep(0.4)",
    "mysql": "SLEEP(0.4)",
}

TABLE_NAME = "vintar_time_products"
DATABASE_NAME = "vintar_corpus"
DATABASE_USER = "vintar_corpus"

DATABASE_PORTS = {
    "postgres": int(os.environ.get("VINTAR_POSTGRES_PORT", "15432")),
    "mysql": int(os.environ.get("VINTAR_MYSQL_PORT", "13306")),
}

SQLITE_MODES = (
    "vulnerable",
    "safe",
    "mimic",
    "slow",
    "jitter",
    "rate_limited",
)

SAFE_LIVE_OUTCOMES = frozenset(
    {
        (TimeAnalysisStatus.NOT_CONFIRMED, "timing_pattern_not_matched"),
        (TimeAnalysisStatus.INCONCLUSIVE, "unstable_timing"),
    }
)
DELAY_SIGNAL_LIVE_OUTCOMES = frozenset(
    {
        (TimeAnalysisStatus.CANDIDATE, "timing_pattern_matched"),
        (TimeAnalysisStatus.INCONCLUSIVE, "unstable_timing"),
    }
)

RECORDED_ELAPSED_SECONDS = {
    "delay_signal": (
        0.006,
        0.003,
        0.404,
        0.003,
        0.403,
        0.002,
        0.405,
        0.002,
        0.002,
    ),
    "safe": (0.006, 0.003, 0.003, 0.003, 0.002, 0.002, 0.003, 0.002, 0.002),
    "slow": (0.404, 0.403, 0.403, 0.402, 0.402, 0.402, 0.403, 0.402, 0.402),
    "jitter": (0.006, 0.003, 0.003, 0.003, 0.003, 0.220, 0.003, 0.002, 0.002),
}


@dataclass(repr=False)
class FixtureState:
    requests: Counter = field(default_factory=Counter)
    sql_executions: Counter = field(default_factory=Counter)
    errors: Counter = field(default_factory=Counter)
    delay_evaluations: Counter = field(default_factory=Counter)
    received: dict[str, list[str]] = field(default_factory=dict)
    lock: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
    )

    def record_request(self, key: str, value: str) -> int:
        with self.lock:
            self.requests[key] += 1
            self.received.setdefault(key, []).append(value)
            return self.requests[key]

    def record_sql(self, key: str) -> None:
        with self.lock:
            self.sql_executions[key] += 1

    def record_error(self, key: str) -> None:
        with self.lock:
            self.errors[key] += 1

    def record_delay_evaluation(self, key: str, seconds: float) -> None:
        with self.lock:
            self.delay_evaluations[(key, seconds)] += 1

    def delay_evaluation_count(self, key: str, seconds: float) -> int:
        with self.lock:
            return self.delay_evaluations[(key, seconds)]

    def snapshot(self, key: str) -> tuple[int, int, int]:
        with self.lock:
            return (
                self.requests[key],
                self.sql_executions[key],
                self.errors[key],
            )

    def values_since(
        self,
        key: str,
        index: int,
    ) -> tuple[str, ...]:
        with self.lock:
            return tuple(self.received.get(key, ()))[index:]


def sqlite_query(
    category: str,
    *,
    vulnerable: bool,
    on_delay: Callable[[float], None],
) -> bytes:
    """Execute an intentionally unsafe query in an in-memory test DB."""
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.create_function(
            "vintar_delay",
            1,
            lambda seconds: _sqlite_delay(seconds, on_delay),
        )
        connection.execute("CREATE TABLE products (name TEXT, category TEXT)")
        connection.execute(
            "INSERT INTO products VALUES (?, ?)",
            ("Cat toy", "Pets"),
        )

        if vulnerable:
            rows = connection.execute(
                f"SELECT name FROM products WHERE category = '{category}'"
            ).fetchall()
        else:
            rows = connection.execute(
                "SELECT name FROM products WHERE category = ?",
                (category,),
            ).fetchall()

    return "\n".join(row[0] for row in rows).encode("utf-8")


def _sqlite_delay(
    seconds: float,
    on_delay: Callable[[float], None],
) -> int:
    on_delay(seconds)
    time.sleep(seconds)
    return 1


def database_connection(engine: str, password: str):
    if engine == "postgres":
        return psycopg.connect(
            host="127.0.0.1",
            port=DATABASE_PORTS["postgres"],
            dbname=DATABASE_NAME,
            user=DATABASE_USER,
            password=password,
            connect_timeout=3,
            autocommit=True,
        )

    if engine == "mysql":
        return pymysql.connect(
            host="127.0.0.1",
            port=DATABASE_PORTS["mysql"],
            database=DATABASE_NAME,
            user=DATABASE_USER,
            password=password,
            connect_timeout=3,
            read_timeout=3,
            write_timeout=3,
            autocommit=True,
            charset="utf8mb4",
        )

    raise ValueError("Unsupported test database.")


def prepare_database(engine: str, password: str) -> None:
    """Initialize a dedicated table only after identity verification."""
    with (
        closing(database_connection(engine, password)) as connection,
        closing(connection.cursor()) as cursor,
    ):
        if engine == "postgres":
            cursor.execute("SELECT current_database(), current_user")
            identity = cursor.fetchone()
            expected = (DATABASE_NAME, DATABASE_USER)
        else:
            cursor.execute("SELECT DATABASE(), CURRENT_USER()")
            identity = cursor.fetchone()
            expected = (
                DATABASE_NAME,
                f"{DATABASE_USER}@%",
            )

        if identity != expected:
            raise RuntimeError("Test database identity mismatch.")

        cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {TABLE_NAME} "
            "(name VARCHAR(100), category VARCHAR(100))"
        )
        cursor.execute(f"DELETE FROM {TABLE_NAME}")
        cursor.execute(
            f"INSERT INTO {TABLE_NAME} (name, category) VALUES (%s, %s)",
            ("Cat toy", "Pets"),
        )


def database_query(
    engine: str,
    mode: str,
    category: str,
    password: str,
    on_delay: Callable[[float], None],
) -> bytes:
    with (
        closing(database_connection(engine, password)) as connection,
        closing(connection.cursor()) as cursor,
    ):
        if mode == "vulnerable":
            statement = f"SELECT name FROM {TABLE_NAME} WHERE category = '{category}'"
            cursor.execute(statement)
            if DATABASE_DELAY_EXPRESSIONS[engine] in statement:
                on_delay(ACTUAL_DELAY)
        else:
            cursor.execute(
                f"SELECT name FROM {TABLE_NAME} WHERE category = %s",
                (category,),
            )

        rows = cursor.fetchall()

    return "\n".join(str(row[0]) for row in rows).encode("utf-8")


@pytest.mark.parametrize(
    ("engine", "delay_payload"),
    (("postgres", POSTGRES_DELAY), ("mysql", MYSQL_DELAY)),
)
def test_database_query_records_executed_delay_expression(
    monkeypatch, engine, delay_payload
):
    cursors = []

    class FakeCursor:
        def __init__(self):
            self.executions = []

        def execute(self, statement, params=None):
            self.executions.append((statement, params))

        def fetchall(self):
            return [("Cat toy",)]

        def close(self):
            return None

    class FakeConnection:
        def __init__(self):
            self.cursor_instance = FakeCursor()
            cursors.append(self.cursor_instance)

        def cursor(self):
            return self.cursor_instance

        def close(self):
            return None

    def fake_connection(_engine, _password):
        return FakeConnection()

    monkeypatch.setitem(globals(), "database_connection", fake_connection)
    vulnerable_delays = []
    safe_delays = []

    vulnerable_body = database_query(
        engine,
        "vulnerable",
        "Pets" + delay_payload,
        "unused",
        vulnerable_delays.append,
    )
    safe_body = database_query(
        engine,
        "safe",
        "Pets" + delay_payload,
        "unused",
        safe_delays.append,
    )

    assert vulnerable_body == b"Cat toy"
    assert safe_body == b"Cat toy"
    assert vulnerable_delays == [ACTUAL_DELAY]
    assert safe_delays == []
    assert DATABASE_DELAY_EXPRESSIONS[engine] in cursors[0].executions[0][0]
    assert cursors[1].executions[0][1] == ("Pets" + delay_payload,)


def create_app(
    state: FixtureState,
    *,
    password: str | None = None,
) -> FastAPI:
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/time/{engine}/{mode}")
    def handle(
        engine: str,
        mode: str,
        request: Request,
    ) -> Response:
        if engine == "sqlite":
            if mode not in SQLITE_MODES:
                return Response(status_code=404)
        elif engine in ("postgres", "mysql"):
            if password is None or mode not in ("vulnerable", "safe"):
                return Response(status_code=404)
        else:
            return Response(status_code=404)

        values = request.query_params.getlist("category")

        if len(values) != 1:
            return Response(status_code=400)

        category = values[0]
        key = f"{engine}:{mode}"
        number = state.record_request(key, category)

        if mode == "rate_limited":
            return Response(status_code=429)

        if mode == "mimic":
            if category.endswith(SQLITE_DELAY):
                state.record_delay_evaluation(key, ACTUAL_DELAY)
                time.sleep(ACTUAL_DELAY)
            return Response(b"non-sql", media_type="text/plain")

        if mode == "slow":
            state.record_delay_evaluation(key, ACTUAL_DELAY)
            time.sleep(ACTUAL_DELAY)
            return Response(b"slow", media_type="text/plain")

        if mode == "jitter":
            if category == "Pets" and number % 2 == 0:
                state.record_delay_evaluation(key, ACTUAL_DELAY)
                time.sleep(ACTUAL_DELAY)
            return Response(b"jitter", media_type="text/plain")

        state.record_sql(key)

        try:
            if engine == "sqlite":
                body = sqlite_query(
                    category,
                    vulnerable=(mode == "vulnerable"),
                    on_delay=lambda seconds: state.record_delay_evaluation(
                        key,
                        seconds,
                    ),
                )
            else:
                assert password is not None
                body = database_query(
                    engine,
                    mode,
                    category,
                    password,
                    on_delay=lambda seconds: state.record_delay_evaluation(
                        key,
                        seconds,
                    ),
                )
        except (sqlite3.Error, psycopg.Error, pymysql.MySQLError):
            state.record_error(key)
            return Response(
                b"query-error",
                status_code=500,
                media_type="text/plain",
            )

        return Response(body, media_type="text/plain")

    return app


@pytest.fixture(scope="module")
def http_server():
    state = FixtureState()
    password = (
        os.environ.get("VINTAR_TEST_DB_PASSWORD")
        if os.environ.get("VINTAR_DB_INTEGRATION") == "1"
        else None
    )

    app = create_app(state, password=password)

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


def make_payloads(engine: str) -> TimePayloads:
    values = {
        "sqlite": (SQLITE_DELAY, SQLITE_CONTROL),
        "postgres": (POSTGRES_DELAY, POSTGRES_CONTROL),
        "mysql": (MYSQL_DELAY, MYSQL_CONTROL),
    }
    delay, control = values[engine]
    return TimePayloads(delay=delay, control=control)


def expected_probe_values(engine: str) -> tuple[str, ...]:
    payloads = make_payloads(engine)
    return (
        "Pets",
        "Pets" + payloads.control,
        "Pets" + payloads.delay,
        "Pets" + payloads.control,
        "Pets" + payloads.delay,
        "Pets",
        "Pets" + payloads.delay,
        "Pets",
        "Pets" + payloads.control,
    )


def run_case(
    origin: str,
    engine: str,
    mode: str,
    *,
    payloads: TimePayloads | None = None,
):
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
        max_response_size=1_048_576,
    )

    report = verify_time_based_sqli(
        template=RequestTemplate(
            method="GET",
            url=f"{origin}/time/{engine}/{mode}",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=payloads or make_payloads(engine),
        expected_delay_seconds=EXPECTED_DELAY,
        context=context,
        max_total_seconds=15.0,
    )

    assert report.budget_used == context.budget.used_requests

    return report


def analyze_fixed_elapsed(elapsed_values: tuple[float, ...]):
    origin = "http://127.0.0.1:18084"
    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", 18084)})
        ),
        budget=RequestBudget(9),
        timeout=3.0,
        rate_limiter=RateLimiter(requests_per_second=100.0),
    )
    plan = prepare_time_plan(
        template=RequestTemplate(
            method="GET",
            url=origin + "/time/sqlite/fixed",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=make_payloads("sqlite"),
        expected_delay_seconds=EXPECTED_DELAY,
        context=context,
    )
    observations = tuple(
        TimeObservation(
            kind=kind,
            sequence=sequence,
            outcome=TimeProbeOutcome.COMPLETED,
            elapsed_seconds=elapsed,
            status_code=200,
        )
        for sequence, (kind, elapsed) in enumerate(
            zip(TIME_PROBE_ORDER, elapsed_values, strict=True), start=1
        )
    )
    return analyze_time_probes(plan=plan, observations=observations)


@pytest.mark.parametrize(
    ("mode", "delay_signal", "uses_sql", "actual_delay_count"),
    [
        ("vulnerable", True, True, 3),
        ("safe", False, True, 0),
        ("mimic", True, False, 3),
        ("slow", False, False, 9),
        ("jitter", False, False, 2),
    ],
)
def test_sqlite_and_non_sql_http_corpus(
    http_server,
    mode,
    delay_signal,
    uses_sql,
    actual_delay_count,
):
    state, origin = http_server
    key = f"sqlite:{mode}"

    before_requests, before_sql, before_errors = state.snapshot(key)

    report = run_case(origin, "sqlite", mode)

    after_requests, after_sql, after_errors = state.snapshot(key)

    analysis = report.analysis
    elapsed_values = tuple(item.elapsed_seconds for item in analysis.observations)
    diagnostic = (
        f"case_id={'sqlite:' + mode!r}, status={analysis.status.value!r}, "
        f"reason_code={analysis.reason_code!r}, elapsed_seconds={elapsed_values!r}"
    )
    allowed = DELAY_SIGNAL_LIVE_OUTCOMES if delay_signal else SAFE_LIVE_OUTCOMES

    assert (analysis.status, analysis.reason_code) in allowed, diagnostic
    if mode == "vulnerable":
        assert analysis.status is not TimeAnalysisStatus.NOT_CONFIRMED, diagnostic
    assert analysis.request_count == 9, diagnostic
    assert report.budget_used == 9, diagnostic
    assert report.transport_attempts == 9, diagnostic
    assert not report.deadline_exceeded, diagnostic

    assert after_requests - before_requests == 9, diagnostic
    assert after_sql - before_sql == (9 if uses_sql else 0), diagnostic
    assert after_errors == before_errors, diagnostic

    values = state.values_since(key, before_requests)
    assert values == expected_probe_values("sqlite"), diagnostic
    assert state.delay_evaluation_count(key, ACTUAL_DELAY) == actual_delay_count, (
        diagnostic
    )

    if mode == "vulnerable":
        assert state.delay_evaluation_count(key, 0.0) == 3
    elif mode == "safe":
        assert state.delay_evaluation_count(key, ACTUAL_DELAY) == 0
        assert state.delay_evaluation_count(key, 0.0) == 0


@pytest.mark.parametrize(
    ("case_id", "recording", "expected_status", "expected_reason"),
    [
        (
            "sqlite:vulnerable",
            "delay_signal",
            TimeAnalysisStatus.CANDIDATE,
            "timing_pattern_matched",
        ),
        (
            "sqlite:safe",
            "safe",
            TimeAnalysisStatus.NOT_CONFIRMED,
            "timing_pattern_not_matched",
        ),
        (
            "sqlite:mimic",
            "delay_signal",
            TimeAnalysisStatus.CANDIDATE,
            "timing_pattern_matched",
        ),
        (
            "sqlite:slow",
            "slow",
            TimeAnalysisStatus.NOT_CONFIRMED,
            "timing_pattern_not_matched",
        ),
        (
            "sqlite:jitter",
            "jitter",
            TimeAnalysisStatus.INCONCLUSIVE,
            "unstable_timing",
        ),
        (
            "postgres:vulnerable",
            "delay_signal",
            TimeAnalysisStatus.CANDIDATE,
            "timing_pattern_matched",
        ),
        (
            "postgres:safe",
            "safe",
            TimeAnalysisStatus.NOT_CONFIRMED,
            "timing_pattern_not_matched",
        ),
        (
            "mysql:vulnerable",
            "delay_signal",
            TimeAnalysisStatus.CANDIDATE,
            "timing_pattern_matched",
        ),
        (
            "mysql:safe",
            "safe",
            TimeAnalysisStatus.NOT_CONFIRMED,
            "timing_pattern_not_matched",
        ),
    ],
)
def test_fixed_observations_classify_http_corpus_exactly(
    case_id, recording, expected_status, expected_reason
):
    analysis = analyze_fixed_elapsed(RECORDED_ELAPSED_SECONDS[recording])
    elapsed_values = tuple(item.elapsed_seconds for item in analysis.observations)
    diagnostic = (
        f"case_id={case_id!r}, status={analysis.status.value!r}, "
        f"reason_code={analysis.reason_code!r}, elapsed_seconds={elapsed_values!r}"
    )

    assert analysis.status is expected_status, diagnostic
    assert analysis.reason_code == expected_reason, diagnostic


def test_http_rate_limit_stops_after_one_request(http_server):
    state, origin = http_server
    key = "sqlite:rate_limited"
    before_requests, before_sql, before_errors = state.snapshot(key)

    report = run_case(origin, "sqlite", "rate_limited")

    after_requests, after_sql, after_errors = state.snapshot(key)

    assert report.analysis.status is TimeAnalysisStatus.INCONCLUSIVE
    assert report.analysis.reason_code == "rate_limited"
    assert report.analysis.request_count == 1
    assert report.budget_used == 1
    assert report.transport_attempts == 1
    assert not report.deadline_exceeded
    assert after_requests - before_requests == 1
    assert after_sql == before_sql
    assert after_errors == before_errors


def test_sql_errors_and_probe_values_are_not_disclosed(http_server, capsys):
    state, origin = http_server
    key = "sqlite:vulnerable"
    marker = "vintar_private_probe_marker"
    before_requests, before_sql, before_errors = state.snapshot(key)

    report = run_case(
        origin,
        "sqlite",
        "vulnerable",
        payloads=TimePayloads(
            delay=f"' AND {marker}=2-- ",
            control=f"' AND {marker}=1-- ",
        ),
    )

    after_requests, after_sql, after_errors = state.snapshot(key)
    captured = capsys.readouterr()

    assert report.analysis.status is TimeAnalysisStatus.INCONCLUSIVE
    assert report.analysis.reason_code == "non_success_status"
    assert report.analysis.request_count == 2
    assert report.budget_used == 2
    assert report.transport_attempts == 2
    assert after_requests - before_requests == 2
    assert after_sql - before_sql == 2
    assert after_errors - before_errors == 1
    assert marker not in repr(report)
    assert marker not in captured.out
    assert marker not in captured.err


@pytest.fixture(scope="module")
def prepared_databases():
    if os.environ.get("VINTAR_DB_INTEGRATION") != "1":
        pytest.skip("Requires explicit VINTAR_DB_INTEGRATION=1.")

    password = os.environ.get("VINTAR_TEST_DB_PASSWORD")
    if not password:
        pytest.fail("VINTAR_TEST_DB_PASSWORD must be configured.")

    for engine in ("postgres", "mysql"):
        try:
            prepare_database(engine, password)
        except (psycopg.Error, pymysql.MySQLError, RuntimeError):
            pytest.fail(f"{engine} dedicated test database unavailable.")

    return True


@pytest.mark.parametrize("engine", ("postgres", "mysql"))
@pytest.mark.parametrize(
    ("mode", "delay_signal"),
    [
        ("vulnerable", True),
        ("safe", False),
    ],
)
def test_database_time_http_corpus(
    prepared_databases,
    http_server,
    engine,
    mode,
    delay_signal,
):
    state, origin = http_server
    key = f"{engine}:{mode}"

    before_requests, before_sql, before_errors = state.snapshot(key)

    report = run_case(origin, engine, mode)

    after_requests, after_sql, after_errors = state.snapshot(key)

    analysis = report.analysis
    elapsed_values = tuple(item.elapsed_seconds for item in analysis.observations)
    diagnostic = (
        f"case_id={engine + ':' + mode!r}, status={analysis.status.value!r}, "
        f"reason_code={analysis.reason_code!r}, elapsed_seconds={elapsed_values!r}"
    )
    allowed = DELAY_SIGNAL_LIVE_OUTCOMES if delay_signal else SAFE_LIVE_OUTCOMES

    assert (analysis.status, analysis.reason_code) in allowed, diagnostic
    if mode == "vulnerable":
        assert analysis.status is not TimeAnalysisStatus.NOT_CONFIRMED, diagnostic
    assert analysis.request_count == 9, diagnostic
    assert report.budget_used == 9, diagnostic
    assert report.transport_attempts == 9, diagnostic
    assert not report.deadline_exceeded, diagnostic

    assert after_requests - before_requests == 9, diagnostic
    assert after_sql - before_sql == 9, diagnostic
    assert after_errors == before_errors, diagnostic
    assert state.values_since(key, before_requests) == expected_probe_values(engine), (
        diagnostic
    )

    assert state.delay_evaluation_count(key, ACTUAL_DELAY) == (
        3 if delay_signal else 0
    ), diagnostic
