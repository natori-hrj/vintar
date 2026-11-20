"""opt-in real HTTP PostgreSQL/MySQL corpus.

Run only with VINTAR_DB_INTEGRATION=1 and local Docker DB fixtures.

The vulnerable SQL is intentionally confined to this test module.
Do not use this fixture against untrusted or production databases.
"""

import os
import socket
import threading
import time
from collections import Counter
from contextlib import closing
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import httpx
import psycopg
import pymysql
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from vintar.checks.sqli.confirmation_runner import (
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.models import Verdict
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

pytestmark = pytest.mark.skipif(
    os.environ.get("VINTAR_DB_INTEGRATION") != "1",
    reason="Requires explicit VINTAR_DB_INTEGRATION=1",
)

TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
BASELINE_PRESERVING_CONTROL = "' AND 7=7-- "

ENGINES = ("postgres", "mysql")
MODES = ("vulnerable", "safe", "simple", "mimic")

PORTS = {
    "postgres": int(os.environ.get("VINTAR_POSTGRES_PORT", "15432")),
    "mysql": int(os.environ.get("VINTAR_MYSQL_PORT", "13306")),
}

DATABASE_NAME = "vintar_corpus"
DATABASE_USER = "vintar_corpus"
TABLE_NAME = "vintar_corpus_products_55_4_2"

EXPECTED = {
    "vulnerable": (ConfirmationStatus.CANDIDATE, 18),
    "safe": (ConfirmationStatus.SKIPPED, 6),
    "simple": (ConfirmationStatus.INCONCLUSIVE, 18),
    "mimic": (ConfirmationStatus.CANDIDATE, 18),
}


@dataclass(frozen=True, slots=True, repr=False)
class DatabaseCredentials:
    password: str = field(repr=False)


class DatabaseIdentityError(RuntimeError):
    """Raised without exposing connection details or credentials."""


def safe_database_error_code(exc: BaseException) -> str:
    """Return only non-sensitive driver error identifiers."""
    if isinstance(exc, DatabaseIdentityError):
        return "identity_mismatch"
    if isinstance(exc, psycopg.Error):
        sqlstate = exc.sqlstate
        if isinstance(sqlstate, str) and len(sqlstate) == 5:
            return f"postgres_sqlstate_{sqlstate}"
        return "postgres_connection_error"
    if isinstance(exc, pymysql.MySQLError):
        number = exc.args[0] if exc.args else None
        if type(number) is int:
            return f"mysql_error_{number}"
        return "mysql_connection_error"
    return "unknown_database_error"


@dataclass(repr=False)
class FixtureState:
    received: Counter = field(default_factory=Counter)
    sql_started: Counter = field(default_factory=Counter)
    sql_completed: Counter = field(default_factory=Counter)
    sql_errors: Counter = field(default_factory=Counter)
    queries: dict[str, list[tuple[str, str]]] = field(default_factory=dict)
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
    )

    def record(self, counter: Counter, key: str) -> None:
        with self._lock:
            counter[key] += 1

    def count(self, counter: Counter, key: str) -> int:
        with self._lock:
            return counter[key]

    def record_request(
        self,
        key: str,
        category: str,
        raw_query: str,
    ) -> None:
        with self._lock:
            self.received[key] += 1
            self.queries.setdefault(key, []).append((category, raw_query))

    def query_slice(
        self,
        key: str,
        start: int,
    ) -> tuple[tuple[str, str], ...]:
        with self._lock:
            return tuple(self.queries.get(key, ())[start:])


def db_connection(engine: str, credentials: DatabaseCredentials):
    """Connect exclusively to the local test DB ports."""
    if engine == "postgres":
        return psycopg.connect(
            host="127.0.0.1",
            port=PORTS["postgres"],
            dbname=DATABASE_NAME,
            user=DATABASE_USER,
            password=credentials.password,
            connect_timeout=3,
            autocommit=True,
        )

    if engine == "mysql":
        return pymysql.connect(
            host="127.0.0.1",
            port=PORTS["mysql"],
            database=DATABASE_NAME,
            user=DATABASE_USER,
            password=credentials.password,
            connect_timeout=3,
            read_timeout=3,
            write_timeout=3,
            autocommit=True,
            charset="utf8mb4",
        )

    raise ValueError("Unsupported database engine")


def prepare_database(engine: str, credentials: DatabaseCredentials) -> None:
    """Initialize known data in the dedicated test database."""
    with (
        closing(db_connection(engine, credentials)) as conn,
        closing(conn.cursor()) as cursor,
    ):
        if engine == "postgres":
            cursor.execute("SELECT current_database(), current_user")
            identity = cursor.fetchone()
            expected_identity = (DATABASE_NAME, DATABASE_USER)
        else:
            cursor.execute("SELECT DATABASE(), CURRENT_USER()")
            identity = cursor.fetchone()
            expected_identity = (
                DATABASE_NAME,
                f"{DATABASE_USER}@%",
            )

        if identity != expected_identity:
            raise DatabaseIdentityError

        cursor.execute(
            f"CREATE TABLE IF NOT EXISTS {TABLE_NAME} "
            "(name VARCHAR(100) NOT NULL, "
            "category VARCHAR(100) NOT NULL)"
        )
        cursor.execute(f"DELETE FROM {TABLE_NAME}")
        cursor.executemany(
            f"INSERT INTO {TABLE_NAME} (name, category) VALUES (%s, %s)",
            (
                ("Cat toy", "Pets"),
                ("Dog toy", "Pets"),
                ("Notebook", "Office"),
            ),
        )


def execute_query(
    engine: str,
    mode: str,
    category: str,
    credentials: DatabaseCredentials,
) -> bytes:
    with (
        closing(db_connection(engine, credentials)) as conn,
        closing(conn.cursor()) as cursor,
    ):
        if mode == "vulnerable":
            # Deliberately unsafe SQL for the isolated test DB.
            cursor.execute(
                f"SELECT name FROM {TABLE_NAME} WHERE category = '{category}'"
            )
        else:
            cursor.execute(
                f"SELECT name FROM {TABLE_NAME} WHERE category = %s",
                (category,),
            )

        rows = cursor.fetchall()

    return "\n".join(sorted(str(row[0]) for row in rows)).encode("utf-8")


def create_app(
    state: FixtureState,
    credentials: DatabaseCredentials,
) -> FastAPI:
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/products/{engine}/{mode}")
    def products(
        engine: str,
        mode: str,
        category: str,
        request: Request,
    ) -> Response:
        if engine not in ENGINES or mode not in MODES:
            return Response(
                b"not-found",
                status_code=404,
            )

        if len(request.query_params.getlist("category")) != 1:
            return Response(
                b"invalid-query",
                status_code=400,
                media_type="text/plain",
            )

        key = f"{engine}:{mode}"
        state.record_request(
            key,
            category,
            request.scope["query_string"].decode("ascii"),
        )

        if mode in ("vulnerable", "safe"):
            state.record(state.sql_started, key)
            try:
                body = execute_query(
                    engine,
                    mode,
                    category,
                    credentials,
                )
            except (psycopg.Error, pymysql.MySQLError):
                state.record(state.sql_errors, key)
                return Response(
                    b"query-error",
                    status_code=500,
                    media_type="text/plain",
                )

            state.record(state.sql_completed, key)
            return Response(
                body,
                media_type="text/plain",
            )

        false_1 = category == "Pets" + FALSE_1
        false_2 = category == "Pets" + FALSE_2

        if mode == "simple":
            body = b"B" if false_1 else b"A"
        else:
            body = b"B" if false_1 or false_2 else b"A"

        return Response(
            body,
            media_type="text/plain",
        )

    return app


@pytest.fixture(scope="module")
def db_credentials():
    password = os.environ.get("VINTAR_TEST_DB_PASSWORD")
    if not password:
        pytest.fail("VINTAR_TEST_DB_PASSWORD must be configured.")
    return DatabaseCredentials(password=password)


@pytest.fixture(scope="module")
def prepared_databases(db_credentials):
    for engine in ENGINES:
        try:
            prepare_database(engine, db_credentials)
        except (
            DatabaseIdentityError,
            psycopg.Error,
            pymysql.MySQLError,
        ) as exc:
            raise AssertionError(
                f"{engine} test database unavailable; "
                f"reason={safe_database_error_code(exc)}."
            ) from None

    return True


@pytest.fixture(scope="module")
def fastapi_origin(prepared_databases, db_credentials):
    state = FixtureState()
    app = create_app(state, db_credentials)

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
            deadline = time.monotonic() + 5

            while (
                not server.started and worker.is_alive() and time.monotonic() < deadline
            ):
                time.sleep(0.01)

            assert server.started
            assert worker.is_alive()
            assert listener.getsockname()[0] == "127.0.0.1"

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


def run_confirmation(
    origin: str,
    engine: str,
    mode: str,
):
    port = urlsplit(origin).port
    assert port is not None

    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", port)})
        ),
        budget=RequestBudget(18),
        timeout=5.0,
        rate_limiter=RateLimiter(
            requests_per_second=100,
        ),
    )

    outcome = verify_boolean_sqli_with_confirmation(
        check_id=f"dbms-{engine}-{mode}",
        template=RequestTemplate(
            method="GET",
            url=f"{origin}/products/{engine}/{mode}",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        true_1=TRUE_1,
        false_1=FALSE_1,
        true_2=TRUE_2,
        false_2=FALSE_2,
        baseline_preserving_control=BASELINE_PRESERVING_CONTROL,
        context=context,
    )

    return outcome, context


@pytest.mark.parametrize("engine", ENGINES)
@pytest.mark.parametrize("mode", MODES)
def test_dbms_confirmation_corpus(
    fastapi_origin,
    engine,
    mode,
):
    state, origin = fastapi_origin
    key = f"{engine}:{mode}"

    before_received = state.count(state.received, key)
    before_started = state.count(state.sql_started, key)
    before_completed = state.count(state.sql_completed, key)
    before_errors = state.count(state.sql_errors, key)

    outcome, context = run_confirmation(
        origin,
        engine,
        mode,
    )

    expected_status, expected_count = EXPECTED[mode]

    assert outcome.status is expected_status
    assert outcome.total_requests == expected_count
    assert outcome.request_count == expected_count
    assert context.budget.used_requests == expected_count

    received = state.count(state.received, key) - before_received
    started = state.count(state.sql_started, key) - before_started
    completed = state.count(state.sql_completed, key) - before_completed
    errors = state.count(state.sql_errors, key) - before_errors
    queries = state.query_slice(key, before_received)

    assert received == expected_count
    assert len(queries) == expected_count
    assert errors == 0

    values = [category for category, _ in queries]
    assert values[:6] == [
        "Pets",
        "Pets" + TRUE_1,
        "Pets" + FALSE_1,
        "Pets",
        "Pets" + FALSE_1,
        "Pets" + TRUE_1,
    ]
    for category, raw_query in queries:
        assert parse_qs(raw_query, keep_blank_values=True) == {"category": [category]}
        assert " " not in raw_query
        assert "'" not in raw_query
        if "'" in category:
            assert "%27" in raw_query

    if mode in ("vulnerable", "safe"):
        assert started == expected_count
        assert completed == expected_count
    else:
        assert started == 0
        assert completed == 0

    assert outcome.initial.verdict is not Verdict.VULNERABLE

    if mode == "vulnerable":
        assert outcome.evidence is not None
        assert outcome.reason_code == "confirmation_pattern_matched"

    if mode == "safe":
        assert outcome.confirmation_requests == 0
        assert outcome.initial.reason_code == ("unexpected_difference")


def test_fastapi_rejects_missing_and_duplicate_query_values(
    fastapi_origin,
):
    state, origin = fastapi_origin
    key = "postgres:safe"
    before = state.count(state.received, key)

    with httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=3,
    ) as client:
        missing = client.get(f"{origin}/products/postgres/safe")
        duplicate = client.get(
            f"{origin}/products/postgres/safe",
            params=(("category", "Pets"), ("category", "Office")),
        )

    assert missing.status_code == 422
    assert duplicate.status_code == 400
    assert state.count(state.received, key) == before


def test_uvicorn_logs_do_not_disclose_payloads(
    fastapi_origin,
    capsys,
):
    _, origin = fastapi_origin

    outcome, _ = run_confirmation(origin, "postgres", "vulnerable")
    captured = capsys.readouterr()

    assert outcome.status is ConfirmationStatus.CANDIDATE
    for sensitive in (TRUE_1, FALSE_1, TRUE_2, FALSE_2):
        assert sensitive not in captured.out
        assert sensitive not in captured.err


@pytest.mark.parametrize("engine", ENGINES)
def test_sql_syntax_errors_are_redacted(
    fastapi_origin,
    capsys,
    engine,
):
    state, origin = fastapi_origin
    key = f"{engine}:vulnerable"
    before_started = state.count(state.sql_started, key)
    before_completed = state.count(state.sql_completed, key)
    before_errors = state.count(state.sql_errors, key)
    malformed = "Pets' AND ("

    with httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=3,
    ) as client:
        response = client.get(
            f"{origin}/products/{engine}/vulnerable",
            params={"category": malformed},
        )

    captured = capsys.readouterr()
    assert response.status_code == 500
    assert response.content == b"query-error"
    assert state.count(state.sql_started, key) - before_started == 1
    assert state.count(state.sql_completed, key) - before_completed == 0
    assert state.count(state.sql_errors, key) - before_errors == 1
    assert malformed not in captured.out
    assert malformed not in captured.err


def test_dbms_corpus_metrics(fastapi_origin):
    _, origin = fastapi_origin
    results = {}
    request_counts = {}

    for engine in ENGINES:
        for mode in MODES:
            outcome, _ = run_confirmation(
                origin,
                engine,
                mode,
            )
            results[(engine, mode)] = outcome.status
            request_counts[(engine, mode)] = outcome.request_count

    assert sum(request_counts.values()) == 120
    assert sum(6 for _ in results) == 48

    vulnerable_cases = [key for key in results if key[1] == "vulnerable"]
    benign_cases = [key for key in results if key[1] != "vulnerable"]

    true_candidates = sum(
        results[key] is ConfirmationStatus.CANDIDATE for key in vulnerable_cases
    )
    false_candidates = sum(
        results[key] is ConfirmationStatus.CANDIDATE for key in benign_cases
    )

    decisive = {
        ConfirmationStatus.CANDIDATE,
        ConfirmationStatus.NOT_CONFIRMED,
    }

    evaluable_benign = sum(results[key] in decisive for key in benign_cases)

    assert true_candidates == 2
    assert false_candidates == 2
    assert evaluable_benign == 2

    assert true_candidates / len(vulnerable_cases) == 1.0
    assert false_candidates / len(benign_cases) == 2 / 6
    assert false_candidates / evaluable_benign == 1.0

    assert sum(status in decisive for status in results.values()) == 4

    # Four candidates, two confirmation mismatches, and two skipped cases.
    assert Counter(results.values()) == {
        ConfirmationStatus.CANDIDATE: 4,
        ConfirmationStatus.INCONCLUSIVE: 2,
        ConfirmationStatus.SKIPPED: 2,
    }

    assert sum(count - 6 for count in request_counts.values()) == 72

    skipped = sum(status is ConfirmationStatus.SKIPPED for status in results.values())
    inconclusive = sum(
        status is ConfirmationStatus.INCONCLUSIVE for status in results.values()
    )
    decidable = sum(status in decisive for status in results.values())

    assert skipped / len(results) == 2 / 8
    assert inconclusive / len(results) == 2 / 8
    assert decidable / len(results) == 4 / 8

    for engine in ENGINES:
        engine_counts = [
            count
            for (result_engine, _), count in request_counts.items()
            if result_engine == engine
        ]
        assert sum(engine_counts) == 60
        assert sum(engine_counts) / len(engine_counts) == 15.0


def test_dbms_corpus_classification_is_repeatable(fastapi_origin):
    _, origin = fastapi_origin
    runs = []

    for _ in range(2):
        result = {}
        for engine in ENGINES:
            for mode in MODES:
                outcome, _ = run_confirmation(origin, engine, mode)
                result[(engine, mode)] = (
                    outcome.status,
                    outcome.reason_code,
                    outcome.request_count,
                )
        runs.append(result)

    assert runs[0] == runs[1]
