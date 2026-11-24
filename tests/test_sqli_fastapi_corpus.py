"""Step 55.4.1: real HTTP SQLi corpus using FastAPI and SQLite.

The vulnerable SQL is confined to an in-memory test fixture.
Uvicorn listens only on 127.0.0.1 using an ephemeral port.

This evaluates candidate detection, not confirmed SQL injection.
No production Verdict, CLI, or Schema changes are involved.
"""

import socket
import sqlite3
import threading
import time
from contextlib import closing
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import pytest
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response

from vintar.checks.sqli.confirmation_runner import (
    ConfirmationOutcome,
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

TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
BASELINE_PRESERVING_CONTROL = "' AND 7=7-- "

INITIAL_ORDER = ("B", "T1", "F1", "B", "F1", "T1")
CONFIRMATION_ORDER = (
    "B",
    "T1",
    "F1",
    "C",
    "T2",
    "F2",
    "B",
    "F2",
    "T2",
    "C",
    "F1",
    "T1",
)

MODES = (
    "vulnerable",
    "safe",
    "simple",
    "mimic",
    "waf",
    "auth",
    "dynamic",
)


@dataclass(frozen=True, repr=False)
class ReceivedRequest:
    path: str
    category: str
    raw_query: str


@dataclass(repr=False)
class FixtureState:
    received: list[ReceivedRequest] = field(default_factory=list)
    sql_started: int = 0
    sql_completed: int = 0
    sql_errors: int = 0
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    def reset(self) -> None:
        with self._lock:
            self.received.clear()
            self.sql_started = 0
            self.sql_completed = 0
            self.sql_errors = 0

    def record_request(self, request: ReceivedRequest) -> int:
        with self._lock:
            self.received.append(request)
            return len(self.received)

    def record_sql_start(self) -> None:
        with self._lock:
            self.sql_started += 1

    def record_sql_completion(self) -> None:
        with self._lock:
            self.sql_completed += 1

    def record_sql_error(self) -> None:
        with self._lock:
            self.sql_errors += 1


def sql_response(
    category: str,
    *,
    vulnerable: bool,
) -> bytes:
    """Execute SQL against a fresh in-memory SQLite database."""
    with closing(sqlite3.connect(":memory:")) as db:
        db.execute("CREATE TABLE products (name TEXT NOT NULL, category TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            (
                ("Cat toy", "Pets"),
                ("Dog toy", "Pets"),
                ("Notebook", "Office"),
            ),
        )

        if vulnerable:
            # Deliberately unsafe; never expose this fixture externally.
            rows = db.execute(
                f"SELECT name FROM products WHERE category = '{category}'"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT name FROM products WHERE category = ?",
                (category,),
            ).fetchall()

    return "\n".join(sorted(row[0] for row in rows)).encode("utf-8")


def create_app(state: FixtureState) -> FastAPI:
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/products/{mode}")
    def products(
        mode: str,
        category: str,
        request: Request,
    ) -> Response:
        if mode not in MODES:
            raise HTTPException(status_code=404)

        number = state.record_request(
            ReceivedRequest(
                path=request.url.path,
                category=category,
                raw_query=request.scope["query_string"].decode("ascii"),
            )
        )

        if mode == "auth" and number >= 7:
            raise HTTPException(
                status_code=401,
                detail="authentication-required",
            )

        if mode in {"vulnerable", "safe"}:
            state.record_sql_start()
            try:
                body = sql_response(
                    category,
                    vulnerable=(mode == "vulnerable"),
                )
            except sqlite3.Error:
                state.record_sql_error()
                # Do not disclose SQL statements or input.
                return Response(
                    b"query-error",
                    status_code=500,
                    media_type="text/plain",
                )
            state.record_sql_completion()

            return Response(
                body,
                media_type="text/plain",
            )

        false_1 = category == "Pets" + FALSE_1
        false_2 = category == "Pets" + FALSE_2
        if mode == "simple":
            body = b"B" if false_1 else b"A"

        elif mode == "mimic":
            body = b"B" if false_1 or false_2 else b"A"

        elif mode == "waf":
            body = b"request-blocked" if false_1 or false_2 else b"products-found"

        elif mode == "auth":
            # Initial six requests remain a valid candidate.
            body = b"B" if false_1 else b"A"

        elif mode == "dynamic":
            # Change only after initial eligibility is established.
            body = (
                f"nonce-{number}".encode("ascii")
                if number >= 7
                else (b"B" if false_1 else b"A")
            )

        else:
            raise AssertionError("Unknown fixture mode")

        return Response(
            body,
            media_type="text/plain",
        )

    return app


@pytest.fixture
def fastapi_server():
    state = FixtureState()
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
            pytest.skip("Loopback socket unavailable")

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

        thread = threading.Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            daemon=True,
        )
        thread.start()

        try:
            deadline = time.monotonic() + 5

            while (
                not server.started and thread.is_alive() and time.monotonic() < deadline
            ):
                time.sleep(0.01)

            assert server.started
            assert thread.is_alive()
            assert listener.getsockname()[0] == "127.0.0.1"

            yield (
                state,
                f"http://127.0.0.1:{port}",
            )
        finally:
            server.should_exit = True
            thread.join(timeout=5)
            if thread.is_alive():
                server.force_exit = True
                thread.join(timeout=5)
            assert not thread.is_alive()
    finally:
        listener.close()


def run_confirmation(
    origin: str,
    mode: str,
) -> tuple[ConfirmationOutcome, ExecutionContext]:
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
        budget=RequestBudget(18),
        timeout=3.0,
        rate_limiter=RateLimiter(
            requests_per_second=100,
        ),
        max_response_size=1_048_576,
    )

    outcome = verify_boolean_sqli_with_confirmation(
        check_id="fastapi-sqlite-corpus",
        template=RequestTemplate(
            method="GET",
            url=f"{origin}/products/{mode}",
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


@pytest.mark.parametrize(
    ("mode", "expected", "count", "sql_count"),
    [
        ("vulnerable", ConfirmationStatus.CANDIDATE, 18, 18),
        ("safe", ConfirmationStatus.SKIPPED, 6, 6),
        ("simple", ConfirmationStatus.INCONCLUSIVE, 18, 0),
        ("mimic", ConfirmationStatus.CANDIDATE, 18, 0),
        ("waf", ConfirmationStatus.CANDIDATE, 18, 0),
        ("auth", ConfirmationStatus.INCONCLUSIVE, 7, 0),
        ("dynamic", ConfirmationStatus.INCONCLUSIVE, 18, 0),
    ],
)
def test_fastapi_sqlite_corpus(
    fastapi_server,
    mode,
    expected,
    count,
    sql_count,
):
    state, origin = fastapi_server

    outcome, context = run_confirmation(origin, mode)

    assert outcome.status is expected
    assert outcome.total_requests == count
    assert outcome.request_count == count
    assert context.budget.used_requests == count
    assert len(state.received) == count
    assert state.sql_started == sql_count
    assert state.sql_completed == sql_count
    assert state.sql_errors == 0

    assert outcome.initial.verdict is not Verdict.VULNERABLE

    if expected is ConfirmationStatus.CANDIDATE:
        assert outcome.reason_code == "confirmation_pattern_matched"
        assert outcome.evidence is not None

    if expected is ConfirmationStatus.SKIPPED:
        assert outcome.confirmation_requests == 0
        assert outcome.evidence is None
        assert outcome.initial.verdict is Verdict.NOT_DETECTED
        assert outcome.initial.reason_code == "no_boolean_difference_literal_input"

    if expected is ConfirmationStatus.INCONCLUSIVE:
        if mode == "simple":
            assert outcome.reason_code == "confirmation_unstable"
            assert outcome.evidence is None
        else:
            assert outcome.evidence is None

    if mode == "auth":
        assert outcome.reason_code == "confirmation_non_success_status"

    if mode == "dynamic":
        assert outcome.reason_code == "confirmation_unstable"


def test_fastapi_fixture_disables_schema_and_documentation_routes():
    app = create_app(FixtureState())
    paths = {route.path for route in app.routes}

    assert paths == {"/products/{mode}"}


def test_fastapi_decodes_injected_query_parameters(
    fastapi_server,
):
    state, origin = fastapi_server

    outcome, _ = run_confirmation(
        origin,
        "vulnerable",
    )

    assert outcome.status is ConfirmationStatus.CANDIDATE
    assert len(state.received) == 18

    values = [item.category for item in state.received]

    assert values[:6] == [
        "Pets",
        "Pets" + TRUE_1,
        "Pets" + FALSE_1,
        "Pets",
        "Pets" + FALSE_1,
        "Pets" + TRUE_1,
    ]

    control_values = [
        value for value in values if value == "Pets" + BASELINE_PRESERVING_CONTROL
    ]

    assert len(control_values) == 2
    assert control_values[0] == control_values[1]

    expected = {
        "B": "Pets",
        "T1": "Pets" + TRUE_1,
        "F1": "Pets" + FALSE_1,
        "T2": "Pets" + TRUE_2,
        "F2": "Pets" + FALSE_2,
        "C": control_values[0],
    }

    assert values[6:] == [expected[key] for key in CONFIRMATION_ORDER]

    for item in state.received:
        assert parse_qs(
            item.raw_query,
            keep_blank_values=True,
        ) == {"category": [item.category]}

        assert " " not in item.raw_query
        assert "'" not in item.raw_query

        if "'" in item.category:
            assert "%27" in item.raw_query


def test_fastapi_candidate_is_not_proof_of_sql_execution(
    fastapi_server,
):
    state, origin = fastapi_server

    state.reset()
    vulnerable, _ = run_confirmation(origin, "vulnerable")
    vulnerable_sql_count = state.sql_completed

    state.reset()
    mimic, _ = run_confirmation(origin, "mimic")
    mimic_sql_count = state.sql_completed

    assert vulnerable.status is ConfirmationStatus.CANDIDATE
    assert mimic.status is ConfirmationStatus.CANDIDATE

    assert vulnerable_sql_count == 18
    assert mimic_sql_count == 0

    assert vulnerable.initial.verdict is Verdict.INCONCLUSIVE
    assert mimic.initial.verdict is Verdict.INCONCLUSIVE


def test_uvicorn_logs_do_not_disclose_probe_values(
    fastapi_server,
    capsys,
):
    _, origin = fastapi_server

    outcome, _ = run_confirmation(origin, "vulnerable")
    captured = capsys.readouterr()

    assert outcome.status is ConfirmationStatus.CANDIDATE
    for sensitive in (TRUE_1, FALSE_1, TRUE_2, FALSE_2):
        assert sensitive not in captured.out
        assert sensitive not in captured.err


def test_fastapi_corpus_metrics_are_explicit(
    fastapi_server,
):
    state, origin = fastapi_server

    results: dict[str, ConfirmationStatus] = {}
    request_counts: dict[str, int] = {}
    requests_used = 0

    for mode in MODES:
        state.reset()

        outcome, context = run_confirmation(origin, mode)

        results[mode] = outcome.status
        request_counts[mode] = outcome.request_count
        requests_used += outcome.request_count

        assert len(state.received) == context.budget.used_requests

    assert requests_used == 103
    assert sum(request_counts.values()) == 103

    initial_requests = 6 * len(MODES)
    confirmation_requests = sum(count - 6 for count in request_counts.values())
    assert initial_requests == 42
    assert confirmation_requests == 61
    assert request_counts["safe"] == 6
    assert request_counts["auth"] == 7
    assert all(
        request_counts[mode] == 18
        for mode in ("vulnerable", "simple", "mimic", "waf", "dynamic")
    )

    # One known-vulnerable case, six known-benign cases.
    candidate_detection = int(results["vulnerable"] is ConfirmationStatus.CANDIDATE)

    false_candidates = sum(
        results[mode] is ConfirmationStatus.CANDIDATE
        for mode in MODES
        if mode != "vulnerable"
    )

    assert candidate_detection == 1
    assert false_candidates == 2

    # These are corpus-specific, not production accuracy estimates.
    candidate_detection_rate = candidate_detection / 1
    candidate_false_positive_rate = false_candidates / 6
    assert candidate_detection_rate == 1.0
    assert candidate_false_positive_rate == 2 / 6

    decisive_statuses = {
        ConfirmationStatus.CANDIDATE,
        ConfirmationStatus.NOT_CONFIRMED,
    }
    benign_modes = set(MODES) - {"vulnerable"}
    evaluable_benign = {
        mode for mode in benign_modes if results[mode] in decisive_statuses
    }
    conditional_false_positive_rate = false_candidates / len(evaluable_benign)
    assert evaluable_benign == {"mimic", "waf"}
    assert conditional_false_positive_rate == 1.0

    inconclusive = sum(
        status is ConfirmationStatus.INCONCLUSIVE for status in results.values()
    )

    skipped = sum(status is ConfirmationStatus.SKIPPED for status in results.values())

    assert inconclusive == 3
    assert skipped == 1

    decidable = sum(status in decisive_statuses for status in results.values())
    decidable_coverage = decidable / len(MODES)
    inconclusive_rate = inconclusive / len(MODES)
    non_decision_rate = (inconclusive + skipped) / len(MODES)

    assert decidable == 3
    assert decidable_coverage == 3 / 7
    assert inconclusive_rate == 3 / 7
    assert non_decision_rate == 4 / 7
