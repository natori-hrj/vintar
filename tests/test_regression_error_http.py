"""Exercise Schema v1 error cases through a repository-owned SQLite loopback app."""

import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from vintar.checks.sqli.models import Verdict
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression.cases import ErrorRegressionCase, parse_regression_case
from vintar.regression.runner import (
    ErrorRegressionOutcome,
    RegressionStatus,
    TrustedExecutionPolicy,
    run_regression_case,
)


class ErrorFixtureServer(ThreadingHTTPServer):
    """Loopback server with synchronized, non-sensitive request observations."""

    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), ErrorFixtureHandler)
        self._lock = threading.Lock()
        self.received_values: list[str] = []
        self.response_counter = 0

    def record(self, value: str) -> int:
        with self._lock:
            self.received_values.append(value)
            self.response_counter += 1
            return self.response_counter

    def reset(self) -> None:
        with self._lock:
            self.received_values.clear()
            self.response_counter = 0

    def snapshot(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self.received_values)


class ErrorFixtureHandler(BaseHTTPRequestHandler):
    server: ErrorFixtureServer

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        values = parse_qs(parsed.query, keep_blank_values=True).get("category", [])
        value = values[0] if len(values) == 1 else ""
        counter = self.server.record(value)

        if parsed.path == "/always-error":
            self._reply(500, b"sqlite3.OperationalError: unrecognized token: test")
            return
        if parsed.path == "/generic-500" and value != "Pets":
            self._reply(500, f"internal error request={counter}".encode())
            return

        connection = sqlite3.connect(":memory:")
        try:
            connection.execute("CREATE TABLE products (category TEXT, name TEXT)")
            connection.execute("INSERT INTO products VALUES ('Pets', 'Cat toy')")
            if parsed.path == "/vulnerable":
                query = f"SELECT name FROM products WHERE category = '{value}'"
                try:
                    rows = connection.execute(query).fetchall()
                except sqlite3.OperationalError as exc:
                    self._reply(500, f"sqlite3.OperationalError: {exc}".encode())
                    return
            else:
                rows = connection.execute(
                    "SELECT name FROM products WHERE category = ?", (value,)
                ).fetchall()
        finally:
            connection.close()

        suffix = f" token={counter}" if parsed.path == "/dynamic" else ""
        self._reply(200, f"rows={len(rows)}{suffix}".encode())

    def _reply(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


@pytest.fixture(scope="module")
def error_regression_server():
    server = ErrorFixtureServer()
    ready = threading.Event()

    def serve() -> None:
        ready.set()
        server.serve_forever(poll_interval=0.01)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    if not ready.wait(timeout=5.0) or not worker.is_alive():
        pytest.fail(
            "The Error SQLi loopback fixture did not start. Check loopback socket permissions and thread scheduling."
        )
    try:
        port = server.server_address[1]
        yield server, f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5.0)
        assert not worker.is_alive(), (
            "The Error SQLi loopback fixture did not stop. Check server shutdown synchronization."
        )


def error_case(origin: str, route: str, expected: str) -> ErrorRegressionCase:
    source = f'''\
version = 1
id = "error-{route}"
type = "sqli.error"
expected_verdict = "{expected}"

[target]
url = "{origin}/{route}"
allowed_origin = "{origin}"

[[target.params]]
name = "category"
value = "Pets"

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
error_payload = "'"

[limits]
max_requests = 4
requests_per_second = 10.0
timeout_seconds = 2.0
'''
    case = parse_regression_case(source)
    assert isinstance(case, ErrorRegressionCase)
    return case


@pytest.mark.parametrize(
    ("route", "expected", "verdict", "reason", "status"),
    [
        (
            "vulnerable",
            "inconclusive",
            Verdict.INCONCLUSIVE,
            "dbms_error_disclosed",
            RegressionStatus.INCONCLUSIVE,
        ),
        (
            "safe",
            "not_detected",
            Verdict.NOT_DETECTED,
            "dbms_error_not_observed",
            RegressionStatus.PASS,
        ),
        (
            "dynamic",
            "not_detected",
            Verdict.NOT_DETECTED,
            "dbms_error_not_observed",
            RegressionStatus.PASS,
        ),
        (
            "generic-500",
            "inconclusive",
            Verdict.INCONCLUSIVE,
            "non_success_status",
            RegressionStatus.INCONCLUSIVE,
        ),
        (
            "always-error",
            "inconclusive",
            Verdict.INCONCLUSIVE,
            "baseline_dbms_error",
            RegressionStatus.INCONCLUSIVE,
        ),
    ],
)
def test_error_case_loopback_order_counts_and_classification(
    error_regression_server,
    route,
    expected,
    verdict,
    reason,
    status,
):
    server, origin = error_regression_server
    server.reset()
    port = urlsplit(origin).port
    assert port is not None
    policy = TrustedExecutionPolicy(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", port)})
        ),
        max_requests=4,
        max_requests_per_second=10.0,
        max_timeout_seconds=2.0,
    )

    outcome = run_regression_case(
        error_case(origin, route, expected),
        policy=policy,
    )

    assert isinstance(outcome, ErrorRegressionOutcome)
    assert outcome.final_verdict is verdict
    assert outcome.final_reason_code == reason
    assert outcome.expectation_match
    assert outcome.status is status
    assert outcome.request_count == 4
    assert outcome.error_run.budget_used == 4
    assert outcome.error_run.transport_attempts == 4
    assert server.snapshot() == ("Pets", "Pets'", "Pets", "Pets'")
    if route == "vulnerable":
        assert outcome.error_run.analysis.evidence is not None
        assert outcome.error_run.analysis.evidence.dbms == "sqlite"
        assert (
            outcome.error_run.analysis.evidence.signature_id
            == "sqlite_operational_syntax"
        )
