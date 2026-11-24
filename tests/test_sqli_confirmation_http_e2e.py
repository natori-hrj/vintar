"""real-loopback HTTP E2E for SQLi confirmation.

Only 127.0.0.1 and ephemeral in-memory SQLite are used.
The production CLI, Schema v1, and Verdict contract are untouched.

This tests the confirmation runner directly, not the CLI.
"""

import socket
import sqlite3
import threading
import time
from collections import Counter
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

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


def sql_response(value: str, *, safe: bool) -> bytes:
    """Execute real SQLite queries without persistent storage."""
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE products (name TEXT NOT NULL, category TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            (
                ("Cat toy", "Pets"),
                ("Dog toy", "Pets"),
                ("Notebook", "Office"),
            ),
        )

        if safe:
            rows = db.execute(
                "SELECT name FROM products WHERE category = ?",
                (value,),
            ).fetchall()
        else:
            # Deliberately vulnerable: local test fixture only.
            rows = db.execute(
                f"SELECT name FROM products WHERE category = '{value}'"
            ).fetchall()

    return "\n".join(sorted(row[0] for row in rows)).encode()


class FixtureServer(HTTPServer):
    def __init__(self):
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.received: list[tuple[str, str, str]] = []
        self.mode = "vulnerable"
        self.fault: str | None = None
        self.fail_at: int | None = None
        self.failed = False
        self.query_errors = 0
        self.requests_seen = 0

    def reset(
        self,
        *,
        mode: str,
        fault: str | None = None,
        fail_at: int | None = None,
    ) -> None:
        self.received.clear()
        self.mode = mode
        self.fault = fault
        self.fail_at = fail_at
        self.failed = False
        self.query_errors = 0
        self.requests_seen = 0

    def handle_error(self, request, client_address):
        # Prevent traceback and request-data disclosure.
        self.failed = True


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        """Suppress request targets and payloads from access logs."""

    def do_GET(self):
        server: FixtureServer = self.server
        server.requests_seen += 1
        parsed = urlsplit(self.path)
        query = parse_qs(
            parsed.query,
            keep_blank_values=True,
        )

        if (
            parsed.path != "/products"
            or set(query) != {"category"}
            or len(query["category"]) != 1
        ):
            self._send(404, b"not-found")
            return

        value = query["category"][0]
        server.received.append((parsed.path, value, parsed.query))

        number = len(server.received)

        if server.fail_at == number:
            if server.fault == "timeout":
                # The client times out before the response is written.
                time.sleep(0.35)

            elif server.fault == "disconnect":
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                self.close_connection = True
                return

            elif server.fault == "incomplete":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "32")
                self.end_headers()
                self.wfile.write(b"partial")
                self.wfile.flush()
                self.connection.close()
                self.close_connection = True
                return

            elif server.fault == "429":
                self._send(429, b"rate-limited")
                return

            elif server.fault == "403":
                self._send(403, b"access-denied")
                return

            elif server.fault == "truncated":
                self._send(200, b"X" * 512)
                return

            elif server.fault == "redirect":
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return

        if server.mode == "auth" and number >= 7:
            self._send(401, b"authentication-required")
            return

        try:
            body = self._body(
                value=value,
                number=number,
            )
        except sqlite3.Error:
            server.query_errors += 1
            self._send(500, b"query-error")
            return

        self._send(200, body)

    def _body(self, *, value: str, number: int) -> bytes:
        server: FixtureServer = self.server
        mode = server.mode

        if mode in {"vulnerable", "safe"}:
            return sql_response(
                value,
                safe=(mode == "safe"),
            )

        if mode == "sql_error":
            raise sqlite3.OperationalError("fixture detail must stay private")

        first_false = value == "Pets" + FALSE_1
        second_false = value == "Pets" + FALSE_2

        if mode == "simple":
            return b"B" if first_false else b"A"

        if mode in {"mimic", "waf"}:
            blocked = first_false or second_false

            if mode == "waf":
                return b"access-denied" if blocked else b"products-found"

            return b"B" if blocked else b"A"

        # The initial six probes still form a Boolean candidate.
        initial = b"B" if first_false else b"A"

        if mode == "auth":
            return initial

        if mode == "dynamic":
            return f"nonce-{number}".encode() if number >= 7 else initial

        if mode == "cache":
            return b"stale-cache" if number >= 9 else initial

        raise AssertionError("Unknown fixture mode")

    def _send(self, status: int, body: bytes) -> None:
        try:
            self.send_response(status)
            self.send_header(
                "Content-Type",
                "text/plain; charset=utf-8",
            )
            self.send_header(
                "Content-Length",
                str(len(body)),
            )
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            # Expected when the client has already timed out.
            pass


@pytest.fixture
def http_server():
    try:
        server = FixtureServer()
    except OSError:
        pytest.skip("Loopback socket unavailable")

    assert server.server_address[0] == "127.0.0.1"

    worker = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    worker.start()

    try:
        yield (
            server,
            f"http://127.0.0.1:{server.server_port}",
        )
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert server.failed is False


class CountingHTTPTransport(httpx.BaseTransport):
    """Count dispatches at the underlying HTTP transport boundary."""

    def __init__(self) -> None:
        self.attempts = 0
        self._transport = httpx.HTTPTransport(
            trust_env=False,
            proxy=None,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.attempts += 1
        return self._transport.handle_request(request)

    def close(self) -> None:
        self._transport.close()


@dataclass(frozen=True, slots=True)
class RealHTTPRun:
    outcome: ConfirmationOutcome
    context: ExecutionContext
    transport_attempts: int | None


def run_real_http(
    origin: str,
    *,
    max_response_size: int = 1_048_576,
    timeout: float = 2.0,
    rate_limiter: RateLimiter | None = None,
    measure_transport_attempts: bool = False,
    headers: tuple[tuple[str, str], ...] = (),
    cookies: tuple[tuple[str, str], ...] = (),
) -> RealHTTPRun:
    port = urlsplit(origin).port
    assert port is not None

    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", port)})
        ),
        budget=RequestBudget(18),
        timeout=timeout,
        rate_limiter=rate_limiter or RateLimiter(requests_per_second=100),
        max_response_size=max_response_size,
    )

    transport = CountingHTTPTransport() if measure_transport_attempts else None
    try:
        outcome = verify_boolean_sqli_with_confirmation(
            check_id="real-http-confirmation",
            template=RequestTemplate(
                method="GET",
                url=origin + "/products",
                headers=headers,
                cookies=cookies,
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
            transport=transport,
        )
    finally:
        if transport is not None:
            transport.close()

    return RealHTTPRun(
        outcome=outcome,
        context=context,
        transport_attempts=(transport.attempts if transport is not None else None),
    )


def assert_request_accounting(
    server: FixtureServer,
    run: RealHTTPRun,
):
    outcome = run.outcome
    assert (
        outcome.request_count
        == outcome.total_requests
        == run.context.budget.used_requests
    )
    assert outcome.total_requests <= 18
    assert len(server.received) <= outcome.total_requests
    if run.transport_attempts is not None:
        assert len(server.received) <= run.transport_attempts
        assert run.transport_attempts <= outcome.total_requests


def assert_query_encoding(server: FixtureServer):
    for path, value, raw_query in server.received:
        assert path == "/products"
        assert parse_qs(
            raw_query,
            keep_blank_values=True,
        ) == {"category": [value]}

        assert " " not in raw_query
        assert "'" not in raw_query

        if "'" in value:
            assert "%27" in raw_query


@pytest.mark.parametrize(
    ("mode", "expected", "count"),
    [
        ("vulnerable", ConfirmationStatus.CANDIDATE, 18),
        ("safe", ConfirmationStatus.SKIPPED, 6),
        ("simple", ConfirmationStatus.INCONCLUSIVE, 18),
        ("mimic", ConfirmationStatus.CANDIDATE, 18),
        ("waf", ConfirmationStatus.CANDIDATE, 18),
        ("auth", ConfirmationStatus.INCONCLUSIVE, 7),
        ("dynamic", ConfirmationStatus.INCONCLUSIVE, 18),
        ("cache", ConfirmationStatus.INCONCLUSIVE, 18),
    ],
)
def test_confirmation_over_real_http(
    http_server,
    mode,
    expected,
    count,
):
    server, origin = http_server
    server.reset(mode=mode)

    run = run_real_http(
        origin,
        measure_transport_attempts=True,
    )
    outcome = run.outcome

    assert outcome.status is expected
    assert outcome.total_requests == count
    assert run.transport_attempts == count
    assert len(server.received) == count
    assert_request_accounting(server, run)
    assert_query_encoding(server)

    if expected is ConfirmationStatus.CANDIDATE:
        assert outcome.reason_code == "confirmation_pattern_matched"
        assert outcome.evidence is not None

    if expected is ConfirmationStatus.SKIPPED:
        assert outcome.confirmation_requests == 0

    if expected is ConfirmationStatus.INCONCLUSIVE:
        if mode == "simple":
            assert outcome.evidence is None
            assert outcome.reason_code == "confirmation_unstable"
        else:
            assert outcome.evidence is None
            assert outcome.reason_code == (
                "confirmation_non_success_status"
                if mode == "auth"
                else "confirmation_unstable"
            )

    # No test fixture may turn a candidate into a VULNERABLE verdict.
    assert outcome.initial.verdict is not Verdict.VULNERABLE


def test_real_http_probe_order_and_baseline_preserving_control(http_server):
    server, origin = http_server
    server.reset(mode="vulnerable")

    run = run_real_http(origin)
    outcome = run.outcome

    assert outcome.status is ConfirmationStatus.CANDIDATE
    assert len(server.received) == 18

    values = [item[1] for item in server.received]

    assert values[:6] == [
        "Pets",
        "Pets" + TRUE_1,
        "Pets" + FALSE_1,
        "Pets",
        "Pets" + FALSE_1,
        "Pets" + TRUE_1,
    ]

    controls = [
        value for value in values if value == "Pets" + BASELINE_PRESERVING_CONTROL
    ]

    assert len(controls) == 2
    assert controls[0] == controls[1]

    expected = {
        "B": "Pets",
        "T1": "Pets" + TRUE_1,
        "F1": "Pets" + FALSE_1,
        "C": controls[0],
        "T2": "Pets" + TRUE_2,
        "F2": "Pets" + FALSE_2,
    }

    assert values[6:] == [expected[kind] for kind in CONFIRMATION_ORDER]

    assert Counter(CONFIRMATION_ORDER) == {kind: 2 for kind in expected}

    assert_request_accounting(server, run)


def test_baseline_preserving_control_is_fixed_between_executions(http_server):
    server, origin = http_server

    controls = []
    for _ in range(2):
        server.reset(mode="vulnerable")
        outcome = run_real_http(origin).outcome

        assert outcome.status is ConfirmationStatus.CANDIDATE

        controls.append(
            next(
                value
                for _, value, _ in server.received
                if value == "Pets" + BASELINE_PRESERVING_CONTROL
            )
        )

    assert controls[0] == controls[1] == "Pets" + BASELINE_PRESERVING_CONTROL


@pytest.mark.parametrize("fail_at", [7, 12, 18])
@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("429", "confirmation_rate_limited"),
        ("403", "confirmation_non_success_status"),
        ("truncated", "confirmation_truncated"),
    ],
)
def test_real_http_confirmation_stops_at_fault(
    http_server,
    fail_at,
    fault,
    reason,
):
    server, origin = http_server
    server.reset(
        mode="vulnerable",
        fault=fault,
        fail_at=fail_at,
    )

    run = run_real_http(
        origin,
        max_response_size=64,
        measure_transport_attempts=True,
    )
    outcome = run.outcome

    assert outcome.status is ConfirmationStatus.INCONCLUSIVE
    assert outcome.reason_code == reason
    assert outcome.evidence is None

    assert outcome.total_requests == fail_at
    assert outcome.confirmation_requests == fail_at - 6
    assert len(server.received) == fail_at

    assert run.transport_attempts == fail_at
    assert_request_accounting(server, run)


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("timeout", "confirmation_timeout"),
        ("disconnect", "confirmation_request_failed"),
        ("incomplete", "confirmation_request_failed"),
    ],
)
def test_real_http_transport_failure_stops_confirmation(
    http_server,
    fault,
    reason,
):
    server, origin = http_server
    server.reset(
        mode="vulnerable",
        fault=fault,
        fail_at=7,
    )

    run = run_real_http(
        origin,
        timeout=0.1 if fault == "timeout" else 2.0,
        measure_transport_attempts=True,
    )
    outcome = run.outcome

    assert outcome.status is ConfirmationStatus.INCONCLUSIVE
    assert outcome.reason_code == reason

    assert outcome.total_requests == 7
    assert outcome.confirmation_requests == 1
    assert outcome.evidence is None

    assert len(server.received) == 7
    assert run.transport_attempts == 7
    assert_request_accounting(server, run)


def test_no_raw_request_content_in_outcome_repr(http_server):
    server, origin = http_server
    server.reset(mode="vulnerable")

    outcome = run_real_http(origin).outcome

    assert outcome.evidence is not None

    rendered = repr(outcome)
    evidence_repr = repr(outcome.evidence)

    for sensitive in (
        TRUE_1,
        FALSE_1,
        TRUE_2,
        FALSE_2,
        BASELINE_PRESERVING_CONTROL,
    ):
        assert sensitive not in rendered
        assert sensitive not in evidence_repr


def test_redirect_is_not_followed(http_server):
    server, origin = http_server
    server.reset(
        mode="vulnerable",
        fault="redirect",
        fail_at=7,
    )

    run = run_real_http(
        origin,
        measure_transport_attempts=True,
    )

    assert run.outcome.status is ConfirmationStatus.INCONCLUSIVE
    assert run.outcome.reason_code == "confirmation_non_success_status"
    assert run.outcome.total_requests == 7
    assert run.transport_attempts == 7
    assert server.requests_seen == 7
    assert len(server.received) == 7


def test_environment_proxy_is_not_used(
    http_server,
    monkeypatch,
):
    server, origin = http_server
    server.reset(mode="safe")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")

    run = run_real_http(origin)

    assert run.outcome.status is ConfirmationStatus.SKIPPED
    assert run.outcome.total_requests == 6
    assert len(server.received) == 6


def test_rate_limit_interruption_prevents_transport_dispatch(
    http_server,
):
    server, origin = http_server
    server.reset(mode="vulnerable")

    def interrupt(_delay: float) -> None:
        raise RuntimeError("synthetic interruption")

    limiter = RateLimiter(
        requests_per_second=100,
        _clock=lambda: 0.0,
        _sleep=interrupt,
    )
    run = run_real_http(
        origin,
        rate_limiter=limiter,
        measure_transport_attempts=True,
    )

    assert run.outcome.status is ConfirmationStatus.SKIPPED
    assert run.outcome.initial.verdict is Verdict.INCONCLUSIVE
    assert run.outcome.initial.reason_code == "probe_failed"
    assert run.outcome.total_requests == 2
    assert run.context.budget.used_requests == 2
    assert run.transport_attempts == 1
    assert server.requests_seen == 1
    assert len(server.received) == 1


def test_sql_errors_and_secrets_are_not_disclosed(
    http_server,
    capsys,
):
    server, origin = http_server
    server.reset(mode="sql_error")
    secret = "highly-sensitive-test-value"

    run = run_real_http(
        origin,
        headers=(("Authorization", f"Bearer {secret}"),),
        cookies=(("session", secret),),
    )

    captured = capsys.readouterr()
    rendered = repr(run.outcome)
    assert run.outcome.status is ConfirmationStatus.SKIPPED
    assert run.outcome.initial.verdict is Verdict.INCONCLUSIVE
    assert run.outcome.initial.reason_code == "non_success_status"
    assert run.outcome.total_requests == 6
    assert server.query_errors == 6
    assert captured.out == ""
    assert captured.err == ""
    assert secret not in rendered
    assert "fixture detail" not in rendered
