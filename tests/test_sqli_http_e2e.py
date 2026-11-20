"""socket-backed SQLite SQLi quality baseline.

Only loopback targets and ephemeral in-memory SQLite are used.
The production six-probe detector remains unchanged.
"""

import json
import os
import runpy
import sqlite3
import subprocess
import sys
import threading
from collections import Counter
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from vintar.checks.sqli.confirmation_runner import (
    ConfirmationOutcome,
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.models import Verdict, VerificationResult
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.checks.sqli.presets import (
    get_boolean_confirmation_preset,
    get_boolean_probe_preset,
)
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

ROOT = Path(__file__).resolve().parents[1]
_VALIDATOR_NAMESPACE = runpy.run_path(str(ROOT / "scripts" / "validate_ci_report.py"))
_validate = cast(
    Callable[[Path, int], None],
    _VALIDATOR_NAMESPACE["_validate"],
)

STRING_QUOTED_PRESET = get_boolean_probe_preset("string-quoted")
NUMERIC_PRESET = get_boolean_probe_preset("numeric")
STRING_QUOTED_CONFIRMATION = get_boolean_confirmation_preset("string-quoted")
TRUE_1 = STRING_QUOTED_PRESET.true_payload
FALSE_1 = STRING_QUOTED_PRESET.false_payload
NUMERIC_TRUE = NUMERIC_PRESET.true_payload
NUMERIC_FALSE = NUMERIC_PRESET.false_payload
TRUE_2 = STRING_QUOTED_CONFIRMATION.true_payload
FALSE_2 = STRING_QUOTED_CONFIRMATION.false_payload
BASELINE_PRESERVING_CONTROL = STRING_QUOTED_CONFIRMATION.baseline_preserving_control
FIXTURE_CATEGORIES = frozenset({"Office", "Pets"})
FIXTURE_PRODUCT_IDS = frozenset({"1", "2", "3"})

PLAN = (
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

CASE = """version = 1
id = "sqlite-http-e2e"
type = "sqli.boolean"
expected_verdict = "{expected_verdict}"

[target]
url = "http://placeholder.invalid:8000{path}"
allowed_origin = "http://placeholder.invalid:8000"

[[target.params]]
name = "category"
value = "Pets"

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
true_payload = "' AND 1=1-- "
false_payload = "' AND 1=2-- "

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 5.0
"""


@dataclass(frozen=True, slots=True)
class LiveEndpoint:
    endpoint_id: str
    path: str
    expected_label: str
    parameter_name: str
    initial_value: str
    preset_name: str
    expected_query_errors: int = 0

    def __post_init__(self) -> None:
        declared = {
            "category": FIXTURE_CATEGORIES,
            "product_id": FIXTURE_PRODUCT_IDS,
        }
        if (
            self.parameter_name not in declared
            or self.initial_value not in declared[self.parameter_name]
        ):
            raise ValueError(
                "initial_value must be a benign value declared for the fixture parameter; "
                "use Pets or Office for category, or 1, 2, or 3 for product_id."
            )
        get_boolean_probe_preset(self.preset_name)
        if (
            type(self.expected_query_errors) is not int
            or self.expected_query_errors < 0
        ):
            raise ValueError("expected_query_errors must be a nonnegative integer.")


@dataclass(frozen=True, slots=True)
class KnownLimitationEndpoint:
    limitation_id: str
    endpoint: LiveEndpoint
    expected_confirmation_status: ConfirmationStatus
    expected_reason_code: str


LIVE_TWIN_ENDPOINTS = (
    LiveEndpoint(
        endpoint_id="sqlite-vulnerable",
        path="/vulnerable",
        expected_label="positive",
        parameter_name="category",
        initial_value="Pets",
        preset_name="string-quoted",
    ),
    LiveEndpoint(
        endpoint_id="sqlite-parameterized",
        path="/safe",
        expected_label="negative",
        parameter_name="category",
        initial_value="Pets",
        preset_name="string-quoted",
    ),
    LiveEndpoint(
        endpoint_id="sqlite-numeric-vulnerable",
        path="/numeric-vulnerable",
        expected_label="positive",
        parameter_name="product_id",
        initial_value="1",
        preset_name="numeric",
    ),
    LiveEndpoint(
        endpoint_id="sqlite-numeric-parameterized",
        path="/numeric-safe",
        expected_label="negative",
        parameter_name="product_id",
        initial_value="1",
        preset_name="numeric",
    ),
)

KNOWN_LIMITATION_ENDPOINTS = (
    KnownLimitationEndpoint(
        limitation_id="structural-full-mimic",
        endpoint=LiveEndpoint(
            endpoint_id="structural-full-mimic",
            path="/mimic",
            expected_label="negative",
            parameter_name="category",
            initial_value="Pets",
            preset_name="string-quoted",
        ),
        expected_confirmation_status=ConfirmationStatus.CANDIDATE,
        expected_reason_code="confirmation_pattern_matched",
    ),
    KnownLimitationEndpoint(
        limitation_id="structural-waf-200",
        endpoint=LiveEndpoint(
            endpoint_id="structural-waf-200",
            path="/waf-200",
            expected_label="negative",
            parameter_name="category",
            initial_value="Pets",
            preset_name="string-quoted",
        ),
        expected_confirmation_status=ConfirmationStatus.CANDIDATE,
        expected_reason_code="confirmation_pattern_matched",
    ),
)

SAFE_PETS_LIMITATION = LiveEndpoint(
    endpoint_id="sqlite-parameterized-pets",
    path="/safe",
    expected_label="negative",
    parameter_name="category",
    initial_value="Pets",
    preset_name="string-quoted",
)


def _sql_result(category: str, *, safe: bool) -> bytes:
    with sqlite3.connect(":memory:") as db:
        db.execute(
            "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL)"
        )
        db.executemany(
            "INSERT INTO products VALUES (?, ?, ?)",
            [
                (1, "Cat toy", "Pets"),
                (2, "Dog toy", "Pets"),
                (3, "Notebook", "Office"),
            ],
        )

        if safe:
            rows = db.execute(
                "SELECT name FROM products WHERE category = ?",
                (category,),
            ).fetchall()
        else:
            # Vulnerability intentionally confined to an
            # in-memory test server.
            rows = db.execute(
                f"SELECT name FROM products WHERE category = '{category}'"
            ).fetchall()

    return "\n".join(sorted(row[0] for row in rows)).encode()


def _numeric_sql_result(product_id: str, *, safe: bool) -> bytes:
    with sqlite3.connect(":memory:") as db:
        db.execute(
            "CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL)"
        )
        db.executemany(
            "INSERT INTO products VALUES (?, ?, ?)",
            [
                (1, "Cat toy", "Pets"),
                (2, "Dog toy", "Pets"),
                (3, "Notebook", "Office"),
            ],
        )
        if safe:
            rows = db.execute(
                "SELECT name FROM products WHERE id = ?", (product_id,)
            ).fetchall()
        else:
            # Vulnerability intentionally confined to an
            # in-memory test server.
            rows = db.execute(
                f"SELECT name FROM products WHERE id = {product_id}"
            ).fetchall()
    return "\n".join(sorted(row[0] for row in rows)).encode()


class _Handler(BaseHTTPRequestHandler):
    def parse_request(self) -> bool:
        parsed = super().parse_request()
        if parsed:
            self.server.total_requests += 1
        return parsed

    def do_GET(self) -> None:
        server = self.server
        path = urlsplit(self.path)
        query = parse_qs(
            path.query,
            keep_blank_values=True,
        )

        expected_parameter = {
            "/vulnerable": "category",
            "/safe": "category",
            "/mimic": "category",
            "/waf-200": "category",
            "/numeric-vulnerable": "product_id",
            "/numeric-safe": "product_id",
        }.get(path.path)

        if (
            expected_parameter is None
            or set(query) != {expected_parameter}
            or len(query[expected_parameter]) != 1
        ):
            status, body = 404, b"not-found"
        else:
            value = query[expected_parameter][0]
            server.received.append((path.path, value, path.query))

            try:
                if path.path in {"/mimic", "/waf-200"}:
                    false_inputs = {
                        "Pets" + FALSE_1,
                        "Pets" + FALSE_2,
                    }

                    if path.path == "/waf-200":
                        body = (
                            b"access-denied"
                            if value in false_inputs
                            else b"products-found"
                        )
                    else:
                        body = (
                            b"no-results"
                            if value in false_inputs
                            else b"products-found"
                        )
                elif path.path in {"/numeric-vulnerable", "/numeric-safe"}:
                    body = _numeric_sql_result(
                        value,
                        safe=(path.path == "/numeric-safe"),
                    )
                else:
                    body = _sql_result(
                        value,
                        safe=(path.path == "/safe"),
                    )

                status = 200

            except sqlite3.Error:
                server.query_errors += 1
                status, body = 500, b"query-error"

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

    def log_message(
        self,
        format: str,
        *args: object,
    ) -> None:
        pass


class _Server(HTTPServer):
    def __init__(self) -> None:
        super().__init__(
            ("127.0.0.1", 0),
            _Handler,
        )

        self.received: list[tuple[str, str, str]] = []
        self.total_requests = 0
        self.handler_failed = False
        self.query_errors = 0

    def handle_error(
        self,
        request: object,
        client_address: tuple[str, int],
    ) -> None:
        self.handler_failed = True


class LoopbackStartupError(RuntimeError):
    """The loopback server thread could not start."""


class LoopbackShutdownError(RuntimeError):
    """The loopback server thread could not stop."""


class LoopbackFixtureCheckError(RuntimeError):
    """The loopback fixture state disagreed with the completed check."""


@contextmanager
def running_server(server):
    assert server.server_address[0] == "127.0.0.1"

    started = threading.Event()

    def serve() -> None:
        started.set()
        server.serve_forever()

    worker = threading.Thread(
        target=serve,
        daemon=True,
    )
    try:
        worker.start()
    except RuntimeError as exc:
        server.server_close()
        raise LoopbackStartupError(
            "The loopback worker could not start. Check thread availability on the runner."
        ) from exc

    if not started.wait(timeout=5):
        server.server_close()
        worker.join(timeout=5)
        raise LoopbackStartupError(
            "The loopback worker did not signal startup. Check thread scheduling and transport setup."
        )

    try:
        yield (
            server,
            f"http://127.0.0.1:{server.server_port}",
        )

    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            raise LoopbackShutdownError(
                "The loopback worker did not stop. Check server shutdown and outstanding requests."
            )


def run_live_endpoint(
    endpoint: LiveEndpoint,
    binder: Callable[[], _Server] = _Server,
) -> tuple[VerificationResult, int]:
    """Run the production Boolean check against one fresh loopback server."""
    server = binder()
    port = server.server_port

    with running_server(server) as (_, origin):
        preset = get_boolean_probe_preset(endpoint.preset_name)
        context = ExecutionContext(
            scope=ScopePolicy(
                allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", port)})
            ),
            budget=RequestBudget(6),
            timeout=5,
            rate_limiter=RateLimiter(requests_per_second=100),
            max_response_size=1_048_576,
        )
        result = verify_boolean_sqli(
            check_id=endpoint.endpoint_id,
            template=RequestTemplate(
                method="GET",
                url=origin + endpoint.path,
                params=((endpoint.parameter_name, endpoint.initial_value),),
            ),
            point=InjectionPoint(
                location=InjectionLocation.QUERY,
                name=endpoint.parameter_name,
                mode=InjectionMode.APPEND,
            ),
            true_payload=preset.true_payload,
            false_payload=preset.false_payload,
            context=context,
        )

        assert result.request_count == context.budget.used_requests
        assert server.total_requests == result.request_count
        assert len(server.received) == result.request_count
        assert not server.handler_failed
        assert server.query_errors == endpoint.expected_query_errors

    return result, port


def run_confirmed_live_endpoint(
    endpoint: LiveEndpoint,
    binder: Callable[[], _Server] = _Server,
) -> tuple[ConfirmationOutcome, int]:
    """Run the initial and confirmation probes on one fresh loopback server."""
    server = binder()
    port = server.server_port

    with running_server(server) as (_, origin):
        initial = get_boolean_probe_preset(endpoint.preset_name)
        confirmation = get_boolean_confirmation_preset(endpoint.preset_name)
        context = ExecutionContext(
            scope=ScopePolicy(
                allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", port)})
            ),
            budget=RequestBudget(18),
            timeout=5,
            rate_limiter=RateLimiter(requests_per_second=100),
            max_response_size=1_048_576,
        )
        outcome = verify_boolean_sqli_with_confirmation(
            check_id=endpoint.endpoint_id,
            template=RequestTemplate(
                method="GET",
                url=origin + endpoint.path,
                params=((endpoint.parameter_name, endpoint.initial_value),),
            ),
            point=InjectionPoint(
                location=InjectionLocation.QUERY,
                name=endpoint.parameter_name,
                mode=InjectionMode.APPEND,
            ),
            true_1=initial.true_payload,
            false_1=initial.false_payload,
            true_2=confirmation.true_payload,
            false_2=confirmation.false_payload,
            baseline_preserving_control=(confirmation.baseline_preserving_control),
            context=context,
        )

        if outcome.request_count != context.budget.used_requests:
            raise LoopbackFixtureCheckError(
                "Confirmation request accounting disagreed with the shared budget. "
                "Check the confirmation runner and ExecutionContext accounting."
            )
        if server.total_requests != outcome.request_count:
            raise LoopbackFixtureCheckError(
                "The loopback server observed a different total request count. "
                "Check transport setup and confirmation request accounting."
            )
        if len(server.received) != outcome.request_count:
            raise LoopbackFixtureCheckError(
                "The loopback handler recorded a different accepted request count. "
                "Check endpoint routing and query validation."
            )
        if server.handler_failed:
            raise LoopbackFixtureCheckError(
                "The loopback handler failed while serving confirmation probes. "
                "Check the fixture implementation and handler state."
            )
        if server.query_errors != endpoint.expected_query_errors:
            raise LoopbackFixtureCheckError(
                "The loopback fixture observed an unexpected SQL error count. "
                "Check the declared fixture expectation and probe context."
            )

    return outcome, port


@pytest.fixture
def local_server():
    try:
        server = _Server()
    except OSError:
        pytest.skip("Loopback binding is not available")

    with running_server(server) as running:
        yield running
        assert not server.handler_failed, (
            "The loopback handler failed. Check the SQLite fixture and server logs."
        )


def fixed_loopback_record(category: str | None, message: str) -> dict[str, str | None]:
    return {
        "endpoint_id": "/safe",
        "mode": "fixed_loopback",
        "status": "passed" if category is None else "failed",
        "failure_category": category,
        "message": message,
    }


def check_parameterized_benign_response(
    binder: Callable[[], _Server] = _Server,
) -> dict[str, str | None]:
    try:
        server = binder()
    except OSError:
        return fixed_loopback_record(
            "socket_bind",
            "Cannot bind the fixed-app fixture. Check that the runner permits IPv4 loopback sockets.",
        )

    try:
        with (
            running_server(server) as (_, origin),
            httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as client,
        ):
            try:
                result = client.get(origin + "/safe", params={"category": "Pets"})
            except httpx.RequestError:
                return fixed_loopback_record(
                    "transport",
                    "The fixed-app request failed. Check loopback transport and the server response.",
                )
            if result.status_code != 200 or result.content != b"Cat toy\nDog toy":
                return fixed_loopback_record(
                    "unexpected_response",
                    f"The fixed endpoint returned status {result.status_code} or an unexpected body. "
                    "Check the seeded SQLite rows, parameter binding, and response ordering.",
                )
            if (
                [(path, category) for path, category, _ in server.received]
                != [("/safe", "Pets")]
                or server.query_errors
                or server.handler_failed
            ):
                return fixed_loopback_record(
                    "unexpected_response",
                    "The fixed endpoint did not record one successful benign lookup. "
                    "Check the route and query parameter handling.",
                )
    except LoopbackStartupError as exc:
        return fixed_loopback_record("startup", str(exc))
    except LoopbackShutdownError as exc:
        return fixed_loopback_record("shutdown", str(exc))

    return fixed_loopback_record(
        None, "The parameterized endpoint returned the expected benign response."
    )


def _cli_environment(origin: str) -> dict[str, str]:
    env = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "VINTAR_TARGET_ORIGIN": origin,
        "VINTAR_ALLOWED_ORIGIN": origin,
    }

    if configuration := os.environ.get("COVERAGE_PROCESS_CONFIG"):
        env["COVERAGE_PROCESS_CONFIG"] = configuration

    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if value := os.environ.get(name):
                env[name] = value

    return env


@pytest.mark.parametrize(
    ("path", "verdict", "reason", "similarity", "exit_code", "status"),
    [
        (
            "/vulnerable",
            "inconclusive",
            "boolean_candidate",
            (1.0, 0.0, 0.0),
            3,
            "inconclusive",
        ),
        (
            "/safe",
            "not_detected",
            "no_boolean_difference_literal_input",
            (0.0, 0.0, 1.0),
            0,
            "pass",
        ),
        (
            "/mimic",
            "inconclusive",
            "boolean_candidate",
            (1.0, 0.0, 0.0),
            3,
            "inconclusive",
        ),
    ],
)
def test_real_http_vintar_cli(
    local_server,
    tmp_path,
    path,
    verdict,
    reason,
    similarity,
    exit_code,
    status,
):
    server, origin = local_server

    case_path = tmp_path / "case.toml"
    case_path.write_text(
        CASE.format(path=path, expected_verdict=verdict),
        encoding="utf-8",
    )

    before = len(server.received)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "vintar.cli",
            "verify",
            "--cases",
            str(case_path),
            "--max-requests",
            "6",
            "--rps",
            "10",
            "--timeout",
            "5",
            "--authorized",
        ],
        cwd=ROOT,
        env=_cli_environment(origin),
        capture_output=True,
        check=False,
        timeout=30,
    )

    assert result.returncode == exit_code, "Unexpected CLI exit code"
    assert result.stderr == b"", "Unexpected CLI stderr"

    report = json.loads(result.stdout)

    report_path = tmp_path / "report.json"
    report_path.write_bytes(result.stdout)
    _validate(report_path, result.returncode)

    assert report["status"] == status
    assert report["exit_code"] == exit_code
    assert report["requests_used"] == 6
    assert report["complete"] is True
    assert report["executed_count"] == 1

    outcome = report["outcomes"][0]

    assert outcome["expected_verdict"] == verdict
    assert outcome["actual_verdict"] == verdict
    assert outcome["expectation_match"] is True
    assert outcome["status"] == status

    verification = outcome["verification"]

    assert verification["reason_code"] == reason
    assert verification["request_count"] == 6
    assert verification["failures"] == []

    evidence = verification["evidence"]

    assert (
        tuple(
            evidence[key]
            for key in (
                "baseline_true_similarity",
                "baseline_false_similarity",
                "true_false_similarity",
            )
        )
        == similarity
    )

    assert [entry[0] for entry in server.received[before:]] == [path] * 6

    expected_values = [
        "Pets",
        "Pets" + TRUE_1,
        "Pets" + FALSE_1,
        "Pets",
        "Pets" + FALSE_1,
        "Pets" + TRUE_1,
    ]

    received = server.received[before:]
    assert [entry[1] for entry in received] == expected_values

    for (_, decoded, raw_query), expected in zip(
        received,
        expected_values,
        strict=True,
    ):
        assert decoded == expected
        assert parse_qs(
            raw_query,
            keep_blank_values=True,
        ) == {"category": [expected]}
        assert " " not in raw_query
        if "'" in expected:
            assert "'" not in raw_query
            assert "%27" in raw_query


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/vulnerable", "candidate"),
        ("/safe", "not_confirmed"),
        ("/mimic", "candidate"),
    ],
)
def test_real_http_twelve_probe_experiment(
    local_server,
    path,
    expected,
):
    server, origin = local_server

    values = {
        "B": "Pets",
        "T1": "Pets" + TRUE_1,
        "F1": "Pets" + FALSE_1,
        "C": "Pets" + BASELINE_PRESERVING_CONTROL,
        "T2": "Pets" + TRUE_2,
        "F2": "Pets" + FALSE_2,
    }

    observations: dict[
        str,
        list[tuple[int, bytes]],
    ] = {kind: [] for kind in values}

    before = len(server.received)

    with httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=5,
    ) as client:
        for kind in PLAN:
            response = client.get(
                origin + path,
                params={
                    "category": values[kind],
                },
            )

            observations[kind].append(
                (
                    response.status_code,
                    response.content,
                )
            )

    assert len(server.received) - before == 12

    assert Counter(PLAN) == {kind: 2 for kind in values}

    assert [entry[1] for entry in server.received[before:]] == [
        values[kind] for kind in PLAN
    ]

    for (_, decoded, raw_query), kind in zip(
        server.received[before:],
        PLAN,
        strict=True,
    ):
        assert parse_qs(
            raw_query,
            keep_blank_values=True,
        ) == {"category": [decoded]}
        assert decoded == values[kind]
        assert " " not in raw_query
        if "'" in decoded:
            assert "'" not in raw_query
            assert "%27" in raw_query

    assert all(len(items) == 2 for items in observations.values())

    assert all(items[0] == items[1] for items in observations.values())

    assert all(
        200 <= status < 300 for items in observations.values() for status, _ in items
    )

    b, t1, f1, t2, f2, control = (
        observations[kind][0]
        for kind in (
            "B",
            "T1",
            "F1",
            "T2",
            "F2",
            "C",
        )
    )

    relation = b == t1 == t2 == control and f1 == f2 and b != f1

    actual = "candidate" if relation else "not_confirmed"

    assert actual == expected

    if path == "/safe":
        assert b[1]
        assert t1[1] == f1[1] == t2[1] == f2[1] == control[1] == b""


def test_sqlite_error_is_generic_and_quiet(
    local_server,
    capsys,
):
    server, origin = local_server

    with httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=5,
    ) as client:
        response = client.get(
            origin + "/vulnerable",
            params={"category": "'"},
        )

    assert response.status_code == 500
    assert response.content == b"query-error"
    assert server.query_errors == 1
    assert server.handler_failed is False
    assert capsys.readouterr() == ("", "")


def test_numeric_preset_does_not_clear_string_quoted_vulnerability():
    endpoint = LiveEndpoint(
        endpoint_id="string-vulnerable-numeric-preset",
        path="/vulnerable",
        expected_label="positive",
        parameter_name="category",
        initial_value="Pets",
        preset_name="numeric",
    )

    result, _ = run_live_endpoint(endpoint)

    assert result.verdict is Verdict.NOT_DETECTED
    assert result.reason_code == "no_boolean_difference_literal_input"
    assert result.request_count == 6


def test_string_quoted_preset_is_inconclusive_for_numeric_vulnerability():
    endpoint = LiveEndpoint(
        endpoint_id="numeric-vulnerable-string-preset",
        path="/numeric-vulnerable",
        expected_label="positive",
        parameter_name="product_id",
        initial_value="1",
        preset_name="string-quoted",
        expected_query_errors=4,
    )

    result, _ = run_live_endpoint(endpoint)

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "non_success_status"
    assert result.request_count == 6


@pytest.mark.parametrize(
    "endpoint",
    [
        endpoint
        for endpoint in LIVE_TWIN_ENDPOINTS
        if endpoint.expected_label == "positive"
    ],
    ids=lambda endpoint: endpoint.endpoint_id,
)
def test_real_sqlite_positive_twins_survive_confirmation(endpoint):
    outcome, _ = run_confirmed_live_endpoint(endpoint)

    assert outcome.initial.reason_code == "boolean_candidate"
    assert outcome.status is ConfirmationStatus.CANDIDATE
    assert outcome.reason_code == "confirmation_pattern_matched"
    assert outcome.request_count == 18


@pytest.mark.parametrize(
    "limitation",
    KNOWN_LIMITATION_ENDPOINTS,
    ids=lambda limitation: limitation.limitation_id,
)
def test_structural_known_limitations_survive_confirmation(limitation):
    outcome, _ = run_confirmed_live_endpoint(limitation.endpoint)

    assert outcome.initial.reason_code == "boolean_candidate"
    assert outcome.status is limitation.expected_confirmation_status
    assert outcome.reason_code == limitation.expected_reason_code
    assert outcome.request_count == 18


def test_unexpected_requests_are_counted_before_validation():
    try:
        server = _Server()
    except OSError:
        pytest.fail(
            "Cannot bind the request-count fixture. Check that the runner permits IPv4 loopback sockets."
        )

    with (
        running_server(server) as (_, origin),
        httpx.Client(trust_env=False, follow_redirects=False, timeout=5) as client,
    ):
        unexpected_query = client.get(
            origin + "/safe", params={"unexpected": "fixture-value"}
        )
        unexpected_method = client.post(origin + "/safe")

    assert unexpected_query.status_code == 404
    assert unexpected_method.status_code == 501
    assert server.total_requests == 2
    assert server.received == []
    assert server.query_errors == 0
    assert server.handler_failed is False


def test_cli_environment_does_not_inherit_ambient_values(
    monkeypatch,
):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("VINTAR_TARGET_ORIGIN", "https://wrong.invalid")
    monkeypatch.setenv("VINTAR_ALLOWED_ORIGIN", "https://wrong.invalid")
    monkeypatch.setenv("VINTAR_TEST_SECRET", "not-for-child")
    monkeypatch.setenv("COVERAGE_PROCESS_CONFIG", "coverage-configuration")

    environment = _cli_environment("http://127.0.0.1:43210")

    assert environment["VINTAR_TARGET_ORIGIN"] == "http://127.0.0.1:43210"
    assert environment["VINTAR_ALLOWED_ORIGIN"] == "http://127.0.0.1:43210"
    assert environment["COVERAGE_PROCESS_CONFIG"] == "coverage-configuration"
    assert "HTTP_PROXY" not in environment
    assert "HTTPS_PROXY" not in environment
    assert "VINTAR_TEST_SECRET" not in environment
