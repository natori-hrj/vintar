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
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
_VALIDATOR_NAMESPACE = runpy.run_path(str(ROOT / "scripts" / "validate_ci_report.py"))
_validate = cast(
    Callable[[Path, int], None],
    _VALIDATOR_NAMESPACE["_validate"],
)

TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
CONTROL = "__vintar_control_7f4a9c2e"

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
expected_verdict = "inconclusive"

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


def _sql_result(category: str, *, safe: bool) -> bytes:
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE products (name TEXT NOT NULL, category TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            [
                ("Cat toy", "Pets"),
                ("Dog toy", "Pets"),
                ("Notebook", "Office"),
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


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        path = urlsplit(self.path)
        query = parse_qs(
            path.query,
            keep_blank_values=True,
        )

        if (
            path.path
            not in (
                "/vulnerable",
                "/safe",
                "/mimic",
            )
            or set(query) != {"category"}
            or len(query["category"]) != 1
        ):
            status, body = 404, b"not-found"
        else:
            category = query["category"][0]
            server.received.append((path.path, category, path.query))

            try:
                if path.path == "/mimic":
                    false_inputs = {
                        "Pets" + FALSE_1,
                        "Pets" + FALSE_2,
                        "Pets" + CONTROL,
                    }

                    body = (
                        b"no-results" if category in false_inputs else b"products-found"
                    )
                else:
                    body = _sql_result(
                        category,
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
        self.handler_failed = False
        self.query_errors = 0

    def handle_error(
        self,
        request: object,
        client_address: tuple[str, int],
    ) -> None:
        self.handler_failed = True


@pytest.fixture
def local_server():
    try:
        server = _Server()
    except OSError:
        pytest.skip("Loopback binding is not available")

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
        assert not server.handler_failed

    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        assert not worker.is_alive()


def _cli_environment(origin: str) -> dict[str, str]:
    env = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "VINTAR_TARGET_ORIGIN": origin,
        "VINTAR_ALLOWED_ORIGIN": origin,
    }

    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            if value := os.environ.get(name):
                env[name] = value

    return env


@pytest.mark.parametrize(
    ("path", "reason", "similarity"),
    [
        (
            "/vulnerable",
            "boolean_candidate",
            (1.0, 0.0, 0.0),
        ),
        (
            "/safe",
            "unexpected_difference",
            (0.0, 0.0, 1.0),
        ),
        (
            "/mimic",
            "boolean_candidate",
            (1.0, 0.0, 0.0),
        ),
    ],
)
def test_real_http_vintar_cli(
    local_server,
    tmp_path,
    path,
    reason,
    similarity,
):
    server, origin = local_server

    case_path = tmp_path / "case.toml"
    case_path.write_text(
        CASE.format(path=path),
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

    assert result.returncode == 3, "Unexpected CLI exit code"
    assert result.stderr == b"", "Unexpected CLI stderr"

    report = json.loads(result.stdout)

    report_path = tmp_path / "report.json"
    report_path.write_bytes(result.stdout)
    _validate(report_path, result.returncode)

    assert report["status"] == "inconclusive"
    assert report["exit_code"] == 3
    assert report["requests_used"] == 6
    assert report["complete"] is True
    assert report["executed_count"] == 1

    outcome = report["outcomes"][0]

    assert outcome["expected_verdict"] == "inconclusive"
    assert outcome["actual_verdict"] == "inconclusive"
    assert outcome["expectation_match"] is True
    assert outcome["status"] == "inconclusive"

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
        "C": "Pets" + CONTROL,
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

    relation = b == t1 == t2 and f1 == f2 == control and b != f1

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


def test_cli_environment_does_not_inherit_ambient_values(
    monkeypatch,
):
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("VINTAR_TARGET_ORIGIN", "https://wrong.invalid")
    monkeypatch.setenv("VINTAR_ALLOWED_ORIGIN", "https://wrong.invalid")
    monkeypatch.setenv("VINTAR_TEST_SECRET", "not-for-child")

    environment = _cli_environment("http://127.0.0.1:43210")

    assert environment["VINTAR_TARGET_ORIGIN"] == "http://127.0.0.1:43210"
    assert environment["VINTAR_ALLOWED_ORIGIN"] == "http://127.0.0.1:43210"
    assert "HTTP_PROXY" not in environment
    assert "HTTPS_PROXY" not in environment
    assert "VINTAR_TEST_SECRET" not in environment
