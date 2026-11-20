"""Measure candidate-signal response relations on deterministic loopback fixtures.

The positive cases are synthetic: they switch responses by comparing request values
and do not execute SQL. They are distinct from the real SQLite fixture measurements.
The negative pagination branch uses the same response-switching mechanism to measure
a known false-candidate shape.
"""

import json
import threading
from collections import Counter
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest
from test_sqli_candidate_reliability import classify

from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.checks.sqli.presets import get_boolean_probe_preset
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


@dataclass(frozen=True, slots=True)
class PrecisionCase:
    name: str
    expected_label: str
    simulation: str
    expected_verdict: Verdict
    expected_reason: str


CASES = (
    PrecisionCase(
        "global-noise",
        "negative",
        "A response-wide request ID changes on every request.",
        Verdict.INCONCLUSIVE,
        "unstable_response",
    ),
    PrecisionCase(
        "localized-csrf",
        "negative",
        "A localized CSRF token changes on every request.",
        Verdict.INCONCLUSIVE,
        "possible_dynamic_response",
    ),
    PrecisionCase(
        "pagination-branch",
        "negative",
        "Business logic maps the false-looking value to a different page.",
        Verdict.INCONCLUSIVE,
        "boolean_candidate",
    ),
    PrecisionCase(
        "waf-200",
        "negative",
        "A filter returns a stable HTTP 200 block page for the false probe.",
        Verdict.INCONCLUSIVE,
        "boolean_candidate",
    ),
    PrecisionCase(
        "waf-403",
        "negative",
        "A filter returns HTTP 403 for injected values.",
        Verdict.INCONCLUSIVE,
        "non_success_status",
    ),
    PrecisionCase(
        "quote-sanitizer",
        "negative",
        "Sanitization removes the quoted suffix before application logic.",
        Verdict.NOT_DETECTED,
        "no_boolean_difference",
    ),
    PrecisionCase(
        "length-cap",
        "negative",
        "The parameter is capped to the benign baseline length.",
        Verdict.NOT_DETECTED,
        "no_boolean_difference",
    ),
    PrecisionCase(
        "input-echo",
        "negative",
        "The application safely echoes the literal parameter value.",
        Verdict.INCONCLUSIVE,
        "unexpected_difference",
    ),
    PrecisionCase(
        "synthetic-positive-small-diff",
        "positive",
        "A synthetic positive relation changes only one response byte.",
        Verdict.INCONCLUSIVE,
        "boolean_candidate",
    ),
    PrecisionCase(
        "synthetic-positive-json",
        "positive",
        "A synthetic positive JSON relation returns rows versus an empty array.",
        Verdict.INCONCLUSIVE,
        "boolean_candidate",
    ),
    PrecisionCase(
        "synthetic-positive-error-200",
        "positive",
        "A synthetic positive relation renders its false branch as an HTTP 200 error page.",
        Verdict.INCONCLUSIVE,
        "boolean_candidate",
    ),
)


class _PrecisionHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        parsed = urlsplit(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        value = query.get("category", [""])[0]
        mode = parsed.path.removeprefix("/")
        server.request_count += 1
        body, status = _response(mode, value, server.request_count)

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class _PrecisionServer(HTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _PrecisionHandler)
        self.request_count = 0


def _response(mode: str, value: str, request_count: int) -> tuple[bytes, int]:
    preset = get_boolean_probe_preset("string-quoted")
    baseline = "Pets"
    false_value = baseline + preset.false_payload

    if mode == "global-noise":
        return f"request-{request_count:02d}-{'x' * request_count}".encode(), 200
    if mode == "localized-csrf":
        return f"products|csrf={request_count:08d}|footer-content".encode(), 200
    if mode == "pagination-branch":
        return (b"page-two" if value == false_value else b"page-one"), 200
    if mode == "waf-200":
        return (b"blocked" if value == false_value else b"products"), 200
    if mode == "waf-403":
        return (b"blocked", 403) if value != baseline else (b"products", 200)
    if mode == "quote-sanitizer":
        return b"products", 200
    if mode == "length-cap":
        return value[: len(baseline)].encode(), 200
    if mode == "input-echo":
        return f"value={value}".encode(), 200
    if mode == "synthetic-positive-small-diff":
        return (b"1" if value != false_value else b"0"), 200
    if mode == "synthetic-positive-json":
        body = {"items": [1]} if value != false_value else {"items": []}
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), 200
    if mode == "synthetic-positive-error-200":
        return (b"sql-error" if value == false_value else b"products"), 200
    raise AssertionError(f"Unknown precision fixture mode: {mode}")


@contextmanager
def _running_server():
    try:
        server = _PrecisionServer()
    except OSError:
        pytest.fail(
            "Cannot bind the precision fixture to loopback. Check that the runner "
            "permits ephemeral IPv4 loopback sockets."
        )
    started = threading.Event()

    def serve() -> None:
        started.set()
        server.serve_forever()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    if not started.wait(timeout=5):
        server.server_close()
        pytest.fail(
            "The precision fixture did not start. Check thread scheduling and "
            "loopback transport setup."
        )
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)
        if worker.is_alive():
            pytest.fail(
                "The precision fixture did not stop. Check server shutdown and "
                "outstanding loopback requests."
            )


def _measure(case: PrecisionCase):
    with _running_server() as server:
        port = server.server_port
        context = ExecutionContext(
            scope=ScopePolicy(
                allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", port)})
            ),
            budget=RequestBudget(6),
            timeout=5,
            rate_limiter=RateLimiter(requests_per_second=100),
            max_response_size=1_048_576,
        )
        preset = get_boolean_probe_preset("string-quoted")
        result = verify_boolean_sqli(
            check_id=case.name,
            template=RequestTemplate(
                method="GET",
                url=f"http://127.0.0.1:{port}/{case.name}",
                params=(("category", "Pets"),),
            ),
            point=InjectionPoint(
                location=InjectionLocation.QUERY,
                name="category",
                mode=InjectionMode.APPEND,
            ),
            true_payload=preset.true_payload,
            false_payload=preset.false_payload,
            context=context,
        )
        assert server.request_count == result.request_count == 6
        return result


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.name)
def test_precision_case_measurement(case: PrecisionCase):
    result = _measure(case)
    assert result.verdict is case.expected_verdict
    assert result.reason_code == case.expected_reason


def test_positive_cases_are_explicitly_synthetic_response_relations():
    positive_cases = [case for case in CASES if case.expected_label == "positive"]
    assert positive_cases
    assert all(case.name.startswith("synthetic-positive-") for case in positive_cases)


def test_precision_confusion_table():
    rows = [(case, _measure(case)) for case in CASES]
    counts = Counter(
        classify(case.expected_label, result.verdict, result.reason_code)
        for case, result in rows
    )

    assert {key: counts[key] for key in ("tp", "tn", "fp", "fn", "non_decision")} == {
        "tp": 3,
        "tn": 2,
        "fp": 2,
        "fn": 0,
        "non_decision": 4,
    }
