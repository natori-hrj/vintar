"""End-to-end smoke tests for the Vintar CI contract."""

import json
import os
import runpy
import subprocess
import sys
import tempfile
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
REPORT_LIMIT = 2_097_152
ERROR_MESSAGE = "Vintar CI E2E verification failed."
_VALIDATOR_NAMESPACE = runpy.run_path(str(ROOT / "scripts" / "validate_ci_report.py"))
_validate = cast(
    Callable[[Path, int], None],
    _VALIDATOR_NAMESPACE["_validate"],
)

CASE_TEMPLATE = """
version = 1
id = "fixture-case"
type = "sqli.boolean"
expected_verdict = "{expected}"

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
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 5.0
"""


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic, localhost-only HTTP fixture."""

    def do_GET(self) -> None:
        path = urlsplit(self.path).path

        server = cast("FixtureServer", self.server)
        if self.client_address[0] != "127.0.0.1":
            server.handler_failed = True
            self.send_error(403)
            return

        server.received_paths.append(path)

        if path == "/ok":
            status = 200
            body = b"fixed-response"
        elif path == "/limited":
            status = 429
            body = b"rate-limited"
        else:
            status = 404
            body = b"not-found"

        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Do not put request details into CI logs."""


class FixtureServer(HTTPServer):
    """Loopback fixture with private request accounting and quiet errors."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), FixtureHandler)
        self.received_paths: list[str] = []
        self.handler_failed = False

    def handle_error(
        self,
        request: object,
        client_address: tuple[str, int],
    ) -> None:
        """Record handler failures without logging request data."""
        self.handler_failed = True


def _write_case(
    folder: Path,
    *,
    expected: str,
    path: str,
) -> Path:
    filename = folder / "case.toml"
    filename.write_text(
        CASE_TEMPLATE.format(
            expected=expected,
            path=path,
        ),
        encoding="utf-8",
    )
    return filename


def _cli_environment(origin: str) -> dict[str, str]:
    """Build a minimal child environment with no ambient CI values."""
    # Pass only values required by the CLI. In particular, do not inherit
    # CI secrets, production target bindings, proxy settings, or PYTHONPATH.
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


def _run_cli(
    case: Path,
    *,
    origin: str,
) -> subprocess.CompletedProcess[bytes]:
    env = _cli_environment(origin)

    return subprocess.run(
        [
            sys.executable,
            "-m",
            "vintar.cli",
            "verify",
            "--cases",
            str(case),
            "--max-requests",
            "6",
            "--rps",
            "10",
            "--authorized",
        ],
        cwd=ROOT,
        env=env,
        capture_output=True,
        timeout=30,
        check=False,
    )


def _check_scenario(
    name: str,
    case: Path,
    *,
    origin: str,
    expected_code: int,
    expected_requests: int,
    server: FixtureServer,
    report_dir: Path,
) -> None:
    requests_before = len(server.received_paths)
    completed = _run_cli(case, origin=origin)
    requests_received = len(server.received_paths) - requests_before

    if completed.returncode != expected_code:
        raise RuntimeError("Unexpected CLI exit code.")

    if requests_received != expected_requests or server.handler_failed:
        raise RuntimeError("Unexpected loopback request count.")

    if expected_code != 2 and completed.stderr:
        raise RuntimeError("Unexpected CLI diagnostic output.")

    if expected_code == 2:
        if completed.stdout:
            raise RuntimeError("ERROR unexpectedly produced JSON.")
        if completed.stderr != (
            b"Error: regression verification could not be completed.\n"
        ):
            raise RuntimeError("Unexpected ERROR diagnostic output.")
        print("ERROR: verified")
        return

    if not completed.stdout or len(completed.stdout) > REPORT_LIMIT:
        raise RuntimeError("Invalid report output.")

    report_path = report_dir / f".{name}.pending"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(report_path, flags, 0o600)

    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(completed.stdout)

        # Reuse the exact production CI validator.
        _validate(report_path, expected_code)

        report = json.loads(completed.stdout)

        if report["complete"] is not True:
            raise RuntimeError("Unexpected incomplete fixture result.")

        if report["executed_count"] != 1:
            raise RuntimeError("Unexpected fixture case count.")

        if report["requests_used"] != expected_requests:
            raise RuntimeError("Unexpected report request count.")

        outcome = report["outcomes"][0]
        expected_results = {
            "pass": ("not_detected", "not_detected", True, "pass"),
            "fail": ("vulnerable", "not_detected", False, "fail"),
            "inconclusive": (
                "inconclusive",
                "inconclusive",
                True,
                "inconclusive",
            ),
        }
        expected_verdict, actual_verdict, matched, status = expected_results[name]
        if (
            outcome["expected_verdict"],
            outcome["actual_verdict"],
            outcome["expectation_match"],
            outcome["status"],
        ) != (expected_verdict, actual_verdict, matched, status):
            raise RuntimeError("Unexpected fixture verdict.")

        if name == "inconclusive" and (
            outcome["verification"]["reason_code"] != "rate_limited"
        ):
            raise RuntimeError("Expected HTTP 429 rate-limit result.")

        os.replace(
            report_path,
            report_dir / f"{name}.json",
        )
    finally:
        report_path.unlink(missing_ok=True)

    print(f"{name.upper()}: verified")


def run_e2e(report_dir: Path) -> None:
    """Verify all four CI exit paths against real loopback HTTP."""
    report_dir.mkdir(mode=0o700, parents=True, exist_ok=False)

    server = FixtureServer()

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    origin = f"http://127.0.0.1:{server.server_port}"

    try:
        with tempfile.TemporaryDirectory(
            prefix="vintar-e2e-cases-",
        ) as temporary:
            cases_dir = Path(temporary)

            scenarios = (
                ("pass", "not_detected", "/ok", 0, 6),
                ("fail", "vulnerable", "/ok", 1, 6),
                ("inconclusive", "inconclusive", "/limited", 3, 1),
            )

            for name, expected, path, code, requests in scenarios:
                case = _write_case(
                    cases_dir,
                    expected=expected,
                    path=path,
                )
                _check_scenario(
                    name,
                    case,
                    origin=origin,
                    expected_code=code,
                    expected_requests=requests,
                    server=server,
                    report_dir=report_dir,
                )

            # An invalid case must produce ERROR with no JSON.
            invalid = cases_dir / "invalid.toml"
            invalid.write_text(
                'invalid = "unsupported"',
                encoding="utf-8",
            )
            _check_scenario(
                "error",
                invalid,
                origin=origin,
                expected_code=2,
                expected_requests=0,
                server=server,
                report_dir=report_dir,
            )

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("Fixture server did not stop.")


def main() -> int:
    try:
        base = Path(os.environ.get("RUNNER_TEMP") or tempfile.gettempdir())
        run_e2e(base / "vintar-e2e-reports")
        return 0

    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired):
        print(ERROR_MESSAGE, file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        code = main()
    except Exception as exc:
        print(ERROR_MESSAGE, file=sys.stderr)
        raise SystemExit(2) from exc
    raise SystemExit(code)
