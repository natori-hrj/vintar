"""End-to-end smoke tests for the Vintar CI contract."""

import base64
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

GET_V2_TEMPLATE = """
version = 2
identity_id = "example-identity"
id = "{case_id}"
type = "sqli.boolean"
expected_verdict = "not_detected"

[request]
method = "GET"
url = "http://placeholder.invalid:8000{path}"
allowed_origin = "http://placeholder.invalid:8000"
params = [["category", "baseline"]]

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "replace"

[probes]
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 5.0

[approval]
method = "GET"
path = "{path}"
environment_class = "isolated_test"
"""

POST_V2_TEMPLATE = """
version = 2
identity_id = "example-identity"
id = "{case_id}"
type = "sqli.boolean"
expected_verdict = "not_detected"

[request]
method = "POST"
url = "http://placeholder.invalid:8000{path}"
allowed_origin = "http://placeholder.invalid:8000"
json_body = '{{"name":"baseline"}}'

[injection]
location = "json_body"
pointer = "/name"
mode = "replace"

[probes]
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 5.0

[approval]
candidate_id = "post-json-candidate-00000000000000000000000000000000"
method = "POST"
path = "{path}"
operation_pointer = "/paths/~1items/post"
request_body_pointer = "/paths/~1items/post/requestBody/content/application~1json"
operation_definition_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"
baseline_body_sha256 = "5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d"
side_effect = "no_side_effect"
environment_class = "isolated_test"

[approval.review]
schema_version = 2
report_type = "post_json_discovery_review"
"""

SYNTHETIC_CREDENTIALS = {
    "bearer": ("Authorization", "example-token-value", "Bearer example-token-value"),
    "api_key_header": ("X-Example-Key", "example-key-value", "example-key-value"),
    "basic": (
        "Authorization",
        "example-user:example-password",
        "Basic " + base64.b64encode(b"example-user:example-password").decode("ascii"),
    ),
}


class FixtureHandler(BaseHTTPRequestHandler):
    """Deterministic, localhost-only HTTP fixture."""

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        self._handle()

    def _handle(self) -> None:
        path = urlsplit(self.path).path

        server = cast("FixtureServer", self.server)
        if self.client_address[0] != "127.0.0.1":
            server.handler_failed = True
            self.send_error(403)
            return

        server.received_paths.append(path)

        if path == "/auth-redirect":
            expected = SYNTHETIC_CREDENTIALS["bearer"]
            status = 302 if self.headers.get(expected[0]) == expected[2] else 401
            body = b"redirect-refused"
        elif path.startswith("/auth/"):
            kind = path.rsplit("/", 1)[-1]
            expected = SYNTHETIC_CREDENTIALS[kind]
            status = 200 if self.headers.get(expected[0]) == expected[2] else 401
            body = b"fixed-response"
        elif path == "/ok":
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
        if path == "/auth-redirect":
            self.send_header("Location", "https://other.invalid/should-not-follow")
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
    executable: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    env = _cli_environment(origin)
    if extra_env is not None:
        env.update(extra_env)

    command = (
        [str(executable.resolve())]
        if executable
        else [sys.executable, "-m", "vintar.cli"]
    )
    return subprocess.run(
        [
            *command,
            "verify",
            "--cases",
            str(case),
            "--max-requests",
            "6",
            "--rps",
            "10",
            "--authorized",
        ],
        cwd=case.parent if executable else ROOT,
        env=env,
        capture_output=True,
        timeout=30,
        check=False,
    )


def _write_authenticated_case(
    folder: Path, *, method: str, kind: str
) -> tuple[Path, str, str]:
    case_id = f"auth-{method.lower()}-{kind.replace('_', '-')}"
    path = f"/auth/{method.lower()}/{kind}"
    case = folder / f"{case_id}.toml"
    template = GET_V2_TEMPLATE if method == "GET" else POST_V2_TEMPLATE
    case.write_text(template.format(case_id=case_id, path=path), encoding="utf-8")
    return case, case_id, path


def _auth_policy(
    origin: str,
    case_id: str,
    path: str,
    method: str,
    kind: str,
    *,
    expires_at: str | None = None,
) -> str:
    header, _raw, _expected = SYNTHETIC_CREDENTIALS[kind]
    approval = {
        "case_id": case_id,
        "identity_id": "example-identity",
        "credential_kind": kind,
        "credential_env_var": "VINTAR_EXAMPLE_CREDENTIAL",
        "method": method,
        "path": path,
        "origin": origin,
        "allowed_environment_classes": ["isolated_test"],
    }
    if method == "POST":
        approval.update(
            {
                "operation_definition_sha256": "0" * 64,
                "baseline_body_sha256": "5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d",
                "allowed_side_effect": "no_side_effect",
            }
        )
    identity = {
        "identity_id": "example-identity",
        "credential_kind": kind,
        "env_var": "VINTAR_EXAMPLE_CREDENTIAL",
        "header_name": header,
    }
    if expires_at is not None:
        identity["expires_at"] = expires_at
    return json.dumps(
        {
            "schema_version": 1,
            "policy_type": "post_json_execution",
            "identities": [identity],
            "approvals": [approval],
            "limits": {
                "max_requests": 6,
                "max_requests_per_second": 10.0,
                "max_timeout_seconds": 5.0,
                "max_response_size": 1_048_576,
                "max_time_execution_seconds": 45.0,
            },
        },
        separators=(",", ":"),
    )


def _check_authenticated_scenario(
    case: Path,
    *,
    case_id: str,
    path: str,
    method: str,
    kind: str,
    origin: str,
    server: FixtureServer,
    executable: Path | None,
) -> None:
    before = len(server.received_paths)
    _header, raw, expected = SYNTHETIC_CREDENTIALS[kind]
    completed = _run_cli(
        case,
        origin=origin,
        executable=executable,
        extra_env={
            "VINTAR_RUNTIME_POLICY_JSON": _auth_policy(
                origin, case_id, path, method, kind
            ),
            "VINTAR_EXAMPLE_CREDENTIAL": raw,
        },
    )
    combined = completed.stdout + completed.stderr
    forbidden = (
        raw,
        expected,
        "example-identity",
        "VINTAR_EXAMPLE_CREDENTIAL",
        SYNTHETIC_CREDENTIALS[kind][0],
    )
    if any(value.encode() in combined for value in forbidden):
        raise RuntimeError("Authentication data reached CLI output.")
    if completed.returncode != 0 or completed.stderr:
        raise RuntimeError("Authenticated CLI scenario failed.")
    if len(server.received_paths) - before != 6:
        raise RuntimeError("Unexpected authenticated request count.")
    report = json.loads(completed.stdout)
    if report["status"] != "pass" or report["requests_used"] != 6:
        raise RuntimeError("Unexpected authenticated report.")


def _check_authenticated_failure(
    case: Path,
    *,
    policy: str,
    credential: str,
    origin: str,
    expected_requests: int,
    server: FixtureServer,
    executable: Path | None,
) -> None:
    before = len(server.received_paths)
    completed = _run_cli(
        case,
        origin=origin,
        executable=executable,
        extra_env={
            "VINTAR_RUNTIME_POLICY_JSON": policy,
            "VINTAR_EXAMPLE_CREDENTIAL": credential,
        },
    )
    if completed.returncode != 2 or completed.stdout:
        raise RuntimeError("Authenticated failure did not fail closed.")
    if len(server.received_paths) - before != expected_requests:
        raise RuntimeError("Unexpected authenticated failure request count.")
    if credential.encode() in completed.stderr:
        raise RuntimeError("Credential reached authenticated failure output.")


def _check_scenario(
    name: str,
    case: Path,
    *,
    origin: str,
    expected_code: int,
    expected_requests: int,
    server: FixtureServer,
    report_dir: Path,
    executable: Path | None = None,
) -> None:
    requests_before = len(server.received_paths)
    completed = _run_cli(case, origin=origin, executable=executable)
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


def run_e2e(report_dir: Path, *, executable: Path | None = None) -> None:
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
                    executable=executable,
                )

            for method in ("GET", "POST"):
                for kind in SYNTHETIC_CREDENTIALS:
                    auth_case, case_id, path = _write_authenticated_case(
                        cases_dir, method=method, kind=kind
                    )
                    _check_authenticated_scenario(
                        auth_case,
                        case_id=case_id,
                        path=path,
                        method=method,
                        kind=kind,
                        origin=origin,
                        server=server,
                        executable=executable,
                    )

            failure_case, failure_id, failure_path = _write_authenticated_case(
                cases_dir, method="GET", kind="bearer"
            )
            failure_policy = _auth_policy(
                origin, failure_id, failure_path, "GET", "bearer"
            )
            _check_authenticated_failure(
                failure_case,
                policy=failure_policy,
                credential="wrong-example-value",
                origin=origin,
                expected_requests=1,
                server=server,
                executable=executable,
            )
            _check_authenticated_failure(
                failure_case,
                policy=_auth_policy(
                    origin,
                    failure_id,
                    failure_path,
                    "GET",
                    "bearer",
                    expires_at="2000-01-01T00:00:00Z",
                ),
                credential="example-token-value",
                origin=origin,
                expected_requests=0,
                server=server,
                executable=executable,
            )
            other_origin = "http://127.0.0.1:1"
            _check_authenticated_failure(
                failure_case,
                policy=_auth_policy(
                    other_origin, failure_id, failure_path, "GET", "bearer"
                ),
                credential="example-token-value",
                origin=origin,
                expected_requests=0,
                server=server,
                executable=executable,
            )

            redirect_case = cases_dir / "auth-redirect.toml"
            redirect_case.write_text(
                GET_V2_TEMPLATE.format(case_id="auth-redirect", path="/auth-redirect"),
                encoding="utf-8",
            )
            before_redirect = len(server.received_paths)
            redirected = _run_cli(
                redirect_case,
                origin=origin,
                executable=executable,
                extra_env={
                    "VINTAR_RUNTIME_POLICY_JSON": _auth_policy(
                        origin,
                        "auth-redirect",
                        "/auth-redirect",
                        "GET",
                        "bearer",
                    ),
                    "VINTAR_EXAMPLE_CREDENTIAL": "example-token-value",
                },
            )
            if redirected.returncode != 3 or redirected.stderr:
                raise RuntimeError(
                    "Redirect refusal did not produce inconclusive output."
                )
            if len(server.received_paths) - before_redirect != 6:
                raise RuntimeError("Redirect was followed or request count changed.")

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
                executable=executable,
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
