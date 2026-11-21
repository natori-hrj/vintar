"""CLI tests for environment-based regression target binding."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from typer.testing import CliRunner

from vintar import regression_cli
from vintar.cli import app
from vintar.core import http
from vintar.regression import batch as batch_module

cli = CliRunner()

CASE_SOURCE = """
version = 1
id = "case-one"
type = "sqli.boolean"
expected_verdict = "not_detected"

[target]
url = "http://placeholder.invalid:8000/products"
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
requests_per_second = 2.0
timeout_seconds = 10.0
"""

TIME_CASE_SOURCE = """
version = 1
id = "time-case"
type = "sqli.time"
expected_verdict = "not_detected"

[target]
url = "http://placeholder.invalid:8000/products"
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
delay_payload = "-delay"
control_payload = "-control"
expected_delay_seconds = 0.25

[limits]
max_requests = 9
requests_per_second = 10.0
timeout_seconds = 3.0
"""

ERROR_CASE_SOURCE = """
version = 1
id = "error-case"
type = "sqli.error"
expected_verdict = "inconclusive"

[target]
url = "http://placeholder.invalid:8000/products"
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
error_payload = "'"

[limits]
max_requests = 4
requests_per_second = 10.0
timeout_seconds = 3.0
"""

ENV = {
    "VINTAR_TARGET_ORIGIN": "http://127.0.0.1:8765",
    "VINTAR_ALLOWED_ORIGIN": "http://127.0.0.1:8765",
}


def write_case(
    directory: Path,
    case_id: str = "case-one",
    *,
    expected: str = "not_detected",
    path: str = "/products",
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)

    source = (
        CASE_SOURCE.replace(
            'id = "case-one"',
            f'id = "{case_id}"',
        )
        .replace(
            'expected_verdict = "not_detected"',
            f'expected_verdict = "{expected}"',
        )
        .replace(
            "placeholder.invalid:8000/products",
            f"placeholder.invalid:8000{path}",
        )
    )

    file = directory / f"{case_id}.toml"
    file.write_text(source, encoding="utf-8")
    return file


def write_time_case(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    file = directory / "time-case.toml"
    file.write_text(TIME_CASE_SOURCE, encoding="utf-8")
    return file


def write_error_case(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    file = directory / "error-case.toml"
    file.write_text(ERROR_CASE_SOURCE, encoding="utf-8")
    return file


def args_for(
    path: Path,
    max_requests: int = 6,
) -> list[str]:
    return [
        "verify",
        "--cases",
        str(path),
        "--max-requests",
        str(max_requests),
        "--authorized",
    ]


@pytest.fixture
def mock_http(monkeypatch):
    """Run the actual batch engine with an isolated HTTP transport."""
    real_batch = regression_cli.run_regression_batch
    received: list[httpx.Request] = []
    response_status = [200]
    now = 0.0

    def clock() -> float:
        return now

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal now
        received.append(request)
        now += 0.125
        if isinstance(response_status[0], Exception):
            raise response_status[0]
        return httpx.Response(
            response_status[0],
            content=b"same",
        )

    transport = httpx.MockTransport(handler)

    def isolated_batch(cases, *, policy):
        return real_batch(
            cases,
            policy=policy,
            transport=transport,
        )

    def virtual_limiter(*, requests_per_second):
        from vintar.core.rate_limit import RateLimiter

        def sleep(seconds):
            nonlocal now
            now += seconds

        return RateLimiter(
            requests_per_second=requests_per_second,
            _clock=clock,
            _sleep=sleep,
        )

    monkeypatch.setattr(
        regression_cli,
        "run_regression_batch",
        isolated_batch,
    )
    monkeypatch.setattr(
        batch_module,
        "RateLimiter",
        virtual_limiter,
    )
    monkeypatch.setattr(http, "time", SimpleNamespace(perf_counter=clock))

    return received, response_status


@pytest.mark.parametrize(
    ("expected", "http_status", "verdict", "status", "exit_code"),
    [
        ("not_detected", 200, "not_detected", "pass", 0),
        ("vulnerable", 200, "not_detected", "fail", 1),
        ("inconclusive", 429, "inconclusive", "inconclusive", 3),
    ],
)
def test_verify_enum_json_and_exit_code_are_contract(
    tmp_path, mock_http, expected, http_status, verdict, status, exit_code
):
    case = write_case(tmp_path, expected=expected)
    _, statuses = mock_http
    statuses[0] = http_status

    result = cli.invoke(app, args_for(case), env=ENV)

    assert result.exit_code == exit_code
    report = json.loads(result.stdout)
    assert report["exit_code"] == exit_code
    assert report["status"] == status
    [outcome] = report["outcomes"]
    assert outcome["status"] == status
    assert outcome["expected_verdict"] == expected
    assert outcome["actual_verdict"] == verdict
    assert outcome["verification"]["verdict"] == verdict


def test_time_case_cli_emits_time_report_and_existing_exit_contract(
    tmp_path, mock_http
):
    case = write_time_case(tmp_path)
    received, _ = mock_http

    result = cli.invoke(app, args_for(case, max_requests=9), env=ENV)

    assert result.exit_code == 3
    report = json.loads(result.stdout)
    assert report["exit_code"] == 3
    [outcome] = report["outcomes"]
    assert outcome["check_type"] == "sqli.time"
    assert outcome["actual_verdict"] == "inconclusive"
    assert outcome["actual_reason_code"] == "unstable_timing"
    assert outcome["request_count"] == 9
    assert outcome["timing"] == {
        "status": "inconclusive",
        "reason_code": "unstable_timing",
        "request_count": 9,
    }
    assert "verification" not in outcome
    assert "confirmation" not in outcome
    assert result.stderr == ""
    assert result.exception is not None
    assert len(received) == 9


def test_time_case_cli_rejects_impossible_operator_deadline_before_http(
    tmp_path, mock_http
):
    case = write_time_case(tmp_path)
    received, _ = mock_http

    result = cli.invoke(
        app,
        [*args_for(case, max_requests=9), "--time-deadline", "1.0"],
        env=ENV,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "cannot accommodate" in result.stderr
    assert "Increase --time-deadline" in result.stderr
    assert received == []


def test_environment_rebinds_target_origin(
    tmp_path,
    mock_http,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 0
    assert result.stderr == ""

    report = json.loads(result.stdout)

    assert report["status"] == "pass"
    assert report["complete"] is True
    assert report["exit_code"] == result.exit_code
    assert report["requests_used"] == 6
    assert len(received) == 6

    assert all(
        request.url.host == "127.0.0.1"
        and request.url.port == 8765
        and request.url.path == "/products"
        for request in received
    )
    assert all("placeholder.invalid" not in str(request.url) for request in received)


def test_case_injection_is_preserved_after_binding(
    tmp_path,
    mock_http,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    result = cli.invoke(app, args_for(case), env=ENV)

    assert result.exit_code == 0

    assert [request.url.params["category"] for request in received] == [
        "Pets",
        "Petstrue-probe",
        "Petsfalse-probe",
        "Pets",
        "Petsfalse-probe",
        "Petstrue-probe",
    ]


def test_mismatched_allowed_origin_sends_nothing(
    tmp_path,
    mock_http,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    environment = {
        **ENV,
        "VINTAR_ALLOWED_ORIGIN": "http://example.com:8765",
    }

    result = cli.invoke(
        app,
        args_for(case),
        env=environment,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert received == []


@pytest.mark.parametrize(
    "missing",
    [
        "VINTAR_TARGET_ORIGIN",
        "VINTAR_ALLOWED_ORIGIN",
    ],
)
def test_missing_runtime_configuration_fails_closed(
    tmp_path,
    mock_http,
    missing,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    environment = {
        **ENV,
        missing: "",
    }

    result = cli.invoke(
        app,
        args_for(case),
        env=environment,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert received == []


@pytest.mark.parametrize(
    "invalid",
    [
        "https://user:password@example.com",
        "http://@example.com",
        "https://example.com/private",
        "https://example.com?x=1",
        "https://example.com#fragment",
        "file:///etc/passwd",
        "http://127.0.0.1:0",
        "http://example.com:",
        "http://example.com\\@evil.example",
        "http://example%2ecom",
        " http://127.0.0.1:8765 ",
    ],
)
@pytest.mark.parametrize(
    "variable",
    ["VINTAR_TARGET_ORIGIN", "VINTAR_ALLOWED_ORIGIN"],
)
def test_invalid_runtime_origin_rejected(
    tmp_path,
    mock_http,
    invalid,
    variable,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    result = cli.invoke(
        app,
        args_for(case),
        env={**ENV, variable: invalid},
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert received == []


@pytest.mark.parametrize("option", ["--target-origin", "--allow-origin"])
def test_cli_cannot_override_environment_origins(
    tmp_path,
    mock_http,
    option,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    result = cli.invoke(
        app,
        [*args_for(case), option, "http://attacker.invalid:9999"],
        env=ENV,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert len(received) == 0
    assert "attacker.invalid" not in result.stderr


@pytest.mark.parametrize(
    ("target_origin", "allowed_origin", "expected_host", "expected_port"),
    [
        ("http://[::1]:8765", "http://[::1]:8765", "::1", 8765),
        (
            "http://例え.テスト:8765",
            "http://xn--r8jz45g.xn--zckzah:8765",
            "例え.テスト",
            8765,
        ),
        ("http://example.com", "http://example.com:80", "example.com", 80),
    ],
    ids=("ipv6", "idn", "default-port"),
)
def test_runtime_origin_normalization(
    tmp_path,
    mock_http,
    target_origin,
    allowed_origin,
    expected_host,
    expected_port,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    result = cli.invoke(
        app,
        args_for(case),
        env={
            "VINTAR_TARGET_ORIGIN": target_origin,
            "VINTAR_ALLOWED_ORIGIN": allowed_origin,
        },
    )

    assert result.exit_code == 0
    assert len(received) == 6
    assert all(request.url.host == expected_host for request in received)
    assert all(
        (request.url.port or (443 if request.url.scheme == "https" else 80))
        == expected_port
        for request in received
    )


def test_binding_preserves_raw_percent_encoded_path(tmp_path, mock_http):
    case = write_case(tmp_path, path="/a%2Fb/%7Euser")
    received, _ = mock_http

    result = cli.invoke(app, args_for(case), env=ENV)

    assert result.exit_code == 0
    assert len(received) == 6
    assert all(
        request.url.raw_path.split(b"?", 1)[0] == b"/a%2Fb/%7Euser"
        for request in received
    )


def test_two_cases_share_budget_and_emit_one_json(
    tmp_path,
    mock_http,
):
    write_case(tmp_path, "a-case")
    write_case(tmp_path, "b-case")

    received, _ = mock_http

    result = cli.invoke(
        app,
        args_for(tmp_path, max_requests=12),
        env=ENV,
    )

    assert result.exit_code == 0

    report = json.loads(result.stdout)

    assert report["planned_case_ids"] == [
        "a-case",
        "b-case",
    ]
    assert report["requests_used"] == 12
    assert len(received) == 12

    # One compact JSON document, not one report per case.
    assert result.stdout.count("\n") == 1


def test_429_is_inconclusive(
    tmp_path,
    mock_http,
):
    case = write_case(
        tmp_path,
        expected="inconclusive",
    )

    received, statuses = mock_http
    statuses[0] = 429

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 3

    report = json.loads(result.stdout)

    assert report["status"] == "inconclusive"
    assert report["exit_code"] == 3
    assert len(received) == 1


def test_partial_batch_does_not_pass(
    tmp_path,
    mock_http,
):
    write_case(tmp_path, "a-case")
    write_case(tmp_path, "b-case")

    received, statuses = mock_http
    statuses[0] = 429

    result = cli.invoke(
        app,
        args_for(tmp_path, max_requests=12),
        env=ENV,
    )

    assert result.exit_code == 3

    report = json.loads(result.stdout)

    assert report["complete"] is False
    assert report["executed_case_ids"] == ["a-case"]
    assert report["not_run_case_ids"] == ["b-case"]
    assert len(received) == 1


def test_transport_failure_is_inconclusive_and_sanitized(tmp_path, mock_http):
    case = write_case(tmp_path)
    received, responses = mock_http
    responses[0] = httpx.ConnectError("SECRET_CONNECTION_DETAIL")

    result = cli.invoke(app, args_for(case), env=ENV)

    assert result.exit_code == 3
    assert len(received) == 1
    assert "SECRET_CONNECTION_DETAIL" not in result.stdout
    assert "SECRET_CONNECTION_DETAIL" not in result.stderr
    assert json.loads(result.stdout)["status"] == "inconclusive"


def test_expected_verdict_mismatch_is_failure(
    tmp_path,
    mock_http,
):
    case = write_case(
        tmp_path,
        expected="vulnerable",
    )

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 1

    report = json.loads(result.stdout)

    assert report["status"] == "fail"
    assert report["outcomes"][0]["expectation_match"] is False


def test_missing_authorization_blocks_execution(
    tmp_path,
    mock_http,
):
    case = write_case(tmp_path)
    received, _ = mock_http

    command = args_for(case)
    command.remove("--authorized")

    result = cli.invoke(app, command, env=ENV)

    assert result.exit_code == 2
    assert result.stdout == ""
    assert received == []


def test_insufficient_budget_blocks_all_requests(
    tmp_path,
    mock_http,
):
    write_case(tmp_path, "a-case")
    write_case(tmp_path, "b-case")

    received, _ = mock_http

    result = cli.invoke(
        app,
        args_for(tmp_path, max_requests=11),
        env=ENV,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "cannot cover every selected case" in result.stderr
    assert "Increase --max-requests" in result.stderr
    assert received == []


def test_case_source_is_not_modified(
    tmp_path,
    mock_http,
):
    case = write_case(tmp_path)
    original = case.read_bytes()

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 0
    assert case.read_bytes() == original


def test_sensitive_runtime_configuration_is_not_exported(
    tmp_path,
    mock_http,
):
    case = write_case(tmp_path)

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 0

    def assert_no_runtime_configuration(value: object) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                assert_no_runtime_configuration(key)
                assert_no_runtime_configuration(item)
        elif isinstance(value, list):
            for item in value:
                assert_no_runtime_configuration(item)
        elif isinstance(value, str):
            for marker in ("placeholder.invalid", "127.0.0.1", ":8765"):
                assert marker not in value
        elif type(value) is int:
            assert value != 8765

    assert_no_runtime_configuration(json.loads(result.stdout))


def test_invalid_toml_does_not_leak_content(
    tmp_path,
    mock_http,
):
    case = tmp_path / "bad.toml"
    secret = "SECRET_NEVER_EXPORT"
    case.write_text(
        f'invalid = "{secret}"',
        encoding="utf-8",
    )

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert secret not in result.stderr


def test_symlinked_case_rejected(
    tmp_path,
    mock_http,
):
    actual = write_case(tmp_path / "real")
    link = tmp_path / "linked.toml"

    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable.")

    result = cli.invoke(
        app,
        args_for(link),
        env=ENV,
    )

    assert result.exit_code == 2
    assert result.stdout == ""


def test_duplicate_ids_rejected(
    tmp_path,
    mock_http,
):
    first = write_case(tmp_path, "same")
    (tmp_path / "duplicate.toml").write_bytes(first.read_bytes())

    received, _ = mock_http

    result = cli.invoke(
        app,
        args_for(tmp_path, max_requests=12),
        env=ENV,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert received == []


def test_serialization_failure_is_sanitized(
    tmp_path,
    mock_http,
    monkeypatch,
):
    case = write_case(tmp_path)

    def fail(*args, **kwargs):
        raise ValueError("SECRET_INTERNAL_DETAIL")

    monkeypatch.setattr(
        regression_cli,
        "regression_batch_report_json",
        fail,
    )

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "SECRET_INTERNAL_DETAIL" not in result.stderr


def test_broken_pipe_is_sanitized(
    tmp_path,
    mock_http,
    monkeypatch,
):
    case = write_case(tmp_path)

    def fail_output(payload):
        raise BrokenPipeError("SECRET_OUTPUT_DETAIL")

    monkeypatch.setattr(
        regression_cli,
        "_emit_json",
        fail_output,
    )

    result = cli.invoke(
        app,
        args_for(case),
        env=ENV,
    )

    assert result.exit_code == 2
    assert "SECRET_OUTPUT_DETAIL" not in result.stderr


def test_unicode_output_failure_is_sanitized(
    tmp_path,
    mock_http,
    monkeypatch,
):
    case = write_case(tmp_path)

    def fail_output(payload):
        raise UnicodeError("SECRET_UNICODE_DETAIL")

    monkeypatch.setattr(regression_cli, "_emit_json", fail_output)

    result = cli.invoke(app, args_for(case), env=ENV)

    assert result.exit_code == 2
    assert "SECRET_UNICODE_DETAIL" not in result.stderr


def test_keyboard_interrupt_returns_130_without_report(
    tmp_path,
    mock_http,
    monkeypatch,
):
    case = write_case(tmp_path)

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(regression_cli, "run_regression_batch", interrupt)

    result = cli.invoke(app, args_for(case), env=ENV)

    assert result.exit_code == 130
    assert result.stdout == ""
    assert result.stderr == "Error: regression verification was cancelled.\n"


def test_pretty_output(
    tmp_path,
    mock_http,
):
    case = write_case(tmp_path)

    result = cli.invoke(
        app,
        [*args_for(case), "--pretty"],
        env=ENV,
    )

    assert result.exit_code == 0
    assert "\n  " in result.stdout
    assert json.loads(result.stdout)["status"] == "pass"


def test_verify_uses_real_local_http_transport(tmp_path):
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "4")
            self.end_headers()
            self.wfile.write(b"same")

        def log_message(self, format, *args):
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        pytest.skip("Local sockets are unavailable in this environment.")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        case = write_case(tmp_path)
        case.write_text(
            case.read_text(encoding="utf-8").replace(
                "requests_per_second = 2.0",
                "requests_per_second = 10.0",
            ),
            encoding="utf-8",
        )
        origin = f"http://127.0.0.1:{server.server_port}"

        result = cli.invoke(
            app,
            [*args_for(case), "--rps", "10"],
            env={
                "VINTAR_TARGET_ORIGIN": origin,
                "VINTAR_ALLOWED_ORIGIN": origin,
            },
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result.exit_code == 0
    assert result.stderr == ""
    assert json.loads(result.stdout)["requests_used"] == 6
    assert len(requests) == 6
    assert all(path.startswith("/products?category=") for path in requests)
