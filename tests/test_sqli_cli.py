import json

import httpx
import pytest
from typer.testing import CliRunner

from vintar import sqli_cli
from vintar.checks.sqli.models import (
    Observation,
    ProbeError,
    ProbeFailure,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.cli import app
from vintar.core import executor
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import InjectionMode

runner = CliRunner()

BASE_ARGS = [
    "sqli",
    "verify",
    "--url",
    "http://localhost:8000/items",
    "--allow-origin",
    "http://localhost:8000",
    "--param",
    "id=1",
    "--inject-param",
    "id",
    "--true-payload",
    "true-probe",
    "--false-payload",
    "false-probe",
]


def mock_result() -> VerificationResult:
    return VerificationResult(
        check_id="cli-sqli",
        verdict=Verdict.INCONCLUSIVE,
        observations=(),
        request_count=0,
        reason_code="budget_unavailable",
        reason="No request budget available.",
    )


def test_missing_authorization_blocks_execution(monkeypatch):
    calls = []

    def fake_verify(**kwargs):
        calls.append(kwargs)
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    result = runner.invoke(app, BASE_ARGS)

    assert result.exit_code == 2
    assert calls == []
    assert result.stdout == ""
    assert "authorization" in result.stderr.lower()


def test_successful_command_prints_json(monkeypatch):
    calls = []

    def fake_verify(**kwargs):
        calls.append(kwargs)
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    result = runner.invoke(app, [*BASE_ARGS, "--authorized"])

    assert result.exit_code == 0
    assert len(calls) == 1

    report = json.loads(result.stdout)

    assert report["schema_version"] == 1
    assert report["verdict"] == "inconclusive"
    assert report["reason_code"] == "budget_unavailable"
    assert result.stderr == ""


def test_sqli_verify_enum_json_and_exit_code_are_contract(monkeypatch):
    verification = VerificationResult(
        check_id="cli-sqli",
        verdict=Verdict.INCONCLUSIVE,
        observations=(
            Observation(
                kind=ProbeKind.BASELINE,
                status_code=200,
                body_size=1,
                elapsed=0.0,
                body_digest="a" * 64,
            ),
        ),
        failures=(ProbeFailure(kind=ProbeKind.TRUE, error=ProbeError.TIMEOUT),),
        request_count=2,
        reason_code="probe_failed",
        reason="A probe timed out.",
    )
    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", lambda **kwargs: verification)

    result = runner.invoke(app, [*BASE_ARGS, "--authorized"])

    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["verdict"] == "inconclusive"
    assert [item["kind"] for item in report["observations"]] == ["baseline"]
    assert report["failures"] == [
        {"kind": "true", "error": "timeout", "elapsed": None},
    ]


def test_context_has_required_limits(monkeypatch):
    contexts = []

    def fake_verify(**kwargs):
        contexts.append(kwargs["context"])
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    result = runner.invoke(app, [*BASE_ARGS, "--authorized"])

    assert result.exit_code == 0
    assert contexts[0].budget.max_requests == 6
    assert contexts[0].rate_limiter.requests_per_second == 2.0
    assert contexts[0].timeout == 10.0


def test_out_of_scope_target_is_rejected(monkeypatch):
    calls = []

    def fake_verify(**kwargs):
        calls.append(kwargs)
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    args = BASE_ARGS.copy()
    args[3] = "http://example.com/items"

    result = runner.invoke(app, [*args, "--authorized"])

    assert result.exit_code == 2
    assert calls == []
    assert result.stdout == ""


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost:8000/secret",
        "http://user:pass@localhost:8000",
        "file:///tmp/test",
        "http://localhost:8000/?x=1",
    ],
)
def test_invalid_origin_is_rejected(origin, monkeypatch):
    calls = []

    def fake_verify(**kwargs):
        calls.append(kwargs)
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    args = BASE_ARGS.copy()
    args[5] = origin

    result = runner.invoke(app, [*args, "--authorized"])

    assert result.exit_code == 2
    assert calls == []
    assert result.stdout == ""


def test_invalid_query_parameter_is_rejected(monkeypatch):
    calls = []

    def fake_verify(**kwargs):
        calls.append(kwargs)
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    args = BASE_ARGS.copy()
    args[7] = "missing-equals"

    result = runner.invoke(app, [*args, "--authorized"])

    assert result.exit_code == 2
    assert calls == []


def test_pretty_output_is_valid_json(monkeypatch):
    monkeypatch.setattr(
        sqli_cli,
        "verify_boolean_sqli",
        lambda **kwargs: mock_result(),
    )

    result = runner.invoke(
        app,
        [*BASE_ARGS, "--authorized", "--pretty"],
    )

    assert result.exit_code == 0
    assert json.loads(result.stdout)["schema_version"] == 1
    assert "\n  " in result.stdout


def test_internal_validation_does_not_leak_secrets(monkeypatch):
    def fake_verify(**kwargs):
        raise ValueError("secret-payload-123")

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    result = runner.invoke(app, [*BASE_ARGS, "--authorized"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "secret-payload-123" not in result.stderr


def test_unexpected_exception_does_not_leak_secrets(monkeypatch):
    def fake_verify(**kwargs):
        raise RuntimeError("secret-url-and-payload-123")

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    result = runner.invoke(app, [*BASE_ARGS, "--authorized"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert "secret-url-and-payload-123" not in result.stderr
    assert "Traceback" not in result.stderr


def test_keyboard_interrupt_is_safely_reported(monkeypatch):
    def fake_verify(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    result = runner.invoke(app, [*BASE_ARGS, "--authorized"])

    assert result.exit_code == 130
    assert result.stdout == ""
    assert "cancelled" in result.stderr.lower()
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    ("url", "origin"),
    [
        ("http://localhost/items", "http://localhost:80"),
        ("https://localhost:443/items", "https://localhost"),
        ("http://[::1]:80/items", "http://[::1]"),
        ("http://例え.テスト/items", "http://例え.テスト"),
    ],
)
def test_equivalent_origins_are_normalized(url, origin, monkeypatch):
    monkeypatch.setattr(
        sqli_cli,
        "verify_boolean_sqli",
        lambda **kwargs: mock_result(),
    )
    args = BASE_ARGS.copy()
    args[3] = url
    args[5] = origin

    result = runner.invoke(app, [*args, "--authorized"])

    assert result.exit_code == 0


def test_explicit_zero_port_is_rejected_before_verification(monkeypatch):
    calls = []

    def fake_verify(**kwargs):
        calls.append(kwargs)
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)
    args = BASE_ARGS.copy()
    args[5] = "http://localhost:0"

    result = runner.invoke(app, [*args, "--authorized"])

    assert result.exit_code == 2
    assert calls == []
    assert result.stdout == ""


def test_duplicate_parameter_occurrence_and_append_are_preserved(monkeypatch):
    calls = []

    def fake_verify(**kwargs):
        calls.append(kwargs)
        return mock_result()

    monkeypatch.setattr(sqli_cli, "verify_boolean_sqli", fake_verify)

    result = runner.invoke(
        app,
        [
            *BASE_ARGS,
            "--param",
            "id=2",
            "--param",
            "greeting=こんにちは",
            "--occurrence",
            "1",
            "--append",
            "--authorized",
        ],
    )

    assert result.exit_code == 0
    assert calls[0]["template"].params == (
        ("id", "1"),
        ("id", "2"),
        ("greeting", "こんにちは"),
    )
    assert calls[0]["point"].occurrence == 1
    assert calls[0]["point"].mode is InjectionMode.APPEND


@pytest.mark.parametrize(
    "extra_args",
    [
        ["--occurrence", "1"],
        ["--false-payload", "true-probe"],
    ],
)
def test_invalid_probe_plan_is_rejected_before_execution(extra_args, monkeypatch):
    calls = []

    def fake_execute(self, template, *, transport=None):
        calls.append((template, transport))
        raise AssertionError("HTTP execution must not be reached")

    monkeypatch.setattr(executor.ExecutionContext, "execute", fake_execute)

    result = runner.invoke(app, BASE_ARGS + extra_args + ["--authorized"])

    assert result.exit_code == 2
    assert calls == []
    assert result.stdout == ""


def test_cli_runs_six_probes_through_execution_context(monkeypatch):
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        value = request.url.params["id"]
        body = b"baseline" if value in {"1", "true-probe"} else b"false"
        return httpx.Response(200, content=body)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(executor.httpx, "HTTPTransport", lambda **kwargs: transport)

    now = [0.0]

    def sleep(delay: float) -> None:
        now[0] += delay

    monkeypatch.setattr(
        sqli_cli,
        "RateLimiter",
        lambda *, requests_per_second: RateLimiter(
            requests_per_second=requests_per_second,
            _clock=lambda: now[0],
            _sleep=sleep,
        ),
    )

    result = runner.invoke(app, [*BASE_ARGS, "--authorized"])

    assert result.exit_code == 0
    assert len(requests) == 6
    assert [request.url.params["id"] for request in requests] == [
        "1",
        "true-probe",
        "false-probe",
        "1",
        "false-probe",
        "true-probe",
    ]
    assert json.loads(result.stdout)["reason_code"] == "boolean_candidate"
    assert result.stderr == ""
