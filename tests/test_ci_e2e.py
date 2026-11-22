"""Tests for the local CI E2E fixture."""

import json
import os
import re
import runpy
import socket
import stat
from pathlib import Path

import pytest

from vintar.regression.cases import load_regression_case

_E2E = runpy.run_path("scripts/run_ci_e2e.py")
_cli_environment = _E2E["_cli_environment"]
_write_case = _E2E["_write_case"]
run_e2e = _E2E["run_e2e"]

_E2E_ACTIONS = {
    "actions/checkout",
    "actions/upload-artifact",
    "astral-sh/setup-uv",
}


def _assert_action_policy(workflow: str, allowed_actions: set[str]) -> None:
    """Require reviewed action names and immutable commit references."""
    uses_values = re.findall(r"uses:\s+([^\s#]+)", workflow)
    action_names: set[str] = set()
    for uses_value in uses_values:
        action, separator, reference = uses_value.rpartition("@")
        assert separator and action in allowed_actions, (
            f"uses: {uses_value} uses action {action or uses_value!r} outside the allowed "
            "set; add the action to the allowed set deliberately after review"
        )
        assert re.fullmatch(r"[0-9a-f]{40}", reference), (
            f"uses: {uses_value} is not pinned to a full 40-character lowercase "
            "commit SHA; pin the action to a commit SHA instead of a tag or branch"
        )
        action_names.add(action)
    assert action_names == allowed_actions, (
        f"workflow actions {sorted(action_names)!r} differ from the deliberately allowed "
        f"set {sorted(allowed_actions)!r}; add or remove an allowed action deliberately"
    )


def test_fixture_case_is_valid(tmp_path):
    case_path = _write_case(
        tmp_path,
        expected="not_detected",
        path="/ok",
    )

    case = load_regression_case(case_path)

    assert case.case_id == "fixture-case"
    assert case.expected_verdict.value == "not_detected"
    assert case.template.url.endswith("/ok")
    assert case.max_requests == 6


def test_fixture_reuses_schema_v1(tmp_path):
    case_path = _write_case(
        tmp_path,
        expected="vulnerable",
        path="/ok",
    )

    case = load_regression_case(case_path)

    assert case.schema_version == 1
    assert case.expected_verdict.value == "vulnerable"


def test_cli_environment_does_not_inherit_ambient_values(monkeypatch):
    monkeypatch.setenv("TOP_SECRET", "must-not-reach-child")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid")
    monkeypatch.setenv("VINTAR_TARGET_ORIGIN", "https://production.invalid")
    monkeypatch.setenv("COVERAGE_PROCESS_CONFIG", "coverage-configuration")

    env = _cli_environment("http://127.0.0.1:12345")

    assert env["VINTAR_TARGET_ORIGIN"] == "http://127.0.0.1:12345"
    assert env["VINTAR_ALLOWED_ORIGIN"] == "http://127.0.0.1:12345"
    assert env["COVERAGE_PROCESS_CONFIG"] == "coverage-configuration"
    assert "TOP_SECRET" not in env
    assert "HTTP_PROXY" not in env
    assert "PYTHONPATH" not in env


def test_full_loopback_e2e(tmp_path):
    # Some CI sandboxes prohibit binding sockets, even on loopback.
    try:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
    except OSError:
        pytest.skip("Loopback socket is unavailable.")

    report_dir = tmp_path / "reports"
    run_e2e(report_dir)

    assert sorted(path.name for path in report_dir.glob("*.json")) == [
        "fail.json",
        "inconclusive.json",
        "pass.json",
    ]

    reports = {
        path.stem: json.loads(path.read_text(encoding="utf-8"))
        for path in report_dir.glob("*.json")
    }
    assert reports["pass"]["exit_code"] == 0
    assert reports["pass"]["requests_used"] == 6
    assert reports["fail"]["exit_code"] == 1
    assert reports["fail"]["requests_used"] == 6
    assert reports["inconclusive"]["exit_code"] == 3
    assert reports["inconclusive"]["requests_used"] == 1

    if os.name != "nt":
        assert stat.S_IMODE(report_dir.stat().st_mode) == 0o700
        assert all(
            stat.S_IMODE(path.stat().st_mode) == 0o600
            for path in report_dir.glob("*.json")
        )


def test_e2e_workflow_is_manual_loopback_only():
    workflow = Path(".github/workflows/vintar-e2e.yml").read_text(encoding="utf-8")
    _assert_action_policy(workflow, _E2E_ACTIONS)
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "pull_request_target" not in workflow
    assert "workflow_run" not in workflow
    assert "environment:" not in workflow
    assert "secrets." not in workflow
    assert "vars." not in workflow
    assert "VINTAR_TARGET_ORIGIN" not in workflow
    assert "VINTAR_ALLOWED_ORIGIN" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "ubuntu-latest" not in workflow
    assert workflow.count("runs-on: ubuntu-24.04") == 2
    assert "refs/heads/main" in workflow
    assert "scripts.run_ci_e2e" in workflow
    assert "retention-days: 1" in workflow


@pytest.mark.parametrize(
    ("broken_use", "message"),
    [
        (
            "actions/checkout@v4",
            r"uses: actions/checkout@v4.*full 40-character lowercase commit SHA.*pin the action to a commit SHA",
        ),
        (
            "actions/checkout@0123456789abcdef",
            r"uses: actions/checkout@0123456789abcdef.*full 40-character lowercase commit SHA.*pin the action to a commit SHA",
        ),
        (
            "unreviewed/example@" + "a" * 40,
            r"uses: unreviewed/example@a+.*outside the allowed set.*add the action to the allowed set deliberately",
        ),
    ],
)
def test_action_policy_rejects_mutable_or_unreviewed_uses(broken_use, message):
    workflow = f"""
jobs:
  test:
    steps:
      - uses: {broken_use}
      - uses: astral-sh/setup-uv@{"b" * 40}
"""

    with pytest.raises(AssertionError, match=message):
        _assert_action_policy(
            workflow,
            {"actions/checkout", "astral-sh/setup-uv"},
        )


def test_installed_loopback_uses_console_executable_outside_checkout(
    monkeypatch, tmp_path
):
    executable = tmp_path / "venv/bin/vintar"
    cases = tmp_path / "cases"
    case = cases / "case.toml"

    def run(args, **kwargs):
        assert args[:4] == [str(executable), "verify", "--cases", str(case)]
        assert kwargs["cwd"] == cases
        return "installed executable result"

    monkeypatch.setattr("subprocess.run", run)
    assert (
        _E2E["_run_cli"](case, origin="http://127.0.0.1:12345", executable=executable)
        == "installed executable result"
    )
