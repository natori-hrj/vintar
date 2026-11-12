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

    env = _cli_environment("http://127.0.0.1:12345")

    assert env["VINTAR_TARGET_ORIGIN"] == "http://127.0.0.1:12345"
    assert env["VINTAR_ALLOWED_ORIGIN"] == "http://127.0.0.1:12345"
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
    actions = set(re.findall(r"uses:\s+([^\s#]+)", workflow))
    action_refs = re.findall(r"uses:\s+[^@\s]+@([^\s#]+)", workflow)

    assert actions == {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
        "astral-sh/setup-uv@68559e99cc807c1eb7e9238fd43a15bba460eec2",
    }
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
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
