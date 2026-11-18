"""Check installed-wheel smoke contracts without installing any packages."""

import runpy
import subprocess
import sys
from pathlib import Path

import pytest

_SCRIPT = runpy.run_path("scripts/check_distributions.py")
smoke_wheel = _SCRIPT["smoke_wheel"]
_RUN_PROCESS = subprocess.run

AUTHORIZATION_ERROR = "Error: explicit testing authorization is required.\n"


@pytest.fixture
def smoke_processes(monkeypatch, tmp_path):
    responses = [
        (0, "", ""),
        (0, "", ""),
        (0, "", ""),
        (0, "0.1.0\n", ""),
        (0, "Vintar v0.1.0\n", ""),
        (0, "--cases --authorized\n", ""),
        (2, "", AUTHORIZATION_ERROR),
    ]
    commands = []
    for name in (
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "VINTAR_TARGET_ORIGIN",
        "VINTAR_ALLOWED_ORIGIN",
    ):
        monkeypatch.setenv(name, "ambient-value")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("FORCE_COLOR", "1")
    monkeypatch.setenv("COLUMNS", "24")

    def execute(command, *, cwd, env, **kwargs):
        assert cwd == tmp_path
        assert "PYTHONPATH" not in env
        assert "PYTHONHOME" not in env
        assert "VIRTUAL_ENV" not in env
        assert "VINTAR_TARGET_ORIGIN" not in env
        assert "VINTAR_ALLOWED_ORIGIN" not in env
        assert env["NO_COLOR"] == "1"
        if len(commands) >= 3:
            assert env == {
                "NO_COLOR": "1",
                "TERM": "dumb",
                "COLUMNS": "100",
                "PYTHONIOENCODING": "utf-8",
            }
        code, stdout, stderr = responses[len(commands)]
        commands.append(command)
        return subprocess.CompletedProcess(command, code, stdout, stderr)

    monkeypatch.setattr(subprocess, "run", execute)
    return responses, commands


def test_smoke_wheel_runs_installed_commands_in_order(tmp_path, smoke_processes):
    _, commands = smoke_processes
    wheel = tmp_path / "vintar-0.1.0-py3-none-any.whl"
    venv = tmp_path / "wheel-venv"
    python = str(venv / "bin" / "python")
    cli = str(venv / "bin" / "vintar")

    assert smoke_wheel(wheel, tmp_path) == venv

    assert commands[:3] == [
        ["uv", "venv", "--python", "cpython@3.13", str(venv)],
        ["uv", "pip", "install", "--python", python, str(wheel)],
        ["uv", "pip", "check", "--python", python],
    ]
    assert commands[3][:3] == [python, "-I", "-c"]
    assert "importlib.metadata" in commands[3][3]
    assert commands[4:] == [
        [cli, "version"],
        [cli, "verify", "--help"],
        [cli, "verify", "--cases", "case.toml"],
    ]


def test_smoke_wheel_checks_real_help_under_runner_environment(
    monkeypatch, tmp_path, smoke_processes
):
    mock_run = subprocess.run

    def execute(command, **kwargs):
        result = mock_run(command, **kwargs)
        if command[-2:] == ["verify", "--help"]:
            return _RUN_PROCESS(
                [sys.executable, "-m", "vintar.cli", "verify", "--help"], **kwargs
            )
        return result

    monkeypatch.setattr(subprocess, "run", execute)
    smoke_wheel(tmp_path / "fixture.whl", tmp_path)


@pytest.mark.parametrize("exit_code", [0, 1])
def test_smoke_wheel_help_failure_includes_bounded_output(
    tmp_path, smoke_processes, exit_code
):
    responses, _ = smoke_processes
    responses[5] = (exit_code, "outside excerpt" + "x" * 2100 + "visible help tail", "")

    with pytest.raises(ValueError, match="Captured help stdout") as caught:
        smoke_wheel(tmp_path / "fixture.whl", tmp_path)

    assert "visible help tail" in str(caught.value)
    assert "outside excerpt" not in str(caught.value)


@pytest.mark.parametrize(
    ("step", "response", "reason", "remediation"),
    [
        (0, (1, "", "missing interpreter"), "Could not create", "Install Python 3.13"),
        (
            1,
            (1, "", "install error"),
            "wheel could not be installed",
            "Fix its package metadata",
        ),
        (
            2,
            (1, "", "conflict"),
            "dependencies are inconsistent",
            "Fix the runtime dependency declarations",
        ),
        (
            3,
            (1, "", "missing metadata"),
            "Could not read the installed version",
            "includes vintar distribution metadata",
        ),
        (
            4,
            (0, "Vintar v0.2.0\n", ""),
            "CLI version differs",
            "Read the version from importlib.metadata",
        ),
        (
            5,
            (0, "--cases\n", ""),
            "help is missing",
            "Restore --cases and --authorized",
        ),
        (
            6,
            (0, "", ""),
            "wrong status without authorization",
            "Reject before verification with exit 2",
        ),
        (
            6,
            (2, "unexpected stdout", AUTHORIZATION_ERROR),
            "Unexpected output without authorization",
            "diagnostic on stderr",
        ),
        (
            6,
            (2, "", "wrong error\n"),
            "Unexpected output without authorization",
            "diagnostic on stderr",
        ),
    ],
    ids=[
        "venv",
        "install",
        "dependencies",
        "metadata",
        "version",
        "help",
        "exit",
        "stdout",
        "stderr",
    ],
)
def test_smoke_wheel_failures_explain_the_fix(
    tmp_path, smoke_processes, step, response, reason, remediation
):
    responses, commands = smoke_processes
    responses[step] = response

    with pytest.raises(ValueError, match=reason) as caught:
        smoke_wheel(tmp_path / "fixture.whl", tmp_path)

    assert remediation in str(caught.value)
    assert len(commands) == step + 1


def test_smoke_wheel_rejects_a_directory_inside_the_checkout(smoke_processes):
    _, commands = smoke_processes
    root = Path(_SCRIPT["ROOT"])

    with pytest.raises(
        ValueError, match="Set TMPDIR to a location outside the repository"
    ):
        smoke_wheel(root / "fixture.whl", root)

    assert commands == []
