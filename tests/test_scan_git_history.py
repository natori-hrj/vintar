"""Exercise the pinned secret scanner against temporary Git histories."""

import secrets
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scan_git_history.py"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        [
            "git",
            "-c",
            "user.name=Fixture Author",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgSign=false",
            "-c",
            "core.hooksPath=/dev/null",
            *args,
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def commit(repo: Path, name: str, content: str) -> str:
    (repo / "fixture.txt").write_text(content + "\n", encoding="utf-8")
    git(repo, "add", "fixture.txt")
    git(repo, "commit", "-qm", name)
    return git(repo, "rev-parse", "HEAD")


def scan(repo: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture
def repository(tmp_path, monkeypatch):
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    git(tmp_path, "init", "-q", "--template=")
    return tmp_path


def test_clean_history_passes(repository):
    commit(repository, "Add clean fixture", "Ordinary fixture text")
    result = scan(repository)

    assert result.returncode == 0, result.stderr
    assert "found no secrets in Git history" in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize(
    "remove_later", [False, True], ids=["current", "removed-later"]
)
def test_synthetic_match_fails_without_disclosing_value(repository, remove_later):
    token = "_".join(("ghp", secrets.token_hex(18)))
    affected_commit = commit(repository, "Add synthetic fixture", token)
    if remove_later:
        commit(repository, "Remove synthetic fixture", "Ordinary fixture text")

    result = scan(repository)
    output = result.stdout + result.stderr
    if token in output:
        pytest.fail("The secret scanner disclosed the generated fixture value.")

    assert result.returncode == 42, output
    assert "Commit rejected because Gitleaks detected a possible secret." in output
    assert "Revoke or rotate" in output
    assert "environment variable" in output
    assert affected_commit in output
    assert "fixture.txt" in output
