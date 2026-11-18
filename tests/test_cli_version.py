"""Test that the CLI displays the installed distribution version."""

from importlib import metadata

from typer.testing import CliRunner

from vintar.cli import app


def test_cli_version_matches_installed_metadata():
    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout == f"Vintar v{metadata.version('vintar')}\n"


def test_cli_version_reads_metadata_at_runtime(monkeypatch):
    def installed_version(name):
        assert name == "vintar"
        return "9.8.7"

    monkeypatch.setattr(metadata, "version", installed_version)

    result = CliRunner().invoke(app, ["version"])

    assert result.exit_code == 0
    assert result.stdout == "Vintar v9.8.7\n"
