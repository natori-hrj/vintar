"""POST JSON inventory CLI output and privacy contracts."""

import json
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vintar.cli import app


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("POST JSON inventory attempted network access")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)


def private_spec(sentinel: str) -> dict:
    return {
        "openapi": "3.1.2",
        "info": {"title": sentinel, "version": "1"},
        "servers": [{"url": sentinel}],
        "security": [{"key": []}],
        "paths": {
            "/items": {
                "post": {
                    "operationId": "createItem",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "example": sentinel,
                                    "default": sentinel,
                                    "enum": [sentinel],
                                    "const": sentinel,
                                    "externalValue": sentinel,
                                    "description": sentinel,
                                    "x-private": sentinel,
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        }
                    },
                }
            }
        },
        "components": {
            "securitySchemes": {
                "key": {"type": "apiKey", "in": "header", "name": sentinel}
            }
        },
    }


def test_cli_is_private_deterministic_and_atomic(tmp_path, monkeypatch):
    sentinel = "PRIVATE-SENTINEL-VALUE"
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps(private_spec(sentinel)), encoding="utf-8")
    output = tmp_path / "report.json"
    args = ["inventory-post-json", "--spec", str(spec), "--output", str(output)]
    first = CliRunner().invoke(app, args)
    assert first.exit_code == 0 and first.stderr == ""
    first_bytes = output.read_bytes()
    second = CliRunner().invoke(app, args)
    assert second.exit_code == 0 and output.read_bytes() == first_bytes
    assert first.stdout == second.stdout
    assert sentinel not in first.stdout + first.stderr
    assert sentinel.encode() not in first_bytes
    assert first.stdout == (
        "POST JSON inventory: 1 operations; 0 case-generatable; "
        "1 fields; 0 injectable; 0 diagnostics.\n"
    )

    original_replace = __import__(
        "vintar.post_json_inventory_cli", fromlist=["os"]
    ).os.replace

    def fail_replace(source, destination):
        assert Path(destination) == output
        raise OSError("PRIVATE-SENTINEL-VALUE")

    monkeypatch.setattr("vintar.post_json_inventory_cli.os.replace", fail_replace)
    failed = CliRunner().invoke(app, args)
    assert failed.exit_code == 2 and failed.stdout == ""
    assert sentinel not in failed.stderr
    assert output.read_bytes() == first_bytes
    monkeypatch.setattr("vintar.post_json_inventory_cli.os.replace", original_replace)
    assert not list(tmp_path.glob("tmp*"))


def test_interrupt_has_no_stdout_or_report(tmp_path, monkeypatch):
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps({"openapi": "3.1.2", "paths": {}}), encoding="utf-8")
    output = tmp_path / "report.json"
    monkeypatch.setattr(
        "vintar.post_json_inventory_cli.analyze_post_json",
        lambda path: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    result = CliRunner().invoke(
        app,
        ["inventory-post-json", "--spec", str(spec), "--output", str(output)],
    )
    assert result.exit_code == 130
    assert result.stdout == "" and "interrupted" in result.stderr
    assert not output.exists()
