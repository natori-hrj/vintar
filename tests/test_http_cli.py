import httpx
import pytest
from typer.testing import CliRunner

from vintar import cli
from vintar.core.models import HttpResult

URL = "https://example.invalid/items"


@pytest.mark.parametrize(
    ("method", "options", "diagnostic"),
    [
        ("PUT", [], "Only GET and POST are supported."),
        ("GET", ["-H", "missing-colon"], "Invalid header: missing-colon"),
        ("GET", ["-H", ": value"], "Header name cannot be empty."),
        ("GET", ["-C", "missing-equals"], "Invalid cookies: missing-equals"),
        ("GET", ["-C", "=value"], "Cookie name cannot be empty."),
        ("GET", ["-p", "missing-equals"], "Invalid parameter: missing-equals"),
        ("GET", ["-p", "=value"], "Parameter name cannot be empty."),
    ],
)
def test_http_send_rejects_invalid_arguments(monkeypatch, method, options, diagnostic):
    calls = []
    monkeypatch.setattr(cli, "send_request", lambda **kwargs: calls.append(kwargs))

    result = CliRunner().invoke(cli.app, ["http", "send", method, URL, *options])

    assert result.exit_code == 1
    assert diagnostic in result.output
    assert calls == []


def test_http_send_normalizes_options_and_reports_response(monkeypatch):
    calls = []

    def send(**kwargs):
        calls.append(kwargs)
        return HttpResult(status_code=201, elapsed=0.125, body=b"example", headers={})

    monkeypatch.setattr(cli, "send_request", send)
    result = CliRunner().invoke(
        cli.app,
        [
            "http",
            "send",
            "post",
            URL,
            "--body",
            "example",
            "-H",
            " X-Example : sample ",
            "-C",
            " theme=plain",
            "-p",
            "tag=one",
            "-p",
            "tag=two",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "method": "POST",
            "url": URL,
            "body": "example",
            "headers": {"X-Example": "sample"},
            "cookies": {"theme": "plain"},
            "params": [("tag", "one"), ("tag", "two")],
            "timeout": 10.0,
        }
    ]
    assert f"Target: {URL}" in result.output
    assert "Method: POST" in result.output
    assert "Status: 201" in result.output
    assert "Response time: 0.125s" in result.output
    assert "Content size: 7 bytes" in result.output


def test_http_send_reports_transport_failure(monkeypatch):
    def send(**kwargs):
        raise httpx.ConnectError("synthetic connection failure")

    monkeypatch.setattr(cli, "send_request", send)
    result = CliRunner().invoke(cli.app, ["http", "send", "GET", URL])

    assert result.exit_code == 1
    assert "Request failed: synthetic connection failure" in result.output
