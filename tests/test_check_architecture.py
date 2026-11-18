"""Tests for the source-level HTTP architecture checks."""

import runpy
from pathlib import Path

import pytest

check_source = runpy.run_path("scripts/check_architecture.py")["check_source"]


@pytest.mark.parametrize(
    ("source", "api"),
    [
        ("import httpx\nhttpx.Client()", "httpx.Client"),
        ("import httpx as hx; hx.Client()", "httpx.Client"),
        ("import httpx as http\nhttp.AsyncClient()", "httpx.AsyncClient"),
        ("from httpx import AsyncClient as AC; AC()", "httpx.AsyncClient"),
        ("from httpx import request as send\nsend()", "httpx.request"),
        ("import httpx\nhttpx.get()", "httpx.get"),
        ("from httpx import get; get('http://localhost/')", "httpx.get"),
        (
            "from vintar.core.template import send_template as st",
            "vintar.core.template.send_template",
        ),
        (
            "from vintar.core.template import send_template as send\nsend()",
            "vintar.core.template.send_template",
        ),
        (
            "from ...core import template as templates\nsend = templates.send_template",
            "vintar.core.template.send_template",
        ),
    ],
)
def test_rejects_unscoped_http_api(source, api):
    [diagnostic] = check_source(Path("checks/sqli/example.py"), source)

    assert api in diagnostic
    assert "scope, request budgets, and rate limits" in diagnostic
    assert "vintar.core.executor.ExecutionContext" in diagnostic


@pytest.mark.parametrize("path", ["core/http.py", "core/executor.py"])
def test_allows_http_calls_in_shared_http_files(path):
    assert not check_source(Path(path), "import httpx\nhttpx.Client()\nhttpx.post()")


def test_allows_http_types_and_template_validation_in_checks():
    source = """
import httpx
from vintar.core.template import validate_template

def check(client: httpx.Client, other: httpx.AsyncClient):
    validate_template()
    try:
        httpx.URL("http://localhost/")
    except httpx.HTTPError:
        raise
"""
    assert not check_source(Path("checks/example.py"), source)
