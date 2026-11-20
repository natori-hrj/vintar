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


@pytest.mark.parametrize(
    "source",
    [
        "import httpx as hx",
        "import urllib.request",
        "from socket import socket",
        "from vintar.core.executor import ExecutionContext",
        "from vintar.regression import run_regression_batch",
        "from .runner import run_regression_case",
        "import requests",
    ],
)
def test_discovery_cannot_import_http_or_execution(source):
    [diagnostic] = check_source(Path("regression/discovery.py"), source)
    assert "must remain offline" in diagnostic
    assert "Use the local parser" in diagnostic


def test_discovery_can_import_pure_url_parsing():
    assert not check_source(
        Path("regression/discovery.py"), "from urllib.parse import unquote"
    )


def test_discover_cli_imports_inventory_but_not_execution():
    path = Path("discover_cli.py")
    assert not check_source(
        path, "from vintar.regression.discovery import load_inventory"
    )
    for module in ("httpx", "vintar.core.executor", "vintar.regression.runner"):
        [diagnostic] = check_source(path, f"import {module}")
        assert "Discovery must remain offline" in diagnostic


def test_draft_serializer_stays_offline():
    path = Path("regression/discovery_drafts.py")
    assert not check_source(path, "from vintar.regression.discovery import Inventory")
    for module in ("httpx", "vintar.regression.runner", "vintar.regression.cases"):
        [diagnostic] = check_source(path, f"import {module}")
        assert "Discovery must remain offline" in diagnostic


@pytest.mark.parametrize(
    "path", ["review_draft_cli.py", "regression/discovery_review.py"]
)
def test_review_draft_imports_stay_offline(path):
    for module in ("httpx", "vintar.regression.runner", "vintar.regression.cases"):
        [diagnostic] = check_source(Path(path), f"import {module}")
        assert "Discovery must remain offline" in diagnostic
