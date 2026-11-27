"""Tests for the source-level HTTP architecture checks."""

import ast
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
    "path",
    [
        "checks/sqli/example.py",
        "cli.py",
        "regression/batch.py",
        "regression/binding.py",
        "regression/report.py",
        "core/executor.py",
    ],
)
def test_json_body_injection_is_rejected_outside_narrow_allowlist(path):
    source = """
from vintar.core.request import InjectionLocation

location = InjectionLocation.JSON_BODY
"""
    [diagnostic] = check_source(Path(path), source)
    assert "trusted POST execution adapter" in diagnostic


def test_json_body_injection_is_available_to_trusted_runner_adapter():
    source = """
from vintar.core.request import InjectionLocation

location = InjectionLocation.JSON_BODY
"""
    assert not check_source(Path("regression/runner.py"), source)


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


@pytest.mark.parametrize(
    "path",
    [
        "post_json_inventory_cli.py",
        "post_json_review_cli.py",
        "regression/post_json_inventory.py",
        "regression/post_json_review.py",
    ],
)
def test_post_json_discovery_and_review_stay_offline(path):
    for module in (
        "httpx",
        "vintar.core.executor",
        "vintar.regression.runner",
        "vintar.regression.cases",
    ):
        [diagnostic] = check_source(Path(path), f"import {module}")
        assert "Discovery must remain offline" in diagnostic


def test_post_json_review_can_reuse_json_body_primitives():
    assert not check_source(
        Path("regression/post_json_review.py"),
        "from vintar.core.json_body import JsonBody, JsonPointer",
    )


def test_only_legacy_case_materialization_may_import_sqli_catalog():
    source = "from vintar.checks.sqli.catalog import _materialize_legacy_boolean_family"

    assert not check_source(Path("regression/case_materialization.py"), source)
    [diagnostic] = check_source(Path("regression/runner.py"), source)
    assert "catalog expansion may be imported only" in diagnostic

    module_source = (
        "from vintar.checks.sqli import catalog\n"
        "catalog._materialize_legacy_boolean_family(name)"
    )
    [diagnostic] = check_source(Path("regression/runner.py"), module_source)
    assert "catalog expansion may be imported only" in diagnostic


@pytest.mark.parametrize(
    "path",
    ["regression/authorization_cases.py", "regression/authorization_policy.py"],
)
def test_authorization_contract_parsers_stay_offline(path):
    for module in ("vintar.core.executor", "vintar.regression.runner", "socket"):
        [diagnostic] = check_source(Path(path), f"import {module}")
        assert "must remain offline" in diagnostic


def test_authorization_case_parser_can_use_only_pure_check_contracts():
    assert not check_source(
        Path("regression/authorization_cases.py"),
        "from vintar.checks.authorization.models import AuthorizationExpectation",
    )
    [diagnostic] = check_source(
        Path("regression/authorization_cases.py"),
        "from vintar.checks.sqli.models import Verdict",
    )
    assert "must remain offline" in diagnostic


def test_runner_may_import_auth_application_for_authenticated_execution():
    assert check_source(Path("regression/runner.py"), "import vintar.auth.apply") == []


def test_authorization_composition_may_import_auth_application():
    assert (
        check_source(
            Path("regression/authorization_execution.py"),
            "import vintar.auth.apply",
        )
        == []
    )


@pytest.mark.parametrize("path", ["regression/batch.py", "cli.py", "regression_cli.py"])
def test_only_runner_may_import_auth_application(path):
    [diagnostic] = check_source(Path(path), "import vintar.auth.apply")
    assert "regression/runner.py or regression/authorization_execution.py" in diagnostic


@pytest.mark.parametrize("path", ["regression/batch.py", "cli.py", "regression_cli.py"])
def test_current_entry_points_cannot_import_authorization_execution(path):
    [diagnostic] = check_source(
        Path(path), "import vintar.regression.authorization_execution"
    )
    assert "Authorization execution composition" in diagnostic


def test_checks_cannot_import_authentication_material():
    [diagnostic] = check_source(Path("checks/example.py"), "import vintar.auth")
    assert "cannot import authentication" in diagnostic


def test_only_auth_apply_can_mutate_request_headers():
    source = 'request.headers["Authorization"] = value'
    [diagnostic] = check_source(Path("core/example.py"), source)
    assert "only by vintar.auth.apply" in diagnostic
    assert not check_source(Path("auth/apply.py"), source)


def test_repository_only_runner_imports_auth_apply():
    for path in (
        Path("src/vintar/regression/batch.py"),
        Path("src/vintar/cli.py"),
        Path("src/vintar/regression_cli.py"),
        Path("src/vintar/regression/report.py"),
    ):
        assert "vintar.auth.apply" not in path.read_text(encoding="utf-8")
    assert "vintar.auth.apply" in Path("src/vintar/regression/runner.py").read_text(
        encoding="utf-8"
    )
    assert "vintar.auth.apply" in Path(
        "src/vintar/regression/authorization_execution.py"
    ).read_text(encoding="utf-8")


def test_only_authorization_execution_disables_auth_failure_rejection():
    expected = Path("src/vintar/regression/authorization_execution.py")
    observed = []
    for path in Path("src/vintar").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg == "reject_auth_failure_statuses"
                    and isinstance(keyword.value, ast.Constant)
                    and keyword.value.value is False
                ):
                    observed.append(path)
    assert observed == [expected]
