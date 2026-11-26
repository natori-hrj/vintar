"""Trusted runtime binding for Case Schema v2."""

import json
from pathlib import Path

import httpx
import pytest

from vintar.core.scope import ScopePolicy
from vintar.regression import load_regression_case, parse_regression_case
from vintar.regression.binding import bind_runtime_target, parse_runtime_origin
from vintar.regression.cases_v2 import PostJsonRegressionCase
from vintar.regression.post_json_policy import parse_post_json_runtime_policy


def case_v2() -> PostJsonRegressionCase:
    case = load_regression_case(Path("tests/golden/cases/post-json-boolean-v2.toml"))
    assert isinstance(case, PostJsonRegressionCase)
    return case


def policy_for(
    case: PostJsonRegressionCase,
    *,
    case_id: str | None = None,
    operation_digest: str | None = None,
    path: str | None = None,
):
    value = {
        "schema_version": 1,
        "policy_type": "post_json_execution",
        "identities": [
            {
                "identity_id": case.identity_id,
                "credential_kind": "bearer",
                "env_var": "VINTAR_TEST_TOKEN",
                "header_name": "Authorization",
            }
        ],
        "approvals": [
            {
                "case_id": case_id or case.case_id,
                "identity_id": case.identity_id,
                "credential_kind": "bearer",
                "credential_env_var": "VINTAR_TEST_TOKEN",
                "method": "POST",
                "path": path or case.approval.path,
                "origin": "https://golden.invalid",
                "operation_definition_sha256": operation_digest
                or case.approval.operation_definition_sha256,
                "baseline_body_sha256": case.approval.baseline_body_sha256,
                "allowed_environment_classes": [case.approval.environment_class],
                "allowed_side_effect": "no_side_effect",
            }
        ],
        "limits": {
            "max_requests": 6,
            "max_requests_per_second": 2.0,
            "max_timeout_seconds": 5.0,
            "max_response_size": 1_048_576,
            "max_time_execution_seconds": 45.0,
        },
    }
    return parse_post_json_runtime_policy(json.dumps(value).encode())


@pytest.mark.parametrize(
    ("supplied_policy", "error"),
    [
        (None, "post_json_runtime_policy_required"),
        (object(), "Invalid POST JSON runtime policy"),
    ],
)
def test_v2_binding_rejects_missing_or_invalid_policy_before_transport(
    monkeypatch, supplied_policy, error
):
    case = case_v2()
    target = parse_runtime_origin("https://golden.invalid")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("transport must not be constructed")

    monkeypatch.setattr(httpx, "HTTPTransport", forbidden)
    with pytest.raises((TypeError, ValueError), match=error):
        bind_runtime_target(
            case,
            target=target,
            trusted_scope=ScopePolicy(frozenset({target})),
            post_json_policy=supplied_policy,
        )


def test_v2_binding_rejects_unapproved_case_before_transport(monkeypatch):
    case = case_v2()
    target = parse_runtime_origin("https://golden.invalid")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("transport must not be constructed")

    monkeypatch.setattr(httpx, "HTTPTransport", forbidden)
    with pytest.raises(ValueError, match="post_json_case_not_approved"):
        bind_runtime_target(
            case,
            target=target,
            trusted_scope=ScopePolicy(frozenset({target})),
            post_json_policy=policy_for(case, case_id="another-case"),
        )


def test_v2_binding_rejects_non_intersecting_approval_before_transport(monkeypatch):
    case = case_v2()
    target = parse_runtime_origin("https://golden.invalid")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("transport must not be constructed")

    monkeypatch.setattr(httpx, "HTTPTransport", forbidden)
    with pytest.raises(ValueError, match="post_json_approval_mismatch"):
        bind_runtime_target(
            case,
            target=target,
            trusted_scope=ScopePolicy(frozenset({target})),
            post_json_policy=policy_for(case, operation_digest="1" * 64),
        )


def test_v2_binding_succeeds_only_with_exact_independent_approval():
    case = case_v2()
    target = parse_runtime_origin("https://golden.invalid")
    rebound = bind_runtime_target(
        case,
        target=target,
        trusted_scope=ScopePolicy(frozenset({target})),
        post_json_policy=policy_for(case),
    )
    assert isinstance(rebound, PostJsonRegressionCase)
    assert rebound.url == case.url


def test_post_binding_uses_byte_preserved_path_for_approval_and_dispatch():
    source = Path("tests/golden/cases/post-json-boolean-v2.toml").read_text(
        encoding="utf-8"
    )
    parsed = parse_regression_case(source.replace("/items", "/a%2Fb"))
    assert isinstance(parsed, PostJsonRegressionCase)
    target = parse_runtime_origin("https://golden.invalid")

    with pytest.raises(ValueError, match="post_json_operation_not_approved") as caught:
        bind_runtime_target(
            parsed,
            target=target,
            trusted_scope=ScopePolicy(frozenset({target})),
            post_json_policy=policy_for(parsed, path="/a/b"),
        )
    assert "/a%2Fb" not in str(caught.value)
    assert "/a/b" not in str(caught.value)

    rebound = bind_runtime_target(
        parsed,
        target=target,
        trusted_scope=ScopePolicy(frozenset({target})),
        post_json_policy=policy_for(parsed),
    )
    assert httpx.URL(rebound.url).raw_path == b"/a%2Fb"


@pytest.mark.parametrize("path", ["/a/../b", "/a/./b"])
def test_post_case_load_rejects_httpx_literal_path_rewrite(path):
    source = Path("tests/golden/cases/post-json-boolean-v2.toml").read_text(
        encoding="utf-8"
    )

    with pytest.raises(ValueError, match="case_request_target_changed") as caught:
        parse_regression_case(source.replace("/items", path))

    assert "request target would differ" in str(caught.value)
    assert "normalized literal path" in str(caught.value)
    assert path not in str(caught.value)
