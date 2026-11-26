"""Identity-bound Case Schema v2 and runtime policy contracts."""

import json

import httpx
import pytest

from vintar.auth import CredentialKind, reserved_header_names
from vintar.core.budget import RequestBudget
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import ScopePolicy
from vintar.regression import (
    TrustedExecutionPolicy,
    parse_regression_case,
    run_regression_case,
)
from vintar.regression.binding import bind_runtime_target, parse_runtime_origin
from vintar.regression.cases_v2 import QueryRegressionCaseV2
from vintar.regression.post_json_policy import parse_post_json_runtime_policy
from vintar.regression.runner import _run_with_resources

GET_CASE = """\
version = 2
identity_id = "billing-reader"
id = "get-query-boolean"
type = "sqli.boolean"
expected_verdict = "not_detected"

[request]
method = "GET"
url = "https://case.invalid/items"
allowed_origin = "https://case.invalid"
params = [["name", "baseline"]]

[injection]
location = "query"
name = "name"
occurrence = 0
mode = "replace"

[probes]
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 2.0
timeout_seconds = 5.0

[approval]
method = "GET"
path = "/items"
environment_class = "isolated_test"
"""


def policy_value(*, kind="bearer", header="Authorization", expires_at=None):
    identity = {
        "identity_id": "billing-reader",
        "credential_kind": kind,
        "env_var": "VINTAR_BILLING_CREDENTIAL",
        "header_name": header,
    }
    if expires_at is not None:
        identity["expires_at"] = expires_at
    return {
        "schema_version": 1,
        "policy_type": "post_json_execution",
        "identities": [identity],
        "approvals": [
            {
                "case_id": "get-query-boolean",
                "identity_id": "billing-reader",
                "credential_kind": kind,
                "credential_env_var": "VINTAR_BILLING_CREDENTIAL",
                "method": "GET",
                "path": "/items",
                "origin": "https://runtime.invalid",
                "allowed_environment_classes": ["isolated_test"],
            }
        ],
        "limits": {
            "max_requests": 48,
            "max_requests_per_second": 2.0,
            "max_timeout_seconds": 10.0,
            "max_response_size": 1048576,
            "max_time_execution_seconds": 45.0,
        },
    }


def parse_policy(value):
    return parse_post_json_runtime_policy(json.dumps(value).encode())


def test_get_case_v2_requires_explicit_identity_and_runtime_policy():
    case = parse_regression_case(GET_CASE)
    assert isinstance(case, QueryRegressionCaseV2)
    assert case.identity_id == "billing-reader"
    calls: list[str] = []
    with pytest.raises(ValueError, match="post_json_runtime_policy_required"):
        run_regression_case(
            case,
            policy=TrustedExecutionPolicy(scope=case.scope),
            transport=httpx.MockTransport(
                lambda _request: calls.append("sent") or httpx.Response(200)
            ),
        )
    assert calls == []
    with pytest.raises(ValueError, match="post_json_case_schema_invalid"):
        parse_regression_case(GET_CASE.replace('identity_id = "billing-reader"\n', ""))


@pytest.mark.parametrize(
    ("kind", "header"),
    [
        ("bearer", "Authorization"),
        ("basic", "authorization"),
        ("api_key_header", "X-API-Key"),
    ],
)
def test_closed_credential_kinds_and_reserved_headers(kind, header):
    policy = parse_policy(policy_value(kind=kind, header=header))
    source = policy.identities[0]
    assert source.credential_kind is CredentialKind(kind)
    assert "authorization" in reserved_header_names(source)
    if kind == "api_key_header":
        assert "x-api-key" in reserved_header_names(source)


def test_policy_expiry_is_explicit_metadata_without_token_inspection():
    policy = parse_policy(policy_value(expires_at="2030-01-02T03:04:05Z"))
    assert policy.identities[0].expires_at is not None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["identities"][0].update(credential="literal-secret"),
        lambda value: value["identities"][0].update(credential_kind="cookie"),
        lambda value: value["identities"][0].update(placement="query"),
        lambda value: value["identities"][0].update(expires_at="not-a-time"),
        lambda value: value["approvals"][0].update(credential_env_var="OTHER_ENV"),
        lambda value: value["approvals"][0].update(credential_kind="basic"),
    ],
)
def test_policy_rejects_literals_query_placement_unknown_kinds_and_pin_drift(mutation):
    value = policy_value()
    mutation(value)
    expected = (
        "auth_query_placement_unsupported"
        if "placement" in value["identities"][0]
        else "post_json_policy_schema_invalid"
    )
    with pytest.raises(ValueError, match=expected) as caught:
        parse_policy(value)
    assert "literal-secret" not in str(caught.value)


def test_query_placement_diagnostic_directs_operator_to_a_header():
    value = policy_value(kind="api_key_header", header="X-API-Key")
    value["identities"][0]["placement"] = "query"
    with pytest.raises(ValueError, match="api_key_header") as caught:
        parse_policy(value)
    assert "header" in str(caught.value)


def test_literal_credential_is_rejected_without_echoing_it():
    value = policy_value()
    value["identities"][0]["credential"] = "literal-value-canary"
    with pytest.raises(ValueError, match="post_json_policy_schema_invalid") as caught:
        parse_policy(value)
    assert "literal-value-canary" not in str(caught.value)


def test_unknown_credential_kind_is_rejected_by_the_closed_enum():
    value = policy_value()
    value["identities"][0]["credential_kind"] = "cookie"
    with pytest.raises(ValueError, match="post_json_policy_schema_invalid"):
        parse_policy(value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [("credential_kind", "basic"), ("credential_env_var", "OTHER_ENV")],
)
def test_approval_rejects_credential_kind_and_env_var_name_drift(field, replacement):
    value = policy_value()
    value["approvals"][0][field] = replacement
    with pytest.raises(ValueError, match="post_json_policy_schema_invalid"):
        parse_policy(value)


@pytest.mark.parametrize(
    "expires_at",
    ["2030-01-02", "2030-01-02T03:04:05", "2030-01-02T03:04:05+00:00"],
)
def test_expires_at_rejects_non_rfc3339_utc_metadata(expires_at):
    with pytest.raises(ValueError, match="post_json_policy_schema_invalid"):
        parse_policy(policy_value(expires_at=expires_at))


def test_environment_value_is_never_loaded_or_exposed(monkeypatch):
    monkeypatch.setenv("VINTAR_BILLING_CREDENTIAL", "environment-value-canary")
    policy = parse_policy(policy_value())
    assert "environment-value-canary" not in repr(policy)
    assert "environment-value-canary" not in str(policy)


def test_get_binding_requires_exact_identity_approval():
    case = parse_regression_case(GET_CASE)
    assert isinstance(case, QueryRegressionCaseV2)
    target = parse_runtime_origin("https://runtime.invalid")
    policy = parse_policy(policy_value())
    rebound = bind_runtime_target(
        case,
        target=target,
        trusted_scope=ScopePolicy(frozenset({target})),
        post_json_policy=policy,
    )
    assert isinstance(rebound, QueryRegressionCaseV2)
    assert rebound.url == "https://runtime.invalid/items"

    changed = policy_value()
    changed["approvals"][0]["identity_id"] = "other-user"
    changed["identities"].append(
        {
            "identity_id": "other-user",
            "credential_kind": "bearer",
            "env_var": "VINTAR_BILLING_CREDENTIAL",
            "header_name": "Authorization",
        }
    )
    with pytest.raises(ValueError, match="post_json_case_not_approved"):
        bind_runtime_target(
            case,
            target=target,
            trusted_scope=ScopePolicy(frozenset({target})),
            post_json_policy=parse_policy(changed),
        )


@pytest.mark.parametrize(
    ("case_path", "approved_path"),
    [
        ("/a%2Fb", "/a/b"),
        ("/a%2fb", "/a%2Fb"),
        ("/a/%2e%2e/b", "/a/../b"),
    ],
)
def test_get_binding_compares_byte_preserved_paths(case_path, approved_path):
    source = GET_CASE.replace("/items", case_path)
    case = parse_regression_case(source)
    assert isinstance(case, QueryRegressionCaseV2)
    value = policy_value()
    value["approvals"][0]["path"] = approved_path
    target = parse_runtime_origin("https://runtime.invalid")

    with pytest.raises(ValueError, match="post_json_operation_not_approved") as caught:
        bind_runtime_target(
            case,
            target=target,
            trusted_scope=ScopePolicy(frozenset({target})),
            post_json_policy=parse_policy(value),
        )

    assert case_path not in str(caught.value)
    assert approved_path not in str(caught.value)


@pytest.mark.parametrize("path", ["/a/../b", "/a/./b"])
def test_get_case_load_rejects_httpx_literal_path_rewrite(path):
    with pytest.raises(ValueError, match="case_request_target_changed") as caught:
        parse_regression_case(GET_CASE.replace("/items", path))

    assert "request target would differ" in str(caught.value)
    assert "normalized literal path" in str(caught.value)
    assert path not in str(caught.value)


@pytest.mark.parametrize(
    "path",
    ["/a%2Fb", "/a%2fb", "/a/%2e/b", "/a/%2E%2E/b", "/a//b"],
)
def test_get_binding_dispatch_path_is_byte_identical_to_approval(path):
    case = parse_regression_case(GET_CASE.replace("/items", path))
    assert isinstance(case, QueryRegressionCaseV2)
    value = policy_value()
    value["approvals"][0]["path"] = path
    target = parse_runtime_origin("https://runtime.invalid")

    rebound = bind_runtime_target(
        case,
        target=target,
        trusted_scope=ScopePolicy(frozenset({target})),
        post_json_policy=parse_policy(value),
    )

    assert httpx.URL(rebound.url).raw_path == path.encode("ascii")


@pytest.mark.parametrize(
    ("check_type", "probes", "requests"),
    [
        (
            "sqli.time",
            'delay_payload = "delay"\ncontrol_payload = "control"\nexpected_delay_seconds = 0.25',
            9,
        ),
        ("sqli.error", 'error_payload = "\'"', 4),
    ],
)
def test_get_v2_parses_each_check_specific_contract(check_type, probes, requests):
    source = GET_CASE.replace('type = "sqli.boolean"', f'type = "{check_type}"')
    source = source.replace(
        'true_payload = "true-probe"\nfalse_payload = "false-probe"', probes
    ).replace("max_requests = 6", f"max_requests = {requests}")
    if check_type == "sqli.time":
        source = source.replace("timeout_seconds = 5.0", "timeout_seconds = 1.0")
    case = parse_regression_case(source)
    assert isinstance(case, QueryRegressionCaseV2)
    assert case.check_type == check_type
    assert case.max_requests == requests


@pytest.mark.parametrize(
    "source",
    [
        GET_CASE.replace("occurrence = 0", "occurrence = 1"),
        GET_CASE.replace('path = "/items"', 'path = "/other"'),
        GET_CASE.replace("max_requests = 6", "max_requests = 5"),
        GET_CASE.replace('false_payload = "false-probe"', 'false_payload = "baseline"'),
    ],
)
def test_get_v2_semantic_mismatches_are_rejected(source):
    with pytest.raises(ValueError, match="get_case_semantic_invalid"):
        parse_regression_case(source)


def test_internal_runner_also_requires_get_v2_policy_before_resources():
    case = parse_regression_case(GET_CASE)
    assert isinstance(case, QueryRegressionCaseV2)
    with pytest.raises(ValueError, match="post_json_runtime_policy_required"):
        _run_with_resources(
            case,
            policy=TrustedExecutionPolicy(scope=case.scope),
            budget=RequestBudget(6),
            rate_limiter=RateLimiter(2.0),
            scope=case.scope,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["identities"][0].update(env_var="not-valid-name"),
        lambda value: value["identities"][0].update(header_name="Bad Header"),
        lambda value: value["identities"][0].update(header_name="X-Wrong"),
        lambda value: value["identities"].append(dict(value["identities"][0])),
    ],
)
def test_identity_source_rejects_invalid_names_headers_and_duplicates(mutation):
    value = policy_value()
    mutation(value)
    with pytest.raises(ValueError, match="post_json_policy_schema_invalid"):
        parse_policy(value)


@pytest.mark.parametrize(
    "header",
    [
        "Host",
        "Content-Length",
        "Transfer-Encoding",
        "Connection",
        "Cookie",
        "Proxy-Authorization",
        "Content-Type",
        "Bad Header",
    ],
)
def test_api_key_header_rejects_reserved_hop_by_hop_and_unsafe_names(header):
    with pytest.raises(ValueError, match="post_json_policy_schema_invalid"):
        parse_policy(policy_value(kind="api_key_header", header=header))
