"""Trusted execution of reviewed Case Schema v2 POST JSON cases."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from vintar.core.json_body import JsonBody, JsonPointer
from vintar.regression import (
    TrustedExecutionPolicy,
    load_regression_case,
    regression_batch_report_json,
    run_regression_batch,
    run_regression_case,
)
from vintar.regression.cases_v2 import PostJsonRegressionCase
from vintar.regression.post_json_policy import parse_post_json_runtime_policy

CASES = Path("tests/golden/cases")
CANARY = "runtime-policy-json-canary"


def load_case(name: str = "post-json-boolean-v2.toml") -> PostJsonRegressionCase:
    case = load_regression_case(CASES / name)
    assert isinstance(case, PostJsonRegressionCase)
    return case


def runtime_policy(
    case: PostJsonRegressionCase,
    *,
    environments: list[str] | None = None,
    operation_digest: str | None = None,
    baseline_digest: str | None = None,
    max_requests: int = 48,
    case_id: str | None = None,
    path: str | None = None,
    origin: str | None = None,
    max_requests_per_second: float = 10.0,
    max_timeout_seconds: float = 10.0,
    max_response_size: int = 1_048_576,
    max_time_execution_seconds: float = 120.0,
):
    value = {
        "schema_version": 1,
        "policy_type": "post_json_execution",
        "approvals": [
            {
                "case_id": case_id or case.case_id,
                "method": "POST",
                "path": path or case.approval.path,
                "origin": origin or case.url.split(case.approval.path, 1)[0],
                "operation_definition_sha256": operation_digest
                or case.approval.operation_definition_sha256,
                "baseline_body_sha256": baseline_digest
                or case.approval.baseline_body_sha256,
                "allowed_environment_classes": environments or ["isolated_test"],
                "allowed_side_effect": "no_side_effect",
            }
        ],
        "limits": {
            "max_requests": max_requests,
            "max_requests_per_second": max_requests_per_second,
            "max_timeout_seconds": max_timeout_seconds,
            "max_response_size": max_response_size,
            "max_time_execution_seconds": max_time_execution_seconds,
        },
    }
    return parse_post_json_runtime_policy(json.dumps(value).encode())


def execution_policy(case: PostJsonRegressionCase, **kwargs) -> TrustedExecutionPolicy:
    post_policy = runtime_policy(case, **kwargs)
    return TrustedExecutionPolicy(
        scope=case.scope,
        max_requests=post_policy.limits.max_requests,
        max_requests_per_second=post_policy.limits.max_requests_per_second,
        max_timeout_seconds=post_policy.limits.max_timeout_seconds,
        max_response_size=post_policy.limits.max_response_size,
        max_time_execution_seconds=post_policy.limits.max_time_execution_seconds,
        post_json_policy=post_policy,
    )


@pytest.mark.parametrize(
    ("name", "expected_count"),
    [
        ("post-json-boolean-v2.toml", 6),
        ("post-json-time-v2.toml", 9),
        ("post-json-error-v2.toml", 4),
    ],
)
def test_all_post_json_check_types_execute_with_exact_budgets(name, expected_count):
    case = load_case(name)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, content=b"constant")

    outcome = run_regression_case(
        case,
        policy=execution_policy(case),
        transport=httpx.MockTransport(handler),
    )
    assert outcome.request_count == expected_count
    assert len(requests) == expected_count
    assert all(request.method == "POST" for request in requests)
    assert all(
        request.headers["content-type"] == "application/json" for request in requests
    )
    assert all(request.url.query == b"" for request in requests)
    decoded = [json.loads(request.content) for request in requests]
    assert all(set(body) == {"name"} for body in decoded)
    assert all(type(body["name"]) is str for body in decoded)


@pytest.mark.parametrize(
    ("policy_kwargs", "code"),
    [
        ({"case_id": "another-case"}, "post_json_case_not_approved"),
        ({"path": "/other"}, "post_json_operation_not_approved"),
        ({"origin": "https://other.invalid"}, "post_json_operation_not_approved"),
        ({"environments": ["other"]}, "post_json_environment_not_approved"),
        ({"operation_digest": "1" * 64}, "post_json_operation_integrity_mismatch"),
        ({"baseline_digest": "1" * 64}, "post_json_policy_baseline_mismatch"),
    ],
)
def test_policy_intersection_rejects_before_transport(policy_kwargs, code):
    case = load_case()
    calls: list[str] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append("sent")
        return httpx.Response(200)

    with pytest.raises(ValueError, match=code) as caught:
        run_regression_case(
            case,
            policy=execution_policy(case, **policy_kwargs),
            transport=httpx.MockTransport(handler),
        )
    assert calls == []
    assert case.url not in str(caught.value)
    assert case.approval.path not in str(caught.value)


def test_case_cannot_grant_side_effect_permission():
    case = load_case()
    changed = replace(
        case,
        approval=replace(case.approval, side_effect="mutating"),
    )
    with pytest.raises(ValueError, match="post_json_side_effect_not_allowed"):
        run_regression_case(changed, policy=execution_policy(case))


def test_integrity_and_string_leaf_are_rechecked_before_sending():
    case = load_case()
    numeric_body = JsonBody.from_bytes(b'{"name":7}')
    digest = hashlib.sha256(numeric_body.to_bytes()).hexdigest()
    changed = replace(
        case,
        json_body=numeric_body,
        approval=replace(case.approval, baseline_body_sha256=digest),
    )
    with pytest.raises(ValueError, match="post_json_pointer_target_not_string"):
        run_regression_case(
            changed,
            policy=execution_policy(changed, baseline_digest=digest),
            transport=httpx.MockTransport(lambda _request: pytest.fail("sent")),
        )


def test_baseline_digest_and_missing_pointer_are_rechecked_before_sending():
    case = load_case()
    changed_body = JsonBody.from_bytes(b'{"name":"changed"}')
    with pytest.raises(ValueError, match="post_json_baseline_integrity_mismatch"):
        run_regression_case(
            replace(case, json_body=changed_body),
            policy=execution_policy(case),
            transport=httpx.MockTransport(lambda _request: pytest.fail("sent")),
        )

    missing = replace(case, pointer=JsonPointer.parse("/missing"))
    with pytest.raises(ValueError, match="post_json_pointer_target_missing"):
        run_regression_case(
            missing,
            policy=execution_policy(case),
            transport=httpx.MockTransport(lambda _request: pytest.fail("sent")),
        )


def test_trusted_budget_cannot_be_widened_by_case_contract():
    case = load_case()
    with pytest.raises(ValueError, match="budget is insufficient"):
        run_regression_case(case, policy=execution_policy(case, max_requests=5))


def test_trusted_policy_type_clamps_every_api_limit():
    case = load_case()
    post_policy = runtime_policy(
        case,
        max_requests=12,
        max_requests_per_second=1.0,
        max_timeout_seconds=2.0,
        max_response_size=1024,
        max_time_execution_seconds=20.0,
    )
    policy = TrustedExecutionPolicy(
        scope=case.scope,
        max_requests=768,
        max_requests_per_second=10.0,
        max_timeout_seconds=60.0,
        max_response_size=1_048_576,
        max_time_execution_seconds=120.0,
        post_json_policy=post_policy,
    )
    assert policy.max_requests == post_policy.limits.max_requests
    assert policy.max_requests_per_second == post_policy.limits.max_requests_per_second
    assert policy.max_timeout_seconds == post_policy.limits.max_timeout_seconds
    assert policy.max_response_size == post_policy.limits.max_response_size
    assert (
        policy.max_time_execution_seconds
        == post_policy.limits.max_time_execution_seconds
    )


@pytest.mark.parametrize(("status", "expected_requests"), [(302, 6), (429, 1)])
def test_post_json_execution_never_redirects_or_retries(status, expected_requests):
    case = load_case()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            status,
            headers={"location": "https://redirect.invalid/secret?token=hidden"},
        )

    outcome = run_regression_case(
        case,
        policy=execution_policy(case),
        transport=httpx.MockTransport(handler),
    )
    assert outcome.request_count == expected_requests
    assert len(requests) == expected_requests
    assert all(request.url.host == "golden.invalid" for request in requests)
    assert all(request.url.path == "/items" for request in requests)


def test_batch_preflights_every_policy_approval_before_first_send():
    first = load_case()
    second = replace(first, case_id="unapproved-second")
    calls: list[str] = []
    with pytest.raises(ValueError, match="post_json_case_not_approved"):
        run_regression_batch(
            [first, second],
            policy=execution_policy(first, max_requests=12),
            transport=httpx.MockTransport(
                lambda _request: calls.append("sent") or httpx.Response(200)
            ),
        )
    assert calls == []


def test_report_v1_is_unchanged_and_contains_no_policy_canary(monkeypatch):
    case = load_case()
    monkeypatch.setenv("VINTAR_RUNTIME_POLICY_JSON", CANARY)
    result = run_regression_batch(
        [case],
        policy=execution_policy(case),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, content=b"constant")
        ),
    )
    report = regression_batch_report_json(result)
    assert '"schema_version":1' in report
    assert CANARY not in report
    assert case.url not in report
    assert case.approval.baseline_body_sha256 not in report


def test_request_plan_and_report_serialization_are_deterministic():
    case = load_case()

    def execute():
        bodies: list[bytes] = []
        result = run_regression_batch(
            [case],
            policy=execution_policy(case),
            transport=httpx.MockTransport(
                lambda request: (
                    bodies.append(request.content)
                    or httpx.Response(200, content=b"constant")
                )
            ),
        )
        return bodies, result

    first_bodies, first_result = execute()
    second_bodies, _ = execute()
    assert first_bodies == second_bodies
    assert regression_batch_report_json(first_result) == regression_batch_report_json(
        first_result
    )
