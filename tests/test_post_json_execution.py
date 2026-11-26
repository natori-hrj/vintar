"""Schema v2 identity-bound cases fail closed until auth integration."""

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from vintar.core.budget import RequestBudget
from vintar.core.json_body import JsonBody, JsonPointer
from vintar.core.rate_limit import RateLimiter
from vintar.regression import (
    TrustedExecutionPolicy,
    load_regression_case,
    run_regression_batch,
    run_regression_case,
)
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.cases_v2 import PostJsonRegressionCase
from vintar.regression.post_json_policy import parse_post_json_runtime_policy
from vintar.regression.report import regression_batch_report_json
from vintar.regression.runner import (
    RegressionStatus,
    _post_json_approval,
    _post_json_execution_inputs,
    _run_with_resources,
)

CASES = Path("tests/golden/cases")


def load_case(name="post-json-boolean-v2.toml"):
    case = load_regression_case(CASES / name)
    assert isinstance(case, PostJsonRegressionCase)
    return case


def runtime_policy(case, **changes):
    approval = {
        "case_id": case.case_id,
        "identity_id": case.identity_id,
        "credential_kind": "bearer",
        "credential_env_var": "VINTAR_TEST_TOKEN",
        "method": "POST",
        "path": case.approval.path,
        "origin": case.url.split(case.approval.path, 1)[0],
        "operation_definition_sha256": case.approval.operation_definition_sha256,
        "baseline_body_sha256": case.approval.baseline_body_sha256,
        "allowed_environment_classes": [case.approval.environment_class],
        "allowed_side_effect": "no_side_effect",
    }
    approval.update(changes)
    identities = [
        {
            "identity_id": case.identity_id,
            "credential_kind": "bearer",
            "env_var": "VINTAR_TEST_TOKEN",
            "header_name": "Authorization",
        }
    ]
    if approval["identity_id"] != case.identity_id:
        identities.append(
            {
                "identity_id": approval["identity_id"],
                "credential_kind": "bearer",
                "env_var": "VINTAR_TEST_TOKEN",
                "header_name": "Authorization",
            }
        )
    value = {
        "schema_version": 1,
        "policy_type": "post_json_execution",
        "identities": identities,
        "approvals": [approval],
        "limits": {
            "max_requests": 48,
            "max_requests_per_second": 10.0,
            "max_timeout_seconds": 10.0,
            "max_response_size": 1_048_576,
            "max_time_execution_seconds": 120.0,
        },
    }
    return parse_post_json_runtime_policy(json.dumps(value).encode())


def execution_policy(case, **changes):
    post_policy = runtime_policy(case, **changes)
    return TrustedExecutionPolicy(
        scope=case.scope,
        max_requests=post_policy.limits.max_requests,
        max_requests_per_second=post_policy.limits.max_requests_per_second,
        max_timeout_seconds=post_policy.limits.max_timeout_seconds,
        max_response_size=post_policy.limits.max_response_size,
        max_time_execution_seconds=post_policy.limits.max_time_execution_seconds,
        post_json_policy=post_policy,
    )


def run_pre_auth_layer(case, *, policy, transport):
    return _run_with_resources(
        case,
        policy=policy,
        budget=RequestBudget(case.max_requests),
        rate_limiter=RateLimiter(case.requests_per_second),
        transport=transport,
        scope=case.scope,
    )


@pytest.mark.parametrize(
    "name",
    [
        "post-json-boolean-v2.toml",
        "post-json-time-v2.toml",
        "post-json-error-v2.toml",
    ],
)
def test_identity_bound_post_cases_fail_closed_before_transport(name):
    case = load_regression_case(Path("tests/golden/cases") / name)
    assert isinstance(case, PostJsonRegressionCase)
    calls: list[str] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append("sent")
        return httpx.Response(200)

    policy = TrustedExecutionPolicy(scope=case.scope, max_requests=48)
    with pytest.raises(
        ValueError, match="authenticated_execution_unavailable"
    ) as caught:
        run_regression_case(
            case,
            policy=policy,
            transport=httpx.MockTransport(handler),
        )
    assert "Wait for the authenticated runner integration" in str(caught.value)
    assert case.identity_id not in str(caught.value)
    assert calls == []


def test_batch_fails_closed_before_first_transport():
    case = load_regression_case(Path("tests/golden/cases/post-json-boolean-v2.toml"))
    assert isinstance(case, PostJsonRegressionCase)
    calls: list[str] = []
    with pytest.raises(ValueError, match="authenticated_execution_unavailable"):
        run_regression_batch(
            [case],
            policy=TrustedExecutionPolicy(scope=case.scope, max_requests=48),
            transport=httpx.MockTransport(
                lambda _request: calls.append("sent") or httpx.Response(200)
            ),
        )
    assert calls == []


@pytest.mark.parametrize(
    ("name", "expected_count"),
    [
        ("post-json-boolean-v2.toml", 6),
        ("post-json-time-v2.toml", 9),
        ("post-json-error-v2.toml", 4),
    ],
)
def test_pre_auth_post_layer_retains_exact_request_plans(name, expected_count):
    case = load_case(name)
    requests = []
    outcome = run_pre_auth_layer(
        case,
        policy=execution_policy(case),
        transport=httpx.MockTransport(
            lambda request: (
                requests.append(request) or httpx.Response(200, content=b"constant")
            )
        ),
    )
    assert outcome.request_count == expected_count
    assert len(requests) == expected_count
    assert all(request.method == "POST" for request in requests)
    assert all(
        request.headers["content-type"] == "application/json" for request in requests
    )
    assert all(set(json.loads(request.content)) == {"name"} for request in requests)


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"case_id": "another-case"}, "post_json_case_not_approved"),
        ({"identity_id": "another-user"}, "post_json_case_not_approved"),
        ({"path": "/other"}, "post_json_operation_not_approved"),
        ({"origin": "https://other.invalid"}, "post_json_operation_not_approved"),
        (
            {"allowed_environment_classes": ["other"]},
            "post_json_environment_not_approved",
        ),
        (
            {"operation_definition_sha256": "1" * 64},
            "post_json_operation_integrity_mismatch",
        ),
        ({"baseline_body_sha256": "1" * 64}, "post_json_policy_baseline_mismatch"),
    ],
)
def test_pre_auth_policy_intersection_retains_all_rejections(changes, code):
    case = load_case()
    policy = execution_policy(case, **changes)
    with pytest.raises(ValueError, match=code):
        _post_json_execution_inputs(case, policy)


def test_pre_auth_integrity_side_effect_and_pointer_rechecks_remain_covered():
    case = load_case()
    with pytest.raises(ValueError, match="post_json_side_effect_not_allowed"):
        _post_json_execution_inputs(
            replace(case, approval=replace(case.approval, side_effect="mutating")),
            execution_policy(case),
        )
    with pytest.raises(ValueError, match="post_json_baseline_integrity_mismatch"):
        _post_json_execution_inputs(
            replace(case, json_body=JsonBody.from_bytes(b'{"name":"changed"}')),
            execution_policy(case),
        )
    with pytest.raises(ValueError, match="post_json_pointer_target_missing"):
        _post_json_execution_inputs(
            replace(case, pointer=JsonPointer.parse("/missing")),
            execution_policy(case),
        )
    numeric = JsonBody.from_bytes(b'{"name":7}')
    digest = hashlib.sha256(numeric.to_bytes()).hexdigest()
    changed = replace(
        case,
        json_body=numeric,
        approval=replace(case.approval, baseline_body_sha256=digest),
    )
    with pytest.raises(ValueError, match="post_json_pointer_target_not_string"):
        _post_json_execution_inputs(
            changed,
            execution_policy(changed, baseline_body_sha256=digest),
        )


def test_policy_limit_clamping_remains_covered():
    case = load_case()
    post_policy = runtime_policy(case)
    policy = TrustedExecutionPolicy(
        scope=case.scope,
        max_requests=768,
        max_requests_per_second=10.0,
        max_timeout_seconds=60.0,
        max_response_size=2_000_000,
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


def test_pre_auth_approval_requires_runtime_policy():
    case = load_case()
    with pytest.raises(ValueError, match="post_json_runtime_policy_required"):
        _post_json_approval(case, TrustedExecutionPolicy(scope=case.scope))


@pytest.mark.parametrize(("status", "expected"), [(302, 6), (429, 1)])
def test_pre_auth_post_layer_retains_no_redirect_or_retry(status, expected):
    case = load_case()
    requests = []
    run_pre_auth_layer(
        case,
        policy=execution_policy(case),
        transport=httpx.MockTransport(
            lambda request: (
                requests.append(request)
                or httpx.Response(status, headers={"location": "https://other.invalid"})
            )
        ),
    )
    assert len(requests) == expected
    assert all(request.url.host == "golden.invalid" for request in requests)


def test_pre_auth_outcome_still_serializes_as_report_v1_without_policy_data():
    case = load_case()
    outcome = run_pre_auth_layer(
        case,
        policy=execution_policy(case),
        transport=httpx.MockTransport(
            lambda _request: httpx.Response(200, content=b"constant")
        ),
    )
    result = RegressionBatchResult(
        planned_case_ids=(case.case_id,),
        outcomes=(outcome,),
        status=RegressionStatus.PASS,
        requests_used=outcome.request_count,
    )
    report = regression_batch_report_json(result)
    assert '"schema_version":1' in report
    assert case.identity_id not in report
    assert "VINTAR_TEST_TOKEN" not in report
    assert case.url not in report
