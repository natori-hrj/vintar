"""Trusted authorization_execution policy v1 parsing."""

import json

import pytest

from vintar.regression.authorization_policy import (
    AuthorizationPolicyError,
    load_authorization_runtime_policy,
    parse_authorization_runtime_policy,
)


def policy_value() -> dict[str, object]:
    return {
        "schema_version": 1,
        "policy_type": "authorization_execution",
        "identities": [
            {
                "identity_id": "reader-a",
                "authentication": "required",
                "credential_kind": "bearer",
                "env_var": "VINTAR_READER_A",
                "header_name": "Authorization",
            },
            {"identity_id": "public-user", "authentication": "none"},
        ],
        "approvals": [
            {
                "case_id": "tenant-document-read",
                "case_sha256": "0" * 64,
                "origin": "https://api.example.test",
                "environment_class": "ci-isolated",
                "operations": [
                    {
                        "operation_id": "reader-control",
                        "identity_id": "reader-a",
                        "method": "GET",
                        "path": "/documents/own",
                        "expected": "allow",
                    },
                    {
                        "operation_id": "reader-deny",
                        "identity_id": "reader-a",
                        "method": "GET",
                        "path": "/documents/other",
                        "expected": "deny",
                    },
                    {
                        "operation_id": "public-control",
                        "identity_id": "public-user",
                        "method": "GET",
                        "path": "/health",
                        "expected": "allow",
                    },
                ],
            }
        ],
        "limits": {
            "max_requests": 8,
            "max_requests_per_second": 2.0,
            "max_timeout_seconds": 10.0,
            "max_response_size": 1_048_576,
        },
    }


def policy_bytes(value=None):
    return json.dumps(
        policy_value() if value is None else value, separators=(",", ":")
    ).encode()


def test_policy_is_separate_closed_and_secret_free():
    policy = parse_authorization_runtime_policy(policy_bytes())
    assert policy.policy_type == "authorization_execution"
    assert policy.identities[1].credential_source is None
    assert "api.example.test" not in repr(policy)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(policy_type="post_json_execution"),
        lambda value: value.update(extra=True),
        lambda value: value["approvals"][0]["operations"][0].update(method="POST"),
        lambda value: value["approvals"][0]["operations"][0].update(path="/items/{id}"),
        lambda value: value["identities"][0].update(identity_id="Reader.A"),
    ],
)
def test_policy_rejects_other_policy_types_unknown_fields_post_and_templates(mutate):
    value = policy_value()
    mutate(value)
    with pytest.raises(
        AuthorizationPolicyError, match="authorization_policy_schema_invalid"
    ):
        parse_authorization_runtime_policy(policy_bytes(value))


def test_policy_rejects_shared_credential_sources():
    value = policy_value()
    duplicate = dict(value["identities"][0])
    duplicate["identity_id"] = "reader-b"
    value["identities"].append(duplicate)
    with pytest.raises(
        AuthorizationPolicyError, match="authorization_policy_schema_invalid"
    ):
        parse_authorization_runtime_policy(policy_bytes(value))


def test_inline_source_has_precedence_without_file_fallback(tmp_path):
    policy_file = tmp_path / "policy.json"
    policy_file.write_bytes(policy_bytes())
    with pytest.raises(AuthorizationPolicyError):
        load_authorization_runtime_policy(
            {
                "VINTAR_AUTHORIZATION_POLICY_JSON": "invalid",
                "VINTAR_AUTHORIZATION_POLICY_FILE": str(policy_file),
            }
        )


def test_policy_rejects_duplicate_json_keys_without_echoing_values():
    canary = "credential-canary-must-not-appear"
    source = (
        '{"schema_version":1,"schema_version":1,"policy_type":"'
        + canary
        + '","identities":[],"approvals":[],"limits":{}}'
    ).encode()
    with pytest.raises(AuthorizationPolicyError) as caught:
        parse_authorization_runtime_policy(source)
    assert canary not in str(caught.value)
