"""Authorization GET runner decisions and execution boundaries."""

import ast
import json
from pathlib import Path

import httpx

from vintar.checks.authorization.models import (
    AUTHORIZATION_REASON_VERDICTS,
    AuthorizationReason,
    AuthorizationVerdict,
)
from vintar.regression.authorization_cases import parse_authorization_case
from vintar.regression.authorization_execution import _build_authorization_execution
from vintar.regression.authorization_policy import parse_authorization_runtime_policy
from vintar.regression.authorization_runner import _run_authorization_case


class FailingStream(httpx.SyncByteStream):
    def __init__(self, failure: httpx.HTTPError) -> None:
        self.failure = failure

    def __iter__(self):
        yield b"{"
        raise self.failure


def inputs(
    responses: dict[str, tuple[int, bytes | httpx.SyncByteStream, str | None]],
    *,
    allow_empty: frozenset[str] = frozenset(),
):
    operations = ""
    for operation_id, expected, control in (
        ("control", "allow", "positive"),
        ("allow-cell", "allow", "negative"),
        ("deny-cell", "deny", "negative"),
    ):
        statuses = "[200]" if expected == "allow" else "[403, 404]"
        required = (
            '["/ok"]'
            if expected == "allow" and operation_id not in allow_empty
            else "[]"
        )
        forbidden = "[]" if expected == "allow" else '["/secret"]'
        empty_allowed = str(operation_id in allow_empty).lower()
        operations += f'''\n[[operations]]
id = "{operation_id}"
identity_id = "reader"
resource_id = "resource"
control = "{control}"
expected = "{expected}"
[operations.request]
method = "GET"
url = "https://runner.invalid/{operation_id}"
allowed_origin = "https://runner.invalid"
[operations.assertions]
status_codes = {statuses}
media_type = "application/json"
required_json_pointers = {required}
forbidden_json_pointers = {forbidden}
allow_empty_body = {empty_allowed}
'''
    case = parse_authorization_case(
        """version = 1
id = "runner"
type = "authorization.access"
category = "tenant_isolation"
environment_class = "test"
[[identities]]
id = "reader"
label = "reader"
authentication = "none"
"""
        + operations
    )
    policy = parse_authorization_runtime_policy(
        json.dumps(
            {
                "schema_version": 1,
                "policy_type": "authorization_execution",
                "identities": [{"identity_id": "reader", "authentication": "none"}],
                "approvals": [
                    {
                        "case_id": case.case_id,
                        "case_sha256": case.case_sha256,
                        "origin": "https://runner.invalid",
                        "environment_class": "test",
                        "operations": [
                            {
                                "operation_id": item.operation_id,
                                "identity_id": item.identity_id,
                                "method": "GET",
                                "path": item.request.path,
                                "expected": item.expected.value,
                            }
                            for item in case.operations
                        ],
                    }
                ],
                "limits": {
                    "max_requests": 3,
                    "max_requests_per_second": 10,
                    "max_timeout_seconds": 1,
                    "max_response_size": 64,
                },
            }
        ).encode()
    )

    def transport_factory(_identity_id: str) -> httpx.BaseTransport:
        def respond(request: httpx.Request) -> httpx.Response:
            status, body, media_type = responses[request.url.path]
            headers = {"Content-Type": media_type} if media_type else {}
            if isinstance(body, bytes):
                return httpx.Response(status, headers=headers, content=body)
            return httpx.Response(status, headers=headers, stream=body)

        return httpx.MockTransport(respond)

    def execution_factory(case_value, policy_value, environ_value):
        return _build_authorization_execution(
            case_value,
            policy_value,
            environ_value,
            transport_factory=transport_factory,
            clock=lambda: 0.0,
        )

    return case, policy, execution_factory


def test_failed_control_executes_allow_but_not_deny_and_normalizes_failures():
    case, policy, factory = inputs(
        {
            "/control": (401, b'{"error":true}', "application/json"),
            "/allow-cell": (403, b'{"error":true}', "application/json"),
            "/deny-cell": (403, b'{"error":true}', "application/json"),
        }
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert [item.operation_id for item in result.operations] == [
        "control",
        "allow-cell",
        "deny-cell",
    ]
    assert [item.reason for item in result.operations] == [
        AuthorizationReason.POSITIVE_CONTROL_FAILED,
        AuthorizationReason.POSITIVE_CONTROL_FAILED,
        AuthorizationReason.POSITIVE_CONTROL_FAILED,
    ]
    assert result.requests_used == 2


def test_failed_control_still_accepts_a_satisfying_allow_response():
    case, policy, factory = inputs(
        {
            "/control": (401, b"{}", "application/json"),
            "/allow-cell": (200, b'{"ok":true}', "application/json"),
            "/deny-cell": (403, b"{}", "application/json"),
        }
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert result.operations[1].verdict is AuthorizationVerdict.CONFORMS
    assert result.operations[1].reason is (
        AuthorizationReason.DECLARED_ALLOW_OBSERVED_SUCCESS
    )
    assert result.requests_used == 2


def test_violation_does_not_stop_later_cells():
    case, policy, factory = inputs(
        {
            "/control": (200, b'{"ok":true}', "application/json"),
            "/allow-cell": (200, b'{"ok":true}', "application/json"),
            "/deny-cell": (200, b'{"secret":true}', "application/json"),
        }
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert result.requests_used == 3
    assert result.operations[-1].reason is (
        AuthorizationReason.DECLARED_DENY_OBSERVED_SUCCESS
    )


def test_empty_denial_with_wrong_media_type_is_inconclusive():
    case, policy, factory = inputs(
        {
            "/control": (200, b'{"ok":true}', "application/json"),
            "/allow-cell": (200, b'{"ok":true}', "application/json"),
            "/deny-cell": (403, b"", "text/html"),
        },
        allow_empty=frozenset({"deny-cell"}),
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert result.operations[-1].verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.operations[-1].reason is AuthorizationReason.MEDIA_TYPE_MISMATCH


def test_empty_denial_with_matching_or_missing_media_type_conforms():
    for media_type in ("application/json", None):
        case, policy, factory = inputs(
            {
                "/control": (200, b'{"ok":true}', "application/json"),
                "/allow-cell": (200, b'{"ok":true}', "application/json"),
                "/deny-cell": (403, b"", media_type),
            },
            allow_empty=frozenset({"deny-cell"}),
        )
        result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
        assert result.operations[-1].verdict is AuthorizationVerdict.CONFORMS
        assert result.operations[-1].reason is (
            AuthorizationReason.DECLARED_DENY_OBSERVED_DENIAL
        )


def test_empty_allow_validates_media_type_before_body_assertions():
    case, policy, factory = inputs(
        {
            "/control": (200, b'{"ok":true}', "application/json"),
            "/allow-cell": (200, b"", "text/html"),
            "/deny-cell": (403, b'{"error":true}', "application/json"),
        },
        allow_empty=frozenset({"allow-cell"}),
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert result.operations[1].verdict is AuthorizationVerdict.INCONCLUSIVE
    assert result.operations[1].reason is AuthorizationReason.MEDIA_TYPE_MISMATCH


def test_empty_allow_with_matching_media_type_conforms():
    case, policy, factory = inputs(
        {
            "/control": (200, b'{"ok":true}', "application/json"),
            "/allow-cell": (200, b"", "application/json"),
            "/deny-cell": (403, b'{"error":true}', "application/json"),
        },
        allow_empty=frozenset({"allow-cell"}),
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert result.operations[1].verdict is AuthorizationVerdict.CONFORMS
    assert result.operations[1].reason is (
        AuthorizationReason.DECLARED_ALLOW_OBSERVED_SUCCESS
    )


def test_timeout_while_reading_body_is_transport_timeout():
    request = httpx.Request("GET", "https://runner.invalid/deny-cell")
    case, policy, factory = inputs(
        {
            "/control": (200, b'{"ok":true}', "application/json"),
            "/allow-cell": (200, b'{"ok":true}', "application/json"),
            "/deny-cell": (
                403,
                FailingStream(httpx.ReadTimeout("timed out", request=request)),
                "application/json",
            ),
        }
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert result.operations[-1].reason is AuthorizationReason.TRANSPORT_TIMEOUT


def test_early_eof_while_reading_body_is_response_truncated():
    request = httpx.Request("GET", "https://runner.invalid/deny-cell")
    case, policy, factory = inputs(
        {
            "/control": (200, b'{"ok":true}', "application/json"),
            "/allow-cell": (200, b'{"ok":true}', "application/json"),
            "/deny-cell": (
                403,
                FailingStream(httpx.ReadError("early EOF", request=request)),
                "application/json",
            ),
        }
    )
    result = _run_authorization_case(case, policy, {}, _execution_factory=factory)
    assert result.operations[-1].reason is AuthorizationReason.RESPONSE_TRUNCATED


def test_reason_codes_are_closed_and_have_one_fixed_verdict():
    assert set(AUTHORIZATION_REASON_VERDICTS) == set(AuthorizationReason)
    for reason, verdict in AUTHORIZATION_REASON_VERDICTS.items():
        assert type(reason) is AuthorizationReason
        assert type(verdict) is AuthorizationVerdict


def test_production_modules_never_set_the_test_execution_factory():
    source_root = Path("src/vintar")
    offenders = []
    for path in source_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if (
                any(keyword.arg == "_execution_factory" for keyword in node.keywords)
                and path != source_root / "regression" / "authorization_runner.py"
            ):
                offenders.append(path)
    assert offenders == []


def test_only_authorization_runner_imports_execution_composition():
    importers = []
    for path in Path("src/vintar").rglob("*.py"):
        if path.name == "authorization_execution.py":
            continue
        source = path.read_text(encoding="utf-8")
        if "vintar.regression.authorization_execution" in source:
            importers.append(path)
    assert importers == [Path("src/vintar/regression/authorization_runner.py")]
