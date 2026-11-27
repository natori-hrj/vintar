"""Loopback-only E2E for the internal authorization GET runner."""

import base64
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from vintar.checks.authorization.models import AuthorizationReason
from vintar.regression.authorization_cases import parse_authorization_case
from vintar.regression.authorization_execution import build_authorization_execution
from vintar.regression.authorization_policy import parse_authorization_runtime_policy
from vintar.regression.authorization_runner import (
    _run_authorization_case,
    run_authorization_case,
)


class AuthorizationHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    records: ClassVar[list[tuple[str, str | None, str | None, str | None]]] = []

    def do_GET(self) -> None:
        authorization = self.headers.get("Authorization")
        api_key = self.headers.get("X-API-Key")
        cookie = self.headers.get("Cookie")
        self.records.append((self.path, authorization, api_key, cookie))
        status = 200
        body = b'{"ok":true}'
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.path.startswith("/bearer-"):
            if authorization != "Bearer bearer-value":
                status, body = 401, b'{"error":true}'
            elif self.path == "/bearer-control":
                headers["Set-Cookie"] = "session=bearer; Path=/"
            elif self.path == "/bearer-deny":
                body = b'{"secret":true}'
        elif self.path.startswith("/api-"):
            if api_key != "api-value":
                status, body = 401, b'{"error":true}'
            elif self.path == "/api-control":
                headers["Set-Cookie"] = "session=api; Path=/"
            else:
                status, body = 403, b'{"error":true}'
        elif self.path.startswith("/basic-"):
            expected = base64.b64encode(b"basic-user:basic-password").decode()
            if authorization != f"Basic {expected}":
                status, body = 401, b'{"error":true}'
            elif self.path == "/basic-control":
                headers["Set-Cookie"] = "session=basic; Path=/"
            else:
                status, body = 403, b'{"error":true}'
        elif self.path == "/public-deny":
            status, body = 404, b""
            headers = {}
        elif self.path == "/budget-deny":
            status, body = 403, b'{"error":true}'
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


@contextmanager
def server() -> Iterator[str]:
    AuthorizationHandler.records = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), AuthorizationHandler)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}"
    finally:
        httpd.shutdown()
        thread.join()
        httpd.server_close()


def operation(
    operation_id: str,
    identity_id: str,
    expected: str,
    control: str,
    origin: str,
) -> str:
    denied = expected == "deny"
    statuses = "[403, 404]" if denied else "[200]"
    required = "[]" if denied else '["/ok"]'
    forbidden = (
        "[]" if operation_id == "public-deny" else '["/secret"]' if denied else "[]"
    )
    allow_empty = "true" if operation_id == "public-deny" else "false"
    media = "" if operation_id == "public-deny" else 'media_type = "application/json"\n'
    return f'''\n[[operations]]
id = "{operation_id}"
identity_id = "{identity_id}"
resource_id = "resource"
control = "{control}"
expected = "{expected}"
[operations.request]
method = "GET"
url = "{origin}/{operation_id}"
allowed_origin = "{origin}"
[operations.assertions]
status_codes = {statuses}
{media}required_json_pointers = {required}
forbidden_json_pointers = {forbidden}
allow_empty_body = {allow_empty}
'''


def inputs(origin: str, selected: tuple[str, ...] | None = None):
    definitions = (
        ("bearer-control", "bearer-id", "allow", "positive"),
        ("bearer-deny", "bearer-id", "deny", "negative"),
        ("api-control", "api-id", "allow", "positive"),
        ("api-deny", "api-id", "deny", "negative"),
        ("basic-control", "basic-id", "allow", "positive"),
        ("basic-allow", "basic-id", "allow", "negative"),
        ("public-control", "public-id", "allow", "positive"),
        ("public-deny", "public-id", "deny", "negative"),
    )
    if selected is not None:
        definitions = tuple(item for item in definitions if item[0] in selected)
    used = {item[1] for item in definitions}
    identities = (
        ("bearer-id", "required"),
        ("api-id", "required"),
        ("basic-id", "required"),
        ("public-id", "none"),
    )
    identity_toml = "".join(
        f'''[[identities]]
id = "{identity_id}"
label = "{identity_id}"
authentication = "{authentication}"
'''
        for identity_id, authentication in identities
        if identity_id in used
    )
    case = parse_authorization_case(
        """version = 1
id = "loopback"
type = "authorization.access"
category = "tenant_isolation"
environment_class = "test"
"""
        + identity_toml
        + "".join(operation(*item, origin) for item in definitions)
    )
    policy_identities = []
    credentials = {
        "bearer-id": ("bearer", "BEARER_VALUE", "Authorization"),
        "api-id": ("api_key_header", "API_VALUE", "X-API-Key"),
        "basic-id": ("basic", "BASIC_VALUE", "Authorization"),
    }
    for identity_id, authentication in identities:
        if identity_id not in used:
            continue
        item = {"identity_id": identity_id, "authentication": authentication}
        if identity_id in credentials:
            kind, variable, header = credentials[identity_id]
            item.update(credential_kind=kind, env_var=variable, header_name=header)
        policy_identities.append(item)
    policy = parse_authorization_runtime_policy(
        json.dumps(
            {
                "schema_version": 1,
                "policy_type": "authorization_execution",
                "identities": policy_identities,
                "approvals": [
                    {
                        "case_id": case.case_id,
                        "case_sha256": case.case_sha256,
                        "origin": origin,
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
                    "max_requests": len(case.operations),
                    "max_requests_per_second": 10,
                    "max_timeout_seconds": 1,
                    "max_response_size": 128,
                },
            }
        ).encode()
    )
    return case, policy


ENVIRONMENT = {
    "BEARER_VALUE": "bearer-value",
    "API_VALUE": "api-value",
    "BASIC_VALUE": "basic-user:basic-password",
}


def test_multi_identity_verdicts_and_wire_isolation():
    with server() as origin:
        case, policy = inputs(origin)
        result = run_authorization_case(case, policy, ENVIRONMENT)
    reasons = {item.operation_id: item.reason for item in result.operations}
    assert [record[0] for record in AuthorizationHandler.records] == [
        "/api-control",
        "/api-deny",
        "/basic-control",
        "/basic-allow",
        "/bearer-control",
        "/bearer-deny",
        "/public-control",
        "/public-deny",
    ]
    assert reasons["bearer-deny"] is (
        AuthorizationReason.DECLARED_DENY_OBSERVED_SUCCESS
    )
    assert reasons["api-deny"] is AuthorizationReason.DECLARED_DENY_OBSERVED_DENIAL
    assert reasons["basic-allow"] is AuthorizationReason.DECLARED_ALLOW_OBSERVED_DENY
    assert reasons["public-deny"] is AuthorizationReason.DECLARED_DENY_OBSERVED_DENIAL
    records = {
        path: (authorization, key, cookie)
        for path, authorization, key, cookie in AuthorizationHandler.records
    }
    assert records["/bearer-deny"] == ("Bearer bearer-value", None, "session=bearer")
    assert records["/api-deny"] == (None, "api-value", "session=api")
    assert records["/basic-allow"][0].startswith("Basic ")
    assert records["/basic-allow"][1:] == (None, "session=basic")
    assert records["/public-deny"] == (None, None, None)


def test_failed_control_keeps_allow_inconclusive_and_does_not_send_deny():
    with server() as origin:
        selected = ("bearer-control", "bearer-deny")
        case, policy = inputs(origin, selected)
        result = run_authorization_case(
            case, policy, {"BEARER_VALUE": "rejected-value"}
        )
    assert [item.reason for item in result.operations] == [
        AuthorizationReason.POSITIVE_CONTROL_FAILED,
        AuthorizationReason.POSITIVE_CONTROL_FAILED,
    ]
    assert [record[0] for record in AuthorizationHandler.records] == ["/bearer-control"]


def test_shared_budget_exhaustion_marks_remaining_cell_without_dispatch():
    with server() as origin:
        selected = ("public-control", "public-deny")
        case, policy = inputs(origin, selected)

        def depleted_factory(case_value, policy_value, environ_value):
            execution = build_authorization_execution(
                case_value, policy_value, environ_value
            )
            execution.budget.consume()
            return execution

        result = _run_authorization_case(
            case, policy, {}, _execution_factory=depleted_factory
        )
    assert [item.reason for item in result.operations] == [
        AuthorizationReason.DECLARED_ALLOW_OBSERVED_SUCCESS,
        AuthorizationReason.REQUEST_BUDGET_EXHAUSTED,
    ]
    assert [record[0] for record in AuthorizationHandler.records] == ["/public-control"]
