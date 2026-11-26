"""Multi-identity authorization execution composition and isolation."""

import json

import httpx
import pytest

from vintar.regression.authorization_cases import parse_authorization_case
from vintar.regression.authorization_execution import (
    AuthorizationExecution,
    AuthorizationExecutionError,
    _build_authorization_execution,
)
from vintar.regression.authorization_policy import parse_authorization_runtime_policy

CASE = """
version = 1
id = "identity-isolation"
type = "authorization.access"
category = "tenant_isolation"
environment_class = "ci-isolated"

[[identities]]
id = "reader-a"
label = "reader-a"
authentication = "required"
[[identities]]
id = "reader-b"
label = "reader-b"
authentication = "required"
[[identities]]
id = "public-user"
label = "public-user"
authentication = "none"

[[operations]]
id = "reader-a-control"
identity_id = "reader-a"
resource_id = "a"
control = "positive"
expected = "allow"
[operations.request]
method = "GET"
url = "https://api.example.test/a"
allowed_origin = "https://api.example.test"
[operations.assertions]
status_codes = [200]
required_json_pointers = []
forbidden_json_pointers = []
allow_empty_body = true

[[operations]]
id = "reader-b-control"
identity_id = "reader-b"
resource_id = "b"
control = "positive"
expected = "allow"
[operations.request]
method = "GET"
url = "https://api.example.test/b"
allowed_origin = "https://api.example.test"
[operations.assertions]
status_codes = [200]
required_json_pointers = []
forbidden_json_pointers = []
allow_empty_body = true

[[operations]]
id = "public-control"
identity_id = "public-user"
resource_id = "public"
control = "positive"
expected = "allow"
[operations.request]
method = "GET"
url = "https://api.example.test/public"
allowed_origin = "https://api.example.test"
[operations.assertions]
status_codes = [200]
required_json_pointers = []
forbidden_json_pointers = []
allow_empty_body = true
"""


def inputs(*, expires_at: str | None = None):
    case = parse_authorization_case(CASE)
    identities = [
        {
            "identity_id": "reader-a",
            "authentication": "required",
            "credential_kind": "bearer",
            "env_var": "AUTH_A",
            "header_name": "Authorization",
        },
        {
            "identity_id": "reader-b",
            "authentication": "required",
            "credential_kind": "api_key_header",
            "env_var": "AUTH_B",
            "header_name": "X-Reader-B-Key",
        },
        {"identity_id": "public-user", "authentication": "none"},
    ]
    if expires_at is not None:
        identities[0]["expires_at"] = expires_at
    operations = [
        {
            "operation_id": operation.operation_id,
            "identity_id": operation.identity_id,
            "method": operation.request.method,
            "path": operation.request.path,
            "expected": operation.expected.value,
        }
        for operation in case.operations
    ]
    value = {
        "schema_version": 1,
        "policy_type": "authorization_execution",
        "identities": identities,
        "approvals": [
            {
                "case_id": case.case_id,
                "case_sha256": case.case_sha256,
                "origin": "https://api.example.test",
                "environment_class": case.environment_class,
                "operations": operations,
            }
        ],
        "limits": {
            "max_requests": 8,
            "max_requests_per_second": 10,
            "max_timeout_seconds": 1,
            "max_response_size": 1024,
        },
    }
    policy = parse_authorization_runtime_policy(json.dumps(value).encode())
    return case, policy


class StatefulTransport(httpx.BaseTransport):
    def __init__(self, identity_id: str) -> None:
        self.identity_id = identity_id
        self.requests: list[httpx.Request] = []
        self.close_count = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        headers = {}
        if self.identity_id == "reader-a" and len(self.requests) == 1:
            headers["Set-Cookie"] = "session=a-only; Path=/"
        return httpx.Response(200, headers=headers, content=b"{}", request=request)

    def close(self) -> None:
        self.close_count += 1


class CountingEnvironment(dict[str, str]):
    def __init__(self) -> None:
        super().__init__(AUTH_A="secret-a", AUTH_B="secret-b")
        self.reads: list[str] = []

    def __getitem__(self, name: str) -> str:
        self.reads.append(name)
        return super().__getitem__(name)


def execution() -> tuple[
    AuthorizationExecution, dict[str, StatefulTransport], CountingEnvironment
]:
    case, policy = inputs()
    transports: dict[str, StatefulTransport] = {}

    def factory(identity_id: str) -> httpx.BaseTransport:
        transport = StatefulTransport(identity_id)
        transports[identity_id] = transport
        return transport

    environment = CountingEnvironment()
    composed = _build_authorization_execution(
        case,
        policy,
        environment,
        transport_factory=factory,
        clock=lambda: 0.0,
    )
    return composed, transports, environment


def test_builds_isolated_clients_cookie_jars_transports_and_pools():
    composed, transports, environment = execution()
    with composed as active:
        clients = [identity.client for identity in active.identities]
        assert len({id(client) for client in clients}) == 3
        assert len({id(client.cookies) for client in clients}) == 3
        assert len({id(identity.transport) for identity in active.identities}) == 3
        assert len({id(item) for item in transports.values()}) == 3
        assert environment.reads == ["AUTH_A", "AUTH_B"]
        assert active.reserved_headers == {"authorization", "x-reader-b-key"}
        assert active.budget is active.budget
        assert active.rate_limiter is active.rate_limiter
    assert all(transport.close_count == 1 for transport in transports.values())


def test_cookie_credentials_and_pool_state_never_cross_identities():
    composed, transports, _environment = execution()
    with composed as active:
        active.client_for("reader-a").get("https://api.example.test/a")
        active.client_for("reader-a").get("https://api.example.test/a")
        active.client_for("reader-b").get("https://api.example.test/b")
        active.client_for("public-user").get("https://api.example.test/public")
    a_first, a_second = transports["reader-a"].requests
    [b_request] = transports["reader-b"].requests
    [public_request] = transports["public-user"].requests
    assert a_first.headers["Authorization"] == "Bearer secret-a"
    assert "session=a-only" in a_second.headers["Cookie"]
    assert b_request.headers["X-Reader-B-Key"] == "secret-b"
    assert "Authorization" not in b_request.headers
    assert "Cookie" not in b_request.headers
    assert "Authorization" not in public_request.headers
    assert "X-Reader-B-Key" not in public_request.headers
    assert "Cookie" not in public_request.headers


@pytest.mark.parametrize(
    ("identity_id", "method", "url"),
    [
        ("reader-a", "GET", "https://api.example.test/different"),
        ("reader-a", "POST", "https://api.example.test/a"),
        ("reader-a", "GET", "https://api.example.test/a?query=different"),
        ("reader-a", "GET", "https://api.example.test/a/"),
        ("reader-a", "GET", "https://api.example.test/%61"),
        ("reader-b", "GET", "https://api.example.test/a"),
    ],
)
def test_dispatch_rejects_every_unapproved_identity_method_or_raw_target(
    identity_id, method, url
):
    composed, transports, _environment = execution()
    observed: list[httpx.Request] = []
    with composed as active:
        client = active.client_for(identity_id)
        client.event_hooks["request"].append(observed.append)
        with pytest.raises(AuthorizationExecutionError) as caught:
            client.request(method, url)
    assert str(caught.value) == (
        "authorization_operation_unapproved: Why: the final request is not an "
        "exact operation approved for this identity. Instead: dispatch only the "
        "approved method, origin, and byte-preserved request target through its "
        "bound identity."
    )
    assert len(observed) == 1
    assert "Authorization" not in observed[0].headers
    assert "X-Reader-B-Key" not in observed[0].headers
    assert all(not transport.requests for transport in transports.values())


@pytest.mark.parametrize("identity_id", ["reader-a", "reader-b", "public-user"])
def test_run_wide_reserved_union_rejects_client_default_collision(identity_id):
    composed, transports, _environment = execution()
    approved_url = {
        "reader-a": "https://api.example.test/a",
        "reader-b": "https://api.example.test/b",
        "public-user": "https://api.example.test/public",
    }[identity_id]
    with composed as active:
        active.client_for(identity_id).headers["X-Reader-B-Key"] = "collision-canary"
        with pytest.raises(AuthorizationExecutionError) as caught:
            active.client_for(identity_id).get(approved_url)
    assert str(caught.value).startswith("auth_collision:")
    assert "collision-canary" not in str(caught.value)
    assert all(not transport.requests for transport in transports.values())


def test_preflight_failure_reads_no_credentials_and_builds_no_transport():
    case, policy = inputs()
    policy = type(policy)(
        policy.schema_version,
        policy.policy_type,
        policy.identities,
        policy.approvals,
        type(policy.limits)(2, 10, 1, 1024),
    )
    environment = CountingEnvironment()
    created: list[str] = []
    with pytest.raises(
        AuthorizationExecutionError,
        match="authorization_request_budget_insufficient",
    ):
        _build_authorization_execution(
            case,
            policy,
            environment,
            transport_factory=lambda identity: created.append(identity),
            clock=lambda: 0.0,
        )
    assert environment.reads == []
    assert created == []


def test_auth_error_is_fixed_and_redacts_source_name_and_value():
    case, policy = inputs()
    with pytest.raises(AuthorizationExecutionError) as caught:
        _build_authorization_execution(
            case,
            policy,
            {"AUTH_A": "secret-a"},
            transport_factory=lambda identity: StatefulTransport(identity),
            clock=lambda: 0.0,
        )
    diagnostic = str(caught.value)
    assert diagnostic.startswith("auth_material_unavailable:")
    assert "AUTH_B" not in diagnostic
    assert "secret-a" not in diagnostic
    assert "api.example.test" not in diagnostic


def test_shared_schedule_covers_all_identities_and_rate_waits():
    composed, _transports, _environment = execution()
    with composed as active:
        assert active.schedule.requests_per_second == 10
        assert active.schedule.planned_max_run_seconds == pytest.approx(3.2)


def test_context_close_is_idempotent():
    composed, transports, _environment = execution()
    composed.close()
    composed.close()
    assert all(transport.close_count == 1 for transport in transports.values())
