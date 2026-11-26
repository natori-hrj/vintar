"""Credential resolution and the isolated authentication application boundary."""

import base64
import copy
import json
import logging
import pickle
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from vintar.auth.apply import (
    EXPIRY_SAFETY_MARGIN_SECONDS,
    AuthenticationError,
    CredentialBinding,
    PlannedAuthenticatedRequest,
    apply_authentication,
    preflight_authentication,
    resolve_credentials,
)
from vintar.auth.contracts import CredentialKind, IdentityCredentialSource
from vintar.core.request import RequestTemplate
from vintar.core.scope import AllowedOrigin

NOW = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
ORIGIN = AllowedOrigin("https", "api.example", 443)
CANARY = "vintar-secret-canary"


def source(
    kind: CredentialKind = CredentialKind.BEARER,
    *,
    identity: str = "reader",
    env_var: str = "VINTAR_READER_TOKEN",
    header: str = "Authorization",
    expires_at: datetime | None = None,
) -> IdentityCredentialSource:
    return IdentityCredentialSource(identity, kind, env_var, header, expires_at)


def binding(item: IdentityCredentialSource | None = None) -> CredentialBinding:
    return CredentialBinding(item or source(), frozenset({ORIGIN}))


def plan(
    item: CredentialBinding | None = None,
    *,
    templates: tuple[RequestTemplate, ...] | None = None,
    now: datetime = NOW,
):
    return preflight_authentication(
        (item or binding(),),
        tuple(
            PlannedAuthenticatedRequest("reader", template)
            for template in (
                templates or (RequestTemplate("POST", "https://api.example/items"),)
            )
        ),
        planned_max_run_seconds=30,
        now=now,
    )


@pytest.mark.parametrize(
    ("kind", "raw", "header", "expected"),
    [
        (CredentialKind.BEARER, CANARY, "Authorization", f"Bearer {CANARY}"),
        (CredentialKind.API_KEY_HEADER, CANARY, "X-API-Key", CANARY),
        (
            CredentialKind.BASIC,
            "usér:päss",
            "Authorization",
            "Basic " + base64.b64encode("usér:päss".encode()).decode("ascii"),
        ),
    ],
)
def test_applies_each_closed_credential_kind_at_dispatch(kind, raw, header, expected):
    selected = binding(source(kind, header=header))
    run = resolve_credentials(plan(selected), {selected.source.env_var: raw}, now=NOW)
    request = httpx.Request(
        "POST",
        "https://api.example/items?fixed=yes",
        headers={"X-Case": "kept"},
        content=b'{"probe":"kept"}',
    )
    before = (request.method, request.url, request.content, request.headers["X-Case"])

    apply_authentication(request, run, identity_id="reader")

    assert request.headers[header] == expected
    assert (
        request.method,
        request.url,
        request.content,
        request.headers["X-Case"],
    ) == before


class CountingEnvironment(dict[str, str]):
    def __init__(self, values):
        super().__init__(values)
        self.reads: list[str] = []

    def __getitem__(self, name):
        self.reads.append(name)
        return super().__getitem__(name)


def test_reads_each_approved_environment_name_once_after_preflight():
    environment = CountingEnvironment({"VINTAR_READER_TOKEN": CANARY})
    prepared = plan()
    assert environment.reads == []

    run = resolve_credentials(prepared, environment, now=NOW)
    first = httpx.Request("GET", "https://api.example/one")
    second = httpx.Request("GET", "https://api.example/two")
    apply_authentication(first, run, identity_id="reader")
    apply_authentication(second, run, identity_id="reader")

    assert environment.reads == ["VINTAR_READER_TOKEN"]


def test_shared_environment_name_is_rejected_before_reading_secret():
    first = binding()
    second = binding(source(identity="writer"))
    environment = CountingEnvironment({"VINTAR_READER_TOKEN": CANARY})
    with pytest.raises(
        AuthenticationError, match=r"one secret source.*multiple identities"
    ):
        preflight_authentication(
            (first, second),
            (
                PlannedAuthenticatedRequest(
                    "reader", RequestTemplate("GET", "https://api.example/")
                ),
            ),
            planned_max_run_seconds=1,
            now=NOW,
        )
    assert environment.reads == []


def test_expiry_covers_the_whole_plan_and_fixed_margin_strictly():
    boundary = NOW + timedelta(seconds=30 + EXPIRY_SAFETY_MARGIN_SECONDS)
    with pytest.raises(AuthenticationError, match="auth_material_expired"):
        plan(binding(source(expires_at=boundary)))
    assert plan(binding(source(expires_at=boundary + timedelta(microseconds=1))))
    with pytest.raises(AuthenticationError, match="auth_material_expired"):
        resolve_credentials(
            plan(binding(source(expires_at=boundary + timedelta(seconds=1)))),
            {"VINTAR_READER_TOKEN": CANARY},
            now=NOW + timedelta(seconds=2),
        )


def test_naive_expiry_and_preflight_origin_mismatch_fail_before_resolution():
    with pytest.raises(AuthenticationError, match="timezone-aware"):
        plan(binding(source(expires_at=datetime(2030, 1, 2, 4, 0, 0))))
    with pytest.raises(AuthenticationError, match="auth_origin_mismatch"):
        plan(templates=(RequestTemplate("GET", "https://other.example/unapproved"),))


@pytest.mark.parametrize(
    "template",
    [
        RequestTemplate(
            "GET", "https://api.example/", headers=(("authorization", "case"),)
        ),
        RequestTemplate(
            "GET",
            "https://api.example/",
            headers=(("X-API-Key", "one"), ("x-api-key", "two")),
        ),
    ],
)
def test_preflight_rejects_reserved_and_duplicate_fields_without_reading(template):
    selected = binding(source(CredentialKind.API_KEY_HEADER, header="X-API-Key"))
    with pytest.raises(AuthenticationError, match="auth_collision"):
        plan(selected, templates=(template,))


@pytest.mark.parametrize(
    "raw",
    ["", " token", "token ", "line\nbreak", "line\x00break"],
)
def test_missing_empty_and_malformed_bearer_fail_without_value_details(raw):
    environment = {} if raw == "" else {"VINTAR_READER_TOKEN": raw}
    if raw == "":
        environment = {"VINTAR_READER_TOKEN": raw}
    with pytest.raises(AuthenticationError) as caught:
        resolve_credentials(plan(), environment, now=NOW)
    diagnostic = str(caught.value)
    assert raw not in diagnostic or raw == ""
    assert "Why:" in diagnostic
    assert "Instead:" in diagnostic


def test_missing_diagnostic_may_name_only_the_approved_environment_variable():
    with pytest.raises(AuthenticationError) as caught:
        resolve_credentials(plan(), {}, now=NOW)
    assert "VINTAR_READER_TOKEN" in str(caught.value)
    assert CANARY not in str(caught.value)


@pytest.mark.parametrize(
    "raw", ["unique-user-no-separator", ":unique-password", "unique-user:"]
)
def test_basic_requires_non_empty_username_and_password(raw):
    selected = binding(source(CredentialKind.BASIC))
    with pytest.raises(AuthenticationError, match="username:password") as caught:
        resolve_credentials(plan(selected), {selected.source.env_var: raw}, now=NOW)
    assert raw not in str(caught.value)


def test_secret_objects_reject_text_comparison_hash_copy_and_serialization():
    run = resolve_credentials(plan(), {"VINTAR_READER_TOKEN": CANARY}, now=NOW)
    secret = run._credentials[0].value
    assert repr(secret) == "<credential redacted>"
    operations = (
        lambda: str(secret),
        lambda: f"{secret}",
        lambda: secret == object(),
        lambda: hash(secret),
        lambda: copy.copy(secret),
        lambda: copy.deepcopy(secret),
        lambda: pickle.dumps(secret),
        lambda: json.dumps(secret),
        lambda: str(ValueError(secret)),
        lambda: logging.LogRecord(
            "auth-test", logging.ERROR, __file__, 1, "credential=%s", (secret,), None
        ).getMessage(),
    )
    for operation in operations:
        with pytest.raises(TypeError) as caught:
            operation()
        assert CANARY not in repr(caught.value)


def test_canaries_do_not_leak_from_auth_objects_or_failures():
    basic = "canary-user:canary-password"
    derived = base64.b64encode(basic.encode()).decode()
    selected = binding(source(CredentialKind.BASIC))
    run = resolve_credentials(plan(selected), {selected.source.env_var: basic}, now=NOW)
    request = httpx.Request("GET", "https://other.example/")
    with pytest.raises(AuthenticationError) as caught:
        apply_authentication(request, run, identity_id="reader")
    surfaces = (
        repr(run),
        str(caught.value),
        repr(caught.value),
        repr(caught.value.args),
    )
    assert all(basic not in surface and derived not in surface for surface in surfaces)


def test_exact_origin_and_final_collision_are_rechecked_before_application():
    run = resolve_credentials(plan(), {"VINTAR_READER_TOKEN": CANARY}, now=NOW)
    with pytest.raises(AuthenticationError, match="auth_origin_mismatch"):
        apply_authentication(
            httpx.Request("GET", "https://api.example:444/"),
            run,
            identity_id="reader",
        )
    with pytest.raises(AuthenticationError, match="auth_collision"):
        apply_authentication(
            httpx.Request(
                "GET", "https://api.example/", headers={"AUTHORIZATION": "case"}
            ),
            run,
            identity_id="reader",
        )


def test_redirect_response_is_not_followed_or_reapplied():
    run = resolve_credentials(plan(), {"VINTAR_READER_TOKEN": CANARY}, now=NOW)
    requests: list[httpx.Request] = []

    def handler(request):
        requests.append(request)
        return httpx.Response(302, headers={"location": "https://other.example/"})

    request = httpx.Request("GET", "https://api.example/")
    apply_authentication(request, run, identity_id="reader")
    with httpx.Client(
        transport=httpx.MockTransport(handler), follow_redirects=False
    ) as client:
        response = client.send(request)
    assert response.status_code == 302
    assert len(requests) == 1
    assert requests[0].url.host == "api.example"
