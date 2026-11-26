"""Offline authorization Case v1 contracts."""

import pytest

from vintar.regression.authorization_cases import (
    AuthorizationCaseValidationError,
    load_authorization_case,
    parse_authorization_case,
)
from vintar.regression.cases import (
    AuthorizationExecutionUnavailableError,
    parse_regression_case,
)

CASE = """
version = 1
id = "tenant-document-read"
type = "authorization.access"
category = "tenant_isolation"
environment_class = "ci-isolated"

[[identities]]
id = "tenant-a-reader"
label = "reader-a"
authentication = "required"

[[identities]]
id = "public-user"
label = "public-user"
authentication = "none"

[[operations]]
id = "tenant-a-control"
identity_id = "tenant-a-reader"
resource_id = "own-document"
control = "positive"
expected = "allow"
[operations.request]
method = "GET"
url = "https://placeholder.invalid/documents/own"
allowed_origin = "https://placeholder.invalid"
[operations.assertions]
status_codes = [200]
media_type = "application/json"
required_json_pointers = ["/document"]
forbidden_json_pointers = []
allow_empty_body = false

[[operations]]
id = "tenant-a-deny"
identity_id = "tenant-a-reader"
resource_id = "other-document"
control = "negative"
expected = "deny"
[operations.request]
method = "GET"
url = "https://placeholder.invalid/documents/other"
allowed_origin = "https://placeholder.invalid"
[operations.assertions]
status_codes = [403, 404]
media_type = "application/json"
required_json_pointers = []
forbidden_json_pointers = ["/document"]
allow_empty_body = false

[[operations]]
id = "public-control"
identity_id = "public-user"
resource_id = "health"
control = "positive"
expected = "allow"
[operations.request]
method = "GET"
url = "https://placeholder.invalid/health"
allowed_origin = "https://placeholder.invalid"
[operations.assertions]
status_codes = [200]
required_json_pointers = []
forbidden_json_pointers = []
allow_empty_body = true
"""


def test_case_parses_explicit_identities_controls_and_literal_gets():
    case = parse_authorization_case(CASE)
    assert case.check_type == "authorization.access"
    assert len(case.identities) == 2
    assert len(case.operations) == 3
    assert len(case.case_sha256) == 64
    assert "placeholder.invalid" not in repr(case)


def test_case_digest_is_deterministic():
    assert (
        parse_authorization_case(CASE).case_sha256
        == parse_authorization_case(CASE).case_sha256
    )


def test_case_loader_accepts_regular_file_and_rejects_symlink(tmp_path):
    case_file = tmp_path / "authorization.toml"
    case_file.write_text(CASE, encoding="utf-8")
    assert load_authorization_case(case_file).case_id == "tenant-document-read"

    link = tmp_path / "authorization-link.toml"
    link.symlink_to(case_file)
    with pytest.raises(
        AuthorizationCaseValidationError, match="authorization_case_unreadable"
    ):
        load_authorization_case(link)


def test_case_preserves_percent_encoded_literal_path():
    source = CASE.replace("/documents/own", "/documents/own%20document")
    assert (
        parse_authorization_case(source).operations[0].request.path
        == "/documents/own%20document"
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://placeholder.invalid/{id}",
        "https://placeholder.invalid/items/{id}/x",
        "https://placeholder.invalid/%7Bid%7D",
        "https://placeholder.invalid/%7bid%7d",
    ],
)
def test_case_rejects_plain_and_encoded_path_templates(url):
    source = CASE.replace(
        "https://placeholder.invalid/documents/own",
        url,
        1,
    )
    with pytest.raises(
        AuthorizationCaseValidationError,
        match="authorization_case_path_template_unsupported",
    ) as caught:
        parse_authorization_case(source)
    assert url not in str(caught.value)


def test_case_origin_defaults_only_when_port_is_absent():
    implicit_https = parse_authorization_case(CASE).operations[0].request.origin
    explicit_https = (
        parse_authorization_case(
            CASE.replace(
                "https://placeholder.invalid", "https://placeholder.invalid:443"
            )
        )
        .operations[0]
        .request.origin
    )
    implicit_http = (
        parse_authorization_case(
            CASE.replace("https://placeholder.invalid", "http://placeholder.invalid")
        )
        .operations[0]
        .request.origin
    )
    explicit_http = (
        parse_authorization_case(
            CASE.replace("https://placeholder.invalid", "http://placeholder.invalid:80")
        )
        .operations[0]
        .request.origin
    )

    assert implicit_https == explicit_https
    assert implicit_https.port == 443
    assert implicit_http == explicit_http
    assert implicit_http.port == 80


@pytest.mark.parametrize("port", ["0", "65536"])
def test_case_rejects_out_of_range_origin_port_with_fixed_diagnostic(port):
    source = CASE.replace(
        "https://placeholder.invalid",
        f"https://placeholder.invalid:{port}",
    )
    with pytest.raises(
        AuthorizationCaseValidationError,
        match="authorization_case_origin_port_invalid",
    ) as caught:
        parse_authorization_case(source)
    assert port not in str(caught.value)


def test_case_invalid_url_is_redacted_without_exception_chaining():
    offending = "not-a-port-canary"
    source = CASE.replace(
        "https://placeholder.invalid",
        f"https://placeholder.invalid:{offending}",
    )
    expected = (
        "authorization_case_schema_invalid: Why: the case does not match the closed "
        "authorization Case v1 contract. Instead: supply only explicit reviewed "
        "identities, GET operations, literal paths, controls, and bounded assertions."
    )
    with pytest.raises(AuthorizationCaseValidationError) as caught:
        parse_authorization_case(source)
    assert str(caught.value) == expected
    assert offending not in str(caught.value)
    assert offending not in repr(caught.value)
    assert caught.value.__cause__ is None

    with pytest.raises(AuthorizationExecutionUnavailableError) as cli_error:
        parse_regression_case(source)
    assert offending not in str(cli_error.value)


@pytest.mark.parametrize("alias", ["Uppercase", "contains.dot", "contains space", ""])
def test_aliases_are_closed_lowercase_non_identifying_tokens(alias):
    source = CASE.replace('id = "tenant-document-read"', f'id = "{alias}"', 1)
    with pytest.raises(
        AuthorizationCaseValidationError, match="authorization_case_schema_invalid"
    ):
        parse_authorization_case(source)


def test_deny_cannot_use_2xx_even_for_an_empty_result():
    source = CASE.replace("status_codes = [403, 404]", "status_codes = [200]")
    with pytest.raises(
        AuthorizationCaseValidationError,
        match="authorization_deny_success_status_unsupported",
    ):
        parse_authorization_case(source)


def test_deny_requires_body_assertion_or_explicit_empty_body():
    source = CASE.replace(
        'forbidden_json_pointers = ["/document"]', "forbidden_json_pointers = []"
    )
    with pytest.raises(
        AuthorizationCaseValidationError,
        match="authorization_deny_body_assertion_required",
    ):
        parse_authorization_case(source)

    accepted = source.replace(
        'status_codes = [403, 404]\nmedia_type = "application/json"\nrequired_json_pointers = []\nforbidden_json_pointers = []\nallow_empty_body = false',
        'status_codes = [403, 404]\nmedia_type = "application/json"\nrequired_json_pointers = []\nforbidden_json_pointers = []\nallow_empty_body = true',
    )
    assert parse_authorization_case(accepted).operations[1].assertions.allow_empty_body


def test_every_identity_origin_pair_requires_its_own_positive_control():
    source = CASE.replace(
        "https://placeholder.invalid/documents/other",
        "https://second.invalid/documents/other",
    ).replace(
        'allowed_origin = "https://placeholder.invalid"\n[operations.assertions]\nstatus_codes = [403, 404]',
        'allowed_origin = "https://second.invalid"\n[operations.assertions]\nstatus_codes = [403, 404]',
        1,
    )
    with pytest.raises(
        AuthorizationCaseValidationError,
        match="authorization_positive_control_required",
    ):
        parse_authorization_case(source)


def test_unauthenticated_identity_also_requires_positive_control():
    source = CASE.rsplit("[[operations]]", 1)[0]
    with pytest.raises(
        AuthorizationCaseValidationError,
        match="authorization_positive_control_required",
    ):
        parse_authorization_case(source)


def test_existing_regression_execution_loader_fails_closed_with_dedicated_reason():
    with pytest.raises(
        AuthorizationExecutionUnavailableError,
        match="authorization_execution_unavailable",
    ):
        parse_regression_case(CASE)
