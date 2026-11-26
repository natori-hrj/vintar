"""Strict offline parser for explicit authorization Case Schema v1."""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, cast

import httpx

from vintar.checks.authorization.models import (
    AuthenticationMode,
    AuthorizationExpectation,
    ControlKind,
    ResponseAssertions,
)
from vintar.core.json_body import JsonPointer
from vintar.core.scope import AllowedOrigin
from vintar.regression.file_io import (
    NoFollowUnavailableError,
    read_bounded_regular_file,
)

AUTHORIZATION_CASE_VERSION = 1
MAX_AUTHORIZATION_CASE_BYTES = 65_536
AUTHORIZATION_CASE_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "authorization-case-v1.schema.json"
)


class AuthorizationCaseValidationError(ValueError):
    """A stable diagnostic that never echoes case data."""


def _fail(code: str, why: str, instead: str) -> AuthorizationCaseValidationError:
    return AuthorizationCaseValidationError(f"{code}: Why: {why} Instead: {instead}")


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationIdentity:
    identity_id: str
    label: str
    authentication: AuthenticationMode


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationRequest:
    method: str
    url: str
    origin: AllowedOrigin
    path: str


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationOperation:
    operation_id: str
    identity_id: str
    resource_id: str
    control: ControlKind
    expected: AuthorizationExpectation
    request: AuthorizationRequest
    assertions: ResponseAssertions


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationCase:
    schema_version: int
    case_id: str
    check_type: str
    category: str
    environment_class: str
    identities: tuple[AuthorizationIdentity, ...]
    operations: tuple[AuthorizationOperation, ...]
    case_sha256: str


def _origin(url: httpx.URL) -> AllowedOrigin:
    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.username
        or url.password
    ):
        raise ValueError
    return AllowedOrigin(
        url.scheme, url.host, url.port or (443 if url.scheme == "https" else 80)
    )


def _assertions(
    value: dict[str, object], expected: AuthorizationExpectation
) -> ResponseAssertions:
    status_codes = tuple(cast(list[int], value["status_codes"]))
    required = tuple(cast(list[str], value["required_json_pointers"]))
    forbidden = tuple(cast(list[str], value["forbidden_json_pointers"]))
    media_type = cast(str | None, value.get("media_type"))
    allow_empty = cast(bool, value["allow_empty_body"])
    for pointer in required + forbidden:
        JsonPointer.parse(pointer)
    if expected is AuthorizationExpectation.DENY:
        if any(200 <= code <= 299 for code in status_codes):
            raise _fail(
                "authorization_deny_success_status_unsupported",
                "authorization Case v1 cannot represent denial as a 2xx response, including an empty result.",
                "use an explicit non-2xx denial contract or defer this case to a future schema.",
            )
        if not forbidden and not allow_empty:
            raise _fail(
                "authorization_deny_body_assertion_required",
                "a denial operation has no protected-field absence assertion and does not explicitly allow an empty body.",
                "declare at least one forbidden_json_pointer or set allow_empty_body to true after review.",
            )
    return ResponseAssertions(
        status_codes, media_type, required, forbidden, allow_empty
    )


def parse_authorization_case_mapping(value: object) -> AuthorizationCase:
    """Validate a decoded mapping without performing network operations."""
    try:
        schema = json.loads(AUTHORIZATION_CASE_SCHEMA.read_text(encoding="utf-8"))
        validator = cast(Any, import_module("jsonschema")).Draft202012Validator(schema)
        if (
            next(validator.iter_errors(value), None) is not None
            or type(value) is not dict
        ):
            raise ValueError
        root = cast(dict[str, object], value)
        identities = tuple(
            AuthorizationIdentity(
                cast(str, item["id"]),
                cast(str, item["label"]),
                AuthenticationMode(cast(str, item["authentication"])),
            )
            for item in cast(list[dict[str, object]], root["identities"])
        )
        identity_ids = {identity.identity_id for identity in identities}
        if len(identity_ids) != len(identities):
            raise ValueError
        operations: list[AuthorizationOperation] = []
        operation_ids: set[str] = set()
        for item in cast(list[dict[str, object]], root["operations"]):
            operation_id = cast(str, item["id"])
            if operation_id in operation_ids or item["identity_id"] not in identity_ids:
                raise ValueError
            operation_ids.add(operation_id)
            expected = AuthorizationExpectation(cast(str, item["expected"]))
            control = ControlKind(cast(str, item["control"]))
            if (
                control is ControlKind.POSITIVE
                and expected is not AuthorizationExpectation.ALLOW
            ):
                raise ValueError
            request = cast(dict[str, object], item["request"])
            parsed = httpx.URL(cast(str, request["url"]))
            approved = httpx.URL(cast(str, request["allowed_origin"]))
            origin = _origin(approved)
            if (
                approved.path not in {"", "/"}
                or approved.query
                or approved.fragment
                or _origin(parsed) != origin
            ):
                raise ValueError
            raw_path = parsed.raw_path.decode("ascii")
            if parsed.query or parsed.fragment or "{" in raw_path or "}" in raw_path:
                raise ValueError
            operations.append(
                AuthorizationOperation(
                    operation_id,
                    item["identity_id"],
                    cast(str, item["resource_id"]),
                    control,
                    expected,
                    AuthorizationRequest(
                        "GET", cast(str, request["url"]), origin, raw_path
                    ),
                    _assertions(cast(dict[str, object], item["assertions"]), expected),
                )
            )
        used_pairs = {
            (operation.identity_id, operation.request.origin)
            for operation in operations
        }
        controls = {
            (operation.identity_id, operation.request.origin)
            for operation in operations
            if operation.control is ControlKind.POSITIVE
        }
        used_identity_ids = {identity_id for identity_id, _origin_value in used_pairs}
        if used_pairs != controls or used_identity_ids != identity_ids:
            raise _fail(
                "authorization_positive_control_required",
                "every identity and exact origin used by the case must have its own positive control, including unauthenticated identities.",
                "add one reviewed public positive control for each unauthenticated identity and one authenticated control for every other identity-origin pair.",
            )
        canonical = json.dumps(
            root,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return AuthorizationCase(
            AUTHORIZATION_CASE_VERSION,
            cast(str, root["id"]),
            "authorization.access",
            cast(str, root["category"]),
            cast(str, root["environment_class"]),
            identities,
            tuple(operations),
            hashlib.sha256(canonical).hexdigest(),
        )
    except AuthorizationCaseValidationError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError, OSError):
        raise _fail(
            "authorization_case_schema_invalid",
            "the case does not match the closed authorization Case v1 contract.",
            "supply only explicit reviewed identities, GET operations, literal paths, controls, and bounded assertions.",
        ) from None


def parse_authorization_case(source: str) -> AuthorizationCase:
    if (
        type(source) is not str
        or len(source.encode("utf-8")) > MAX_AUTHORIZATION_CASE_BYTES
    ):
        raise _fail(
            "authorization_case_source_invalid",
            "the case source is invalid or too large.",
            "supply one bounded UTF-8 TOML case.",
        )
    try:
        return parse_authorization_case_mapping(tomllib.loads(source))
    except AuthorizationCaseValidationError:
        raise
    except (tomllib.TOMLDecodeError, ValueError, UnicodeError):
        raise _fail(
            "authorization_case_source_invalid",
            "the case is not valid bounded TOML.",
            "supply one authorization Case v1 TOML document.",
        ) from None


def load_authorization_case(path: str | Path) -> AuthorizationCase:
    """Read one bounded regular UTF-8 case file without following symlinks."""
    try:
        data = read_bounded_regular_file(Path(path), MAX_AUTHORIZATION_CASE_BYTES)
        return parse_authorization_case(data.decode("utf-8"))
    except AuthorizationCaseValidationError:
        raise
    except NoFollowUnavailableError:
        raise _fail(
            "authorization_case_unreadable",
            "this platform cannot open case files without following symlinks.",
            "supply a case on a platform with O_NOFOLLOW support.",
        ) from None
    except (OSError, TypeError, ValueError, UnicodeError):
        raise _fail(
            "authorization_case_unreadable",
            "the selected case is not a bounded regular UTF-8 file.",
            "select one reviewed authorization Case v1 file.",
        ) from None
