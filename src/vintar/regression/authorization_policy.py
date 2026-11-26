"""Strict, secret-free authorization_execution runtime policy v1 parser."""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

import httpx

from vintar.auth.contracts import CredentialKind, IdentityCredentialSource
from vintar.checks.authorization.models import (
    AuthenticationMode,
    AuthorizationExpectation,
)
from vintar.core.scope import AllowedOrigin
from vintar.core.strict_json import DuplicateJsonKeyError, parse_strict_json
from vintar.regression.binding import parse_runtime_origin
from vintar.regression.file_io import (
    NoFollowUnavailableError,
    read_bounded_regular_file,
)

MAX_AUTHORIZATION_POLICY_BYTES = 262_144
MAX_AUTHORIZATION_APPROVALS = 128
_ALIAS_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")
_DIGEST_CHARS = frozenset("0123456789abcdef")


class AuthorizationPolicyError(ValueError):
    """A stable policy diagnostic without operator data."""


def _fail(code: str, why: str, instead: str) -> AuthorizationPolicyError:
    return AuthorizationPolicyError(f"{code}: Why: {why} Instead: {instead}")


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationPolicyIdentity:
    identity_id: str
    authentication: AuthenticationMode
    credential_source: IdentityCredentialSource | None


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationOperationApproval:
    operation_id: str
    identity_id: str
    method: str
    path: str
    expected: AuthorizationExpectation


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationCaseApproval:
    case_id: str
    case_sha256: str
    origin: AllowedOrigin
    environment_class: str
    operations: tuple[AuthorizationOperationApproval, ...]


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationPolicyLimits:
    max_requests: int
    max_requests_per_second: float
    max_timeout_seconds: float
    max_response_size: int


@dataclass(frozen=True, slots=True, repr=False)
class AuthorizationRuntimePolicy:
    schema_version: int
    policy_type: str
    identities: tuple[AuthorizationPolicyIdentity, ...]
    approvals: tuple[AuthorizationCaseApproval, ...]
    limits: AuthorizationPolicyLimits


def _closed(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(cast(dict[object, object], value)) != keys:
        raise ValueError
    return cast(dict[str, object], value)


def _text(value: object, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or value != value.strip()
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError
    return value


def _alias(value: object) -> str:
    result = _text(value, 64)
    if any(char not in _ALIAS_CHARS for char in result):
        raise ValueError
    return result


def _digest(value: object) -> str:
    result = _text(value, 64)
    if len(result) != 64 or any(char not in _DIGEST_CHARS for char in result):
        raise ValueError
    return result


def _number(value: object, minimum: float, maximum: float) -> float:
    if type(value) not in {int, float}:
        raise ValueError
    result = float(cast(int | float, value))
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError
    return result


def _origin(value: object) -> AllowedOrigin:
    try:
        return parse_runtime_origin(_text(value, 2048))
    except (TypeError, ValueError, httpx.InvalidURL):
        raise _fail(
            "authorization_policy_origin_invalid",
            "an authorization policy origin is not an exact HTTP origin with a valid port.",
            "use an exact HTTP origin with a port from 1 through 65535, or omit the port to select the scheme default.",
        ) from None


def _literal_path(value: object) -> str:
    path = _text(value, 2048)
    path_bytes = path.encode("ascii")
    encoded = path.casefold()
    if (
        not path.startswith("/")
        or any(char in path for char in "?#{}")
        or "%7b" in encoded
        or "%7d" in encoded
    ):
        raise _fail(
            "authorization_policy_path_template_unsupported",
            "an authorization policy operation path is not one literal path.",
            "supply one ASCII path without query, fragment, braces, or encoded braces.",
        )
    if any(
        segment in {".", ".."} for segment in encoded.replace("%2e", ".").split("/")
    ):
        raise _fail(
            "authorization_policy_path_dot_segment_unsupported",
            "an authorization policy operation path contains a dot segment.",
            "supply one reviewed literal path without raw or percent-encoded dot segments.",
        )
    if httpx.URL(f"https://placeholder.invalid{path}").raw_path != path_bytes:
        raise _fail(
            "authorization_policy_request_target_changed",
            "the request target would differ from the reviewed literal path.",
            "review and approve the byte-preserved normalized literal path instead.",
        )
    return path


def _identity(value: object) -> AuthorizationPolicyIdentity:
    if type(value) is not dict:
        raise ValueError
    item = cast(dict[str, object], value)
    mode = AuthenticationMode(cast(str, item.get("authentication")))
    if mode is AuthenticationMode.NONE:
        root = _closed(item, frozenset({"identity_id", "authentication"}))
        return AuthorizationPolicyIdentity(_alias(root["identity_id"]), mode, None)
    required = frozenset(
        {"identity_id", "authentication", "credential_kind", "env_var", "header_name"}
    )
    if frozenset(item) not in {required, required | {"expires_at"}}:
        raise ValueError
    root = item
    identity_id = _alias(root["identity_id"])
    expires_at: datetime | None = None
    if "expires_at" in root:
        expiry = _text(root["expires_at"], 64)
        if (
            re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
                expiry,
            )
            is None
        ):
            raise _fail(
                "authorization_policy_expiry_invalid",
                "an authenticated identity expiry is not an RFC 3339 UTC timestamp.",
                "use a timestamp ending in Z with an explicit date and time, or omit expires_at.",
            )
        try:
            expires_at = datetime.fromisoformat(expiry)
        except ValueError:
            raise _fail(
                "authorization_policy_expiry_invalid",
                "an authenticated identity expiry is not an RFC 3339 UTC timestamp.",
                "use a timestamp ending in Z with an explicit date and time, or omit expires_at.",
            ) from None
    source = IdentityCredentialSource(
        identity_id,
        CredentialKind(_text(root["credential_kind"], 32)),
        _text(root["env_var"], 128),
        _text(root["header_name"], 128),
        expires_at,
    )
    return AuthorizationPolicyIdentity(identity_id, mode, source)


def parse_authorization_runtime_policy(data: bytes) -> AuthorizationRuntimePolicy:
    """Parse one strict JSON policy without reading credential values."""
    if (
        type(data) is not bytes
        or not data
        or len(data) > MAX_AUTHORIZATION_POLICY_BYTES
    ):
        raise _fail(
            "authorization_policy_source_invalid",
            "the selected policy is empty or too large.",
            "supply one bounded strict JSON policy.",
        )
    try:
        root = _closed(
            parse_strict_json(data),
            frozenset(
                {"schema_version", "policy_type", "identities", "approvals", "limits"}
            ),
        )
        if (
            root["schema_version"] != 1
            or type(root["schema_version"]) is not int
            or root["policy_type"] != "authorization_execution"
        ):
            raise ValueError
        raw_identities = root["identities"]
        if type(raw_identities) is not list or not 1 <= len(raw_identities) <= 32:
            raise ValueError
        identities = tuple(_identity(item) for item in raw_identities)
        identity_ids = {item.identity_id for item in identities}
        if len(identity_ids) != len(identities):
            raise ValueError
        env_vars = [
            item.credential_source.env_var
            for item in identities
            if item.credential_source is not None
        ]
        if len(env_vars) != len(set(env_vars)):
            raise ValueError
        raw_approvals = root["approvals"]
        if (
            type(raw_approvals) is not list
            or not 1 <= len(raw_approvals) <= MAX_AUTHORIZATION_APPROVALS
        ):
            raise ValueError
        approvals: list[AuthorizationCaseApproval] = []
        approval_keys: set[tuple[str, AllowedOrigin]] = set()
        for raw in raw_approvals:
            approval = _closed(
                raw,
                frozenset(
                    {
                        "case_id",
                        "case_sha256",
                        "origin",
                        "environment_class",
                        "operations",
                    }
                ),
            )
            origin = _origin(approval["origin"])
            key = (_alias(approval["case_id"]), origin)
            if key in approval_keys:
                raise ValueError
            approval_keys.add(key)
            raw_operations = approval["operations"]
            if type(raw_operations) is not list or not 1 <= len(raw_operations) <= 128:
                raise ValueError
            operations: list[AuthorizationOperationApproval] = []
            operation_ids: set[str] = set()
            for raw_operation in raw_operations:
                operation = _closed(
                    raw_operation,
                    frozenset(
                        {"operation_id", "identity_id", "method", "path", "expected"}
                    ),
                )
                operation_id = _alias(operation["operation_id"])
                identity_id = _alias(operation["identity_id"])
                path = _literal_path(operation["path"])
                if (
                    operation_id in operation_ids
                    or identity_id not in identity_ids
                    or operation["method"] != "GET"
                ):
                    raise ValueError
                operation_ids.add(operation_id)
                operations.append(
                    AuthorizationOperationApproval(
                        operation_id,
                        identity_id,
                        "GET",
                        path,
                        AuthorizationExpectation(_text(operation["expected"], 8)),
                    )
                )
            approvals.append(
                AuthorizationCaseApproval(
                    key[0],
                    _digest(approval["case_sha256"]),
                    origin,
                    _alias(approval["environment_class"]),
                    tuple(operations),
                )
            )
        limits = _closed(
            root["limits"],
            frozenset(
                {
                    "max_requests",
                    "max_requests_per_second",
                    "max_timeout_seconds",
                    "max_response_size",
                }
            ),
        )
        max_requests = limits["max_requests"]
        max_response_size = limits["max_response_size"]
        if (
            type(max_requests) is not int
            or not 1 <= max_requests <= 256
            or type(max_response_size) is not int
            or not 1 <= max_response_size <= 1_048_576
        ):
            raise ValueError
        parsed_limits = AuthorizationPolicyLimits(
            max_requests,
            _number(limits["max_requests_per_second"], 0.1, 10.0),
            _number(limits["max_timeout_seconds"], 0.1, 60.0),
            max_response_size,
        )
        return AuthorizationRuntimePolicy(
            1, "authorization_execution", identities, tuple(approvals), parsed_limits
        )
    except AuthorizationPolicyError:
        raise
    except DuplicateJsonKeyError:
        raise _fail(
            "authorization_policy_schema_invalid",
            "the selected policy contains duplicate object names.",
            "supply a closed policy with each documented name exactly once.",
        ) from None
    except (
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        UnicodeError,
        httpx.InvalidURL,
    ):
        raise _fail(
            "authorization_policy_schema_invalid",
            "the selected policy does not match authorization_execution v1.",
            "supply explicit approved identities, exact GET operations, literal paths, origins, and bounded limits.",
        ) from None


def load_authorization_runtime_policy(
    environ: os._Environ[str] | dict[str, str],
) -> AuthorizationRuntimePolicy:
    """Load inline policy in preference to a file, without invalid-source fallback."""
    inline = environ.get("VINTAR_AUTHORIZATION_POLICY_JSON")
    path = environ.get("VINTAR_AUTHORIZATION_POLICY_FILE")
    if inline is not None:
        try:
            return parse_authorization_runtime_policy(inline.encode("utf-8"))
        except UnicodeError:
            raise _fail(
                "authorization_policy_source_invalid",
                "the inline policy is not UTF-8 text.",
                "supply strict JSON in VINTAR_AUTHORIZATION_POLICY_JSON.",
            ) from None
    if path is not None:
        try:
            return parse_authorization_runtime_policy(
                read_bounded_regular_file(Path(path), MAX_AUTHORIZATION_POLICY_BYTES)
            )
        except NoFollowUnavailableError:
            raise _fail(
                "authorization_policy_unreadable",
                "this platform cannot open policy files without following symlinks.",
                "supply the policy through VINTAR_AUTHORIZATION_POLICY_JSON.",
            ) from None
        except (OSError, ValueError):
            raise _fail(
                "authorization_policy_unreadable",
                "the selected policy file is not a bounded regular file.",
                "point VINTAR_AUTHORIZATION_POLICY_FILE at an operator-controlled JSON file.",
            ) from None
    raise _fail(
        "authorization_runtime_policy_required",
        "authorization execution has no trusted runtime policy.",
        "set a protected authorization policy source independently of cases.",
    )
