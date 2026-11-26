"""Trusted, secret-free runtime policy for POST JSON execution."""

from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import cast

from vintar.auth.contracts import CredentialKind, IdentityCredentialSource
from vintar.core.scope import AllowedOrigin
from vintar.core.strict_json import DuplicateJsonKeyError, parse_strict_json
from vintar.regression.binding import parse_runtime_origin
from vintar.regression.file_io import (
    NoFollowUnavailableError,
    read_bounded_regular_file,
)

MAX_POLICY_BYTES = 262_144
MAX_POLICY_APPROVALS = 128
_IDENTIFIER_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
)
_DIGEST_CHARS = frozenset("0123456789abcdef")


class PostJsonPolicyError(ValueError):
    """A stable, redacted policy diagnostic with operator guidance."""


def _fail(code: str, reason: str, action: str) -> PostJsonPolicyError:
    return PostJsonPolicyError(f"{code}: {reason} {action}")


@dataclass(frozen=True, slots=True, repr=False)
class PostJsonPolicyLimits:
    max_requests: int
    max_requests_per_second: float
    max_timeout_seconds: float
    max_response_size: int
    max_time_execution_seconds: float


@dataclass(frozen=True, slots=True, repr=False)
class PostJsonPolicyApproval:
    case_id: str
    identity_id: str
    credential_kind: CredentialKind
    credential_env_var: str
    method: str
    path: str
    origin: AllowedOrigin
    operation_definition_sha256: str | None
    baseline_body_sha256: str | None
    allowed_environment_classes: frozenset[str]
    allowed_side_effect: str | None


@dataclass(frozen=True, slots=True, repr=False)
class PostJsonRuntimePolicy:
    schema_version: int
    policy_type: str
    identities: tuple[IdentityCredentialSource, ...]
    approvals: tuple[PostJsonPolicyApproval, ...]
    limits: PostJsonPolicyLimits


def _closed(value: object, required: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError
    result = cast(dict[str, object], value)
    if frozenset(result) != required or not all(type(key) is str for key in result):
        raise ValueError
    return result


def _text(value: object, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ValueError
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError
    return value


def _identifier(value: object) -> str:
    result = _text(value, 64)
    if result[0] in "_.-" or any(
        character not in _IDENTIFIER_CHARS for character in result
    ):
        raise ValueError
    return result


def _digest(value: object) -> str:
    result = _text(value, 64)
    if len(result) != 64 or any(character not in _DIGEST_CHARS for character in result):
        raise ValueError
    return result


def _number(value: object, minimum: float, maximum: float) -> float:
    if type(value) not in (int, float):
        raise ValueError
    result = float(cast(int | float, value))
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError
    return result


def _env_var(value: object) -> str:
    result = _text(value, 128)
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", result) is None:
        raise ValueError
    return result


def _credential_source(value: object) -> IdentityCredentialSource:
    if type(value) is not dict:
        raise ValueError
    item = cast(dict[str, object], value)
    if "placement" in item and item["placement"] == "query":
        raise _fail(
            "auth_query_placement_unsupported",
            "API-key query placement is not supported because URLs can leak credentials.",
            "Configure api_key_header with a dedicated header name instead.",
        )
    allowed = frozenset(
        {"identity_id", "credential_kind", "env_var", "header_name", "expires_at"}
    )
    if not frozenset(item) <= allowed or frozenset(item) not in {
        allowed,
        allowed - {"expires_at"},
    }:
        raise ValueError
    kind = CredentialKind(_text(item["credential_kind"], 32))
    header_name = _text(item["header_name"], 128)
    if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header_name) is None:
        raise ValueError
    if kind in {CredentialKind.BEARER, CredentialKind.BASIC}:
        if header_name.casefold() != "authorization":
            raise ValueError
    elif header_name.casefold() == "authorization":
        raise ValueError
    expires_at: datetime | None = None
    if "expires_at" in item:
        expiry = _text(item["expires_at"], 64)
        if (
            re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z",
                expiry,
            )
            is None
        ):
            raise ValueError
        expires_at = datetime.fromisoformat(expiry)
    return IdentityCredentialSource(
        identity_id=_identifier(item["identity_id"]),
        credential_kind=kind,
        env_var=_env_var(item["env_var"]),
        header_name=header_name,
        expires_at=expires_at,
    )


def parse_post_json_runtime_policy(data: bytes) -> PostJsonRuntimePolicy:
    """Parse one bounded, closed trusted policy without exposing its content."""
    if type(data) is not bytes or not 1 <= len(data) <= MAX_POLICY_BYTES:
        raise _fail(
            "post_json_policy_source_invalid",
            "The selected runtime policy is empty or exceeds the size limit.",
            "Supply one bounded strict JSON runtime policy.",
        )
    try:
        root = _closed(
            parse_strict_json(data),
            frozenset(
                {"schema_version", "policy_type", "identities", "approvals", "limits"}
            ),
        )
        if type(root["schema_version"]) is not int or root["schema_version"] != 1:
            raise ValueError
        if root["policy_type"] != "post_json_execution":
            raise ValueError
        identity_values = root["identities"]
        if (
            type(identity_values) is not list
            or not 1 <= len(identity_values) <= MAX_POLICY_APPROVALS
        ):
            raise ValueError
        identities = tuple(_credential_source(item) for item in identity_values)
        identity_map = {item.identity_id: item for item in identities}
        if len(identity_map) != len(identities):
            raise ValueError
        approval_values = root["approvals"]
        if (
            type(approval_values) is not list
            or not 1 <= len(approval_values) <= MAX_POLICY_APPROVALS
        ):
            raise ValueError
        approvals: list[PostJsonPolicyApproval] = []
        for item in approval_values:
            if type(item) is not dict:
                raise ValueError
            item_mapping = cast(dict[str, object], item)
            common_keys = frozenset(
                {
                    "case_id",
                    "identity_id",
                    "credential_kind",
                    "credential_env_var",
                    "method",
                    "path",
                    "origin",
                    "allowed_environment_classes",
                }
            )
            post_keys = common_keys | {
                "operation_definition_sha256",
                "baseline_body_sha256",
                "allowed_side_effect",
            }
            method = item_mapping.get("method")
            approval = _closed(
                item_mapping, post_keys if method == "POST" else common_keys
            )
            path = _text(approval["path"], 2048)
            if (
                not path.startswith("/")
                or "?" in path
                or "#" in path
                or "{" in path
                or "}" in path
            ):
                raise ValueError
            environments = approval["allowed_environment_classes"]
            if type(environments) is not list or not 1 <= len(environments) <= 32:
                raise ValueError
            environment_set = frozenset(_identifier(item) for item in environments)
            if len(environment_set) != len(environments):
                raise ValueError
            if method not in {"GET", "POST"}:
                raise ValueError
            if method == "POST" and approval["allowed_side_effect"] != "no_side_effect":
                raise ValueError
            identity_id = _identifier(approval["identity_id"])
            source = identity_map.get(identity_id)
            credential_kind = CredentialKind(_text(approval["credential_kind"], 32))
            credential_env_var = _env_var(approval["credential_env_var"])
            if (
                source is None
                or source.credential_kind is not credential_kind
                or source.env_var != credential_env_var
            ):
                raise ValueError
            approvals.append(
                PostJsonPolicyApproval(
                    case_id=_identifier(approval["case_id"]),
                    identity_id=identity_id,
                    credential_kind=credential_kind,
                    credential_env_var=credential_env_var,
                    method=cast(str, method),
                    path=path,
                    origin=parse_runtime_origin(_text(approval["origin"], 2048)),
                    operation_definition_sha256=(
                        _digest(approval["operation_definition_sha256"])
                        if method == "POST"
                        else None
                    ),
                    baseline_body_sha256=(
                        _digest(approval["baseline_body_sha256"])
                        if method == "POST"
                        else None
                    ),
                    allowed_environment_classes=environment_set,
                    allowed_side_effect=(
                        "no_side_effect" if method == "POST" else None
                    ),
                )
            )
        approval_keys = {
            (item.case_id, item.identity_id, item.method, item.path, item.origin)
            for item in approvals
        }
        if len(approval_keys) != len(approvals):
            raise ValueError
        limit_values = _closed(
            root["limits"],
            frozenset(
                {
                    "max_requests",
                    "max_requests_per_second",
                    "max_timeout_seconds",
                    "max_response_size",
                    "max_time_execution_seconds",
                }
            ),
        )
        max_requests = limit_values["max_requests"]
        max_response_size = limit_values["max_response_size"]
        if type(max_requests) is not int or not 1 <= max_requests <= 768:
            raise ValueError
        if (
            type(max_response_size) is not int
            or not 1 <= max_response_size <= 1_048_576
        ):
            raise ValueError
        limits = PostJsonPolicyLimits(
            max_requests=max_requests,
            max_requests_per_second=_number(
                limit_values["max_requests_per_second"], 0.1, 10.0
            ),
            max_timeout_seconds=_number(limit_values["max_timeout_seconds"], 0.1, 60.0),
            max_response_size=max_response_size,
            max_time_execution_seconds=_number(
                limit_values["max_time_execution_seconds"], 0.1, 120.0
            ),
        )
    except PostJsonPolicyError:
        raise
    except DuplicateJsonKeyError:
        raise _fail(
            "post_json_policy_schema_invalid",
            "The selected runtime policy contains duplicate JSON object names.",
            "Supply a closed policy with each documented name exactly once.",
        ) from None
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError):
        raise _fail(
            "post_json_policy_schema_invalid",
            "The selected runtime policy does not match the closed schema.",
            "Supply strict JSON with documented fields and exact value types.",
        ) from None
    return PostJsonRuntimePolicy(
        schema_version=1,
        policy_type="post_json_execution",
        identities=identities,
        approvals=tuple(approvals),
        limits=limits,
    )


def _read_policy_file(path_text: str) -> bytes:
    try:
        data = read_bounded_regular_file(Path(path_text), MAX_POLICY_BYTES)
        if not data:
            raise OSError
        return data
    except NoFollowUnavailableError:
        raise _fail(
            "post_json_policy_unreadable",
            "This platform cannot open policy files without following symlinks.",
            "Supply the policy through VINTAR_RUNTIME_POLICY_JSON instead.",
        ) from None
    except (OSError, ValueError):
        raise _fail(
            "post_json_policy_unreadable",
            "The selected runtime policy file is not a bounded regular file.",
            "Point VINTAR_RUNTIME_POLICY_FILE at an operator-controlled JSON file.",
        ) from None


def load_post_json_runtime_policy(
    environ: os._Environ[str] | dict[str, str],
) -> PostJsonRuntimePolicy:
    """Load env JSON in preference to a file, with no invalid-source fallback."""
    inline = environ.get("VINTAR_RUNTIME_POLICY_JSON")
    path = environ.get("VINTAR_RUNTIME_POLICY_FILE")
    if inline is not None:
        try:
            data = inline.encode("utf-8")
        except UnicodeError:
            raise _fail(
                "post_json_policy_source_invalid",
                "The selected environment runtime policy is not valid UTF-8 text.",
                "Supply one strict JSON document in VINTAR_RUNTIME_POLICY_JSON.",
            ) from None
        return parse_post_json_runtime_policy(data)
    if path is not None:
        if type(path) is not str or not path:
            raise _fail(
                "post_json_policy_source_invalid",
                "The selected runtime policy file path is empty.",
                "Set VINTAR_RUNTIME_POLICY_FILE to an operator-controlled JSON file.",
            )
        return parse_post_json_runtime_policy(_read_policy_file(path))
    raise _fail(
        "post_json_runtime_policy_required",
        "POST JSON execution has no trusted runtime policy.",
        "Set VINTAR_RUNTIME_POLICY_JSON or VINTAR_RUNTIME_POLICY_FILE from trusted operator configuration.",
    )
