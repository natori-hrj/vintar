"""Strict, offline-only Case Schema v2 models and validation."""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import httpx

from vintar.checks.sqli.error_analyzer import validate_error_probe_payload
from vintar.checks.sqli.models import Verdict
from vintar.core.json_body import JsonBody, JsonPointer, json_leaf_at, replace_json_leaf
from vintar.core.scope import AllowedOrigin, ScopePolicy

CASE_V2_VERSION = 2
CASE_V2_SCHEMA = (
    Path(__file__).resolve().parents[1] / "schemas" / "regression-case-v2.schema.json"
)
_ID_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
)


class CaseV2ValidationError(ValueError):
    """A redacted, actionable Schema v2 diagnostic."""


@dataclass(frozen=True, slots=True, repr=False)
class PostJsonApproval:
    """Review provenance; never runtime authority."""

    candidate_id: str
    method: str
    path: str
    operation_pointer: str
    request_body_pointer: str
    operation_definition_sha256: str
    baseline_body_sha256: str
    side_effect: str
    environment_class: str


@dataclass(frozen=True, slots=True, repr=False)
class PostJsonRegressionCase:
    """A materialized, deliberately unexecutable POST JSON SQLi case."""

    schema_version: int
    case_id: str
    check_type: str
    expected_verdict: Verdict
    url: str
    scope: ScopePolicy
    json_body: JsonBody
    pointer: JsonPointer
    probes: tuple[str, ...]
    expected_delay_seconds: float | None
    max_requests: int
    requests_per_second: float
    timeout_seconds: float
    approval: PostJsonApproval


def _fail(code: str, reason: str, action: str) -> CaseV2ValidationError:
    return CaseV2ValidationError(f"{code}: {reason} {action}")


def validate_case_v2_schema(value: object) -> dict[str, object]:
    """Validate a strict TOML mapping against the published JSON Schema."""
    try:
        schema = json.loads(CASE_V2_SCHEMA.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise _fail(
            "post_json_case_schema_invalid",
            "The Case Schema v2 structure or keys are invalid.",
            "Use only the documented Schema v2 fields for one SQLi check type.",
        ) from exc
    validator_class = cast(Any, import_module("jsonschema")).Draft202012Validator
    validator = validator_class(schema)
    if next(validator.iter_errors(value), None) is not None:
        raise _fail(
            "post_json_case_schema_invalid",
            "The Case Schema v2 structure or keys are invalid.",
            "Use only the documented Schema v2 fields for one SQLi check type.",
        )
    if type(value) is not dict:
        raise _fail(
            "post_json_case_schema_invalid",
            "The Case Schema v2 root is invalid.",
            "Supply one TOML table document.",
        )
    return cast(dict[str, object], value)


def _mapping(value: object) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise _fail(
            "post_json_case_schema_invalid",
            "A Case Schema v2 table is invalid.",
            "Use only documented string-keyed TOML tables.",
        )
    return cast(dict[str, object], value)


def _text(value: object, maximum: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= maximum:
        raise ValueError
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise ValueError
    return value


def _origin(value: object) -> tuple[AllowedOrigin, str]:
    text = _text(value, 2048)
    parsed = httpx.URL(text)
    if (
        text != text.strip()
        or parsed.scheme not in {"http", "https"}
        or not parsed.host
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError
    return (
        AllowedOrigin(
            parsed.scheme,
            parsed.host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
        ),
        text,
    )


def _number(value: object, minimum: float, maximum: float) -> float:
    if type(value) not in (int, float):
        raise ValueError
    result = float(cast(int | float, value))
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError
    return result


def parse_case_v2_mapping(value: object) -> PostJsonRegressionCase:
    """Run semantic checks after JSON Schema validation, without I/O or execution."""
    root = validate_case_v2_schema(value)
    try:
        case_id = _text(root["id"], 64)
        if case_id[0] not in _ID_CHARS - frozenset("_.-") or any(
            character not in _ID_CHARS for character in case_id
        ):
            raise ValueError
        check_type = _text(root["type"], 32)
        expected = Verdict(_text(root["expected_verdict"], 32))
        request = _mapping(root["request"])
        url = _text(request["url"], 2048)
        parsed_url = urlsplit(url)
        origin, _ = _origin(request["allowed_origin"])
        if (
            parsed_url.scheme not in {"http", "https"}
            or not parsed_url.netloc
            or parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError
        actual_origin, _ = _origin(f"{parsed_url.scheme}://{parsed_url.netloc}")
        if actual_origin != origin:
            raise ValueError
        body = JsonBody.from_bytes(_text(request["json_body"], 65_536).encode("utf-8"))
        injection = _mapping(root["injection"])
        pointer = JsonPointer.parse(cast(str, injection["pointer"]))
        selected = json_leaf_at(body, pointer)
        if type(selected) is not str:
            raise _fail(
                "post_json_pointer_target_not_string",
                "The reviewed pointer does not select a JSON string leaf.",
                "Re-materialize a review whose concrete pointer selects an existing string.",
            )
        approval_value = _mapping(root["approval"])
        approval = PostJsonApproval(
            candidate_id=cast(str, approval_value["candidate_id"]),
            method=cast(str, approval_value["method"]),
            path=cast(str, approval_value["path"]),
            operation_pointer=cast(str, approval_value["operation_pointer"]),
            request_body_pointer=cast(str, approval_value["request_body_pointer"]),
            operation_definition_sha256=cast(
                str, approval_value["operation_definition_sha256"]
            ),
            baseline_body_sha256=cast(str, approval_value["baseline_body_sha256"]),
            side_effect=cast(str, approval_value["side_effect"]),
            environment_class=cast(str, approval_value["environment_class"]),
        )
        if parsed_url.path != approval.path:
            raise _fail(
                "post_json_target_operation_mismatch",
                "The target path does not exactly match the reviewed literal operation path.",
                "Set request.url to the reviewed path on the selected origin.",
            )
        if "{" in approval.path or "}" in approval.path:
            raise _fail(
                "post_json_path_parameter_unsupported",
                "The reviewed operation path contains a path parameter.",
                "Review an operation with a literal path; path binding is deferred.",
            )
        digest = hashlib.sha256(body.to_bytes()).hexdigest()
        if digest != approval.baseline_body_sha256:
            raise _fail(
                "post_json_baseline_digest_mismatch",
                "The canonical baseline body digest does not match its approval provenance.",
                "Re-materialize from the current reviewed baseline.",
            )
        probes_value = _mapping(root["probes"])
        delay: float | None = None
        probes: tuple[str, ...]
        if check_type == "sqli.boolean":
            probes = (
                _text(probes_value["true_payload"], 512),
                _text(probes_value["false_payload"], 512),
            )
            required_requests = 6
        elif check_type == "sqli.time":
            probes = (
                _text(probes_value["delay_payload"], 512),
                _text(probes_value["control_payload"], 512),
            )
            delay = _number(probes_value["expected_delay_seconds"], 0.25, 2.0)
            required_requests = 9
        else:
            probes = (validate_error_probe_payload(probes_value["error_payload"]),)
            required_requests = 4
        if len(set(probes)) != len(probes):
            raise _fail(
                "post_json_probe_not_distinct",
                "The reviewed probe values are not distinct.",
                "Supply distinct explicit probes for the selected check.",
            )
        planned = tuple(replace_json_leaf(body, pointer, probe) for probe in probes)
        if len({body, *planned}) != len(planned) + 1:
            raise _fail(
                "post_json_probe_not_distinct",
                "A probe produces the baseline body or another planned body.",
                "Supply distinct probes that change the reviewed string leaf.",
            )
        limits = _mapping(root["limits"])
        max_requests = limits["max_requests"]
        if type(max_requests) is not int or max_requests != required_requests:
            raise ValueError
        rps = _number(limits["requests_per_second"], 0.1, 10.0)
        timeout = _number(limits["timeout_seconds"], 0.1, 60.0)
        if check_type == "sqli.time" and (
            timeout > 8.0 or timeout < cast(float, delay) + 0.5
        ):
            raise ValueError
    except CaseV2ValidationError:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError):
        raise _fail(
            "post_json_case_semantic_invalid",
            "The Case Schema v2 values violate the bounded POST JSON contracts.",
            "Re-materialize with a literal reviewed target, valid probes, and check-specific limits.",
        ) from None
    return PostJsonRegressionCase(
        schema_version=CASE_V2_VERSION,
        case_id=case_id,
        check_type=check_type,
        expected_verdict=expected,
        url=url,
        scope=ScopePolicy(allowed_origins=frozenset({origin})),
        json_body=body,
        pointer=pointer,
        probes=probes,
        expected_delay_seconds=delay,
        max_requests=max_requests,
        requests_per_second=rps,
        timeout_seconds=timeout,
        approval=approval,
    )
