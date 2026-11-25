"""Materialize an explicitly reviewed POST JSON candidate entirely offline."""

from __future__ import annotations

import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from vintar.core.strict_json import DuplicateJsonKeyError, parse_strict_json
from vintar.regression.cases import MAX_CASE_BYTES, parse_regression_case
from vintar.regression.cases_v2 import PostJsonRegressionCase
from vintar.regression.discovery import JSON, DiscoveryError, _read
from vintar.regression.discovery_drafts import DraftExportError, write_drafts
from vintar.regression.post_json_review import (
    MAX_REVIEW_BYTES,
    PostJsonReviewError,
    resolve_post_json_review,
)


class PostJsonCaseMaterializationError(ValueError):
    """A stable, redacted, actionable materialization diagnostic."""


@dataclass(frozen=True, slots=True, repr=False)
class MaterializedPostJsonCase:
    """Validated Schema v2 bytes plus safe summary metadata."""

    content: bytes
    case_id: str
    check_type: str
    candidate_id: str


def _error(code: str, why: str, action: str) -> PostJsonCaseMaterializationError:
    return PostJsonCaseMaterializationError(f"{code}: {why} {action}")


def _mapping(value: object, code: str, action: str) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise _error(code, "The input structure is invalid.", action)
    return cast(dict[str, object], value)


def _read_review(path: Path) -> dict[str, JSON]:
    try:
        data = _read(path)
        if len(data) > MAX_REVIEW_BYTES:
            raise ValueError
        value = parse_strict_json(data)
        result = _mapping(
            value,
            "post_json_review_schema_invalid",
            "Regenerate it with vintar review-post-json.",
        )
        return cast(dict[str, JSON], result)
    except PostJsonCaseMaterializationError:
        raise
    except (DiscoveryError, OSError, DuplicateJsonKeyError, UnicodeError, ValueError):
        raise _error(
            "post_json_review_schema_invalid",
            "The review artifact is unreadable or is not bounded strict JSON.",
            "Regenerate it with vintar review-post-json.",
        ) from None


def _read_config(path: Path) -> dict[str, object]:
    try:
        value: object = tomllib.loads(_read(path).decode("utf-8"))
    except (DiscoveryError, OSError, UnicodeError, ValueError, RecursionError):
        raise _error(
            "post_json_config_invalid",
            "The materialization config is not bounded UTF-8 TOML.",
            "Supply the documented version 1 POST JSON materialization config.",
        ) from None
    root = _mapping(
        value,
        "post_json_config_invalid",
        "Supply the documented version 1 POST JSON materialization config.",
    )
    if (
        root.keys()
        != {
            "config_version",
            "id",
            "type",
            "expected_verdict",
            "request",
            "probes",
            "limits",
        }
        or root.get("config_version") != 1
    ):
        raise _error(
            "post_json_config_invalid",
            "The config has an unsupported version, missing field, or unknown field.",
            "Use only config_version, id, type, expected_verdict, request, probes, and limits.",
        )
    request = _mapping(
        root["request"],
        "post_json_config_invalid",
        "Supply only url and allowed_origin in the request table.",
    )
    if request.keys() != {"url", "allowed_origin"}:
        raise _error(
            "post_json_credentials_forbidden",
            "Request config may not contain headers, cookies, credentials, authorization, or other fields.",
            "Remove them; trusted authentication is outside Case Schema v2.",
        )
    _mapping(
        root["probes"],
        "post_json_config_invalid",
        "Supply one check-specific probes table.",
    )
    limits = _mapping(
        root["limits"],
        "post_json_config_invalid",
        "Supply the documented bounded limits table.",
    )
    if limits.keys() != {"max_requests", "requests_per_second", "timeout_seconds"}:
        raise _error(
            "post_json_config_invalid",
            "The limits table has missing or unknown fields.",
            "Use only max_requests, requests_per_second, and timeout_seconds.",
        )
    return root


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _toml_number(value: object) -> str:
    if type(value) is bool or type(value) not in (int, float):
        raise _error(
            "post_json_limits_invalid",
            "A numeric materialization value is invalid.",
            "Supply finite check-specific numeric limits.",
        )
    return str(value)


def _serialize(config: dict[str, object], report: dict[str, JSON], body: str) -> str:
    operation = cast(dict[str, JSON], report["operation"])
    field = cast(dict[str, JSON], report["field"])
    baseline = cast(dict[str, JSON], report["baseline"])
    environment = cast(dict[str, JSON], report["environment"])
    request = cast(dict[str, object], config["request"])
    probes = cast(dict[str, object], config["probes"])
    limits = cast(dict[str, object], config["limits"])
    check_type = cast(str, config["type"])
    lines = [
        "version = 2",
        f"id = {_toml_string(cast(str, config['id']))}",
        f"type = {_toml_string(check_type)}",
        f"expected_verdict = {_toml_string(cast(str, config['expected_verdict']))}",
        "",
        "[request]",
        'method = "POST"',
        f"url = {_toml_string(cast(str, request['url']))}",
        f"allowed_origin = {_toml_string(cast(str, request['allowed_origin']))}",
        f"json_body = {_toml_string(body)}",
        "",
        "[injection]",
        'location = "json_body"',
        f"pointer = {_toml_string(cast(str, field['concrete_json_pointer']))}",
        'mode = "replace"',
        "",
        "[probes]",
    ]
    probe_keys = {
        "sqli.boolean": ("true_payload", "false_payload"),
        "sqli.time": ("delay_payload", "control_payload", "expected_delay_seconds"),
        "sqli.error": ("error_payload",),
    }.get(check_type)
    if probe_keys is None or probes.keys() != set(probe_keys):
        raise _error(
            "post_json_probe_config_invalid",
            "The probes table does not match the selected SQLi check.",
            "Supply exactly the documented explicit probe fields.",
        )
    for key in probe_keys:
        item = probes[key]
        rendered = _toml_string(item) if type(item) is str else _toml_number(item)
        lines.append(f"{key} = {rendered}")
    lines.extend(
        (
            "",
            "[limits]",
            f"max_requests = {_toml_number(limits['max_requests'])}",
            f"requests_per_second = {_toml_number(limits['requests_per_second'])}",
            f"timeout_seconds = {_toml_number(limits['timeout_seconds'])}",
            "",
            "[approval]",
            f"candidate_id = {_toml_string(cast(str, report['candidate_id']))}",
            'method = "POST"',
            f"path = {_toml_string(cast(str, operation['path']))}",
            f"operation_pointer = {_toml_string(cast(str, operation['operation_pointer']))}",
            f"request_body_pointer = {_toml_string(cast(str, operation['request_body_pointer']))}",
            f"operation_definition_sha256 = {_toml_string(cast(str, operation['operation_definition_sha256']))}",
            f"baseline_body_sha256 = {_toml_string(cast(str, baseline['body_sha256']))}",
            'side_effect = "no_side_effect"',
            f"environment_class = {_toml_string(cast(str, environment['class']))}",
            "",
            "[approval.review]",
            "schema_version = 1",
            'report_type = "post_json_discovery_review"',
        )
    )
    return "\n".join(lines) + "\n"


def _review_error_code(message: str) -> str:
    normalized = message.lower()
    if "operation definition changed" in normalized:
        return "post_json_operation_definition_mismatch"
    if "operation_approved" in normalized:
        return "post_json_operation_not_approved"
    if "side effect" in normalized or "side_effect" in normalized:
        return "post_json_side_effect_not_approved"
    if "environment" in normalized:
        return "post_json_environment_not_confirmed"
    if "digest" in normalized:
        return "post_json_baseline_digest_mismatch"
    if "does not select an existing leaf" in normalized:
        return "post_json_pointer_target_missing"
    if "requires a json object at its parent pointer" in normalized:
        return "post_json_pointer_target_missing"
    if "does not select a string" in normalized:
        return "post_json_pointer_target_not_string"
    if "json pointer" in normalized or "array selection" in normalized:
        return "post_json_pointer_invalid"
    if "inventory does not match the spec" in normalized:
        return "post_json_schema_provenance_mismatch"
    return "post_json_review_mismatch"


def materialize_post_json_case(
    spec: Path,
    inventory: Path,
    answers: Path,
    review: Path,
    config: Path,
) -> MaterializedPostJsonCase:
    """Re-resolve approval and produce one validated Schema v2 case."""
    supplied_review = _read_review(review)
    try:
        material = resolve_post_json_review(spec, inventory, answers)
    except PostJsonReviewError as exc:
        raise _error(
            _review_error_code(str(exc)),
            "The current spec, inventory, answers, and explicit review no longer agree.",
            "Regenerate the inventory and review the candidate again.",
        ) from exc
    if supplied_review != material.report:
        raise _error(
            "post_json_review_mismatch",
            "The supplied review is stale or was edited.",
            "Regenerate it from the current spec, inventory, and answers.",
        )
    operation = cast(dict[str, JSON], material.report["operation"])
    path = cast(str, operation["path"])
    if "{" in path or "}" in path:
        raise _error(
            "post_json_path_parameter_unsupported",
            "The reviewed operation path contains a path parameter.",
            "Review a literal-path operation; path binding is deferred.",
        )
    config_value = _read_config(config)
    request = cast(dict[str, object], config_value["request"])
    target = request.get("url")
    if type(target) is not str or urlsplit(target).path != path:
        raise _error(
            "post_json_target_operation_mismatch",
            "The config target path does not exactly match the reviewed literal path.",
            "Set request.url to the reviewed path, excluding origin from the comparison.",
        )
    content = _serialize(
        config_value,
        material.report,
        material.body.to_bytes().decode("ascii"),
    ).encode("utf-8")
    if len(content) > MAX_CASE_BYTES:
        raise _error(
            "post_json_case_too_large",
            "The materialized case exceeds its size limit.",
            "Use a smaller reviewed baseline body.",
        )
    try:
        parsed = parse_regression_case(content.decode("utf-8"))
    except ValueError as exc:
        raise _error(
            "post_json_case_semantic_invalid",
            "The generated case did not pass Schema v2 and semantic validation.",
            "Correct the reviewed target, explicit probes, or bounded limits.",
        ) from exc
    if not isinstance(parsed, PostJsonRegressionCase):
        raise TypeError("Schema v2 materialization produced the wrong case type.")
    return MaterializedPostJsonCase(
        content=content,
        case_id=parsed.case_id,
        check_type=parsed.check_type,
        candidate_id=parsed.approval.candidate_id,
    )


def write_materialized_post_json_case(
    output: Path,
    case: MaterializedPostJsonCase,
    inputs: tuple[Path, ...],
) -> None:
    """Publish one validated case without replacing existing files."""
    if output.suffix != ".toml":
        raise _error(
            "post_json_output_invalid",
            "Schema v2 output requires a .toml filename.",
            "Pass an unused TOML path to --output.",
        )
    try:
        write_drafts(
            output.parent, {output.name: case.content}, inputs, option="--output"
        )
    except DraftExportError as exc:
        raise _error(
            "post_json_output_conflict",
            "The output path conflicts with an input or existing file.",
            "Choose an unused .toml path outside the input files.",
        ) from exc
