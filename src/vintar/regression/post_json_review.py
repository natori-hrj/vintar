"""Resolve explicit POST JSON review decisions entirely offline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from urllib.parse import quote

from vintar.core.json_body import (
    JsonBody,
    JsonPointer,
    json_array_at,
    json_leaf_at,
    json_object_at,
    replace_json_leaf,
)
from vintar.core.strict_json import DuplicateJsonKeyError, parse_strict_json
from vintar.regression.discovery import (
    JSON,
    DiscoveryError,
    Source,
    _load_document,
    _read,
)
from vintar.regression.discovery_drafts import write_drafts
from vintar.regression.post_json_inventory import (
    MAX_REPORT_BYTES,
    ReviewCandidate,
    analyze_post_json,
)

MAX_REVIEW_BYTES = 262_144
STALE_INVENTORY_MESSAGE = (
    "POST JSON inventory is stale or was edited. Regenerate it with "
    "vintar inventory-post-json and review the new candidate."
)
INVENTORY_SPEC_MISMATCH_MESSAGE = (
    "POST JSON inventory does not match the spec. Regenerate it with "
    "vintar inventory-post-json."
)
STALE_BODY_DIGEST_MESSAGE = (
    "Baseline body digest does not match. Recompute body_sha256 from the complete "
    "canonical JSON body and confirm it before reviewing."
)
OPERATION_DEFINITION_CHANGED_MESSAGE = (
    "the operation definition changed since review; review side effects again"
)
INVALID_BASELINE_POINTER_MESSAGE = (
    "Baseline pointer is not an allowed request-body example. Use "
    'requestBody.content["application/json"].example or '
    'requestBody.content["application/json"].examples[name].value.'
)
ARRAY_PATTERN_MESSAGE = (
    "The candidate pointer pattern requires a JSON array at the wildcard position. "
    "Supply a baseline body with an array there."
)


class PostJsonReviewError(ValueError):
    """A redacted, actionable POST review diagnostic."""


@dataclass(frozen=True, slots=True, repr=False)
class PostJsonReviewMaterial:
    """Redacted report plus baseline data retained only in memory."""

    report: dict[str, JSON]
    body: JsonBody
    pointer: JsonPointer


def _load_json(path: Path, limit: int) -> JSON:
    data = _read(path)
    if len(data) > limit:
        raise PostJsonReviewError(
            "JSON input exceeds its size limit. Supply a smaller review artifact."
        )
    try:
        return cast(JSON, parse_strict_json(data))
    except (DuplicateJsonKeyError, UnicodeError, ValueError, RecursionError) as exc:
        raise PostJsonReviewError(
            "Cannot read JSON input. Supply a bounded UTF-8 JSON file with unique keys."
        ) from exc


def _as_json(value: object) -> JSON:
    if isinstance(value, ReviewCandidate):
        return {
            "candidate_id": value.candidate_id,
            "approval": value.approval.value,
            "operation_definition_sha256": value.operation_definition_sha256,
        }
    if isinstance(value, tuple):
        return [_as_json(item) for item in value]
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return {
            name: _as_json(getattr(value, name)) for name in value.__dataclass_fields__
        }
    if value is None or type(value) in (bool, int, float, str):
        return cast(bool | int | float | str | None, value)
    raise TypeError("Unsupported review value.")


def _exact_true(value: object, label: str) -> None:
    if type(value) is not bool or value is not True:
        raise PostJsonReviewError(
            f"{label} must be JSON true. Review and explicitly confirm this decision."
        )


def concrete_review_pointer(
    pattern: str, concrete: object, literal_star_positions: tuple[int, ...]
) -> JsonPointer:
    if not isinstance(concrete, str):
        raise PostJsonReviewError(
            "Concrete JSON Pointer is invalid. Use the candidate pattern with each array wildcard replaced by an explicit index."
        )
    try:
        pattern_pointer = JsonPointer.parse(pattern)
        pointer = JsonPointer.parse(concrete)
    except (TypeError, ValueError) as exc:
        raise PostJsonReviewError(
            "Concrete JSON Pointer is invalid. Use the candidate pattern with each array wildcard replaced by an explicit index."
        ) from exc
    if len(pattern_pointer.tokens) != len(pointer.tokens):
        raise PostJsonReviewError(
            "Concrete JSON Pointer does not match the candidate. Replace each array wildcard with an explicit index."
        )
    if any(
        type(i) is not int
        or not 0 <= i < len(pattern_pointer.tokens)
        or pattern_pointer.tokens[i] != "*"
        for i in literal_star_positions
    ):
        raise PostJsonReviewError("Invalid literal star positions.")
    for index, (expected, actual) in enumerate(
        zip(pattern_pointer.tokens, pointer.tokens, strict=True)
    ):
        if expected == "*" and index not in literal_star_positions:
            if (
                not actual.isascii()
                or not actual.isdecimal()
                or (len(actual) > 1 and actual.startswith("0"))
            ):
                raise PostJsonReviewError(
                    "Concrete JSON Pointer has an invalid array selection. Use a canonical non-negative decimal index."
                )
        elif expected != actual:
            raise PostJsonReviewError(
                "Concrete JSON Pointer does not match the candidate. Change only explicit array indexes."
            )
    return pointer


def _body_from_value(value: JSON) -> JsonBody:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return JsonBody.from_bytes(encoded)
    except (TypeError, ValueError, RecursionError) as exc:
        raise PostJsonReviewError(
            "Baseline body is invalid. Supply one complete bounded strict-JSON document."
        ) from exc


def _allowed_example_values(spec: Path, candidate: ReviewCandidate) -> dict[str, JSON]:
    document = _load_document(spec)
    media_source, media_value = document._pointer(
        f"#{quote(candidate.request_body_pointer, safe='/~')}",
        Source(spec, candidate.request_body_pointer),
    )
    if not isinstance(media_value, dict):
        raise PostJsonReviewError(STALE_INVENTORY_MESSAGE)
    allowed: dict[str, JSON] = {}
    if "example" in media_value:
        allowed[media_source.child("example").pointer] = media_value["example"]
    examples = media_value.get("examples")
    if not isinstance(examples, dict):
        return allowed
    for name, example_value in sorted(examples.items()):
        site = media_source.child("examples").child(name)
        if not isinstance(example_value, dict):
            continue
        if "$ref" in example_value:
            try:
                example, definition, _ = document.resolve(example_value, site)
            except DiscoveryError:
                continue
            if "value" in example and "externalValue" not in example:
                allowed[site.child("value").pointer] = example["value"]
                allowed[definition.child("value").pointer] = example["value"]
        elif "value" in example_value and "externalValue" not in example_value:
            allowed[site.child("value").pointer] = example_value["value"]
    return allowed


def _baseline(
    spec: Path, candidate: ReviewCandidate, decision: object
) -> tuple[JsonBody, JSON]:
    if not isinstance(decision, dict):
        raise PostJsonReviewError(
            "Baseline decision is invalid. Supply value or one explicit bundled example pointer plus body_sha256."
        )
    if set(decision) not in ({"value", "body_sha256"}, {"pointer", "body_sha256"}):
        raise PostJsonReviewError(
            "Baseline decision is invalid. Supply value or one explicit bundled example pointer plus body_sha256."
        )
    source: JSON = "reviewer"
    if "value" in decision:
        value = decision["value"]
    else:
        selected = decision["pointer"]
        if not isinstance(selected, str) or not re.fullmatch(
            r"(?:/(?:[^~/]|~[01])*)*", selected
        ):
            raise PostJsonReviewError(
                "Baseline example pointer is invalid. Use an explicit local bundled example pointer or provide value."
            )
        try:
            allowed = _allowed_example_values(spec, candidate)
        except DiscoveryError as exc:
            raise PostJsonReviewError(
                "Baseline example is missing or stale. Select a current bundled example or provide value."
            ) from exc
        if selected not in allowed:
            raise PostJsonReviewError(INVALID_BASELINE_POINTER_MESSAGE)
        value = allowed[selected]
        source = {"file": spec.name, "pointer": selected}
    body = _body_from_value(value)
    digest = hashlib.sha256(body.to_bytes()).hexdigest()
    if decision["body_sha256"] != digest:
        raise PostJsonReviewError(STALE_BODY_DIGEST_MESSAGE)
    return body, source


def resolve_post_json_review(
    spec: Path, inventory: Path, answers: Path
) -> PostJsonReviewMaterial:
    """Re-derive one candidate and resolve an explicit offline review."""
    try:
        inventory_value = _load_json(inventory, MAX_REPORT_BYTES)
        answer = _load_json(answers, MAX_REVIEW_BYTES)
    except (DiscoveryError, OSError) as exc:
        raise PostJsonReviewError(
            "Cannot read review inputs. Supply the current inventory and bounded review answers."
        ) from exc
    if (
        not isinstance(inventory_value, dict)
        or inventory_value.get("schema_version") != 2
        or inventory_value.get("report_type") != "openapi_post_json_inventory"
        or not isinstance(answer, dict)
    ):
        raise PostJsonReviewError(STALE_INVENTORY_MESSAGE)
    candidate_id = answer.get("candidate_id")
    if not isinstance(candidate_id, str):
        raise PostJsonReviewError(STALE_INVENTORY_MESSAGE)
    operations = inventory_value.get("operations")
    if not isinstance(operations, list):
        raise PostJsonReviewError(STALE_INVENTORY_MESSAGE)
    claimed_operations: list[dict[str, JSON]] = []
    for operation_value in operations:
        if not isinstance(operation_value, dict):
            raise PostJsonReviewError(STALE_INVENTORY_MESSAGE)
        candidate_values = operation_value.get("review_candidates")
        if not isinstance(candidate_values, list):
            raise PostJsonReviewError(STALE_INVENTORY_MESSAGE)
        if any(
            isinstance(candidate_value, dict)
            and candidate_value.get("candidate_id") == candidate_id
            for candidate_value in candidate_values
        ):
            claimed_operations.append(operation_value)
    if len(claimed_operations) != 1:
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    claimed_operation = claimed_operations[0]
    claimed_candidates = claimed_operation.get("review_candidates")
    if not isinstance(claimed_candidates, list):
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    supplied_matches = [
        candidate_value
        for candidate_value in claimed_candidates
        if isinstance(candidate_value, dict)
        and candidate_value.get("candidate_id") == candidate_id
    ]
    if len(supplied_matches) != 1:
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    supplied = supplied_matches[0]
    try:
        current = analyze_post_json(spec)
    except DiscoveryError as exc:
        raise PostJsonReviewError(STALE_INVENTORY_MESSAGE) from exc
    current_operations = [
        operation
        for operation in current.operations
        if operation.path == claimed_operation.get("path")
        and operation.operation_pointer == claimed_operation.get("operation_pointer")
        and operation.request_body_pointer
        == claimed_operation.get("request_body_pointer")
    ]
    if len(current_operations) != 1:
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    current_operation = current_operations[0]
    current_candidates = [
        item
        for item in current_operation.review_candidates
        if item.candidate_id == candidate_id
    ]
    if len(current_candidates) != 1:
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    candidate = current_candidates[0]
    if (
        candidate.method != "POST"
        or candidate.path != current_operation.path
        or candidate.operation_pointer != current_operation.operation_pointer
        or candidate.request_body_pointer != current_operation.request_body_pointer
    ):
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    fields = claimed_operation.get("fields")
    if not isinstance(fields, list):
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    matching_fields = [
        field
        for field in fields
        if isinstance(field, dict)
        and field.get("json_pointer") == candidate.json_pointer_pattern
        and field.get("literal_star_positions", [])
        == list(candidate.literal_star_positions)
        and field.get("schema_pointer") == candidate.schema_pointer
    ]
    supplied_field = matching_fields[0] if len(matching_fields) == 1 else None
    expected_keys = {
        "version",
        "candidate_id",
        "operation_definition_sha256",
        "schema_pointer",
        "schema_definition_pointer",
        "baseline",
        "concrete_pointer",
        "operation_approved",
        "side_effect",
        "environment",
    }
    if answer.keys() != expected_keys or answer.get("version") != 1:
        raise PostJsonReviewError(
            "Review answers are invalid. Use version 1 and only the documented review decisions."
        )
    if answer["operation_definition_sha256"] != candidate.operation_definition_sha256:
        raise PostJsonReviewError(OPERATION_DEFINITION_CHANGED_MESSAGE)
    if (
        supplied != _as_json(candidate)
        or supplied_field is None
        or supplied_field.get("schema_definition_pointer")
        != candidate.schema_definition_pointer
        or answer["schema_pointer"] != candidate.schema_pointer
        or answer["schema_definition_pointer"] != candidate.schema_definition_pointer
    ):
        raise PostJsonReviewError(INVENTORY_SPEC_MISMATCH_MESSAGE)
    _exact_true(answer["operation_approved"], "operation_approved")
    side_effect = answer["side_effect"]
    if not isinstance(side_effect, dict) or side_effect.keys() != {
        "class",
        "confirmed",
    }:
        raise PostJsonReviewError(
            "Side-effect decision is invalid. Explicitly confirm no_side_effect."
        )
    if side_effect["class"] != "no_side_effect":
        raise PostJsonReviewError(
            "POST side effects are not approved. Use no_side_effect only after explicit review; mutating operations are not supported."
        )
    _exact_true(side_effect["confirmed"], "side_effect.confirmed")
    environment = answer["environment"]
    if not isinstance(environment, dict) or environment.keys() != {
        "class",
        "confirmed",
    }:
        raise PostJsonReviewError(
            "Environment decision is invalid. Name and explicitly confirm an isolated test environment class."
        )
    environment_class = environment["class"]
    if not isinstance(environment_class, str) or not re.fullmatch(
        r"[a-z][a-z0-9_-]{0,63}", environment_class
    ):
        raise PostJsonReviewError(
            "Environment class is invalid. Use a lowercase bounded alias for an isolated test environment."
        )
    _exact_true(environment["confirmed"], "environment.confirmed")
    body, source = _baseline(spec, candidate, answer["baseline"])
    pointer = concrete_review_pointer(
        candidate.json_pointer_pattern,
        answer["concrete_pointer"],
        candidate.literal_star_positions,
    )
    pattern = JsonPointer.parse(candidate.json_pointer_pattern)
    for index, token in enumerate(pattern.tokens):
        parent_tokens = pointer.tokens[:index]
        parent_value = "".join(
            "/" + item.replace("~", "~0").replace("/", "~1") for item in parent_tokens
        )
        parent = JsonPointer.parse(parent_value)
        if token != "*" or index in candidate.literal_star_positions:
            try:
                json_object_at(body, parent)
            except ValueError as exc:
                raise PostJsonReviewError(
                    "The candidate property requires a JSON object at its parent pointer."
                ) from exc
            continue
        try:
            json_array_at(body, parent)
        except ValueError as exc:
            raise PostJsonReviewError(ARRAY_PATTERN_MESSAGE) from exc
    try:
        selected = json_leaf_at(body, pointer)
        replace_json_leaf(body, pointer, "vintar-review-validation")
    except (TypeError, ValueError) as exc:
        raise PostJsonReviewError(
            "Concrete JSON Pointer does not select an existing leaf. Use an explicit index and an existing string field."
        ) from exc
    if type(selected) is not str:
        raise PostJsonReviewError(
            "Reviewed JSON Pointer does not select a string. Supply a baseline whose selected field is a JSON string."
        )
    report: dict[str, JSON] = {
        "schema_version": 1,
        "report_type": "post_json_discovery_review",
        "candidate_id": candidate.candidate_id,
        "operation": {
            "approved": True,
            "method": "POST",
            "path": candidate.path,
            "operation_pointer": candidate.operation_pointer,
            "request_body_pointer": candidate.request_body_pointer,
            "operation_definition_sha256": candidate.operation_definition_sha256,
        },
        "field": {
            "json_pointer_pattern": candidate.json_pointer_pattern,
            **(
                {"literal_star_positions": list(candidate.literal_star_positions)}
                if candidate.literal_star_positions
                else {}
            ),
            "concrete_json_pointer": answer["concrete_pointer"],
            "schema_pointer": candidate.schema_pointer,
            "schema_definition_pointer": candidate.schema_definition_pointer,
            "types": ["string"],
        },
        "baseline": {
            "source": source,
            "body_sha256": hashlib.sha256(body.to_bytes()).hexdigest(),
        },
        "side_effect": {"class": "no_side_effect", "confirmed": True},
        "environment": {"class": environment_class, "confirmed": True},
    }
    return PostJsonReviewMaterial(report, body, pointer)


def build_post_json_review(
    spec: Path, inventory: Path, answers: Path
) -> dict[str, JSON]:
    """Build one redacted POST JSON review artifact."""
    return resolve_post_json_review(spec, inventory, answers).report


def serialize_post_json_review(report: dict[str, JSON]) -> str:
    """Serialize a redacted review artifact deterministically."""
    return json.dumps(report, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def write_post_json_review(
    output: Path, report: dict[str, JSON], inputs: tuple[Path, ...]
) -> None:
    if output.suffix != ".json":
        raise PostJsonReviewError(
            "Review output requires a .json filename. Pass a JSON path to --output."
        )
    content = serialize_post_json_review(report).encode("utf-8")
    if len(content) > MAX_REVIEW_BYTES:
        raise PostJsonReviewError(
            "POST JSON review exceeds its size limit. Shorten non-secret environment metadata."
        )
    write_drafts(output.parent, {output.name: content}, inputs, option="--output")
