"""Validate offline review decisions without exporting baseline values."""

import hashlib
import json
import tomllib
from pathlib import Path
from urllib.parse import quote

from vintar.regression.discovery import (
    JSON,
    DiscoveryError,
    Input,
    Source,
    _Discovery,
    _inventory_inputs,
    _load_document,
    _read,
    _read_json,
)
from vintar.regression.discovery_drafts import draft_files, write_drafts


class DraftReviewError(ValueError):
    """A redacted, actionable review diagnostic."""


def _candidates(document: _Discovery, item: Input) -> dict[str, JSON]:
    definition, value = document._pointer(
        f"#{quote(item.definition.pointer, safe='/~')}", item.definition
    )
    parameter, definition, trail = document.resolve(value, definition)
    candidates: dict[str, JSON] = {}

    def add_examples(node: dict[str, JSON], source: Source) -> None:
        if "example" in node:
            candidates[source.child("example").pointer] = node["example"]
        examples = node.get("examples")
        if isinstance(examples, dict):
            for name, example in examples.items():
                site = source.child("examples").child(name)
                if (
                    isinstance(example, dict)
                    and "value" in example
                    and ("$ref" not in example and "externalValue" not in example)
                ):
                    candidates[site.child("value").pointer] = example["value"]

    add_examples(parameter, definition)
    if "schema" in parameter:
        schema, site, _ = document.resolve_schema(
            parameter["schema"], definition.child("schema"), trail
        )
        if isinstance(schema, dict):
            add_examples(schema, site)
            examples = schema.get("examples")
            if isinstance(examples, list):
                for index, example in enumerate(examples):
                    candidates[site.child("examples").child(index).pointer] = example
            if "default" in schema:
                candidates[site.child("default").pointer] = schema["default"]
            choices = schema.get("enum")
            if isinstance(choices, list) and len(choices) == 1:
                candidates[site.child("enum").child(0).pointer] = choices[0]
    return candidates


def _decision(
    document: _Discovery, item: Input, answer: JSON, identifier: str
) -> dict[str, JSON]:
    prefix = f"Input {identifier} parameter {item.name!a}:"
    if not isinstance(answer, dict):
        raise DraftReviewError(
            f"{prefix} missing or invalid baseline decision. Add value, pointer, or omit to --answers."
        )
    keys = set(answer)
    if keys == {"omit"} and answer["omit"] is True:
        if item.required:
            raise DraftReviewError(
                f"{prefix} required parameters cannot be omitted. Supply a value or baseline pointer."
            )
        return {"status": "omitted"}
    source: JSON = "reviewer"
    if keys == {"value"}:
        value = answer["value"]
    elif keys in ({"pointer"}, {"pointer", "value_sha256"}):
        pointer = answer["pointer"]
        candidates = _candidates(document, item)
        if not isinstance(pointer, str) or pointer not in candidates:
            raise DraftReviewError(
                f"{prefix} pointer is not a supported explicit local baseline candidate. "
                "Supply a pointer to a declared example, default, or single-value enum, or provide a value."
            )
        value = candidates[pointer]
        source = {"file": document.source.file.as_posix(), "pointer": pointer}
    else:
        raise DraftReviewError(
            f"{prefix} invalid decision keys. Use value, pointer with optional value_sha256, or omit: true."
        )

    if value is None:
        raise DraftReviewError(
            f"{prefix} baseline query inputs require concrete non-null values. Supply a concrete value or omit the parameter if optional."
        )
    if not isinstance(value, (bool, int, float, str)):
        raise DraftReviewError(
            f"{prefix} baseline query input is not a scalar. Supply a concrete scalar value."
        )
    encoded = json.dumps(
        value, allow_nan=False, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )
    digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    if "value_sha256" in answer and answer["value_sha256"] != digest:
        raise DraftReviewError(
            f"{prefix} stale baseline digest. Rerun discovery and re-confirm the input in --answers."
        )
    return {"status": "resolved", "source": source, "value_sha256": digest}


def build_review(spec: Path, draft: Path, answers: Path) -> dict[str, JSON]:
    cwd = Path.cwd()
    resolved = spec.resolve()
    if not resolved.is_relative_to(cwd):
        raise DraftReviewError(
            "Spec is outside the current working directory. Run from a directory containing the spec."
        )
    relative = resolved.relative_to(cwd)
    try:
        document = _load_document(spec)
        document.source = Source(relative)
        inventory = document.inventory()
        indexed = _inventory_inputs(inventory)
    except DiscoveryError as exc:
        raise DraftReviewError(
            "Cannot inventory the spec. Check its format, declarations, and references, then rerun discovery."
        ) from exc
    try:
        raw_draft = _read(draft)
        parsed: object = tomllib.loads(raw_draft.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        raise DraftReviewError(
            "Cannot read the draft. Supply a UTF-8 draft exported by discover."
        ) from exc
    identifier = parsed.get("input_id") if isinstance(parsed, dict) else None
    if not isinstance(identifier, str) or identifier not in indexed:
        raise DraftReviewError(
            "Draft input is missing or stale. Rerun discovery and review the current input."
        )
    operation, item = indexed[identifier]
    generated = draft_files(inventory, frozenset({identifier}), relative)
    if (
        not operation.compatible
        or not item.compatible
        or raw_draft not in generated.values()
    ):
        raise DraftReviewError(
            f"Draft for {identifier} is stale or incompatible. Rerun discovery and re-confirm the input."
        )
    try:
        config = _read_json(_read(answers), Source(answers))
    except DiscoveryError as exc:
        raise DraftReviewError(
            "Cannot read review answers. Supply a bounded UTF-8 JSON file with unique keys."
        ) from exc
    if (
        not isinstance(config, dict)
        or config.keys() != {"version", "expected_verdict", "parameters"}
        or (type(config["version"]) is not int or config["version"] != 1)
    ):
        raise DraftReviewError(
            "Invalid review answers. Set version to 1 and provide only expected_verdict and parameters."
        )
    verdict = config["expected_verdict"]
    if verdict not in ("not_detected", "inconclusive", "vulnerable"):
        raise DraftReviewError(
            "Expected verdict is missing or invalid. Explicitly set expected_verdict to not_detected, inconclusive, or vulnerable."
        )
    parameters = config["parameters"]
    query = [
        parameter for parameter in operation.inputs if parameter.location == "query"
    ]
    if not isinstance(parameters, dict) or parameters.keys() - {
        parameter.name for parameter in query
    }:
        raise DraftReviewError(
            "Answers contain unknown parameters or an invalid parameters object. Use only declared query names from the draft."
        )
    decisions: dict[str, JSON] = {
        parameter.name: _decision(
            document, parameter, parameters.get(parameter.name), identifier
        )
        for parameter in query
    }
    return {
        "schema_version": 1,
        "report_type": "discovery_draft_review",
        "input_id": identifier,
        "expected_verdict": verdict,
        "source": {"file": relative.as_posix(), "pointer": item.source.pointer},
        "parameters": decisions,
    }


def write_review(
    output: Path, report: dict[str, JSON], inputs: tuple[Path, ...]
) -> None:
    if output.suffix != ".json":
        raise DraftReviewError(
            "Review output requires a .json filename. Pass a JSON path to --output."
        )
    content = (
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    write_drafts(output.parent, {output.name: content}, inputs, option="--output")
