"""Validate offline review decisions without exporting baseline values."""

import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from vintar.regression.discovery import (
    JSON,
    DiscoveryError,
    Input,
    ReferenceLimitError,
    Source,
    _Discovery,
    _inventory_inputs,
    _load_document,
    _local_pointer_fragment,
    _read,
    _read_json,
    _string,
)
from vintar.regression.discovery_drafts import draft_files, write_drafts


class DraftReviewError(ValueError):
    """A redacted, actionable review diagnostic."""


type ReviewScalar = bool | int | float | str


@dataclass(frozen=True, slots=True, repr=False)
class ReviewMaterial:
    """Reviewed decisions with raw values confined to the offline boundary."""

    report: dict[str, JSON]
    values: dict[str, ReviewScalar]
    omitted: frozenset[str]
    case_id: str
    selected_parameter: str


def _candidate(
    document: _Discovery, item: Input, pointer: str
) -> tuple[str, JSON] | None:
    definition, value = document._pointer(
        f"#{quote(item.definition.pointer, safe='/~')}", item.definition
    )
    parameter, definition, trail = document.resolve(value, definition)
    candidates: dict[str, JSON] = {}
    references: list[tuple[Source, dict[str, JSON]]] = []

    def add_examples(node: dict[str, JSON], source: Source) -> None:
        if "example" in node:
            candidates[source.child("example").pointer] = node["example"]
        examples = node.get("examples")
        if isinstance(examples, dict):
            for name, example in examples.items():
                site = source.child("examples").child(name)
                if not isinstance(example, dict):
                    continue
                if "$ref" in example:
                    references.append((site, example))
                elif "value" in example and "externalValue" not in example:
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
    if pointer in candidates:
        return pointer, candidates[pointer]

    local_references = []
    for site, reference in references:
        selected = pointer in {site.pointer, site.child("value").pointer}
        ref_source = site.child("$ref")
        try:
            fragment = _local_pointer_fragment(
                _string(reference["$ref"], ref_source), ref_source
            )
        except DiscoveryError:
            if selected:
                raise
            continue
        selected = selected or pointer == f"{fragment}/value"
        local_references.append((site, reference, selected))

    for site, reference, selected in sorted(
        local_references, key=lambda entry: (not entry[2], entry[0].pointer)
    ):
        try:
            example, target, _ = document.resolve(reference, site)
        except ReferenceLimitError:
            raise
        except DiscoveryError:
            if selected:
                raise
            continue
        canonical = target.child("value").pointer
        if pointer not in {site.pointer, site.child("value").pointer, canonical}:
            continue
        if "value" not in example or "externalValue" in example:
            raise DiscoveryError(
                target,
                "The selected example has no usable local value. Inline a scalar value or provide a value in --answers.",
            )
        return canonical, example["value"]
    return None


def _decision(
    document: _Discovery, item: Input, answer: JSON, identifier: str
) -> tuple[dict[str, JSON], ReviewScalar | None]:
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
        return {"status": "omitted"}, None
    source: JSON = "reviewer"
    if keys == {"value"}:
        value = answer["value"]
    elif keys in ({"pointer"}, {"pointer", "value_sha256"}):
        pointer = answer["pointer"]
        try:
            candidate = (
                _candidate(document, item, pointer)
                if isinstance(pointer, str)
                else None
            )
        except DiscoveryError as exc:
            raise DraftReviewError(
                f"{prefix} Cannot resolve baseline candidates. {exc.reason}"
            ) from exc
        if candidate is None:
            raise DraftReviewError(
                f"{prefix} pointer is not a supported explicit local baseline candidate. "
                "Supply a pointer to a declared example, default, or single-value enum, or provide a value."
            )
        pointer, value = candidate
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
    return {"status": "resolved", "source": source, "value_sha256": digest}, value


def resolve_review(spec: Path, draft: Path, answers: Path) -> ReviewMaterial:
    """Rebuild one review while retaining raw values only in memory."""
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
    case_id = parsed.get("id") if isinstance(parsed, dict) else None
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
    candidate_document = _Discovery(document.root, document.source, document.version)
    resolved_decisions = {
        parameter.name: _decision(
            candidate_document, parameter, parameters.get(parameter.name), identifier
        )
        for parameter in query
    }
    decisions: dict[str, JSON] = {
        name: decision for name, (decision, _) in resolved_decisions.items()
    }
    values: dict[str, ReviewScalar] = {}
    for name, (_, value) in resolved_decisions.items():
        if value is not None:
            values[name] = value
    omitted = frozenset(
        name
        for name, (decision, _) in resolved_decisions.items()
        if decision["status"] == "omitted"
    )
    if not isinstance(case_id, str):
        raise DraftReviewError(
            "Draft case ID is missing or stale. Rerun discovery and review the current input."
        )
    report: dict[str, JSON] = {
        "schema_version": 1,
        "report_type": "discovery_draft_review",
        "input_id": identifier,
        "expected_verdict": verdict,
        "source": {"file": relative.as_posix(), "pointer": item.source.pointer},
        "parameters": decisions,
    }
    return ReviewMaterial(
        report=report,
        values=values,
        omitted=omitted,
        case_id=case_id,
        selected_parameter=item.name,
    )


def build_review(spec: Path, draft: Path, answers: Path) -> dict[str, JSON]:
    """Build one redacted review report."""
    return resolve_review(spec, draft, answers).report


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
