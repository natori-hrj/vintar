"""Offline capability inventory for OpenAPI POST JSON request bodies."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from vintar.regression.discovery import (
    JSON,
    DiscoveryError,
    JSONMap,
    ReferenceLimitError,
    Source,
    _Discovery,
    _load_document,
    _mapping,
    _required,
    _string,
)

# Maximum UTF-8 size accepted by the v1 report validator.
MAX_REPORT_BYTES = 2_097_152


class BlockingReason(StrEnum):
    """Stable reasons the existing case pipeline cannot use a POST body."""

    POST_METHOD_UNSUPPORTED = "post_method_unsupported"
    REQUEST_BODY_CASE_GENERATION_UNSUPPORTED = (
        "request_body_case_generation_unsupported"
    )


class SchemaDiagnosticReason(StrEnum):
    """Stable schema constructs that current discovery cannot fully interpret."""

    MISSING_SCHEMA = "missing_schema"
    BOOLEAN_SCHEMA_UNSUPPORTED = "boolean_schema_unsupported"
    ALL_OF_UNSUPPORTED = "all_of_unsupported"
    ANY_OF_UNSUPPORTED = "any_of_unsupported"
    ONE_OF_UNSUPPORTED = "one_of_unsupported"
    ADDITIONAL_PROPERTIES_UNSUPPORTED = "additional_properties_unsupported"
    DYNAMIC_REF_UNSUPPORTED = "dynamic_ref_unsupported"
    SCHEMA_ID_SCOPE_UNSUPPORTED = "schema_id_scope_unsupported"
    EXTERNAL_REF_UNSUPPORTED = "external_ref_unsupported"
    RECURSIVE_REF_UNSUPPORTED = "recursive_ref_unsupported"
    REFERENCE_SIBLING_UNSUPPORTED = "reference_sibling_unsupported"
    REFERENCE_LIMIT_EXCEEDED = "reference_limit_exceeded"


class AuthSource(StrEnum):
    """Where an operation's effective security declaration came from."""

    NONE = "none"
    GLOBAL = "global"
    OPERATION = "operation"


class CaseGeneration(StrEnum):
    """Whether the existing case pipeline can generate a case."""

    UNSUPPORTED = "unsupported"


class CandidateApproval(StrEnum):
    """Inventory candidates are never execution or review approval."""

    UNAPPROVED = "unapproved"


@dataclass(frozen=True, slots=True)
class SchemaDiagnostic:
    reason: SchemaDiagnosticReason
    schema_pointer: str
    schema_definition_pointer: str | None = None


@dataclass(frozen=True, slots=True)
class BodyField:
    json_pointer: str
    schema_pointer: str
    schema_definition_pointer: str
    types: tuple[str, ...]
    required: bool
    injectable: bool = False
    reasons: tuple[BlockingReason, ...] = (
        BlockingReason.REQUEST_BODY_CASE_GENERATION_UNSUPPORTED,
    )


@dataclass(frozen=True, slots=True)
class ReviewCandidate:
    candidate_id: str
    approval: CandidateApproval
    method: str
    path: str
    operation_pointer: str
    request_body_pointer: str
    operation_definition_sha256: str
    json_pointer_pattern: str
    schema_pointer: str
    schema_definition_pointer: str
    types: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AuthScheme:
    name: str
    type: str


@dataclass(frozen=True, slots=True)
class AuthAlternative:
    schemes: tuple[AuthScheme, ...]


@dataclass(frozen=True, slots=True)
class ResolvedAuth:
    source: AuthSource
    public: bool
    alternatives: tuple[AuthAlternative, ...]


@dataclass(frozen=True, slots=True)
class PostJsonOperation:
    path: str
    operation_id: str | None
    operation_pointer: str
    request_body_pointer: str
    case_generation: CaseGeneration
    blocking_reasons: tuple[BlockingReason, ...]
    auth: ResolvedAuth
    fields: tuple[BodyField, ...]
    diagnostics: tuple[SchemaDiagnostic, ...]
    review_candidates: tuple[ReviewCandidate, ...]


@dataclass(frozen=True, slots=True)
class InventoryCounts:
    operations: int
    case_generatable: int
    fields: int
    injectable_fields: int
    unsupported_inputs: int
    diagnostics: int
    post_operations_without_application_json: int


@dataclass(frozen=True, slots=True)
class PostJsonInventoryReport:
    schema_version: int
    report_type: str
    counts: InventoryCounts
    operations: tuple[PostJsonOperation, ...]


_SCHEMA_REASONS = {
    "allOf": SchemaDiagnosticReason.ALL_OF_UNSUPPORTED,
    "anyOf": SchemaDiagnosticReason.ANY_OF_UNSUPPORTED,
    "oneOf": SchemaDiagnosticReason.ONE_OF_UNSUPPORTED,
    "additionalProperties": SchemaDiagnosticReason.ADDITIONAL_PROPERTIES_UNSUPPORTED,
    "$dynamicRef": SchemaDiagnosticReason.DYNAMIC_REF_UNSUPPORTED,
    "$id": SchemaDiagnosticReason.SCHEMA_ID_SCOPE_UNSUPPORTED,
}
_BLOCKING_REASONS = (
    BlockingReason.POST_METHOD_UNSUPPORTED,
    BlockingReason.REQUEST_BODY_CASE_GENERATION_UNSUPPORTED,
)
_SECURITY_TYPES = frozenset({"apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"})


def _candidate_identity(
    path: str,
    field: BodyField,
) -> list[object]:
    return [
        "POST",
        path,
        field.json_pointer,
    ]


def post_json_candidate_id(
    path: str,
    field: BodyField,
) -> str:
    """Identify one candidate by its stable operation and field location."""
    encoded = json.dumps(
        _candidate_identity(path, field),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return f"post-json-candidate-{hashlib.sha256(encoded).hexdigest()[:32]}"


def _definition_map(
    document: _Discovery,
    value: JSON,
    source: Source,
    trail: tuple[Source, ...],
    kind: str,
) -> JSON:
    if not isinstance(value, dict):
        return value
    return {
        key: _definition_child(document, child, source.child(key), trail, kind, key)
        for key, child in sorted(value.items())
    }


def _definition_list(
    document: _Discovery,
    value: JSON,
    source: Source,
    trail: tuple[Source, ...],
    kind: str,
) -> JSON:
    if not isinstance(value, list):
        return value
    return [
        _definition_value(document, child, source.child(index), trail, kind)
        for index, child in enumerate(value)
    ]


def _definition_entries(
    document: _Discovery,
    value: JSON,
    source: Source,
    trail: tuple[Source, ...],
    kind: str,
) -> JSON:
    if not isinstance(value, dict):
        return value
    return {
        key: _definition_value(document, child, source.child(key), trail, kind)
        for key, child in sorted(value.items())
    }


def _definition_value(
    document: _Discovery,
    value: JSON,
    source: Source,
    trail: tuple[Source, ...],
    kind: str,
) -> JSON:
    if isinstance(value, dict) and "$ref" in value:
        reference_source = source.child("$ref")
        target, referenced = document._pointer(
            _string(value["$ref"], reference_source), reference_source
        )
        if target == source or target in trail:
            raise DiscoveryError(
                reference_source,
                "Reference cycle detected. Break the recursive reference chain.",
            )
        resolved = _definition_value(
            document, referenced, target, (*trail, target), kind
        )
        siblings = _definition_map(
            document,
            {key: child for key, child in value.items() if key != "$ref"},
            source,
            trail,
            kind,
        )
        if isinstance(resolved, dict) and isinstance(siblings, dict):
            return resolved | siblings
        return {"resolved": resolved, "siblings": siblings}
    return _definition_map(document, value, source, trail, kind)


def _schema_child(
    document: _Discovery,
    value: JSON,
    source: Source,
    trail: tuple[Source, ...],
    key: str,
) -> JSON:
    if key.startswith("x-") or key in {
        "example",
        "examples",
        "default",
        "enum",
        "const",
    }:
        return value
    if key in {
        "properties",
        "patternProperties",
        "dependentSchemas",
        "$defs",
        "definitions",
    }:
        return _definition_entries(document, value, source, trail, "schema")
    if key in {"allOf", "anyOf", "oneOf", "prefixItems"}:
        return _definition_list(document, value, source, trail, "schema")
    if key in {
        "items",
        "additionalProperties",
        "unevaluatedProperties",
        "contains",
        "propertyNames",
        "if",
        "then",
        "else",
        "not",
        "unevaluatedItems",
    }:
        return _definition_value(document, value, source, trail, "schema")
    return value


def _definition_child(
    document: _Discovery,
    value: JSON,
    source: Source,
    trail: tuple[Source, ...],
    kind: str,
    key: str,
) -> JSON:
    if key.startswith("x-"):
        return value
    if kind == "schema":
        return _schema_child(document, value, source, trail, key)
    if kind in {"operation", "path_item"}:
        if key == "parameters":
            return _definition_list(document, value, source, trail, "parameter")
        if key == "servers":
            return value
    if kind == "operation":
        if key == "requestBody":
            return _definition_value(document, value, source, trail, "request_body")
        if key == "responses":
            return _definition_entries(document, value, source, trail, "response")
        if key == "callbacks":
            return _definition_entries(document, value, source, trail, "callback")
        return value
    if kind == "path_item":
        if key.lower() in {
            "get",
            "put",
            "post",
            "delete",
            "options",
            "head",
            "patch",
            "trace",
        }:
            return _definition_map(document, value, source, trail, "operation")
        return value
    if kind in {"parameter", "header"}:
        if key == "schema":
            return _definition_value(document, value, source, trail, "schema")
        if key == "content":
            return _definition_entries(document, value, source, trail, "media")
        if key == "examples":
            return _definition_entries(document, value, source, trail, "example")
        if key == "example":
            return value
        return value
    if kind == "request_body":
        if key == "content":
            return _definition_entries(document, value, source, trail, "media")
        return value
    if kind == "media":
        if key == "schema":
            return _definition_value(document, value, source, trail, "schema")
        if key == "examples":
            return _definition_entries(document, value, source, trail, "example")
        if key == "example":
            return value
        if key == "encoding":
            return _definition_entries(document, value, source, trail, "encoding")
        return value
    if kind == "encoding":
        if key == "headers":
            return _definition_entries(document, value, source, trail, "header")
        return value
    if kind == "response":
        if key == "headers":
            return _definition_entries(document, value, source, trail, "header")
        if key == "content":
            return _definition_entries(document, value, source, trail, "media")
        if key == "links":
            return _definition_entries(document, value, source, trail, "link")
        return value
    if kind == "callback":
        return _definition_value(document, value, source, trail, "path_item")
    if kind == "example" and key == "value":
        return value
    return value


def _resolved_operation(
    document: _Discovery,
    value: JSON,
    source: Source,
    trail: tuple[Source, ...],
) -> JSON:
    if isinstance(value, list):
        return [
            _resolved_operation(document, child, source.child(index), trail)
            for index, child in enumerate(value)
        ]
    if not isinstance(value, dict):
        return value
    return _definition_map(document, value, source, trail, "operation")


def _operation_definition_sha256(
    document: _Discovery,
    operation: JSONMap,
    operation_source: Source,
    path_item: JSONMap,
    path_source: Source,
    trail: tuple[Source, ...],
) -> str:
    definition: JSON = {
        "operation": _resolved_operation(document, operation, operation_source, trail),
        "path_parameters": _definition_list(
            document,
            path_item.get("parameters", []),
            path_source.child("parameters"),
            trail,
            "parameter",
        ),
        "path_servers": path_item.get("servers", []),
    }
    encoded = json.dumps(
        definition,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _review_candidates(
    path: str,
    operation_pointer: str,
    request_body_pointer: str,
    fields: tuple[BodyField, ...],
    diagnostics: tuple[SchemaDiagnostic, ...],
    operation_definition_sha256: str,
) -> tuple[ReviewCandidate, ...]:
    if diagnostics:
        return ()
    candidates = []
    for field in fields:
        if field.types != ("string",):
            continue
        candidates.append(
            ReviewCandidate(
                post_json_candidate_id(path, field),
                CandidateApproval.UNAPPROVED,
                "POST",
                path,
                operation_pointer,
                request_body_pointer,
                operation_definition_sha256,
                field.json_pointer,
                field.schema_pointer,
                field.schema_definition_pointer,
                field.types,
            )
        )
    return tuple(sorted(candidates, key=lambda item: item.candidate_id))


def _diagnostic_key(item: SchemaDiagnostic) -> tuple[str, str, str]:
    return (
        item.schema_pointer,
        item.schema_definition_pointer or "",
        item.reason.value,
    )


def _reference_diagnostic(
    exc: DiscoveryError, declared: Source
) -> SchemaDiagnostic | None:
    if isinstance(exc, ReferenceLimitError):
        reason = SchemaDiagnosticReason.REFERENCE_LIMIT_EXCEEDED
    elif exc.reason == "Reference cycle detected. Break the recursive reference chain.":
        reason = SchemaDiagnosticReason.RECURSIVE_REF_UNSUPPORTED
    elif exc.reason == (
        "Unsupported reference. Bundle the spec and use a local JSON Pointer."
    ):
        reason = SchemaDiagnosticReason.EXTERNAL_REF_UNSUPPORTED
    else:
        return None
    return SchemaDiagnostic(reason, declared.pointer)


_SCALAR_SCHEMA_TYPES = frozenset({"string", "number", "integer", "boolean", "null"})
_SCHEMA_TYPES = _SCALAR_SCHEMA_TYPES | {"object", "array"}


def _schema_types(node: JSONMap, source: Source) -> tuple[str, ...]:
    if "type" not in node:
        return ()
    value = node["type"]
    values = [value] if isinstance(value, str) else value
    if isinstance(values, list) and values:
        names: set[str] = set()
        for name in values:
            if not isinstance(name, str) or name not in _SCHEMA_TYPES or name in names:
                break
            names.add(name)
        else:
            return tuple(sorted(names))
    raise DiscoveryError(
        source.child("type"),
        "Invalid schema type. Use a known JSON Schema type name or a non-empty array of distinct known type names.",
    )


def _join_pointer(parent: str, token: str) -> str:
    escaped = token.replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}"


def _walk_schema(
    document: _Discovery,
    value: JSON,
    declared: Source,
    trail: tuple[Source, ...],
    json_pointer: str,
    required: bool,
) -> tuple[list[BodyField], list[SchemaDiagnostic]]:
    reference_siblings: list[SchemaDiagnostic] = []
    if isinstance(value, dict) and "$ref" in value:
        for sibling in sorted(value.keys() - {"$ref", "summary", "description"}):
            reference_siblings.append(
                SchemaDiagnostic(
                    SchemaDiagnosticReason.REFERENCE_SIBLING_UNSUPPORTED,
                    declared.child(sibling).pointer,
                )
            )
    try:
        node, definition, resolved_trail = document.resolve_schema(
            value, declared, trail
        )
    except DiscoveryError as exc:
        diagnostic = _reference_diagnostic(exc, declared)
        if diagnostic is None:
            raise
        return [], [*reference_siblings, diagnostic]

    diagnostics = reference_siblings
    if isinstance(node, bool):
        diagnostics.append(
            SchemaDiagnostic(
                SchemaDiagnosticReason.BOOLEAN_SCHEMA_UNSUPPORTED,
                declared.pointer,
                definition.pointer,
            )
        )
        return [], diagnostics

    for keyword, reason in _SCHEMA_REASONS.items():
        if keyword in node:
            diagnostics.append(
                SchemaDiagnostic(reason, definition.child(keyword).pointer)
            )

    fields: list[BodyField] = []
    types = _schema_types(node, definition)
    scalar_root = (
        not json_pointer and bool(types) and _SCALAR_SCHEMA_TYPES.issuperset(types)
    )
    if json_pointer or scalar_root or len(types) > 1:
        fields.append(
            BodyField(
                json_pointer,
                declared.pointer,
                definition.pointer,
                types,
                required,
            )
        )
    if scalar_root or "$id" in node or "$dynamicRef" in node:
        return fields, diagnostics

    properties_value = node.get("properties", {})
    properties = _mapping(properties_value, definition.child("properties"))
    required_names = node.get("required", [])
    if not isinstance(required_names, list) or any(
        not isinstance(name, str) for name in required_names
    ):
        raise DiscoveryError(
            definition.child("required"),
            "Invalid required property list. Use an array of names.",
        )
    for name, child in sorted(properties.items()):
        child_fields, child_diagnostics = _walk_schema(
            document,
            child,
            definition.child("properties").child(name),
            resolved_trail,
            _join_pointer(json_pointer, name),
            name in required_names,
        )
        fields.extend(child_fields)
        diagnostics.extend(child_diagnostics)
    if "items" in node:
        item_fields, item_diagnostics = _walk_schema(
            document,
            node["items"],
            definition.child("items"),
            resolved_trail,
            f"{json_pointer}/*",
            False,
        )
        fields.extend(item_fields)
        diagnostics.extend(item_diagnostics)
    return fields, diagnostics


def _security_schemes(document: _Discovery) -> dict[str, AuthScheme]:
    components_value = document.root.get("components", {})
    components = _mapping(components_value, document.source.child("components"))
    schemes_value = components.get("securitySchemes", {})
    schemes = _mapping(
        schemes_value, document.source.child("components").child("securitySchemes")
    )
    result: dict[str, AuthScheme] = {}
    for name, value in sorted(schemes.items()):
        site = document.source.child("components").child("securitySchemes").child(name)
        scheme = _mapping(value, site)
        if "$ref" in scheme:
            raise DiscoveryError(
                site.child("$ref"),
                "Referenced security schemes are unsupported. Bundle or inline the security scheme and try again.",
            )
        scheme_type = _string(scheme.get("type"), site.child("type"))
        if scheme_type not in _SECURITY_TYPES:
            raise DiscoveryError(
                site.child("type"),
                "Unsupported security scheme type. Use an OpenAPI security scheme type and try again.",
            )
        result[name] = AuthScheme(name, scheme_type)
    return result


def _resolve_auth(
    document: _Discovery,
    operation: JSONMap,
    operation_source: Source,
    schemes: dict[str, AuthScheme],
) -> ResolvedAuth:
    if "security" in operation:
        source = AuthSource.OPERATION
        value = operation["security"]
        declared = operation_source.child("security")
    elif "security" in document.root:
        source = AuthSource.GLOBAL
        value = document.root["security"]
        declared = document.source.child("security")
    else:
        return ResolvedAuth(AuthSource.NONE, True, ())
    if not isinstance(value, list):
        raise DiscoveryError(
            declared,
            "Invalid security declaration. Use an array of requirement objects.",
        )
    alternatives: set[AuthAlternative] = set()
    for index, requirement_value in enumerate(value):
        requirement_source = declared.child(index)
        requirement = _mapping(requirement_value, requirement_source)
        selected: list[AuthScheme] = []
        for name, scopes in sorted(requirement.items()):
            if name not in schemes:
                raise DiscoveryError(
                    requirement_source.child(name),
                    "Undefined security scheme. Define it in components.securitySchemes and try again.",
                )
            if not isinstance(scopes, list) or any(
                not isinstance(scope, str) for scope in scopes
            ):
                raise DiscoveryError(
                    requirement_source.child(name),
                    "Invalid security requirement. Use an array of scope names and try again.",
                )
            selected.append(schemes[name])
        alternatives.add(AuthAlternative(tuple(selected)))
    ordered = tuple(
        sorted(
            alternatives, key=lambda alt: tuple(scheme.name for scheme in alt.schemes)
        )
    )
    return ResolvedAuth(
        source,
        not ordered or any(not alternative.schemes for alternative in ordered),
        ordered,
    )


def _operation_id(operation: JSONMap, source: Source) -> str | None:
    if "operationId" not in operation:
        return None
    return _string(operation["operationId"], source.child("operationId"))


def analyze_post_json(path: Path) -> PostJsonInventoryReport:
    """Analyze POST JSON bodies without contacting any server or target.

    Match media types case-insensitively after stripping parameters and surrounding
    whitespace. Prefer the exact application/json key, then the lexically first
    original matching key. Pointers identify the original selected media entry.
    """
    document = _load_document(path)
    schemes = _security_schemes(document)
    paths_source = document.source.child("paths")
    paths = _mapping(document.root.get("paths", {}), paths_source)
    operations: list[PostJsonOperation] = []
    without_json = 0
    for operation_path, path_value in sorted(paths.items()):
        if operation_path.startswith("x-"):
            continue
        path_source = paths_source.child(operation_path)
        if (
            not operation_path.startswith("/")
            or operation_path.startswith("//")
            or any(character in operation_path for character in ("?", "#", "\\"))
        ):
            raise DiscoveryError(
                path_source,
                "Invalid operation path. Use a root-relative path without an authority, query, or fragment.",
            )
        path_item, path_definition, path_trail = document.resolve(
            path_value, path_source
        )
        if "post" not in path_item:
            continue
        operation_source = path_definition.child("post")
        operation = _mapping(path_item["post"], operation_source)
        request_source = operation_source.child("requestBody")
        if "requestBody" not in operation:
            without_json += 1
            continue
        try:
            body, body_definition, body_trail = document.resolve(
                operation["requestBody"], request_source, path_trail
            )
        except DiscoveryError as exc:
            diagnostic = _reference_diagnostic(exc, request_source)
            if diagnostic is None:
                raise
            operations.append(
                PostJsonOperation(
                    operation_path,
                    _operation_id(operation, operation_source),
                    operation_source.pointer,
                    request_source.pointer,
                    CaseGeneration.UNSUPPORTED,
                    _BLOCKING_REASONS,
                    _resolve_auth(document, operation, operation_source, schemes),
                    (),
                    (diagnostic,),
                    (),
                )
            )
            continue
        content = _mapping(body.get("content"), body_definition.child("content"))
        media_key = min(
            (
                key
                for key in content
                if key.partition(";")[0].strip().lower() == "application/json"
            ),
            key=lambda key: (key != "application/json", key),
            default=None,
        )
        if media_key is None:
            without_json += 1
            continue
        media_source = body_definition.child("content").child(media_key)
        media = _mapping(content[media_key], media_source)
        fields: list[BodyField] = []
        diagnostics: list[SchemaDiagnostic] = []
        if "schema" not in media:
            diagnostics.append(
                SchemaDiagnostic(
                    SchemaDiagnosticReason.MISSING_SCHEMA, media_source.pointer
                )
            )
        else:
            fields, diagnostics = _walk_schema(
                document,
                media["schema"],
                media_source.child("schema"),
                body_trail,
                "",
                _required(body, body_definition),
            )
        ordered_fields = tuple(
            sorted(fields, key=lambda item: (item.json_pointer, item.schema_pointer))
        )
        ordered_diagnostics = tuple(sorted(set(diagnostics), key=_diagnostic_key))
        operations.append(
            PostJsonOperation(
                operation_path,
                _operation_id(operation, operation_source),
                operation_source.pointer,
                media_source.pointer,
                CaseGeneration.UNSUPPORTED,
                _BLOCKING_REASONS,
                _resolve_auth(document, operation, operation_source, schemes),
                ordered_fields,
                ordered_diagnostics,
                _review_candidates(
                    operation_path,
                    operation_source.pointer,
                    media_source.pointer,
                    ordered_fields,
                    ordered_diagnostics,
                    ""
                    if ordered_diagnostics
                    else _operation_definition_sha256(
                        document,
                        operation,
                        operation_source,
                        path_item,
                        path_definition,
                        path_trail,
                    ),
                ),
            )
        )
    ordered_operations = tuple(
        sorted(operations, key=lambda item: (item.path, item.operation_pointer))
    )
    fields_count = sum(len(operation.fields) for operation in ordered_operations)
    diagnostics_count = sum(
        len(operation.diagnostics) for operation in ordered_operations
    )
    return PostJsonInventoryReport(
        2,
        "openapi_post_json_inventory",
        InventoryCounts(
            len(ordered_operations),
            0,
            fields_count,
            0,
            fields_count,
            diagnostics_count,
            without_json,
        ),
        ordered_operations,
    )


def _json_value(value: object) -> object:
    if isinstance(value, ReviewCandidate):
        return {
            "candidate_id": value.candidate_id,
            "approval": value.approval.value,
            "operation_definition_sha256": value.operation_definition_sha256,
        }
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return {
            name: _json_value(getattr(value, name))
            for name in value.__dataclass_fields__
        }
    return value


def report_data(report: PostJsonInventoryReport) -> dict[str, Any]:
    """Return the privacy-bounded JSON representation of a report."""
    value = _json_value(report)
    if not isinstance(value, dict):
        raise TypeError("Expected a post JSON inventory report.")
    return value


def serialize_report(report: PostJsonInventoryReport) -> str:
    """Serialize a report deterministically with a trailing newline."""
    return (
        json.dumps(report_data(report), sort_keys=True, ensure_ascii=True, indent=2)
        + "\n"
    )
