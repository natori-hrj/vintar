"""Inventory declared OpenAPI inputs from a single local JSON or YAML document."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

import yaml
from yaml.events import (
    AliasEvent,
    DocumentEndEvent,
    DocumentStartEvent,
    Event,
    MappingEndEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceEndEvent,
    SequenceStartEvent,
    StreamEndEvent,
)

MAX_SPEC_BYTES = 1_048_576
MAX_NESTING = 48
MAX_OPERATIONS = 512
MAX_REFERENCE_DEPTH = 24
MAX_REFERENCE_WORK = 4096
MAX_INVENTORY_WORK = 8192
MAX_DOCUMENT_NODES = MAX_INVENTORY_WORK
JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)
LOCATIONS = frozenset({"path", "query", "header", "cookie"})

type JSON = bool | int | float | str | list[JSON] | dict[str, JSON] | None
type JSONMap = dict[str, JSON]


@dataclass(frozen=True)
class Source:
    file: Path
    pointer: str = ""

    def child(self, key: str | int) -> Source:
        token = str(key).replace("~", "~0").replace("/", "~1")
        return Source(self.file, f"{self.pointer}/{token}")


class DiscoveryError(ValueError):
    """The input cannot be inventoried."""

    def __init__(self, source: Source, reason: str) -> None:
        self.source = source
        super().__init__(f"{source.file}#{source.pointer}: {reason}")


@dataclass(frozen=True)
class HeldItem:
    source: Source
    reason: str
    definition: Source | None = None


@dataclass(frozen=True)
class Input:
    location: str
    name: str
    required: bool
    compatible: bool
    source: Source
    definition: Source
    ignored_reason: str | None = None


@dataclass(frozen=True)
class Operation:
    id: str
    method: str
    path: str
    source: Source
    definition: Source
    inputs: tuple[Input, ...]
    compatible: bool


@dataclass(frozen=True)
class Inventory:
    version: str
    source: Source
    operations: tuple[Operation, ...]
    held: tuple[HeldItem, ...]


@dataclass
class _Pairs:
    values: list[tuple[str, object]]


def _validate_unicode(value: str, source: Source) -> None:
    if re.search(r"[\ud800-\udfff]", value):
        raise DiscoveryError(
            source, "Invalid Unicode scalar. Use valid Unicode in the spec."
        )


@dataclass
class _DocumentBudget:
    nodes: int = 0

    def check(self, source: Source, depth: int) -> None:
        if depth > MAX_NESTING:
            raise DiscoveryError(
                source, f"Document nesting exceeds {MAX_NESTING}. Flatten the spec."
            )
        self.nodes += 1
        if self.nodes > MAX_DOCUMENT_NODES:
            raise DiscoveryError(
                source, "Document node limit exceeded. Supply a smaller spec."
            )


def _normalize(
    value: object, source: Source, budget: _DocumentBudget, depth: int = 0
) -> JSON:
    budget.check(source, depth)
    if isinstance(value, _Pairs):
        result: JSONMap = {}
        for key, item in value.values:
            _validate_unicode(key, source)
            child = source.child(key)
            if key in result:
                raise DiscoveryError(child, "Duplicate JSON key. Keep one declaration.")
            result[key] = _normalize(item, child, budget, depth + 1)
        return result
    if isinstance(value, list):
        return [
            _normalize(item, source.child(i), budget, depth + 1)
            for i, item in enumerate(value)
        ]
    if isinstance(value, str):
        _validate_unicode(value, source)
    if isinstance(value, float) and not math.isfinite(value):
        raise DiscoveryError(source, "Invalid JSON number. Use a finite number.")
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    raise DiscoveryError(source, "Invalid JSON value. Use standard JSON values.")


def _reject_constant(value: str) -> None:
    raise ValueError(f"Invalid JSON number {value}. Use finite numbers.")


class _RestrictedYAMLLoader(yaml.SafeLoader):
    """Read parser events and construct only bounded JSON values."""

    @classmethod
    def load_document(cls, text: str, source: Source) -> JSON:
        events = yaml.parse(text, Loader=cls)
        next(events, None)
        if not isinstance(next(events, None), DocumentStartEvent):
            raise DiscoveryError(source, "YAML is empty. Supply one OpenAPI document.")
        result = cls.read_value(
            next(events, None), events, source, _DocumentBudget(), 0
        )
        if not isinstance(next(events, None), DocumentEndEvent) or not isinstance(
            next(events, None), StreamEndEvent
        ):
            raise DiscoveryError(
                source,
                "Multiple YAML documents are unsupported. Supply one OpenAPI document.",
            )
        return result

    @classmethod
    def read_value(
        cls,
        event: Event | None,
        events: Iterator[Event],
        source: Source,
        budget: _DocumentBudget,
        depth: int,
    ) -> JSON:
        budget.check(source, depth)
        node = cls.read_node(event, source)
        if isinstance(node, ScalarEvent):
            return cls.scalar(node, source)
        if isinstance(node, SequenceStartEvent):
            values: list[JSON] = []
            for child_event in events:
                if isinstance(child_event, SequenceEndEvent):
                    break
                values.append(
                    cls.read_value(
                        child_event,
                        events,
                        source.child(len(values)),
                        budget,
                        depth + 1,
                    )
                )
            return values
        result: JSONMap = {}
        for key_event in events:
            if isinstance(key_event, MappingEndEvent):
                break
            key_node = cls.read_node(key_event, source)
            if not isinstance(key_node, ScalarEvent):
                raise DiscoveryError(
                    source, "Non-string YAML mapping key. Use a quoted string key."
                )
            key = cls.scalar(key_node, source)
            if not isinstance(key, str):
                raise DiscoveryError(
                    source,
                    "Non-string YAML mapping key. Quote numbers, true, false, and null to use them as keys.",
                )
            child = source.child(key)
            if key == "<<" and key_node.style is None:
                raise DiscoveryError(
                    child,
                    "YAML merge keys are unsupported. Write the entries explicitly.",
                )
            if key in result:
                raise DiscoveryError(child, "Duplicate YAML key. Keep one declaration.")
            result[key] = cls.read_value(
                next(events, None), events, child, budget, depth + 1
            )
        return result

    @staticmethod
    def read_node(
        event: Event | None, source: Source
    ) -> ScalarEvent | MappingStartEvent | SequenceStartEvent:
        if isinstance(event, AliasEvent):
            raise DiscoveryError(
                source,
                "YAML aliases are unsupported. Write the value explicitly or use a local OpenAPI reference.",
            )
        if not isinstance(event, (ScalarEvent, MappingStartEvent, SequenceStartEvent)):
            raise DiscoveryError(
                source, "Expected a YAML value. Supply a scalar, mapping, or sequence."
            )
        if event.anchor is not None:
            raise DiscoveryError(
                source,
                "YAML anchors are unsupported. Write the value explicitly or use a local OpenAPI reference.",
            )
        if event.tag is not None:
            raise DiscoveryError(
                source,
                "Explicit YAML tags are unsupported. Use plain JSON-compatible YAML values.",
            )
        return event

    @staticmethod
    def scalar(event: ScalarEvent, source: Source) -> JSON:
        value = event.value
        _validate_unicode(value, source)
        if event.style is not None:
            return value
        if value == "null":
            return None
        if value in {"true", "false"}:
            return value == "true"
        if JSON_NUMBER.fullmatch(value):
            try:
                if "." not in value and "e" not in value.lower():
                    return int(value)
                number = float(value)
            except ValueError as exc:
                raise DiscoveryError(
                    source,
                    "YAML number is too large. Use a smaller JSON number or quote it as a string.",
                ) from exc
            if not math.isfinite(number):
                raise DiscoveryError(
                    source,
                    "YAML number is outside the finite range. Use a smaller JSON number or quote it as a string.",
                )
            return number
        return value


def _read_yaml(data: bytes, source: Source) -> JSON:
    try:
        return _RestrictedYAMLLoader.load_document(data.decode("utf-8"), source)
    except DiscoveryError:
        raise
    except (yaml.YAMLError, ValueError) as exc:
        raise DiscoveryError(
            source,
            "Invalid YAML. Use valid Unicode and supply one UTF-8 document with JSON-compatible scalars. "
            "Use true/false for booleans and null for nulls. Dates and yes/no are strings.",
        ) from exc


def _read(path: Path) -> bytes:
    source = Source(path)
    not_regular = (
        "Input is not a regular file. Supply a local JSON file or a YAML file."
    )
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise DiscoveryError(source, not_regular)
        flags = os.O_RDONLY
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise DiscoveryError(source, not_regular)
            data = bytearray()
            while len(data) <= MAX_SPEC_BYTES:
                chunk = os.read(descriptor, min(65_536, MAX_SPEC_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise DiscoveryError(
            source,
            "Cannot read the spec. Supply a readable local JSON file or a YAML file.",
        ) from exc
    if len(data) > MAX_SPEC_BYTES:
        raise DiscoveryError(
            source, f"Spec exceeds {MAX_SPEC_BYTES} bytes. Supply a smaller spec."
        )
    return bytes(data)


def _mapping(value: JSON, source: Source) -> JSONMap:
    if not isinstance(value, dict):
        raise DiscoveryError(
            source, "Expected a JSON object. Supply an object at this location."
        )
    return value


def _string(value: JSON, source: Source) -> str:
    if not isinstance(value, str) or not value:
        raise DiscoveryError(
            source, "Expected a nonempty string. Supply a string at this location."
        )
    return value


def _required(value: JSONMap, source: Source) -> bool:
    required = value.get("required", False)
    if not isinstance(required, bool):
        raise DiscoveryError(
            source.child("required"), "Invalid required flag. Use true or false."
        )
    return required


@dataclass
class _Discovery:
    root: JSONMap
    source: Source
    version: str
    held: list[HeldItem] = field(default_factory=list)
    reference_work: int = 0
    inventory_work: int = 0
    pointers: dict[str, tuple[Source, JSON]] = field(default_factory=dict)

    def count(self, source: Source, entries: int = 1) -> None:
        self.inventory_work += entries
        if self.inventory_work > MAX_INVENTORY_WORK:
            raise DiscoveryError(
                source, "Inventory work limit exceeded. Supply a smaller spec."
            )

    def _pointer(self, reference: str, source: Source) -> tuple[Source, JSON]:
        if reference in self.pointers:
            return self.pointers[reference]
        if not reference.startswith("#"):
            raise DiscoveryError(
                source,
                "Unsupported reference. Bundle the spec and use a local JSON Pointer.",
            )
        target = self.source
        value: JSON = self.root
        if reference == "#":
            return target, value
        if re.search(r"%(?![0-9a-fA-F]{2})", reference):
            raise DiscoveryError(
                source, "Invalid reference encoding. Use percent-encoded UTF-8."
            )
        try:
            fragment = unquote(reference[1:], errors="strict")
        except UnicodeError as exc:
            raise DiscoveryError(
                source, "Invalid reference encoding. Use a UTF-8 JSON Pointer."
            ) from exc
        if not fragment.startswith("/"):
            raise DiscoveryError(
                source,
                "Unsupported reference. Bundle the spec and use a local JSON Pointer.",
            )
        tokens = fragment[1:].split("/")
        if any(re.search(r"~(?![01])", token) for token in tokens):
            raise DiscoveryError(source, "Invalid JSON Pointer escape. Use ~0 or ~1.")
        for token in tokens:
            key = token.replace("~1", "/").replace("~0", "~")
            target = target.child(key)
            if isinstance(value, dict) and key in value:
                value = value[key]
            elif (
                isinstance(value, list)
                and re.fullmatch(r"0|[1-9][0-9]{0,6}", key)
                and int(key) < len(value)
            ):
                value = value[int(key)]
            else:
                raise DiscoveryError(
                    source,
                    "Reference target is missing. Point to an existing declaration.",
                )
        self.pointers[reference] = target, value
        return target, value

    def resolve(
        self, value: JSON, source: Source, trail: tuple[Source, ...] = ()
    ) -> tuple[JSONMap, Source, tuple[Source, ...]]:
        value, source, trail = self._resolve(value, source, trail)
        return _mapping(value, source), source, trail

    def resolve_schema(
        self, value: JSON, source: Source, trail: tuple[Source, ...]
    ) -> tuple[JSONMap | bool, Source, tuple[Source, ...]]:
        value, definition, trail = self._resolve(value, source, trail)
        if isinstance(value, bool):
            if self.version.startswith("3.0."):
                raise DiscoveryError(
                    definition,
                    "OpenAPI 3.0 does not support boolean schemas. Use a schema object.",
                )
            self.held.append(
                HeldItem(
                    source,
                    "Boolean schema is unsupported for compatibility. Review this input separately or use a schema object.",
                    definition,
                )
            )
            return value, definition, trail
        return _mapping(value, definition), definition, trail

    def _resolve(
        self, value: JSON, source: Source, trail: tuple[Source, ...]
    ) -> tuple[JSON, Source, tuple[Source, ...]]:
        while isinstance(value, dict) and "$ref" in value:
            node = value
            site = source.child("$ref")
            self.reference_work += 1
            if (
                self.reference_work > MAX_REFERENCE_WORK
                or len(trail) >= MAX_REFERENCE_DEPTH
            ):
                raise DiscoveryError(
                    site, "Reference work limit exceeded. Simplify or split the spec."
                )
            target, value = self._pointer(_string(node["$ref"], site), site)
            if target == source or target in trail:
                raise DiscoveryError(
                    site,
                    "Reference cycle detected. Break the recursive reference chain.",
                )
            for key in sorted(node.keys() - {"$ref", "summary", "description"}):
                self.count(source)
                self.held.append(
                    HeldItem(
                        source.child(key),
                        "Reference sibling is unsupported. Move it into the referenced declaration.",
                    )
                )
            trail = (*trail, target)
            source = target
        return value, source, trail

    def parameters(self, node: JSONMap, source: Source) -> dict[tuple[str, str], Input]:
        result: dict[tuple[str, str], Input] = {}
        values = node.get("parameters", [])
        container = source.child("parameters")
        if not isinstance(values, list):
            raise DiscoveryError(container, "Invalid parameter list. Use a JSON array.")
        for i, value in enumerate(values):
            declared = container.child(i)
            self.count(declared)
            parameter, definition, trail = self.resolve(value, declared)
            location = _string(parameter.get("in"), definition.child("in"))
            name = _string(parameter.get("name"), definition.child("name"))
            key = (location, name.lower() if location == "header" else name)
            if key in result:
                raise DiscoveryError(
                    declared,
                    "Duplicate parameter. Keep one declaration per name and location.",
                )
            required = _required(parameter, definition)
            if location == "header" and name.lower() in {
                "accept",
                "content-type",
                "authorization",
            }:
                result[key] = Input(
                    location,
                    name,
                    required,
                    False,
                    declared,
                    definition,
                    "OpenAPI ignores this header parameter. Remove the parameter declaration.",
                )
                continue
            if location == "path" and not required:
                raise DiscoveryError(
                    definition.child("required"),
                    "Path parameters must be required. Set required to true.",
                )
            schema: JSONMap | bool = {}
            if "schema" in parameter:
                schema, _, _ = self.resolve_schema(
                    parameter["schema"], definition.child("schema"), trail
                )
            compatible = (
                location == "query"
                and isinstance(schema, dict)
                and schema.get("type") in ("string", "integer", "number", "boolean")
                and parameter.get("style", "form") == "form"
                and parameter.get("allowReserved", False) is False
                and "content" not in parameter
            )
            if location not in LOCATIONS:
                self.held.append(
                    HeldItem(
                        definition.child("in"),
                        "Unknown parameter location. Use path, query, header, or cookie.",
                    )
                )
            elif not compatible and isinstance(schema, dict):
                self.held.append(
                    HeldItem(
                        declared,
                        "Parameter is outside the v1 scalar query model. Review it separately.",
                    )
                )
            result[key] = Input(
                location, name, required, compatible, declared, definition
            )
        return result

    def body_schema(
        self,
        value: JSON,
        source: Source,
        trail: tuple[Source, ...],
        media: str,
        name: str = "",
        required: bool = False,
        depth: int = 0,
    ) -> list[Input]:
        self.count(source)
        if depth > MAX_NESTING:
            raise DiscoveryError(
                source,
                "Expanded body nesting exceeds the limit. Flatten the body schema.",
            )
        node, definition, trail = self.resolve_schema(value, source, trail)
        found = (
            [Input("body", f"{media}#{name}", required, False, source, definition)]
            if name
            else []
        )
        if isinstance(node, bool):
            return found
        keys = {"allOf", "anyOf", "oneOf", "additionalProperties", "$dynamicRef", "$id"}
        for key in sorted(keys & node.keys()):
            self.held.append(
                HeldItem(
                    definition.child(key),
                    "Body schema construct is unsupported. Review its declarations separately.",
                )
            )
        if "$id" in node or "$dynamicRef" in node:
            return found
        properties = _mapping(
            node.get("properties", {}), definition.child("properties")
        )
        required_names = node.get("required", [])
        if not isinstance(required_names, list) or any(
            not isinstance(item, str) for item in required_names
        ):
            raise DiscoveryError(
                definition.child("required"),
                "Invalid required property list. Use an array of names.",
            )
        for key, child in sorted(properties.items()):
            token = key.replace("~", "~0").replace("/", "~1")
            found.extend(
                self.body_schema(
                    child,
                    definition.child("properties").child(key),
                    trail,
                    media,
                    f"{name}/{token}",
                    key in required_names,
                    depth + 1,
                )
            )
        if "items" in node:
            found.extend(
                self.body_schema(
                    node["items"],
                    definition.child("items"),
                    trail,
                    media,
                    f"{name}/*",
                    depth=depth + 1,
                )
            )
        return found

    def operation(
        self,
        method: str,
        path: str,
        value: JSON,
        source: Source,
        declaration: Source,
        inherited: dict[tuple[str, str], Input],
    ) -> Operation:
        node = _mapping(value, source)
        params = inherited | self.parameters(node, source)
        self.count(source, len(params))
        compatible = method == "get" and "requestBody" not in node
        if method != "get":
            self.held.append(
                HeldItem(
                    source, "Method is outside the v1 GET model. Review it separately."
                )
            )
        inputs = [
            Input(
                p.location,
                p.name,
                p.required,
                compatible and p.compatible,
                p.source,
                p.definition,
                p.ignored_reason,
            )
            for _, p in sorted(params.items())
        ]
        if "requestBody" in node:
            declared = source.child("requestBody")
            self.held.append(
                HeldItem(
                    declared,
                    "Request bodies are outside the v1 query model. Review this body separately.",
                )
            )
            body, definition, trail = self.resolve(node["requestBody"], declared)
            content = _mapping(body.get("content"), definition.child("content"))
            for media, media_value in sorted(content.items()):
                media_source = definition.child("content").child(media)
                self.count(media_source)
                descriptor = _mapping(media_value, media_source)
                inputs.append(
                    Input(
                        "body",
                        media,
                        _required(body, definition),
                        False,
                        declared,
                        media_source,
                    )
                )
                if "schema" in descriptor:
                    inputs.extend(
                        self.body_schema(
                            descriptor["schema"],
                            media_source.child("schema"),
                            trail,
                            media,
                        )
                    )
        if "callbacks" in node:
            self.held.append(
                HeldItem(
                    source.child("callbacks"),
                    "Callbacks are outside the inventory model. Review them separately.",
                )
            )
        digest = hashlib.sha256(f"{method.upper()} {path}".encode()).hexdigest()[:32]
        return Operation(
            f"op-{digest}",
            method.upper(),
            path,
            declaration,
            source,
            tuple(sorted(inputs, key=lambda item: (item.location, item.name))),
            any(item.compatible for item in inputs)
            and all(
                item.ignored_reason is not None or not item.required or item.compatible
                for item in inputs
            ),
        )

    def inventory(self) -> Inventory:
        operations: list[Operation] = []
        paths_source = self.source.child("paths")
        paths = _mapping(self.root.get("paths", {}), paths_source)
        if "webhooks" in self.root:
            self.held.append(
                HeldItem(
                    self.source.child("webhooks"),
                    "Webhooks are outside the inventory model. Review them separately.",
                )
            )
        for path, value in sorted(paths.items()):
            if path.startswith("x-"):
                continue
            declaration = paths_source.child(path)
            if (
                not path.startswith("/")
                or path.startswith("//")
                or any(c in path for c in ("?", "#", "\\"))
            ):
                raise DiscoveryError(
                    declaration,
                    "Invalid operation path. Use a root-relative path without an authority, query, or fragment.",
                )
            node, source, _ = self.resolve(value, declaration)
            inherited = self.parameters(node, source)
            for key in sorted(
                node.keys()
                - METHODS
                - {"summary", "description", "servers", "parameters"}
            ):
                if not key.startswith("x-"):
                    field_source = source.child(key)
                    self.count(field_source)
                    self.held.append(
                        HeldItem(
                            field_source,
                            "Unsupported path item field. Review it separately.",
                        )
                    )
            for method in sorted(METHODS & node.keys()):
                if len(operations) >= MAX_OPERATIONS:
                    raise DiscoveryError(
                        source.child(method),
                        f"Operation count exceeds {MAX_OPERATIONS}. Supply a smaller spec.",
                    )
                operations.append(
                    self.operation(
                        method,
                        path,
                        node[method],
                        source.child(method),
                        declaration if declaration != source else source.child(method),
                        inherited,
                    )
                )
        return Inventory(
            self.version,
            self.source,
            tuple(sorted(operations, key=lambda op: (op.method, op.path))),
            tuple(
                sorted(
                    set(self.held), key=lambda item: (item.source.pointer, item.reason)
                )
            ),
        )


def _read_json(data: bytes, source: Source) -> JSON:
    try:
        parsed: object = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_Pairs,
            parse_constant=_reject_constant,
        )
    except (ValueError, RecursionError) as exc:
        raise DiscoveryError(
            source,
            "Invalid JSON or excessive nesting. Supply a bounded UTF-8 JSON document.",
        ) from exc
    return _normalize(parsed, source, _DocumentBudget())


def load_inventory(path: Path) -> Inventory:
    """Inventory a local spec. YAML dates, yes/no, and other non-JSON scalars stay strings."""
    source = Source(path)
    extension = path.suffix.lower()
    if extension not in {".json", ".yaml", ".yml"}:
        raise DiscoveryError(
            source, "Unsupported spec extension. Use .json, .yaml, or .yml."
        )
    data = _read(path)
    root = _mapping(
        _read_json(data, source) if extension == ".json" else _read_yaml(data, source),
        source,
    )
    version = _string(root.get("openapi"), source.child("openapi"))
    if not re.fullmatch(r"3\.[01]\.[0-9]+", version):
        raise DiscoveryError(
            source.child("openapi"),
            "Unsupported OpenAPI version. Supply a 3.0.x or 3.1.x document.",
        )
    if version.startswith("3.0.") and "paths" not in root:
        raise DiscoveryError(
            source.child("paths"), "OpenAPI 3.0 requires paths. Supply a paths object."
        )
    return _Discovery(root, source, version).inventory()
