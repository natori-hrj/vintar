"""Inventory declared OpenAPI inputs from a single local JSON document."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

MAX_SPEC_BYTES = 1_048_576
MAX_NESTING = 48
MAX_OPERATIONS = 512
MAX_REFERENCE_DEPTH = 24
MAX_REFERENCE_WORK = 4096
MAX_INVENTORY_WORK = 8192

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


@dataclass(frozen=True)
class Input:
    location: str
    name: str
    required: bool
    compatible: bool
    source: Source
    definition: Source


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


def _normalize(value: object, source: Source, depth: int = 0) -> JSON:
    if depth > MAX_NESTING:
        raise DiscoveryError(
            source, f"JSON nesting exceeds {MAX_NESTING}. Flatten the spec."
        )
    if isinstance(value, _Pairs):
        result: JSONMap = {}
        for key, item in value.values:
            _validate_unicode(key, source)
            child = source.child(key)
            if key in result:
                raise DiscoveryError(child, "Duplicate JSON key. Keep one declaration.")
            result[key] = _normalize(item, child, depth + 1)
        return result
    if isinstance(value, list):
        return [
            _normalize(item, source.child(i), depth + 1) for i, item in enumerate(value)
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


def _read(path: Path) -> bytes:
    source = Source(path)
    not_regular = "Input is not a regular file. Supply a local JSON file."
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
            source, "Cannot read the spec. Supply a readable local JSON file."
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
        node = _mapping(value, source)
        while "$ref" in node:
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
            node = _mapping(value, source)
        return node, source, trail

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
            if location == "path" and not required:
                raise DiscoveryError(
                    definition.child("required"),
                    "Path parameters must be required. Set required to true.",
                )
            schema: JSONMap = {}
            if "schema" in parameter:
                schema, _, _ = self.resolve(
                    parameter["schema"], definition.child("schema"), trail
                )
            compatible = (
                location == "query"
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
            elif not compatible:
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
        if isinstance(value, bool):
            self.held.append(
                HeldItem(source, "Boolean schema is unsupported. Review it separately.")
            )
            return (
                [Input("body", f"{media}#{name}", required, False, source, source)]
                if name
                else []
            )
        node, definition, trail = self.resolve(value, source, trail)
        found = (
            [Input("body", f"{media}#{name}", required, False, source, definition)]
            if name
            else []
        )
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
            and all(not item.required or item.compatible for item in inputs),
        )

    def inventory(self, version: str) -> Inventory:
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
                    self.held.append(
                        HeldItem(
                            source.child(key),
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
            version,
            self.source,
            tuple(sorted(operations, key=lambda op: (op.method, op.path))),
            tuple(
                sorted(
                    set(self.held), key=lambda item: (item.source.pointer, item.reason)
                )
            ),
        )


def load_inventory(path: Path) -> Inventory:
    """Load a local OpenAPI JSON file and inventory its declared inputs."""
    source = Source(path)
    data = _read(path)
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
    root = _mapping(_normalize(parsed, source), source)
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
    return _Discovery(root, source).inventory(version)
