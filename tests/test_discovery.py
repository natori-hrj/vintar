"""Offline OpenAPI inventory contracts."""

import json
import socket
from pathlib import Path

import pytest

from vintar.regression import discovery
from vintar.regression.discovery import DiscoveryError, Source, load_inventory

FIXTURES = Path(__file__).parent / "fixtures" / "discovery"


def write_spec(tmp_path, *, paths=None, **fields):
    path = tmp_path / "spec.json"
    path.write_text(
        json.dumps({"openapi": "3.1.2", "paths": paths or {}, **fields}),
        encoding="utf-8",
    )
    return path


def test_openapi30_merges_and_reuses_parameters():
    path = FIXTURES / "openapi30.json"
    inventory = load_inventory(path)
    first, override, post = inventory.operations
    assert [(op.method, op.path) for op in inventory.operations] == [
        ("GET", "/a"),
        ("GET", "/z"),
        ("POST", "/z"),
    ]
    [query] = first.inputs
    header, replaced = override.inputs
    inherited_header, inherited_query = post.inputs
    assert query.source == Source(path, "/paths/~1a/get/parameters/0")
    assert (
        query.definition
        == inherited_query.definition
        == Source(path, "/components/parameters/q")
    )
    assert (header.name, inherited_header.name) == ("x-mode", "X-Mode")
    assert (
        replaced.definition
        == replaced.source
        == Source(path, "/paths/~1z/get/parameters/0")
    )
    assert replaced.required and replaced.compatible
    assert not query.required and query.compatible
    assert not inherited_query.compatible and not post.compatible
    assert first.compatible and override.compatible
    assert any(
        held.source == post.source and "GET" in held.reason for held in inventory.held
    )


def test_openapi31_inventories_declared_body_properties_without_network(monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("Discovery attempted network access.")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)

    path = FIXTURES / "openapi31.json"
    inventory = load_inventory(path)
    get, patch = inventory.operations
    assert patch.source == Source(path, "/paths/~1items~1{id}")
    assert patch.definition == Source(path, "/components/pathItems/items/patch")
    assert not get.compatible and not patch.compatible
    assert [(item.location, item.name) for item in patch.inputs] == [
        ("body", "application/json"),
        ("body", "application/json#/children"),
        ("body", "application/json#/children/*"),
        ("body", "application/json#/children/*/x~1y"),
        ("body", "application/json#/code"),
        ("cookie", "mode"),
        ("path", "id"),
    ]
    code = patch.inputs[4]
    assert code.required and not code.compatible
    assert code.source == Source(path, "/components/schemas/Item/properties/code")
    assert all(
        item.source.file == path and item.source.pointer for item in patch.inputs
    )
    pointers = {held.source.pointer for held in inventory.held}
    assert {
        "/webhooks",
        "/components/pathItems/items/patch/callbacks",
        "/components/schemas/Item/additionalProperties",
        "/components/pathItems/items/get/parameters/0",
    } <= pointers
    assert all(held.source.file == path and held.reason for held in inventory.held)


def test_ids_ignore_mapping_order_operation_ids_and_unrelated_operations(tmp_path):
    original = json.loads((FIXTURES / "openapi30.json").read_text(encoding="utf-8"))
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(original), encoding="utf-8")
    inventory = load_inventory(path)
    path.write_text(json.dumps(original, sort_keys=True), encoding="utf-8")
    assert load_inventory(path) == inventory
    original["paths"]["/a"]["get"]["operationId"] = "renamed"
    original["paths"]["/new"] = {"get": {}}
    path.write_text(json.dumps(original), encoding="utf-8")
    assert [op.id for op in load_inventory(path).operations if op.path != "/new"] == [
        op.id for op in inventory.operations
    ]


@pytest.mark.parametrize(
    ("raw", "pointer", "reason"),
    [
        ('{"openapi":"3.1.2","paths":{},"paths":{}}', "/paths", "Keep one declaration"),
        ('{"openapi":"2.0.0","paths":{}}', "/openapi", "Supply a 3.0.x or 3.1.x"),
        ('{"openapi":"3.0.4"}', "/paths", "Supply a paths object"),
        ('{"openapi":"3.1.2","paths":[]}', "/paths", "Supply an object"),
        (
            '{"openapi":"3.1.2","paths":{"//remote":{}}}',
            "/paths/~1~1remote",
            "Use a root-relative path",
        ),
        ('{"openapi": NaN}', "", "Supply a bounded UTF-8 JSON document"),
        ("{", "", "Supply a bounded UTF-8 JSON document"),
    ],
)
def test_invalid_inputs_report_source_and_fix(tmp_path, raw, pointer, reason):
    path = tmp_path / "broken.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(DiscoveryError, match=reason) as caught:
        load_inventory(path)
    assert caught.value.source == Source(path, pointer)


@pytest.mark.parametrize(
    ("reference", "reason"),
    [
        ("https://never-fetch.invalid/spec.json#/item", "Bundle the spec"),
        ("file:///tmp/spec.json#/item", "Bundle the spec"),
        ("other.json#/item", "Bundle the spec"),
        ("#name", "Bundle the spec"),
        ("#/components/missing", "Point to an existing declaration"),
        ("#/components/~2", "Use ~0 or ~1"),
        ("#/components/%FF", "Use a UTF-8 JSON Pointer"),
        ("#/paths/~1example", "Break the recursive reference chain"),
    ],
)
def test_invalid_references_are_rejected_at_use_site(tmp_path, reference, reason):
    path = write_spec(tmp_path, paths={"/example": {"$ref": reference}})
    with pytest.raises(DiscoveryError, match=reason) as caught:
        load_inventory(path)
    assert caught.value.source == Source(path, "/paths/~1example/$ref")


def test_reference_targets_can_use_array_indices_and_escaped_tokens(tmp_path):
    path = write_spec(
        tmp_path,
        paths={
            "/first": {"get": {"parameters": [{"$ref": "#/x-declarations/a~1b~0/0"}]}}
        },
        **{
            "x-declarations": {
                "a/b~": [{"name": "q", "in": "query", "schema": {"type": "string"}}]
            }
        },
    )
    [operation] = load_inventory(path).operations
    assert operation.inputs[0].definition.pointer == "/x-declarations/a~1b~0/0"


def test_recursive_body_reference_reports_cycle(tmp_path):
    path = write_spec(
        tmp_path,
        paths={
            "/a": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Node"}
                            }
                        }
                    }
                }
            }
        },
        components={
            "schemas": {
                "Node": {"properties": {"child": {"$ref": "#/components/schemas/Node"}}}
            }
        },
    )
    with pytest.raises(
        DiscoveryError, match="Break the recursive reference chain"
    ) as caught:
        load_inventory(path)
    assert (
        caught.value.source.pointer == "/components/schemas/Node/properties/child/$ref"
    )


@pytest.mark.parametrize(
    ("constant", "limit", "reason"),
    [
        ("MAX_SPEC_BYTES", 12, "Supply a smaller spec"),
        ("MAX_NESTING", 2, "Flatten the spec"),
        ("MAX_OPERATIONS", 1, "Operation count exceeds"),
        ("MAX_REFERENCE_WORK", 1, "Reference work limit exceeded"),
        ("MAX_REFERENCE_DEPTH", 0, "Reference work limit exceeded"),
        ("MAX_INVENTORY_WORK", 1, "Inventory work limit exceeded"),
    ],
)
def test_inventory_limits(tmp_path, monkeypatch, constant, limit, reason):
    path = FIXTURES / "openapi30.json"
    monkeypatch.setattr(discovery, constant, limit)
    with pytest.raises(DiscoveryError, match=reason) as caught:
        load_inventory(path)
    assert caught.value.source.file == path


def test_only_regular_files_are_read(tmp_path):
    with pytest.raises(DiscoveryError, match="Supply a readable local JSON file"):
        load_inventory(tmp_path / "missing.json")
    with pytest.raises(DiscoveryError, match="Supply a local JSON file"):
        load_inventory(tmp_path)


def test_unknown_path_fields_and_reference_siblings_are_held(tmp_path):
    path = write_spec(
        tmp_path,
        paths={"/a": {"$ref": "#/x-item", "post": {}}},
        **{"x-item": {"connect": {}, "x-extension": {}, "get": {}}},
    )
    inventory = load_inventory(path)
    assert [item.source.pointer for item in inventory.held] == [
        "/paths/~1a/post",
        "/x-item/connect",
    ]


def test_duplicate_parameters_fail_with_declaration_pointer(tmp_path):
    parameter = {"name": "q", "in": "query"}
    path = write_spec(
        tmp_path, paths={"/a": {"get": {"parameters": [parameter, parameter]}}}
    )
    with pytest.raises(
        DiscoveryError, match="Keep one declaration per name and location"
    ) as caught:
        load_inventory(path)
    assert caught.value.source.pointer == "/paths/~1a/get/parameters/1"


@pytest.mark.parametrize(
    ("raw", "pointer", "reason"),
    [
        (r'{"openapi":"3.1.2","paths":{"/\ud800":{}}}', "/paths", "Use valid Unicode"),
        ('{"openapi":"3.1.2","extra":1e999}', "/extra", "Use a finite number"),
        ('{"openapi":"","paths":{}}', "/openapi", "Supply a string"),
    ],
)
def test_nonportable_json_values_fail_with_evidence(tmp_path, raw, pointer, reason):
    path = tmp_path / "invalid.json"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(DiscoveryError, match=reason) as caught:
        load_inventory(path)
    assert caught.value.source == Source(path, pointer)


@pytest.mark.parametrize(
    ("declaration", "suffix", "reason"),
    [
        (
            {"name": "q", "in": "query", "required": "true"},
            "/required",
            "Use true or false",
        ),
        ({"name": "id", "in": "path"}, "/required", "Set required to true"),
    ],
)
def test_invalid_parameter_flags_have_source(tmp_path, declaration, suffix, reason):
    path = write_spec(tmp_path, paths={"/a": {"get": {"parameters": [declaration]}}})
    with pytest.raises(DiscoveryError, match=reason) as caught:
        load_inventory(path)
    assert caught.value.source == Source(path, f"/paths/~1a/get/parameters/0{suffix}")


def test_only_get_with_compatible_required_inputs_is_marked_compatible(tmp_path):
    query = {"name": "q", "in": "query", "schema": {"type": "string"}}
    header = {"name": "X-Mode", "in": "header", "required": True}
    unknown = {"name": "something", "in": "extension"}
    path = write_spec(
        tmp_path, paths={"/a": {"get": {"parameters": [query, header, unknown]}}}
    )
    result = load_inventory(path)
    [operation] = result.operations
    assert not operation.compatible
    assert [(item.location, item.compatible) for item in operation.inputs] == [
        ("extension", False),
        ("header", False),
        ("query", True),
    ]
    assert any(item.source.pointer.endswith("/2/in") for item in result.held)


def test_exact_input_byte_limit_is_accepted(tmp_path, monkeypatch):
    path = write_spec(tmp_path)
    monkeypatch.setattr(discovery, "MAX_SPEC_BYTES", path.stat().st_size)
    assert load_inventory(path).operations == ()


def test_boolean_body_schema_is_held_with_source(tmp_path):
    path = write_spec(
        tmp_path,
        paths={
            "/a": {
                "patch": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"properties": {"flag": True}}
                            }
                        }
                    }
                }
            }
        },
    )
    inventory = load_inventory(path)
    [operation] = inventory.operations
    assert operation.inputs[1].name == "application/json#/flag"
    assert any(
        item.source == operation.inputs[1].source and "Boolean schema" in item.reason
        for item in inventory.held
    )


def test_opened_descriptor_must_still_be_a_regular_file(tmp_path, monkeypatch):
    path = write_spec(tmp_path)
    open_file = discovery.os.open

    def substitute(name, flags):
        return open_file(tmp_path if name == path else name, flags)

    monkeypatch.setattr(discovery.os, "open", substitute)
    with pytest.raises(DiscoveryError, match="Input is not a regular file") as caught:
        load_inventory(path)
    assert caught.value.source == Source(path)
