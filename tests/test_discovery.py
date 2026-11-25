"""Offline OpenAPI inventory contracts."""

import json
import socket
from dataclasses import asdict
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
    directory = tmp_path / "not-a-file.json"
    directory.mkdir()
    with pytest.raises(DiscoveryError, match="Supply a readable local JSON file"):
        load_inventory(tmp_path / "missing.json")
    with pytest.raises(DiscoveryError, match="Supply a local JSON file"):
        load_inventory(directory)


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


@pytest.mark.parametrize("version", ["3.0.4", "3.1.2"])
@pytest.mark.parametrize("reverse", [False, True])
def test_get_shared_schema_chain_matches_pre_pr_golden(tmp_path, version, reverse):
    def operation(label):
        return {
            "get": {
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "schema": {
                            "$ref": "#/components/schemas/Alias",
                            "default": label,
                        },
                    }
                ]
            }
        }

    entries = [("/a", operation("a")), ("/b", operation("b"))]
    if reverse:
        entries.reverse()
    path = write_spec(
        tmp_path,
        paths=dict(entries),
        openapi=version,
        components={
            "schemas": {
                "Alias": {
                    "$ref": "#/components/schemas/Name",
                    "not": {"type": "string"},
                },
                "Name": {"type": "string"},
            }
        },
    )

    inventory = load_inventory(path)

    assert [
        (
            item.method,
            item.path,
            item.compatible,
            item.compatibility_blocker,
            item.inputs[0].compatible,
        )
        for item in inventory.operations
    ] == [
        ("GET", "/a", False, None, False),
        ("GET", "/b", False, None, False),
    ]
    assert [item.source.pointer for item in inventory.held] == [
        "/components/schemas/Alias/not",
        "/paths/~1a/get/parameters/0",
        "/paths/~1a/get/parameters/0/schema/default",
        "/paths/~1b/get/parameters/0",
        "/paths/~1b/get/parameters/0/schema/default",
    ]


def shared_reference_work_spec(operation_count, chain_length):
    schemas = {
        f"Node{index}": (
            {"type": "string"}
            if index == chain_length - 1
            else {"$ref": f"#/components/schemas/Node{index + 1}"}
        )
        for index in range(chain_length)
    }
    paths = {
        f"/op{index:03d}": {
            "get": {
                "parameters": [
                    {
                        "name": "q",
                        "in": "query",
                        "schema": {"$ref": "#/components/schemas/Node0"},
                    }
                ]
            }
        }
        for index in range(operation_count)
    }
    return paths, {"schemas": schemas}


def test_get_cached_reference_work_limit_matches_pre_pr_golden(tmp_path):
    paths, schemas = shared_reference_work_spec(200, 22)
    path = write_spec(tmp_path, paths=paths, components=schemas)

    with pytest.raises(DiscoveryError) as caught:
        load_inventory(path)

    assert caught.value.reason == (
        "Reference work limit exceeded. Simplify or split the spec."
    )
    assert caught.value.source == Source(path, "/components/schemas/Node3/$ref")


def test_get_warm_cache_charges_the_same_work_as_cold_resolution(tmp_path, monkeypatch):
    monkeypatch.setattr(discovery, "MAX_REFERENCE_WORK", 1)
    paths, schemas = shared_reference_work_spec(2, 1)
    path = write_spec(tmp_path, paths=paths, components=schemas)

    with pytest.raises(DiscoveryError) as caught:
        load_inventory(path)

    assert caught.value.reason == (
        "Reference work limit exceeded. Simplify or split the spec."
    )
    assert caught.value.source == Source(
        path, "/paths/~1op001/get/parameters/0/schema/$ref"
    )


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


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("version", ["3.0.4", "3.1.2"])
@pytest.mark.parametrize("referenced", [True, False])
def test_boolean_query_schema_is_version_specific(tmp_path, value, version, referenced):
    definition = "/components/schemas/Boolean"
    source = "/paths/~1a/get/parameters/0/schema"
    schema = {"$ref": f"#{definition}"} if referenced else value
    path = write_spec(
        tmp_path,
        openapi=version,
        paths={
            "/a": {
                "get": {"parameters": [{"in": "query", "name": "q", "schema": schema}]}
            },
            "/b": {
                "get": {
                    "parameters": [
                        {"in": "query", "name": "other", "schema": {"type": "string"}}
                    ]
                }
            },
        },
        components={"schemas": {"Boolean": value}},
    )
    resolved = Source(path, definition if referenced else source)
    if version.startswith("3.0."):
        with pytest.raises(DiscoveryError, match="Use a schema object") as caught:
            load_inventory(path)
        assert caught.value.source == resolved
        return
    inventory = load_inventory(path)
    first, second = inventory.operations
    assert not first.inputs[0].compatible
    assert second.compatible
    [held] = inventory.held
    assert held.source == Source(path, source)
    assert held.definition == resolved
    assert "Review this input separately or use a schema object" in held.reason


@pytest.mark.parametrize("value", [True, False])
@pytest.mark.parametrize("version", ["3.0.4", "3.1.2"])
def test_referenced_boolean_request_body_schema(tmp_path, value, version):
    definition = "/components/schemas/Boolean"
    path = write_spec(
        tmp_path,
        openapi=version,
        paths={
            "/a": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": f"#{definition}"}}
                        }
                    }
                }
            },
            "/b": {"get": {}},
        },
        components={"schemas": {"Boolean": value}},
    )
    if version.startswith("3.0."):
        with pytest.raises(DiscoveryError, match="Use a schema object") as caught:
            load_inventory(path)
        assert caught.value.source == Source(path, definition)
        return
    inventory = load_inventory(path)
    assert [op.path for op in inventory.operations] == ["/b", "/a"]
    [body] = inventory.operations[1].inputs
    assert body.name == "application/json" and not body.compatible
    [held] = [item for item in inventory.held if item.definition is not None]
    assert held.source == Source(
        path, "/paths/~1a/post/requestBody/content/application~1json/schema"
    )
    assert held.definition == Source(path, definition)
    assert "Review this input separately" in held.reason


@pytest.mark.parametrize("header", ["Authorization", "aCCePt", "CONTENT-TYPE"])
def test_openapi_ignored_headers_do_not_block_compatible_query(tmp_path, header):
    path = write_spec(
        tmp_path,
        paths={
            "/a": {
                "get": {
                    "parameters": [
                        {"in": "query", "name": "q", "schema": {"type": "string"}},
                        {
                            "in": "header",
                            "name": header,
                            "required": True,
                            "schema": {"type": "string"},
                        },
                    ]
                }
            }
        },
    )
    inventory = load_inventory(path)
    [operation] = inventory.operations
    ignored, query = operation.inputs
    assert operation.compatible and query.compatible
    assert (ignored.name, ignored.required, ignored.compatible) == (header, True, False)
    assert (
        ignored.source
        == ignored.definition
        == Source(path, "/paths/~1a/get/parameters/1")
    )
    assert (
        ignored.ignored_reason is not None
        and "OpenAPI ignores" in ignored.ignored_reason
    )
    assert inventory.held == ()


def test_reused_path_item_unsupported_fields_consume_work_budget(tmp_path, monkeypatch):
    path = write_spec(
        tmp_path,
        paths={
            f"/{i:02}": {"$ref": "#/components/pathItems/shared"} for i in range(10)
        },
        components={"pathItems": {"shared": {"unsupportedA": {}, "unsupportedB": {}}}},
    )
    monkeypatch.setattr(discovery, "MAX_INVENTORY_WORK", 7)
    with pytest.raises(
        DiscoveryError, match=r"Inventory work limit exceeded. Supply a smaller spec"
    ) as caught:
        load_inventory(path)
    assert caught.value.source == Source(
        path, "/components/pathItems/shared/unsupportedB"
    )


def without_filename(value, path):
    if isinstance(value, Path):
        assert value == path
        return "<spec>"
    if isinstance(value, dict):
        return {key: without_filename(item, path) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(without_filename(item, path) for item in value)
    return value


@pytest.mark.parametrize(
    "stem, extension", [("openapi30", ".yaml"), ("openapi31", ".yml")]
)
def test_yaml_fixtures_match_json_inventory_and_evidence(stem, extension):
    json_path = FIXTURES / f"{stem}.json"
    yaml_path = FIXTURES / f"{stem}{extension}"
    assert without_filename(
        asdict(load_inventory(yaml_path)), yaml_path
    ) == without_filename(asdict(load_inventory(json_path)), json_path)


def test_yaml_scalars_follow_json_spellings():
    text = b"""
true_values: [true, false, null, 12, -2.5, 1e2]
strings: [yes, no, ON, 2026-11-19, 0x10, 01, .nan, Null, "true"]
quoted_key:
  "200": OK
"""
    document = discovery._read_yaml(text, Source(Path("scalars.yaml")))
    assert document == {
        "true_values": [True, False, None, 12, -2.5, 100.0],
        "strings": [
            "yes",
            "no",
            "ON",
            "2026-11-19",
            "0x10",
            "01",
            ".nan",
            "Null",
            "true",
        ],
        "quoted_key": {"200": "OK"},
    }
    assert type(document["true_values"][0]) is bool
    assert type(document["true_values"][3]) is int
    assert type(document["true_values"][5]) is float


@pytest.mark.parametrize(
    ("fragment", "pointer", "reason"),
    [
        ("paths: {}\npaths: {}\n", "/paths", "Keep one declaration"),
        ("paths: &shared {}", "/paths", "YAML anchors are unsupported"),
        ("paths: *shared", "/paths", "YAML aliases are unsupported"),
        ("paths: {<<: *shared}", "/paths/<<", "Write the entries explicitly"),
        ("paths: {<<: {}}", "/paths/<<", "Write the entries explicitly"),
        ("paths: !custom {}", "/paths", "Use plain JSON-compatible YAML values"),
        ("paths: !!map {}", "/paths", "Use plain JSON-compatible YAML values"),
        ("paths: {2: {}}", "/paths", "Quote numbers"),
        ("paths: {true: {}}", "/paths", "Quote numbers"),
        ("paths: {null: {}}", "/paths", "Quote numbers"),
        ("paths: {[one, two]: {}}", "/paths", "Use a quoted string key"),
        ("paths: {", "", "Dates and yes/no are strings"),
        ("paths: {}\n---\npaths: {}\n", "", "Supply one OpenAPI document"),
        ("paths: {}\nx-number: 1e999", "/x-number", "Use a smaller JSON number"),
    ],
)
def test_restricted_yaml_errors_include_source_and_remediation(
    tmp_path, fragment, pointer, reason
):
    path = tmp_path / "restricted.yaml"
    path.write_text(f"openapi: 3.1.2\n{fragment}", encoding="utf-8")
    with pytest.raises(DiscoveryError, match=reason) as caught:
        load_inventory(path)
    assert caught.value.source == Source(path, pointer)


def test_empty_yaml_is_rejected(tmp_path):
    path = tmp_path / "empty.yml"
    path.write_text("# empty\n", encoding="utf-8")
    with pytest.raises(DiscoveryError, match="Supply one OpenAPI document"):
        load_inventory(path)


@pytest.mark.parametrize(
    ("limit", "threshold", "reason"),
    [
        ("MAX_SPEC_BYTES", 12, "Supply a smaller spec"),
        ("MAX_NESTING", 2, "Flatten the spec"),
        ("MAX_DOCUMENT_NODES", 3, "Document node limit exceeded"),
        ("MAX_OPERATIONS", 1, "Operation count exceeds"),
        ("MAX_REFERENCE_WORK", 1, "Reference work limit exceeded"),
        ("MAX_INVENTORY_WORK", 1, "Inventory work limit exceeded"),
    ],
)
def test_yaml_limits_apply_to_construction_and_inventory(
    monkeypatch, limit, threshold, reason
):
    path = FIXTURES / "openapi30.yaml"
    monkeypatch.setattr(discovery, limit, threshold)
    with pytest.raises(DiscoveryError, match=reason) as caught:
        load_inventory(path)
    assert caught.value.source.file == path


def test_unsupported_spec_extension_has_remediation(tmp_path):
    path = tmp_path / "openapi.toml"
    with pytest.raises(DiscoveryError, match=r"Use \.json, \.yaml, or \.yml") as caught:
        load_inventory(path)
    assert caught.value.source == Source(path)


@pytest.mark.parametrize("quote", ['"', "'"])
def test_quoted_merge_spelling_is_an_ordinary_body_property(tmp_path, quote):
    yaml_path = tmp_path / "openapi.yaml"
    yaml_path.write_text(
        f"""openapi: 3.1.2
paths:
  /example:
    post:
      requestBody:
        content:
          application/json:
            schema:
              properties:
                {quote}<<{quote}: {{type: string}}
""",
        encoding="utf-8",
    )
    json_path = write_spec(
        tmp_path,
        paths={
            "/example": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"properties": {"<<": {"type": "string"}}}
                            }
                        }
                    }
                }
            }
        },
    )
    yaml_inventory = load_inventory(yaml_path)
    assert yaml_inventory.operations[0].inputs[1].name == "application/json#/<<"
    assert without_filename(asdict(yaml_inventory), yaml_path) == without_filename(
        asdict(load_inventory(json_path)), json_path
    )


def test_yaml_out_of_range_unicode_escape_names_source(tmp_path):
    path = tmp_path / "bad-unicode.yaml"
    path.write_text(
        'openapi: 3.1.2\npaths: {}\nx-label: "' + r"\U00110000" + '"\n',
        encoding="utf-8",
    )
    with pytest.raises(DiscoveryError, match="Use valid Unicode") as caught:
        load_inventory(path)
    assert caught.value.source == Source(path)
    assert str(path) in str(caught.value)
