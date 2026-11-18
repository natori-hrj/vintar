"""Tests for reviewer selection and the offline discovery command."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vintar import discover_cli
from vintar.cli import app
from vintar.regression import discovery
from vintar.regression.discovery import (
    DiscoveryError,
    HeldItem,
    SelectionError,
    input_id,
    load_inventory,
    load_selection,
)

SPEC = Path(__file__).parent / "fixtures" / "discovery" / "openapi30.json"


def review(path, *ids):
    path.write_text(f"version = 1\napproved = {json.dumps(ids)}\n", encoding="utf-8")
    return path


def test_selection_accepts_approved_ids_and_empty_array(tmp_path):
    inventory = load_inventory(SPEC)
    first = inventory.operations[0]
    identifier = input_id(first, first.inputs[0])
    path = review(tmp_path / "review.toml", identifier)
    before = path.read_bytes()
    assert load_selection(path, inventory) == frozenset({identifier})
    assert path.read_bytes() == before
    assert load_selection(review(path), inventory) == frozenset()


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("", "Use only version and approved"),
        ("version = 1\napproved = []\nother = 1", "Use only version and approved"),
        ("version = 1\nversion = 1\napproved = []", "Invalid selection TOML"),
        ("version = true\napproved = []", "Invalid selection schema"),
        ('version = 1\napproved = "abc"', "Invalid selection schema"),
        ("version = 1\napproved = [1]", r"Invalid input ID at approved\[0\]"),
    ],
)
def test_invalid_selection_forms(tmp_path, text, reason):
    path = tmp_path / "review.toml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(SelectionError, match=reason):
        load_selection(path, load_inventory(SPEC))


def test_selection_must_be_readable(tmp_path):
    with pytest.raises(SelectionError, match="Supply a bounded local TOML file"):
        load_selection(tmp_path / "missing.toml", load_inventory(SPEC))


def test_stale_and_duplicate_ids_name_the_id(tmp_path):
    inventory = load_inventory(SPEC)
    operation = inventory.operations[0]
    identifier = input_id(operation, operation.inputs[0])
    path = tmp_path / "review.toml"
    with pytest.raises(SelectionError, match=f"Duplicate input ID {identifier}"):
        load_selection(review(path, identifier, identifier), inventory)
    stale = "input-" + "0" * 32
    with pytest.raises(SelectionError, match=f"Stale input ID {stale}"):
        load_selection(review(path, stale), inventory)


def test_held_ignored_and_incompatible_ids_are_rejected(tmp_path):
    inventory = load_inventory(SPEC)
    first, second, third = inventory.operations
    [query] = first.inputs
    held_inventory = replace(
        inventory,
        held=(
            *inventory.held,
            HeldItem(query.source.child("schema"), "Review this schema."),
        ),
    )
    path = tmp_path / "review.toml"
    with pytest.raises(SelectionError, match=input_id(first, query)):
        load_selection(review(path, input_id(first, query)), held_inventory)

    header = replace(
        second.inputs[0],
        name="Authorization",
        ignored_reason="OpenAPI ignores this header.",
    )
    ignored_operation = replace(second, inputs=(header, second.inputs[1]))
    ignored_inventory = replace(inventory, operations=(first, ignored_operation, third))
    with pytest.raises(SelectionError, match=input_id(ignored_operation, header)):
        load_selection(
            review(path, input_id(ignored_operation, header)), ignored_inventory
        )

    item = third.inputs[-1]
    with pytest.raises(SelectionError, match=input_id(third, item)):
        load_selection(review(path, input_id(third, item)), inventory)


def test_input_ids_ignore_parameter_positions():
    operation = load_inventory(SPEC).operations[1]
    query = operation.inputs[1]
    moved = replace(
        query,
        source=replace(query.source, pointer="/move"),
        definition=replace(query.definition, pointer="/move"),
    )
    assert input_id(operation, moved) == input_id(operation, query)


def invoke(output, spec=SPEC):
    return CliRunner().invoke(
        app, ["discover", "--spec", str(spec), "--output", str(output)]
    )


def test_discover_without_selection_writes_deterministic_report(tmp_path):
    output = tmp_path / "report.json"
    result = invoke(output)
    assert result.exit_code == 0 and result.stderr == ""
    assert json.loads(result.stdout)["selected"] == 0
    before = output.read_bytes()
    report = json.loads(before)
    assert report["schema_version"] == 1
    assert all(
        not item["selected"]
        for operation in report["operations"]
        for item in operation["inputs"]
    )
    assert invoke(output).exit_code == 0
    assert output.read_bytes() == before


@pytest.mark.parametrize("link_type", ["symlink", "hardlink"])
def test_discovery_refuses_alias_of_input(tmp_path, link_type):
    spec = tmp_path / "spec.json"
    before = SPEC.read_bytes()
    spec.write_bytes(before)
    output = tmp_path / "report.json"
    if link_type == "symlink":
        output.symlink_to(spec)
    else:
        output.hardlink_to(spec)
    result = invoke(output, spec)
    assert result.exit_code == 2 and result.stdout == ""
    assert "Choose a separate report path" in result.stderr
    assert spec.read_bytes() == output.read_bytes() == before


def test_discovery_interrupt_uses_exit_130(tmp_path, monkeypatch):
    def interrupt(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(discover_cli, "load_inventory", interrupt)
    output = tmp_path / "report.json"
    result = invoke(output)
    assert result.exit_code == 130
    assert result.stdout == ""
    assert "Rerun to regenerate the report" in result.stderr
    assert not output.exists()


def test_output_error_is_redacted(tmp_path):
    output = tmp_path / "private-location" / "report.json"
    result = invoke(output)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert "Choose a writable output path" in result.stderr
    assert "private-location" not in result.stderr


def test_selection_rejects_input_with_held_reference_sibling(tmp_path):
    spec = tmp_path / "openapi.json"
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "paths": {
                    "/a": {
                        "get": {
                            "parameters": [
                                {
                                    "name": "q",
                                    "in": "query",
                                    "schema": {
                                        "$ref": "#/components/schemas/Intermediate"
                                    },
                                }
                            ]
                        }
                    }
                },
                "components": {
                    "schemas": {
                        "Intermediate": {
                            "$ref": "#/components/schemas/String",
                            "minLength": 1,
                        },
                        "String": {"type": "string"},
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    inventory = load_inventory(spec)
    [operation] = inventory.operations
    [item] = operation.inputs
    identifier = input_id(operation, item)
    assert not item.compatible
    assert any(
        held.source.pointer.endswith("/Intermediate/minLength")
        for held in inventory.held
    )
    with pytest.raises(SelectionError, match=identifier):
        load_selection(review(tmp_path / "review.toml", identifier), inventory)


@pytest.mark.parametrize(
    "kind", ["path-item-sibling", "required-parameter", "required-flag-sibling"]
)
def test_held_path_item_parameters_block_every_operation(tmp_path, kind):
    spec = tmp_path / "openapi.json"
    query = {"name": "q", "in": "query", "schema": {"type": "string"}}
    header = {"name": "X-Required", "in": "header", "required": True}
    shared = {"get": {"parameters": [query]}, "head": {}}
    path_item = {"$ref": "#/components/pathItems/Shared"}
    components = {
        "pathItems": {"Shared": shared},
        "parameters": {
            "Optional": {"name": "other", "in": "query", "schema": {"type": "string"}}
        },
    }
    if kind == "path-item-sibling":
        path_item["parameters"] = [header]
        pointer = "/paths/~1a/parameters"
        remediation = "Move it into the referenced declaration"
    elif kind == "required-parameter":
        shared["parameters"] = [header]
        pointer = "/components/pathItems/Shared/parameters/0"
        remediation = "Declare required inputs as supported scalar query parameters"
    else:
        shared["parameters"] = [
            {"$ref": "#/components/parameters/Optional", "required": True}
        ]
        pointer = "/components/pathItems/Shared/parameters/0/required"
        remediation = "Move it into the referenced declaration"
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "paths": {"/a": path_item},
                "components": components,
            }
        ),
        encoding="utf-8",
    )

    inventory = load_inventory(spec)
    get, head = inventory.operations
    assert not get.compatible and not head.compatible
    assert get.compatibility_blocker == head.compatibility_blocker
    assert get.compatibility_blocker.source.pointer == pointer
    item = next(item for item in get.inputs if item.name == "q")
    identifier = input_id(get, item)
    with pytest.raises(SelectionError, match=remediation) as caught:
        load_selection(review(tmp_path / "review.toml", identifier), inventory)
    assert identifier in str(caught.value)
    assert pointer in str(caught.value)
    output = tmp_path / "report.json"
    assert invoke(output, spec).exit_code == 0
    operations = json.loads(output.read_text(encoding="utf-8"))["operations"]
    assert [operation["compatibility_status"] for operation in operations] == [
        "unverified",
        "unverified",
    ]


def test_body_ids_distinguish_star_property_and_array_item(tmp_path):
    spec = tmp_path / "openapi.json"
    string = {"$ref": "#/components/schemas/String"}
    schema = {"properties": {"*": string}, "items": string}
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "paths": {
                    "/a": {
                        "post": {
                            "requestBody": {
                                "content": {"application/json": {"schema": schema}}
                            }
                        }
                    }
                },
                "components": {"schemas": {"String": {"type": "string"}}},
            }
        ),
        encoding="utf-8",
    )
    [operation] = load_inventory(spec).operations
    _, property_input, array_input = operation.inputs
    assert property_input.name == array_input.name == "application/json#/*"
    assert property_input.definition == array_input.definition
    assert property_input.source.pointer.endswith("/properties/*")
    assert array_input.source.pointer.endswith("/items")
    assert input_id(operation, property_input) != input_id(operation, array_input)


def test_inventory_rejects_duplicate_input_id(tmp_path, monkeypatch):
    collision = "input-" + "0" * 32
    monkeypatch.setattr(discovery, "input_id", lambda operation, item: collision)
    with pytest.raises(
        DiscoveryError, match=f"Duplicate input ID {collision}"
    ) as caught:
        load_inventory(SPEC)
    assert caught.value.source.file == SPEC
    assert "also declared at /paths/" in str(caught.value)
    assert "Give these inputs distinct declarations" in str(caught.value)
