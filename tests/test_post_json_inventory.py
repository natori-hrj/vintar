"""Offline POST JSON capability inventory contracts."""

import json
import socket
from pathlib import Path

import pytest
import yaml

from vintar.regression import post_json_inventory as inventory
from vintar.regression.discovery import DiscoveryError


def write_spec(tmp_path: Path, document: dict, suffix: str = ".json") -> Path:
    path = tmp_path / f"openapi{suffix}"
    if suffix == ".json":
        path.write_text(json.dumps(document), encoding="utf-8")
    else:
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


def spec(*, schema=None, security_marker=False, paths=None, **extra):
    operation = {
        "operationId": "createItem",
        "requestBody": {
            "required": True,
            "content": {
                "application/json": ({} if schema is None else {"schema": schema})
            },
        },
    }
    if security_marker is not False:
        operation["security"] = security_marker
    return {
        "openapi": "3.1.2",
        "info": {"title": "private title", "version": "1"},
        "paths": paths or {"/items": {"post": operation}},
        **extra,
    }


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("POST JSON inventory attempted network access")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)


def test_simple_nested_and_array_object_fields_are_inventory_only(tmp_path):
    schema = {
        "type": "object",
        "required": ["name", "children"],
        "properties": {
            "name": {"type": "string", "format": "binary", "readOnly": True},
            "children": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {"x/y": {"type": "integer", "writeOnly": True}},
                },
            },
        },
    }
    report = inventory.analyze_post_json(write_spec(tmp_path, spec(schema=schema)))
    [operation] = report.operations
    assert operation.case_generation == "unsupported"
    assert operation.blocking_reasons == tuple(inventory.BlockingReason)
    assert [
        (field.json_pointer, field.type_name, field.required)
        for field in operation.fields
    ] == [
        ("/children", "array", True),
        ("/children/*", "object", False),
        ("/children/*/x~1y", "integer", False),
        ("/name", "string", True),
    ]
    assert all(not field.injectable for field in operation.fields)
    assert operation.diagnostics == ()
    assert report.counts.fields == report.counts.unsupported_inputs == 4
    assert report.counts.injectable_fields == report.counts.case_generatable == 0


def test_scalar_array_and_local_leaf_ref_preserve_schema_pointers(tmp_path):
    document = spec(
        schema={
            "properties": {
                "tags": {"type": "array", "items": {"$ref": "#/components/schemas/Tag"}}
            }
        },
        components={"schemas": {"Tag": {"type": "string"}}},
    )
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    array, item = report.operations[0].fields
    assert (array.json_pointer, item.json_pointer) == ("/tags", "/tags/*")
    assert item.schema_pointer.endswith("/properties/tags/items")
    assert item.schema_definition_pointer == "/components/schemas/Tag"


@pytest.mark.parametrize(
    ("schema", "reason"),
    [
        (True, "boolean_schema_unsupported"),
        ({"allOf": []}, "all_of_unsupported"),
        ({"anyOf": []}, "any_of_unsupported"),
        ({"oneOf": []}, "one_of_unsupported"),
        ({"additionalProperties": False}, "additional_properties_unsupported"),
        ({"$dynamicRef": "#node"}, "dynamic_ref_unsupported"),
        ({"$id": "private-value"}, "schema_id_scope_unsupported"),
    ],
)
def test_schema_diagnostic_reasons(tmp_path, schema, reason):
    report = inventory.analyze_post_json(write_spec(tmp_path, spec(schema=schema)))
    assert [item.reason.value for item in report.operations[0].diagnostics] == [reason]


def test_missing_schema_is_diagnostic(tmp_path):
    report = inventory.analyze_post_json(write_spec(tmp_path, spec()))
    [operation] = report.operations
    assert operation.fields == ()
    assert (
        operation.diagnostics[0].reason
        is inventory.SchemaDiagnosticReason.MISSING_SCHEMA
    )


@pytest.mark.parametrize(
    ("reference", "reason"),
    [
        ("other.json#/Node", "external_ref_unsupported"),
        ("#/components/schemas/Node", "recursive_ref_unsupported"),
    ],
)
def test_external_and_recursive_schema_refs_are_operation_diagnostics(
    tmp_path, reference, reason
):
    document = spec(
        schema={"$ref": reference},
        components={"schemas": {"Node": {"$ref": "#/components/schemas/Node"}}},
    )
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    assert [item.reason.value for item in report.operations[0].diagnostics] == [reason]


def test_indirect_cycle_is_operation_diagnostic(tmp_path):
    document = spec(
        schema={"$ref": "#/components/schemas/A"},
        components={
            "schemas": {
                "A": {"properties": {"b": {"$ref": "#/components/schemas/B"}}},
                "B": {"properties": {"a": {"$ref": "#/components/schemas/A"}}},
            }
        },
    )
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    assert any(
        item.reason is inventory.SchemaDiagnosticReason.RECURSIVE_REF_UNSUPPORTED
        for item in report.operations[0].diagnostics
    )


def test_reference_sibling_and_definition_pointer(tmp_path):
    document = spec(
        schema={"$ref": "#/components/schemas/Name", "maxLength": 20},
        components={
            "schemas": {
                "Name": {"type": "object", "properties": {"x": {"type": "string"}}}
            }
        },
    )
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    [operation] = report.operations
    assert operation.fields[0].schema_definition_pointer.endswith("/Name/properties/x")
    assert (
        operation.diagnostics[0].reason
        is inventory.SchemaDiagnosticReason.REFERENCE_SIBLING_UNSUPPORTED
    )


def test_reference_limit_is_operation_diagnostic(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "MAX_REFERENCE_DEPTH", 0, raising=False)
    document = spec(
        schema={"$ref": "#/components/schemas/Name"},
        components={"schemas": {"Name": {"type": "string"}}},
    )
    # The budget belongs to discovery, so constrain the constructed document directly.
    monkeypatch.setattr("vintar.regression.discovery.MAX_REFERENCE_DEPTH", 0)
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    assert (
        report.operations[0].diagnostics[0].reason.value == "reference_limit_exceeded"
    )


def test_broken_pointer_and_type_errors_remain_fatal(tmp_path):
    broken = spec(schema={"$ref": "#/components/schemas/Missing"})
    with pytest.raises(DiscoveryError, match="Point to an existing declaration"):
        inventory.analyze_post_json(write_spec(tmp_path, broken))
    invalid = spec(schema={"properties": []})
    with pytest.raises(DiscoveryError, match="Supply an object"):
        inventory.analyze_post_json(write_spec(tmp_path, invalid))


def test_post_without_json_is_counted_only(tmp_path):
    paths = {
        "/none": {"post": {}},
        "/text": {"post": {"requestBody": {"content": {"text/plain": {}}}}},
        "/get": {"get": {}},
    }
    report = inventory.analyze_post_json(write_spec(tmp_path, spec(paths=paths)))
    assert report.operations == ()
    assert report.counts.post_operations_without_application_json == 2


def test_json_media_is_selected_when_other_media_are_present(tmp_path):
    document = spec(schema={"properties": {"safe": {"type": "string"}}})
    content = document["paths"]["/items"]["post"]["requestBody"]["content"]
    content["text/plain"] = {"schema": {"properties": {"private": {"type": "string"}}}}
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    assert [field.json_pointer for field in report.operations[0].fields] == ["/safe"]


def test_duplicate_operation_ids_do_not_affect_operation_identity(tmp_path):
    first = spec(schema={"type": "object"})["paths"]["/items"]["post"]
    second = json.loads(json.dumps(first))
    document = spec(paths={"/b": {"post": second}, "/a": {"post": first}})
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    assert [
        (operation.path, operation.operation_id) for operation in report.operations
    ] == [
        ("/a", "createItem"),
        ("/b", "createItem"),
    ]


def test_external_request_body_ref_is_operation_scoped(tmp_path):
    document = spec(schema={"type": "object"})
    document["paths"]["/items"]["post"]["requestBody"] = {
        "$ref": "external.yaml#/requestBodies/item"
    }
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    assert (
        report.operations[0].diagnostics[0].reason.value == "external_ref_unsupported"
    )


def security_document(global_security=None, operation_security=False):
    schemes = {
        "aKey": {"type": "apiKey", "in": "header", "name": "PRIVATE-HEADER"},
        "httpAuth": {"type": "http", "scheme": "basic"},
        "oauth": {
            "type": "oauth2",
            "flows": {
                "implicit": {
                    "authorizationUrl": "https://private.invalid",
                    "scopes": {"private": "private"},
                }
            },
        },
        "oidc": {
            "type": "openIdConnect",
            "openIdConnectUrl": "https://private.invalid",
        },
        "mtls": {"type": "mutualTLS"},
    }
    document = spec(schema={"type": "object"}, components={"securitySchemes": schemes})
    if global_security is not None:
        document["security"] = global_security
    if operation_security is not False:
        document["paths"]["/items"]["post"]["security"] = operation_security
    return document


@pytest.mark.parametrize(
    ("global_security", "operation_security", "source", "public", "names"),
    [
        (None, False, "none", True, []),
        ([], False, "global", True, []),
        ([{"aKey": []}], False, "global", False, [["aKey"]]),
        ([{"aKey": []}], [], "operation", True, []),
        ([{"aKey": []}], [{"httpAuth": []}], "operation", False, [["httpAuth"]]),
        (
            None,
            [{}, {"httpAuth": [], "aKey": []}, {"oauth": ["private"]}],
            "operation",
            True,
            [[], ["aKey", "httpAuth"], ["oauth"]],
        ),
    ],
)
def test_security_resolution(
    tmp_path, global_security, operation_security, source, public, names
):
    document = security_document(global_security, operation_security)
    auth = (
        inventory.analyze_post_json(write_spec(tmp_path, document)).operations[0].auth
    )
    assert auth.source.value == source
    assert auth.public is public
    assert [
        [scheme.name for scheme in alt.schemes] for alt in auth.alternatives
    ] == names


def test_all_security_types_emit_only_component_name_and_type(tmp_path):
    requirements = [
        {name: []} for name in ("aKey", "httpAuth", "oauth", "oidc", "mtls")
    ]
    report = inventory.analyze_post_json(
        write_spec(tmp_path, security_document(operation_security=requirements))
    )
    serialized = inventory.serialize_report(report)
    for scheme_type in ("apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"):
        assert scheme_type in serialized
    for private in ("PRIVATE-HEADER", "basic", "private.invalid", '"private"'):
        assert private not in serialized


def test_undefined_and_referenced_security_schemes_are_fatal(tmp_path):
    undefined = security_document(operation_security=[{"missing-secret": []}])
    with pytest.raises(DiscoveryError, match=r"Define it.*try again") as caught:
        inventory.analyze_post_json(write_spec(tmp_path, undefined))
    assert "missing-secret" not in caught.value.reason
    referenced = spec(
        schema={"type": "object"},
        components={"securitySchemes": {"key": {"$ref": "#/private"}}},
        security=[{"key": []}],
    )
    with pytest.raises(DiscoveryError, match=r"Bundle or inline.*try again"):
        inventory.analyze_post_json(write_spec(tmp_path, referenced))


def test_invalid_security_shapes_are_fatal(tmp_path):
    for security in ({}, [{"aKey": "private"}]):
        document = security_document(operation_security=security)
        with pytest.raises(
            DiscoveryError, match=r"Invalid security.*try again|Use an array"
        ):
            inventory.analyze_post_json(write_spec(tmp_path, document))


def test_json_yaml_reordering_and_unrelated_operation_are_deterministic(tmp_path):
    schema = {"properties": {"z": {"type": "integer"}, "a": {"type": "string"}}}
    document = security_document(operation_security=[{"httpAuth": [], "aKey": []}])
    document["paths"]["/items"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ] = schema
    json_report = inventory.analyze_post_json(write_spec(tmp_path, document, ".json"))
    yaml_report = inventory.analyze_post_json(write_spec(tmp_path, document, ".yaml"))
    assert inventory.serialize_report(json_report) == inventory.serialize_report(
        yaml_report
    )

    reordered = json.loads(json.dumps(document))
    reordered["paths"]["/items"]["post"]["requestBody"]["content"]["application/json"][
        "schema"
    ]["properties"] = {"a": {"type": "string"}, "z": {"type": "integer"}}
    reordered_report = inventory.analyze_post_json(write_spec(tmp_path, reordered))
    assert inventory.serialize_report(json_report) == inventory.serialize_report(
        reordered_report
    )
    reordered["paths"]["/unrelated"] = {"get": {"operationId": "unrelated"}}
    with_unrelated = inventory.analyze_post_json(write_spec(tmp_path, reordered))
    assert with_unrelated.operations == reordered_report.operations


def test_privacy_sentinels_never_enter_model_or_serialization(tmp_path):
    sentinels = [
        "EXAMPLE-SENTINEL",
        "DEFAULT-SENTINEL",
        "ENUM-SENTINEL",
        "CONST-SENTINEL",
        "SERVER-SENTINEL",
        "EXTERNAL-SENTINEL",
        "URL-SENTINEL",
        "SCOPE-SENTINEL",
        "HEADER-SENTINEL",
        "EXTENSION-SENTINEL",
        "TITLE-SENTINEL",
        "DESCRIPTION-SENTINEL",
    ]
    schema = {
        "type": "object",
        "title": sentinels[10],
        "description": sentinels[11],
        "example": sentinels[0],
        "default": sentinels[1],
        "enum": [sentinels[2]],
        "const": sentinels[3],
        "externalValue": sentinels[5],
        "x-private": sentinels[9],
        "properties": {"safe": {"type": "string"}},
    }
    document = spec(
        schema=schema,
        servers=[{"url": sentinels[4]}],
        info={"title": sentinels[10], "version": "1"},
        components={
            "securitySchemes": {
                "key": {"type": "apiKey", "in": "header", "name": sentinels[8]},
                "oauth": {
                    "type": "oauth2",
                    "flows": {
                        "implicit": {
                            "authorizationUrl": sentinels[6],
                            "scopes": {sentinels[7]: "x"},
                        }
                    },
                },
            }
        },
        security=[{"key": [], "oauth": [sentinels[7]]}],
    )
    output = inventory.serialize_report(
        inventory.analyze_post_json(write_spec(tmp_path, document))
    )
    assert output.endswith("\n")
    assert all(value not in output for value in sentinels)
    assert str(tmp_path) not in output


def test_operation_id_absent_is_null(tmp_path):
    document = spec(schema={"type": "object"})
    del document["paths"]["/items"]["post"]["operationId"]
    report = inventory.analyze_post_json(write_spec(tmp_path, document))
    assert report.operations[0].operation_id is None
    assert '"operation_id": null' in inventory.serialize_report(report)
