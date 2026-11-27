import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from typer.testing import CliRunner

from vintar.cli import app


@pytest.mark.parametrize("version", ["3.0.3", "3.1.0"])
def test_skeleton_contract(tmp_path, version):
    spec = tmp_path / "spec.json"
    output = tmp_path / "skeleton.json"
    parameters = [
        {
            "name": name,
            "in": location,
            "required": location == "path",
            "schema": {"type": "string"},
        }
        for name, location in [
            ("id", "path"),
            ("view", "query"),
            ("Accept", "header"),
            ("locale", "cookie"),
        ]
    ]
    parameters.append({"name": "filter", "in": "query"})
    properties = {
        "a/b~": {"type": "string"},
        "nested": {"type": "array", "items": {"type": "integer"}},
    }
    spec.write_text(
        json.dumps(
            {
                "openapi": version,
                "paths": {
                    "/items/{id}": {
                        "parameters": parameters,
                        "get": {},
                        "post": {
                            "operationId": "createItem",
                            "parameters": [
                                {
                                    "name": "view",
                                    "in": "query",
                                    "schema": {"type": "integer"},
                                }
                            ],
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "required": ["a/b~"],
                                            "properties": properties,
                                        }
                                    }
                                }
                            },
                        },
                    }
                },
            }
        )
    )
    args = ["discover", "--spec", str(spec), "--skeleton-output", str(output)]
    runner = CliRunner()
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    raw = output.read_bytes()
    assert runner.invoke(app, args).exit_code == 0
    assert output.read_bytes() == raw
    data = json.loads(raw)
    schema = json.loads(
        (
            Path(__file__).parents[1]
            / "schemas/openapi-discovery-skeleton-v1.schema.json"
        ).read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate(data)
    get, post = data["operations"]
    assert get["operation_id"] is None
    assert post["operation_id"] == "createItem"
    assert post["method"] == "POST"
    assert post["path"] == "/items/{id}"
    assert post["executable"] is False
    fields = {item["name"]: item for item in post["parameters"]}
    assert {item["location"] for item in fields.values()} == {
        "query",
        "path",
        "header",
        "cookie",
        "json_body",
    }
    assert fields["view"]["schema_types"] == ["integer"]
    assert fields["a/b~"]["pointer"].endswith("/properties/a~1b~0")
    assert fields["a/b~"]["required"]
    assert fields["Accept"]["status"] == "ignored"
    assert fields["filter"]["status"] == "held"
    for record, definition in [
        (data, schema),
        (post, schema["$defs"]["operation"]),
        (fields["view"], schema["$defs"]["parameter"]),
    ]:
        assert definition["additionalProperties"] is False
        assert set(record) == set(definition["properties"])
        record["payload"] = None
        assert not validator.is_valid(data)
        del record["payload"]
    assert runner.invoke(app, [*args, "--output", str(output)]).exit_code == 2


def test_yaml_reference_metadata(tmp_path):
    spec = tmp_path / "spec.yaml"
    output = tmp_path / "skeleton.json"
    spec.write_text(
        """openapi: 3.1.0
paths:
  /items:
    get:
      parameters:
        - $ref: '#/components/parameters/category'
components:
  parameters:
    category:
      in: query
      name: category
      schema:
        type: [string, 'null']
"""
    )
    runner = CliRunner()
    args = ["discover", "--spec", str(spec), "--skeleton-output"]
    result = runner.invoke(app, [*args, str(output)])
    assert result.exit_code == 0, result.output
    (parameter,) = json.loads(output.read_text())["operations"][0]["parameters"]
    assert parameter == {
        "location": "query",
        "name": "category",
        "required": False,
        "schema_types": ["null", "string"],
        "pointer": "/paths/~1items/get/parameters/0",
        "baseline_presence": "unverified",
        "status": "supported",
        "reason": "declared_schema",
    }
    assert runner.invoke(app, [*args, str(spec)]).exit_code == 2
