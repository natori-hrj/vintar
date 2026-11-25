"""Schema and semantic validation for POST JSON inventory reports."""

import copy
import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from vintar.regression.post_json_inventory import (
    AuthSource,
    BlockingReason,
    CaseGeneration,
    SchemaDiagnosticReason,
    analyze_post_json,
    report_data,
    serialize_report,
)

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_post_json_inventory.py"
NAMESPACE = runpy.run_path(str(VALIDATOR))
validate = NAMESPACE["_validate"]


def valid_report(tmp_path: Path) -> dict:
    spec = tmp_path / "openapi.json"
    spec.write_text(
        json.dumps(
            {
                "openapi": "3.1.2",
                "security": [{"key": []}],
                "components": {
                    "securitySchemes": {
                        "key": {"type": "apiKey", "in": "header", "name": "X-Key"}
                    }
                },
                "paths": {
                    "/b": {
                        "post": {
                            "operationId": "b",
                            "requestBody": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "z": {"type": "string"},
                                                "a": {"type": ["null", "string"]},
                                            },
                                        }
                                    }
                                }
                            },
                        }
                    },
                    "/a": {
                        "post": {
                            "security": [],
                            "requestBody": {"content": {"application/json": {}}},
                        }
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    report = analyze_post_json(spec)
    path = tmp_path / "valid.json"
    path.write_text(serialize_report(report), encoding="utf-8")
    validate(path)
    return report_data(report)


def test_schema_enums_match_python_contracts():
    schema = json.loads(
        (ROOT / "schemas/openapi-post-json-inventory-v1.schema.json").read_text()
    )
    assert set(schema["$defs"]["blocking_reason"]["enum"]) == {
        item.value for item in BlockingReason
    }
    assert set(schema["$defs"]["diagnostic_reason"]["enum"]) == {
        item.value for item in SchemaDiagnosticReason
    }
    assert set(schema["$defs"]["auth"]["properties"]["source"]["enum"]) == {
        item.value for item in AuthSource
    }
    assert {schema["$defs"]["operation"]["properties"]["case_generation"]["const"]} == {
        item.value for item in CaseGeneration
    }


def run_validator(path: Path, sentinel: str = "") -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.stdout == ""
    if sentinel:
        assert sentinel not in completed.stderr
    return completed


def write_mutation(tmp_path: Path, report: object, name: str) -> Path:
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "name,mutate",
    [
        ("version", lambda r: r.update(schema_version=2)),
        ("report_type", lambda r: r.update(report_type="PRIVATE-SENTINEL")),
        ("unknown", lambda r: r.update(private="PRIVATE-SENTINEL")),
        (
            "enum",
            lambda r: r["operations"][0].update(case_generation="PRIVATE-SENTINEL"),
        ),
        ("count", lambda r: r["counts"].update(fields=999)),
        ("operation_order", lambda r: r["operations"].reverse()),
        (
            "operation_duplicate",
            lambda r: r["operations"].append(copy.deepcopy(r["operations"][0])),
        ),
        ("field_order", lambda r: r["operations"][1]["fields"].reverse()),
        (
            "field_duplicate",
            lambda r: r["operations"][1]["fields"].append(
                copy.deepcopy(r["operations"][1]["fields"][0])
            ),
        ),
        (
            "pointer",
            lambda r: r["operations"][0].update(operation_pointer="/bad~pointer"),
        ),
        ("public", lambda r: r["operations"][0]["auth"].update(public=False)),
        (
            "injectable",
            lambda r: r["operations"][1]["fields"][0].update(injectable=True),
        ),
        ("missing", lambda r: r["counts"].pop("fields")),
        ("wrong_type", lambda r: r["counts"].update(fields="PRIVATE-SENTINEL")),
        (
            "types_order",
            lambda r: r["operations"][1]["fields"][0].update(types=["string", "null"]),
        ),
        (
            "types_duplicate",
            lambda r: r["operations"][1]["fields"][0].update(
                types=["string", "string"]
            ),
        ),
        (
            "scheme_duplicate",
            lambda r: r["operations"][1]["auth"]["alternatives"][0]["schemes"].append(
                copy.deepcopy(
                    r["operations"][1]["auth"]["alternatives"][0]["schemes"][0]
                )
            ),
        ),
    ],
)
def test_mutations_are_rejected_without_value_echo(tmp_path, name, mutate):
    report = valid_report(tmp_path)
    mutate(report)
    completed = run_validator(
        write_mutation(tmp_path, report, name), "PRIVATE-SENTINEL"
    )
    assert completed.returncode == 2
    assert completed.stderr.startswith("Vintar: POST JSON inventory validation failed.")


def test_valid_writer_output_and_invalid_json_contract(tmp_path):
    report = valid_report(tmp_path)
    valid = write_mutation(tmp_path, report, "writer")
    assert run_validator(valid).returncode == 0
    for name, content in (("truncated", "{"), ("invalid", "not PRIVATE-SENTINEL")):
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        assert run_validator(path, "PRIVATE-SENTINEL").returncode == 2


def test_oversized_report_is_rejected_without_reading_value(tmp_path):
    path = tmp_path / "large.json"
    path.write_bytes(b"PRIVATE-SENTINEL" + b" " * 2_097_152)
    completed = run_validator(path, "PRIVATE-SENTINEL")
    assert completed.returncode == 2
