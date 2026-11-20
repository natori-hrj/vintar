"""Offline review decisions, provenance, and output contracts."""

import hashlib
import json
import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from vintar.cli import app
from vintar.regression import discovery, discovery_review
from vintar.regression.cases import ReviewDraftError, load_regression_case
from vintar.regression.discovery import input_id, load_inventory
from vintar.regression.discovery_drafts import draft_files
from vintar.regression.discovery_review import DraftReviewError, build_review

VALUE = "review-value-sentinel"
SCHEMA = "/paths/~1sample/get/parameters/0/schema"
PARAMETER = "/paths/~1sample/get/parameters/0"


@pytest.fixture
def review_inputs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    spec = Path("openapi.json")
    schema = {
        "type": "string",
        "example": VALUE,
        "examples": [VALUE],
        "default": VALUE,
        "enum": [VALUE],
    }
    document = {
        "openapi": "3.1.2",
        "paths": {
            "/sample": {
                "get": {
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "required": True,
                            "schema": schema,
                            "examples": {
                                "sample": {"value": VALUE},
                                "external": {
                                    "externalValue": "https://never-fetch.invalid"
                                },
                            },
                        },
                        {"name": "extra", "in": "query", "schema": {"type": "string"}},
                    ]
                }
            }
        },
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    inventory = load_inventory(spec)
    [operation] = inventory.operations
    q = next(item for item in operation.inputs if item.name == "q")
    drafts = draft_files(inventory, frozenset({input_id(operation, q)}), spec)
    [name] = drafts
    draft = Path(name)
    draft.write_bytes(drafts[name])
    return spec, draft, Path("answers.json")


def answers(path, q, *, extra=None, verdict="not_detected"):
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "expected_verdict": verdict,
                "parameters": {
                    "q": q,
                    "extra": {"omit": True} if extra is None else extra,
                },
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    "pointer",
    [
        f"{SCHEMA}/example",
        f"{SCHEMA}/examples/0",
        f"{SCHEMA}/default",
        f"{SCHEMA}/enum/0",
        f"{PARAMETER}/examples/sample/value",
    ],
)
def test_resolves_explicit_candidate_with_digest_and_optional_omission(
    review_inputs, pointer
):
    spec, draft, config = review_inputs
    digest = hashlib.sha256(json.dumps(VALUE).encode("ascii")).hexdigest()
    answers(config, {"pointer": pointer, "value_sha256": digest})
    report = build_review(spec, draft, config)
    assert report["parameters"] == {
        "q": {
            "status": "resolved",
            "source": {"file": spec.name, "pointer": pointer},
            "value_sha256": digest,
        },
        "extra": {"status": "omitted"},
    }
    assert VALUE not in json.dumps(report)


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        ({"omit": True}, "required parameters cannot be omitted"),
        ({"value": None}, "require concrete non-null values"),
        ({"value": {"unexpected": VALUE}}, "Supply a concrete scalar value"),
        ({"pointer": "/servers/0/url"}, "supported explicit local baseline candidate"),
        (
            {"pointer": f"{PARAMETER}/examples/external/externalValue"},
            "supported explicit local baseline candidate",
        ),
        ({"value": VALUE, "other": True}, "invalid decision keys"),
        (None, "missing or invalid baseline decision"),
    ],
)
def test_invalid_baselines_give_redacted_remediation(review_inputs, answer, reason):
    spec, draft, config = review_inputs
    answers(config, answer)
    with pytest.raises(DraftReviewError, match=reason) as caught:
        build_review(spec, draft, config)
    assert VALUE not in str(caught.value)


def test_same_pointer_with_changed_value_is_stale(review_inputs):
    spec, draft, config = review_inputs
    digest = hashlib.sha256(json.dumps(VALUE).encode("ascii")).hexdigest()
    answers(config, {"pointer": f"{SCHEMA}/default", "value_sha256": digest})
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["paths"]["/sample"]["get"]["parameters"][0]["schema"]["default"] = (
        "changed"
    )
    spec.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(DraftReviewError, match="Rerun discovery and re-confirm"):
        build_review(spec, draft, config)


def run_review(inputs, output):
    spec, draft, config = inputs
    return CliRunner().invoke(
        app,
        [
            "review-draft",
            "--spec",
            str(spec),
            "--draft",
            str(draft),
            "--answers",
            str(config),
            "--output",
            str(output),
        ],
    )


def test_review_cli_is_idempotent_and_report_is_not_a_case(review_inputs):
    _, _, config = review_inputs
    answers(config, {"value": VALUE})
    output = Path("review.json")
    run = run_review(review_inputs, output)
    assert run.exit_code == 0 and run.stderr == ""
    assert VALUE not in run.stdout + output.read_text(encoding="utf-8")
    original = output.stat()
    assert run_review(review_inputs, output).exit_code == 0
    assert (output.stat().st_ino, output.stat().st_mtime_ns) == (
        original.st_ino,
        original.st_mtime_ns,
    )
    with pytest.raises(
        ReviewDraftError, match="Supply a separately reviewed Schema v1 TOML case"
    ):
        load_regression_case(output)
    result = CliRunner().invoke(
        app,
        ["verify", "--authorized", "--cases", str(output)],
        env={
            "VINTAR_TARGET_ORIGIN": "http://fixture.invalid",
            "VINTAR_ALLOWED_ORIGIN": "http://fixture.invalid",
        },
    )
    assert result.exit_code == 2
    assert "Supply a separately reviewed Schema v1 TOML case" in result.stderr
    output.write_bytes(b"existing review")
    result = run_review(review_inputs, output)
    assert result.exit_code == 2 and result.stdout == ""
    assert "already has different content" in result.stderr
    assert output.read_bytes() == b"existing review"


def test_review_requires_explicit_expectation_and_current_draft(review_inputs):
    spec, draft, config = review_inputs
    answers(config, {"value": VALUE}, verdict=None)
    with pytest.raises(DraftReviewError, match="Explicitly set expected_verdict"):
        build_review(spec, draft, config)
    draft.write_bytes(draft.read_bytes() + b"\n# Manual edit")
    with pytest.raises(DraftReviewError, match="Rerun discovery and re-confirm"):
        build_review(spec, draft, config)


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        ('{"version":1,"version":1}', "unique keys"),
        (
            '{"version":true,"expected_verdict":"not_detected","parameters":{}}',
            "Set version to 1",
        ),
        (
            '{"version":1,"expected_verdict":"not_detected","parameters":{"unknown":{}}}',
            "Use only declared query names",
        ),
    ],
)
def test_review_answers_schema_is_strict(review_inputs, content, reason):
    spec, draft, config = review_inputs
    config.write_text(content, encoding="utf-8")
    with pytest.raises(DraftReviewError, match=reason):
        build_review(spec, draft, config)


def test_review_rejects_output_alias_and_non_json_output(review_inputs):
    _, _, config = review_inputs
    answers(config, {"value": VALUE})
    before = config.read_bytes()
    alias = run_review(review_inputs, config)
    assert alias.exit_code == 2 and "aliases an input file" in alias.stderr
    assert config.read_bytes() == before
    wrong_extension = run_review(review_inputs, Path("review.toml"))
    assert (
        wrong_extension.exit_code == 2
        and "Pass a JSON path to --output" in wrong_extension.stderr
    )
    assert not Path("review.toml").exists()


@pytest.mark.parametrize(
    ("reference", "target", "error"),
    [
        ("#/components/examples/E", {"value": VALUE}, None),
        ("https://never-fetch.invalid/example.json", {}, "Bundle the spec"),
        (
            "#/components/examples/E",
            {"$ref": "#/components/examples/E"},
            "Break the recursive reference chain",
        ),
    ],
    ids=["local", "external", "cyclic"],
)
def test_review_resolves_example_references_at_canonical_pointer(
    review_inputs, reference, target, error
):
    spec, _, config = review_inputs
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["components"] = {"examples": {"E": target}}
    document["paths"]["/sample"]["get"]["parameters"][0]["examples"]["sample"] = {
        "$ref": reference
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    pointer = "/components/examples/E/value"
    selection = (
        f"{PARAMETER}/examples/sample" if not reference.startswith("#") else pointer
    )
    answers(config, {"pointer": selection})
    result = run_review(review_inputs, Path("review.json"))
    if error is not None:
        assert result.exit_code == 2 and result.stdout == ""
        assert error in result.stderr
        assert reference not in result.stderr
        assert not Path("review.json").exists()
        return
    assert result.exit_code == 0, result.stderr
    report = json.loads(Path("review.json").read_text(encoding="utf-8"))
    assert report["parameters"]["q"] == {
        "status": "resolved",
        "source": {"file": spec.name, "pointer": pointer},
        "value_sha256": hashlib.sha256(json.dumps(VALUE).encode("ascii")).hexdigest(),
    }


@pytest.mark.parametrize("extra_reference", [False, True])
def test_candidate_reference_budget_is_independent_and_bounded(
    review_inputs, monkeypatch, extra_reference
):
    spec, draft, config = review_inputs
    document = json.loads(spec.read_text(encoding="utf-8"))
    parameter = document["paths"]["/sample"]["get"]["parameters"][0]
    document["components"] = {
        "schemas": {"Q": parameter["schema"]},
        "examples": {"E": {"value": VALUE}},
    }
    parameter["schema"] = {"$ref": "#/components/schemas/Q"}
    if extra_reference:
        parameter["examples"]["sample"] = {"$ref": "#/components/examples/E"}
    spec.write_text(json.dumps(document), encoding="utf-8")
    monkeypatch.setattr(discovery, "MAX_REFERENCE_WORK", 1)
    discovered = CliRunner().invoke(
        app, ["discover", "--spec", str(spec), "--output", "inventory.json"]
    )
    assert discovered.exit_code == 0, discovered.stderr

    pointer = (
        "/components/examples/E/value"
        if extra_reference
        else "/components/schemas/Q/default"
    )
    answers(config, {"pointer": pointer})
    if extra_reference:
        with pytest.raises(DraftReviewError, match="Simplify or split the spec"):
            build_review(spec, draft, config)
    else:
        report = build_review(spec, draft, config)
        assert report["parameters"]["q"]["source"]["pointer"] == pointer


@pytest.mark.parametrize(
    ("reference", "remediation"),
    [
        ("examples.json#/E", "Bundle the spec"),
        ("#/components/examples/Missing", "Point to an existing declaration"),
        ("#/components/examples/Cycle", "Break the recursive reference chain"),
    ],
)
def test_only_selected_bad_example_reference_rejects_review(
    review_inputs, monkeypatch, reference, remediation
):
    spec, _, config = review_inputs
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["components"] = {
        "examples": {
            "Cycle": {"$ref": "#/components/examples/Cycle"},
            "E": {"value": VALUE},
        }
    }
    parameter = document["paths"]["/sample"]["get"]["parameters"][0]
    parameter["examples"] = {
        "unused": {"$ref": reference},
        "valid": {"$ref": "#/components/examples/E"},
    }
    spec.write_text(json.dumps(document), encoding="utf-8")

    def deny_network(*args, **kwargs):
        pytest.fail(
            "Review attempted an external read. Resolve only same-document references."
        )

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    read = discovery_review._read

    def read_input(path):
        assert path in review_inputs, (
            "Review attempted to read an external example file."
        )
        return read(path)

    monkeypatch.setattr(discovery_review, "_read", read_input)
    monkeypatch.setattr(discovery, "_read", read_input)
    for label, decision, provenance in (
        (
            "default",
            {"pointer": f"{SCHEMA}/default"},
            {"file": spec.name, "pointer": f"{SCHEMA}/default"},
        ),
        (
            "local",
            {"pointer": "/components/examples/E/value"},
            {"file": spec.name, "pointer": "/components/examples/E/value"},
        ),
        ("explicit", {"value": VALUE}, "reviewer"),
    ):
        answers(config, decision)
        output = Path(f"{label}.json")
        result = run_review(review_inputs, output)
        assert result.exit_code == 0, result.stderr
        report = json.loads(output.read_text(encoding="utf-8"))
        assert report["parameters"]["q"] == {
            "status": "resolved",
            "source": provenance,
            "value_sha256": hashlib.sha256(
                json.dumps(VALUE).encode("ascii")
            ).hexdigest(),
        }
        assert report["parameters"]["extra"] == {"status": "omitted"}

    answers(config, {"pointer": f"{PARAMETER}/examples/unused/value"})
    result = run_review(review_inputs, Path("rejected.json"))
    assert result.exit_code == 2 and result.stdout == ""
    assert remediation in result.stderr
    assert reference not in result.stderr
    assert not Path("rejected.json").exists()
