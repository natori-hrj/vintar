"""Offline POST JSON review contracts."""

import hashlib
import json
import socket
from pathlib import Path

import pytest

from vintar.regression.post_json_inventory import (
    analyze_post_json,
    report_data,
    serialize_report,
)
from vintar.regression.post_json_review import (
    STALE_BODY_DIGEST_MESSAGE,
    STALE_INVENTORY_MESSAGE,
    PostJsonReviewError,
    resolve_post_json_review,
)

SENTINEL = "PRIVATE-BODY-SENTINEL-74d9"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def deny(*args, **kwargs):
        pytest.fail("POST JSON review attempted network access")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)


def inputs(tmp_path: Path, *, nested: bool = False) -> tuple[Path, Path, Path, dict]:
    pointer = "/orders/*/sku" if nested else "/name"
    schema = (
        {
            "type": "object",
            "properties": {
                "orders": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"sku": {"type": "string"}},
                    },
                }
            },
        }
        if nested
        else {"type": "object", "properties": {"name": {"type": "string"}}}
    )
    body = {"orders": [{"sku": SENTINEL}]} if nested else {"name": SENTINEL}
    document = {
        "openapi": "3.1.2",
        "paths": {
            "/items": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": schema,
                                "example": body,
                            }
                        }
                    }
                }
            }
        },
    }
    spec = tmp_path / "openapi.json"
    spec.write_text(json.dumps(document), encoding="utf-8")
    report = analyze_post_json(spec)
    inventory = tmp_path / "inventory.json"
    inventory.write_text(serialize_report(report), encoding="utf-8")
    candidate = report.operations[0].review_candidates[0]
    canonical = json.dumps(
        body, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("ascii")
    answer = {
        "version": 1,
        "candidate_id": candidate.candidate_id,
        "operation_sha256": candidate.operation_sha256,
        "schema_pointer": candidate.schema_pointer,
        "schema_definition_pointer": candidate.schema_definition_pointer,
        "baseline": {
            "value": body,
            "body_sha256": hashlib.sha256(canonical).hexdigest(),
        },
        "concrete_pointer": pointer.replace("*", "0"),
        "operation_approved": True,
        "side_effect": {"class": "no_side_effect", "confirmed": True},
        "environment": {"class": "isolated_test", "confirmed": True},
    }
    answers = tmp_path / "answers.json"
    answers.write_text(json.dumps(answer), encoding="utf-8")
    return spec, inventory, answers, answer


def write_answer(path: Path, answer: dict) -> None:
    path.write_text(json.dumps(answer), encoding="utf-8")


def test_review_records_only_digest_provenance_and_explicit_array_index(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path, nested=True)

    material = resolve_post_json_review(spec, inventory, answers)
    encoded = json.dumps(material.report, sort_keys=True)

    assert material.pointer.tokens == ("orders", "0", "sku")
    assert material.report["field"]["concrete_json_pointer"] == "/orders/0/sku"
    assert material.report["side_effect"] == {
        "class": "no_side_effect",
        "confirmed": True,
    }
    assert material.report["environment"] == {
        "class": "isolated_test",
        "confirmed": True,
    }
    assert SENTINEL not in encoded


def test_bundled_example_pointer_is_resolved_without_exporting_value(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    answer["baseline"] = {
        "pointer": "/paths/~1items/post/requestBody/content/application~1json/example",
        "body_sha256": answer["baseline"]["body_sha256"],
    }
    write_answer(answers, answer)

    material = resolve_post_json_review(spec, inventory, answers)

    assert material.report["baseline"]["source"]["pointer"].endswith("/example")
    assert SENTINEL not in json.dumps(material.report)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("operation_approved", 1),
        ("operation_approved", "true"),
        ("side_effect.confirmed", 1),
        ("side_effect.confirmed", "true"),
        ("environment.confirmed", 1),
        ("environment.confirmed", "true"),
    ],
)
def test_confirmations_require_json_true_exactly(tmp_path, key, value):
    spec, inventory, answers, answer = inputs(tmp_path)
    if "." in key:
        parent, child = key.split(".")
        answer[parent][child] = value
    else:
        answer[key] = value
    write_answer(answers, answer)

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert "must be JSON true" in str(caught.value)
    assert SENTINEL not in str(caught.value)


def test_body_digest_mismatch_uses_fixed_redacted_message(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    answer["baseline"]["body_sha256"] = "0" * 64
    write_answer(answers, answer)

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == STALE_BODY_DIGEST_MESSAGE
    assert SENTINEL not in str(caught.value)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report["operations"][0]["review_candidates"][0].update(
            candidate_id="post-json-candidate-" + "0" * 32
        ),
        lambda report: report["operations"][0]["review_candidates"][0].update(
            operation_sha256="0" * 64
        ),
        lambda report: report["operations"][0]["fields"][0].update(
            schema_definition_pointer="/edited"
        ),
    ],
)
def test_review_rederives_candidate_and_rejects_edited_inventory(tmp_path, mutation):
    spec, inventory, answers, _ = inputs(tmp_path)
    edited = json.loads(inventory.read_text(encoding="utf-8"))
    mutation(edited)
    inventory.write_text(json.dumps(edited), encoding="utf-8")

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == STALE_INVENTORY_MESSAGE
    assert SENTINEL not in str(caught.value)


def test_review_rejects_edited_spec_with_fixed_stale_message(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    field = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["properties"]["name"]
    field["description"] = "edited"
    field["type"] = "integer"
    spec.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == STALE_INVENTORY_MESSAGE


@pytest.mark.parametrize(
    "pointer",
    [
        "/orders/*/sku",
        "/orders/-/sku",
        "/orders/00/sku",
        "/orders/1/sku",
        "/other/0/sku",
    ],
)
def test_review_rejects_nonconcrete_or_nonmatching_array_selection(tmp_path, pointer):
    spec, inventory, answers, answer = inputs(tmp_path, nested=True)
    answer["concrete_pointer"] = pointer
    write_answer(answers, answer)

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert SENTINEL not in str(caught.value)


def test_serialized_inventory_candidate_is_minimal_and_unapproved(tmp_path):
    spec, _, _, _ = inputs(tmp_path)
    operation = report_data(analyze_post_json(spec))["operations"][0]

    [candidate] = operation["review_candidates"]
    assert candidate.keys() == {"candidate_id", "approval", "operation_sha256"}
    assert candidate["approval"] == "unapproved"
