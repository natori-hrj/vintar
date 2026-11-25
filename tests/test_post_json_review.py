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
    ARRAY_PATTERN_MESSAGE,
    INVALID_BASELINE_POINTER_MESSAGE,
    INVENTORY_SPEC_MISMATCH_MESSAGE,
    OPERATION_DEFINITION_CHANGED_MESSAGE,
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
        "operation_definition_sha256": candidate.operation_definition_sha256,
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


def refresh_inventory_and_answer(
    spec: Path, inventory: Path, answers: Path, answer: dict
) -> object:
    report = analyze_post_json(spec)
    inventory.write_text(serialize_report(report), encoding="utf-8")
    candidate = report.operations[0].review_candidates[0]
    answer.update(
        candidate_id=candidate.candidate_id,
        operation_definition_sha256=candidate.operation_definition_sha256,
        schema_pointer=candidate.schema_pointer,
        schema_definition_pointer=candidate.schema_definition_pointer,
    )
    write_answer(answers, answer)
    return candidate


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
            operation_definition_sha256="0" * 64
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

    assert str(caught.value) == INVENTORY_SPEC_MISMATCH_MESSAGE
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

    assert str(caught.value) == INVENTORY_SPEC_MISMATCH_MESSAGE


def test_review_rejects_operation_with_unresolved_ref_sibling_diagnostic(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    schema = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]
    schema["properties"]["name"] = {
        "$ref": "#/components/schemas/Name",
        "not": {"type": "string"},
    }
    document["components"] = {"schemas": {"Name": {"type": "string"}}}
    spec.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == INVENTORY_SPEC_MISMATCH_MESSAGE


@pytest.mark.parametrize(
    "mutation",
    [
        lambda operation: operation.update(description="side effects changed"),
        lambda operation: operation.update(
            responses={"201": {"description": "created"}}
        ),
    ],
)
def test_operation_definition_change_requires_side_effect_review(tmp_path, mutation):
    spec, inventory, answers, answer = inputs(tmp_path)
    before = analyze_post_json(spec).operations[0].review_candidates[0]
    document = json.loads(spec.read_text(encoding="utf-8"))
    mutation(document["paths"]["/items"]["post"])
    spec.write_text(json.dumps(document), encoding="utf-8")
    after = analyze_post_json(spec).operations[0].review_candidates[0]

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert before.candidate_id == after.candidate_id
    assert str(caught.value) == OPERATION_DEFINITION_CHANGED_MESSAGE
    assert answer["operation_definition_sha256"] != after.operation_definition_sha256


def test_referenced_schema_change_requires_side_effect_review(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    media = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    document["components"] = {
        "schemas": {"Body": media["schema"]},
    }
    media["schema"] = {"$ref": "#/components/schemas/Body"}
    spec.write_text(json.dumps(document), encoding="utf-8")
    before = refresh_inventory_and_answer(spec, inventory, answers, answer)
    document["components"]["schemas"]["Body"]["description"] = "changed"
    spec.write_text(json.dumps(document), encoding="utf-8")
    after = analyze_post_json(spec).operations[0].review_candidates[0]

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert before.candidate_id == after.candidate_id
    assert str(caught.value) == OPERATION_DEFINITION_CHANGED_MESSAGE


@pytest.mark.parametrize("change_target", [True, False])
def test_schema_ref_target_and_siblings_are_hashed_separately(tmp_path, change_target):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    media = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    document["components"] = {"schemas": {"Name": {"type": "string", "minimum": 5}}}
    media["schema"] = {
        "$ref": "#/components/schemas/Name",
        "description": "original annotation",
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    before = refresh_inventory_and_answer(spec, inventory, answers, answer)
    if change_target:
        document["components"]["schemas"]["Name"]["minimum"] = 10
    else:
        media["schema"]["description"] = "changed annotation"
    spec.write_text(json.dumps(document), encoding="utf-8")
    after = analyze_post_json(spec).operations[0].review_candidates[0]

    assert before.candidate_id == after.candidate_id
    assert before.operation_definition_sha256 != after.operation_definition_sha256
    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)
    assert str(caught.value) == OPERATION_DEFINITION_CHANGED_MESSAGE


def test_recursive_response_schema_change_requires_side_effect_review(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    node_ref = {"$ref": "#/components/schemas/Node"}
    node = {"type": "object", "properties": {"child": node_ref}}
    document["components"] = {"schemas": {"Node": node}}
    document["paths"]["/items"]["post"]["responses"] = {
        "200": {
            "description": "Tree",
            "content": {"application/json": {"schema": node_ref}},
        }
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    refresh_inventory_and_answer(spec, inventory, answers, answer)
    resolve_post_json_review(spec, inventory, answers)

    node["properties"]["name"] = {"type": "string"}
    spec.write_text(json.dumps(document), encoding="utf-8")
    inventory.write_text(serialize_report(analyze_post_json(spec)), encoding="utf-8")
    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)
    assert str(caught.value) == OPERATION_DEFINITION_CHANGED_MESSAGE


def test_unrelated_operation_change_does_not_invalidate_review(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["paths"]["/unrelated"] = {
        "get": {
            "description": "unrelated",
            "responses": {"200": {"description": "ok"}},
        }
    }
    spec.write_text(json.dumps(document), encoding="utf-8")

    material = resolve_post_json_review(spec, inventory, answers)

    assert material.report["operation"]["path"] == "/items"


def two_operation_review_inputs(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["paths"]["/other"] = json.loads(json.dumps(document["paths"]["/items"]))
    spec.write_text(json.dumps(document), encoding="utf-8")
    refresh_inventory_and_answer(spec, inventory, answers, answer)
    return spec, inventory, answers


@pytest.mark.parametrize("swap", [True, False])
def test_candidate_must_remain_in_its_claimed_inventory_operation(tmp_path, swap):
    spec, inventory, answers = two_operation_review_inputs(tmp_path)
    report = json.loads(inventory.read_text(encoding="utf-8"))
    first, second = report["operations"]
    if swap:
        first["review_candidates"], second["review_candidates"] = (
            second["review_candidates"],
            first["review_candidates"],
        )
    else:
        [moved] = first["review_candidates"]
        first["review_candidates"] = []
        second["review_candidates"].append(moved)
        second["review_candidates"].sort(key=lambda item: item["candidate_id"])
    inventory.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == INVENTORY_SPEC_MISMATCH_MESSAGE


def test_candidate_operation_binding_accepts_unedited_inventory(tmp_path):
    spec, inventory, answers = two_operation_review_inputs(tmp_path)

    material = resolve_post_json_review(spec, inventory, answers)

    assert material.report["operation"]["path"] == "/items"


@pytest.mark.parametrize(
    ("key", "value"),
    [
        (
            "parameters",
            [
                {
                    "name": "tenant",
                    "in": "header",
                    "schema": {"type": "string"},
                }
            ],
        ),
        ("servers", [{"url": "https://isolated.invalid"}]),
    ],
)
def test_path_level_parameters_and_servers_are_bound_to_side_effect_review(
    tmp_path, key, value
):
    spec, inventory, answers, _ = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["paths"]["/items"][key] = value
    spec.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == OPERATION_DEFINITION_CHANGED_MESSAGE


def test_wildcard_requires_array_parent_not_numeric_object_key(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path, nested=True)
    answer["baseline"]["value"] = {"orders": {"0": {"sku": "x"}}}
    canonical = b'{"orders":{"0":{"sku":"x"}}}'
    answer["baseline"]["body_sha256"] = hashlib.sha256(canonical).hexdigest()
    write_answer(answers, answer)

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == ARRAY_PATTERN_MESSAGE


def test_request_body_inline_and_referenced_examples_are_allowed(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    media = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    media["examples"] = {
        "inline": {"value": {"name": "inline"}},
        "referenced": {"$ref": "#/components/examples/Referenced"},
    }
    document["components"] = {
        "examples": {"Referenced": {"value": {"name": "referenced"}}}
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    refresh_inventory_and_answer(spec, inventory, answers, answer)
    media_pointer = "/paths/~1items/post/requestBody/content/application~1json"

    for pointer, value in (
        (f"{media_pointer}/example", {"name": SENTINEL}),
        (f"{media_pointer}/examples/inline/value", {"name": "inline"}),
        (f"{media_pointer}/examples/referenced/value", {"name": "referenced"}),
        ("/components/examples/Referenced/value", {"name": "referenced"}),
    ):
        canonical = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        answer["baseline"] = {
            "pointer": pointer,
            "body_sha256": hashlib.sha256(canonical).hexdigest(),
        }
        write_answer(answers, answer)
        assert (
            resolve_post_json_review(spec, inventory, answers).report["baseline"][
                "source"
            ]["pointer"]
            == pointer
        )


@pytest.mark.parametrize(
    "pointer",
    [
        "/paths/~1other/post/requestBody/content/application~1json/example",
        "/paths/~1items/post/requestBody/content/application~1json/schema/example",
        "/components/examples/Unreachable/value",
    ],
)
def test_pointer_baseline_rejects_examples_not_reachable_from_request_body(
    tmp_path, pointer
):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["paths"]["/other"] = {
        "post": {
            "requestBody": {
                "content": {"application/json": {"example": {"name": "other"}}}
            }
        }
    }
    media = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    media["schema"]["example"] = {"name": "schema"}
    document["components"] = {
        "examples": {"Unreachable": {"value": {"name": "unreachable"}}}
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    refresh_inventory_and_answer(spec, inventory, answers, answer)
    answer["baseline"] = {"pointer": pointer, "body_sha256": "0" * 64}
    write_answer(answers, answer)

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == INVALID_BASELINE_POINTER_MESSAGE


def test_literal_ref_data_is_opaque_but_bound_to_operation_digest(tmp_path):
    literal = {"$ref": "order-123"}
    document = {
        "openapi": "3.1.2",
        "paths": {
            "/orders": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"$ref": {"type": "string"}},
                                    "default": literal,
                                    "enum": [literal],
                                },
                                "example": literal,
                                "examples": {"named": {"value": literal}},
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
    candidate = report.operations[0].review_candidates[0]
    inventory = tmp_path / "inventory.json"
    inventory.write_text(serialize_report(report), encoding="utf-8")
    canonical = b'{"$ref":"order-123"}'
    answer = {
        "version": 1,
        "candidate_id": candidate.candidate_id,
        "operation_definition_sha256": candidate.operation_definition_sha256,
        "schema_pointer": candidate.schema_pointer,
        "schema_definition_pointer": candidate.schema_definition_pointer,
        "baseline": {
            "pointer": "/paths/~1orders/post/requestBody/content/application~1json/example",
            "body_sha256": hashlib.sha256(canonical).hexdigest(),
        },
        "concrete_pointer": "/$ref",
        "operation_approved": True,
        "side_effect": {"class": "no_side_effect", "confirmed": True},
        "environment": {"class": "isolated_test", "confirmed": True},
    }
    answers = tmp_path / "answers.json"
    write_answer(answers, answer)

    material = resolve_post_json_review(spec, inventory, answers)

    assert material.report["candidate_id"] == candidate.candidate_id
    mutations = (
        lambda media: media["example"].update({"$ref": "order-456"}),
        lambda media: media["examples"]["named"]["value"].update({"$ref": "order-456"}),
        lambda media: media["schema"]["default"].update({"$ref": "order-456"}),
        lambda media: media["schema"]["enum"][0].update({"$ref": "order-456"}),
    )
    changed = None
    for mutate in mutations:
        edited = json.loads(json.dumps(document))
        edited_media = edited["paths"]["/orders"]["post"]["requestBody"]["content"][
            "application/json"
        ]
        mutate(edited_media)
        spec.write_text(json.dumps(edited), encoding="utf-8")
        changed = analyze_post_json(spec).operations[0].review_candidates[0]
        assert changed.candidate_id == candidate.candidate_id
        assert (
            changed.operation_definition_sha256 != candidate.operation_definition_sha256
        )
    assert changed is not None
    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)
    assert str(caught.value) == OPERATION_DEFINITION_CHANGED_MESSAGE


def test_real_component_example_reference_is_resolved_for_digest(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    media = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    media["examples"] = {"referenced": {"$ref": "#/components/examples/Referenced"}}
    document["components"] = {"examples": {"Referenced": {"value": {"name": "first"}}}}
    spec.write_text(json.dumps(document), encoding="utf-8")
    before = refresh_inventory_and_answer(spec, inventory, answers, answer)
    document["components"]["examples"]["Referenced"]["value"]["name"] = "second"
    spec.write_text(json.dumps(document), encoding="utf-8")
    after = analyze_post_json(spec).operations[0].review_candidates[0]

    assert before.candidate_id == after.candidate_id
    assert before.operation_definition_sha256 != after.operation_definition_sha256


def test_unresolvable_reference_object_uses_existing_fixed_message(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["paths"]["/items"]["post"]["responses"] = {
        "200": {"$ref": "#/components/responses/Missing"}
    }
    spec.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)

    assert str(caught.value) == STALE_INVENTORY_MESSAGE


def test_named_entry_extensions_are_opaque_and_sibling_references_resolve(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    path_item = document["paths"]["/items"]
    operation = path_item["post"]
    media = operation["requestBody"]["content"]
    literal = {"$ref": "order-123"}
    path_item["x-path-metadata"] = literal
    operation["x-operation-metadata"] = literal
    media["x-content-mode"] = {"schema": {"$ref": "#/components/schemas/Mode"}}
    media["application/json"]["examples"] = {
        "x-example": {"$ref": "#/components/examples/Mode"}
    }
    operation["responses"] = {
        "200": {"$ref": "#/components/responses/Ok"},
        "X-Mode": {"$ref": "#/components/responses/Ok"},
        "x-response-metadata": literal,
    }
    operation["callbacks"] = {
        "x-notify": {"$ref": "#/components/callbacks/Completed"},
    }
    document["components"] = {
        "schemas": {"Mode": {"type": "string", "description": "mode"}},
        "examples": {"Mode": {"value": {"name": "example"}}},
        "headers": {
            "Mode": {
                "description": "mode",
                "schema": {"$ref": "#/components/schemas/Mode"},
            }
        },
        "responses": {
            "Ok": {
                "description": "ok",
                "headers": {
                    "X-Mode": {"$ref": "#/components/headers/Mode"},
                    "x-mode": {"$ref": "#/components/headers/Mode"},
                },
            }
        },
        "callbacks": {
            "Completed": {
                "x-callback-metadata": literal,
                "{$request.body#/callbackUrl}": {
                    "post": {"responses": {"204": {"description": "done"}}}
                },
            }
        },
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    candidate = refresh_inventory_and_answer(spec, inventory, answers, answer)

    material = resolve_post_json_review(spec, inventory, answers)

    assert material.report["candidate_id"] == candidate.candidate_id
    mutations = (
        lambda doc: doc["paths"]["/items"]["x-path-metadata"].update(
            {"$ref": "order-456"}
        ),
        lambda doc: doc["paths"]["/items"]["post"]["x-operation-metadata"].update(
            {"$ref": "order-456"}
        ),
        lambda doc: doc["paths"]["/items"]["post"]["responses"][
            "x-response-metadata"
        ].update({"$ref": "order-456"}),
        lambda doc: doc["components"]["callbacks"]["Completed"][
            "x-callback-metadata"
        ].update({"$ref": "order-456"}),
    )
    for mutate in mutations:
        edited = json.loads(json.dumps(document))
        mutate(edited)
        spec.write_text(json.dumps(edited), encoding="utf-8")
        changed = analyze_post_json(spec).operations[0].review_candidates[0]
        assert changed.candidate_id == candidate.candidate_id
        assert (
            changed.operation_definition_sha256 != candidate.operation_definition_sha256
        )
    referenced_changes = (
        lambda doc: doc["components"]["headers"]["Mode"].update(
            {"description": "changed"}
        ),
        lambda doc: doc["components"]["schemas"]["Mode"].update(
            {"description": "changed"}
        ),
        lambda doc: doc["components"]["examples"]["Mode"]["value"].update(
            {"name": "changed"}
        ),
    )
    for mutate in referenced_changes:
        edited = json.loads(json.dumps(document))
        mutate(edited)
        spec.write_text(json.dumps(edited), encoding="utf-8")
        changed = analyze_post_json(spec).operations[0].review_candidates[0]
        assert (
            changed.operation_definition_sha256 != candidate.operation_definition_sha256
        )

    callback = document["components"]["callbacks"]["Completed"][
        "{$request.body#/callbackUrl}"
    ]
    callback["post"]["description"] = "Notify the subscriber"
    spec.write_text(json.dumps(document), encoding="utf-8")
    inventory.write_text(serialize_report(analyze_post_json(spec)), encoding="utf-8")
    with pytest.raises(PostJsonReviewError) as caught:
        resolve_post_json_review(spec, inventory, answers)
    assert str(caught.value) == OPERATION_DEFINITION_CHANGED_MESSAGE


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
    assert candidate.keys() == {
        "candidate_id",
        "approval",
        "operation_definition_sha256",
    }
    assert candidate["approval"] == "unapproved"


def test_literal_star_and_array_item_have_distinct_review_candidates(tmp_path):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text())
    media = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    media["schema"] = {
        "type": ["array", "object"],
        "items": {"type": "string"},
        "properties": {"*": {"type": "string"}},
    }
    spec.write_text(json.dumps(document))
    report = analyze_post_json(spec)
    inventory.write_text(serialize_report(report))
    candidates = report.operations[0].review_candidates
    assert (
        len({candidate.candidate_id for candidate in candidates})
        == len(candidates)
        == 2
    )
    for candidate in candidates:
        body, pointer = (
            ({"*": "a"}, "/*") if candidate.literal_star_positions else (["a"], "/0")
        )
        answer.update(
            candidate_id=candidate.candidate_id,
            operation_definition_sha256=candidate.operation_definition_sha256,
            schema_pointer=candidate.schema_pointer,
            schema_definition_pointer=candidate.schema_definition_pointer,
            concrete_pointer=pointer,
            baseline={
                "value": body,
                "body_sha256": hashlib.sha256(
                    json.dumps(body, separators=(",", ":")).encode()
                ).hexdigest(),
            },
        )
        write_answer(answers, answer)
        assert resolve_post_json_review(spec, inventory, answers).pointer.tokens == (
            pointer[1:],
        )
