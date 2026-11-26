"""POST JSON Case Schema v2 materialization and execution boundaries."""

import hashlib
import json
import runpy
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from test_post_json_review import (
    SENTINEL,
    inputs,
    refresh_inventory_and_answer,
    write_answer,
)
from typer.testing import CliRunner

from vintar.cli import app
from vintar.regression import batch, file_io, runner
from vintar.regression import post_json_case_materialization as materialization_module
from vintar.regression.cases import (
    MAX_CASE_BYTES,
    load_regression_case,
    parse_regression_case,
)
from vintar.regression.cases_v2 import PostJsonRegressionCase
from vintar.regression.post_json_case_materialization import (
    MaterializedPostJsonCase,
    PostJsonCaseMaterializationError,
    materialize_post_json_case,
    write_materialized_post_json_case,
)
from vintar.regression.post_json_review import (
    PostJsonReviewMaterial,
    resolve_post_json_review,
    serialize_post_json_review,
)

ORIGIN = "https://materialize.invalid"


def test_materializer_rejects_missing_no_follow_before_open(monkeypatch):
    opened: list[str] = []

    def forbidden_open(*_args, **_kwargs):
        opened.append("opened")
        raise AssertionError("open must not be reached")

    monkeypatch.delattr(file_io.os, "O_NOFOLLOW", raising=False)
    monkeypatch.setattr(file_io, "_open", forbidden_open)
    path = Path("/fixed/materializer-path-canary")

    with pytest.raises(PostJsonCaseMaterializationError) as review_error:
        materialization_module._read_review(path)
    assert str(review_error.value) == (
        "post_json_review_schema_invalid: This platform cannot open review files "
        "without following symlinks. Run materialization on a platform with "
        "O_NOFOLLOW support."
    )

    with pytest.raises(PostJsonCaseMaterializationError) as config_error:
        materialization_module._read_config(path)
    assert str(config_error.value) == (
        "post_json_config_invalid: This platform cannot open config files without "
        "following symlinks. Run materialization on a platform with O_NOFOLLOW support."
    )
    assert "materializer-path-canary" not in str(review_error.value)
    assert "materializer-path-canary" not in str(config_error.value)
    assert opened == []


def _config(path: Path, *, check_type: str = "sqli.boolean") -> Path:
    probes = {
        "sqli.boolean": 'true_payload = "true-probe"\nfalse_payload = "false-probe"',
        "sqli.time": (
            'delay_payload = "delay-probe"\ncontrol_payload = "control-probe"\n'
            "expected_delay_seconds = 0.25"
        ),
        "sqli.error": 'error_payload = "\'"',
    }[check_type]
    requests = {"sqli.boolean": 6, "sqli.time": 9, "sqli.error": 4}[check_type]
    timeout = 1.0 if check_type == "sqli.time" else 5.0
    path.write_text(
        "\n".join(
            (
                "config_version = 1",
                'id = "post-json-case"',
                f'type = "{check_type}"',
                'expected_verdict = "not_detected"',
                "",
                "[request]",
                f'url = "{ORIGIN}/items"',
                f'allowed_origin = "{ORIGIN}"',
                "",
                "[probes]",
                probes,
                "",
                "[limits]",
                f"max_requests = {requests}",
                "requests_per_second = 2.0",
                f"timeout_seconds = {timeout}",
                "",
            )
        ),
        encoding="utf-8",
    )
    return path


def _materialization_inputs(tmp_path: Path, *, nested: bool = False):
    spec, inventory, answers, answer = inputs(tmp_path, nested=nested)
    material = resolve_post_json_review(spec, inventory, answers)
    review = tmp_path / "review.json"
    review.write_text(serialize_post_json_review(material.report), encoding="utf-8")
    config = _config(tmp_path / "config.toml")
    return spec, inventory, answers, review, config, answer


@pytest.mark.parametrize("check_type", ["sqli.boolean", "sqli.time", "sqli.error"])
def test_materializes_each_closed_sqli_union_deterministically(tmp_path, check_type):
    spec, inventory, answers, review, config, _ = _materialization_inputs(
        tmp_path, nested=True
    )
    _config(config, check_type=check_type)

    first = materialize_post_json_case(spec, inventory, answers, review, config)
    second = materialize_post_json_case(spec, inventory, answers, review, config)
    parsed = parse_regression_case(first.content.decode("utf-8"))

    assert first.content == second.content
    assert isinstance(parsed, PostJsonRegressionCase)
    assert parsed.check_type == check_type
    assert parsed.pointer.tokens == ("orders", "0", "sku")
    assert SENTINEL in parsed.json_body.to_bytes().decode("ascii")
    assert parsed.identity_id == "reviewed-user"


def test_committed_v2_goldens_pass_loader_and_independent_validator():
    assert (
        Path("schemas/regression-case-v2.schema.json").read_bytes()
        == Path("src/vintar/schemas/regression-case-v2.schema.json").read_bytes()
    ), (
        "The packaged Case Schema v2 drifted from schemas/regression-case-v2.schema.json. "
        "Copy the reviewed root schema to src/vintar/schemas/regression-case-v2.schema.json."
    )
    paths = sorted(Path("tests/golden/cases").glob("post-json-*-v2.toml"))
    assert len(paths) == 3
    for path in paths:
        assert isinstance(load_regression_case(path), PostJsonRegressionCase)
        completed = subprocess.run(
            [sys.executable, "scripts/validate_regression_case_v2.py", str(path)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, path
        assert completed.stdout == completed.stderr == ""


def test_approval_metadata_comes_from_re_resolved_review_not_config(tmp_path):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    config.write_text(
        config.read_text(encoding="utf-8").replace(
            "[probes]", '[approval]\nside_effect = "mutating"\n\n[probes]'
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_config_invalid"
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


@pytest.mark.parametrize("version", [None, 1, True, 2.0])
def test_post_review_schema_version_is_checked_before_integrity_comparison(
    tmp_path, version
):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    value = json.loads(review.read_text(encoding="utf-8"))
    if version is None:
        value.pop("schema_version")
    else:
        value["schema_version"] = version
    review.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_review_schema_invalid"
    ) as caught:
        materialize_post_json_case(spec, inventory, answers, review, config)

    assert SENTINEL not in str(caught.value)


def test_nested_equal_but_different_json_type_uses_review_mismatch(tmp_path):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    value = json.loads(review.read_text(encoding="utf-8"))
    value["operation"]["approved"] = 1
    review.write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_review_mismatch"
    ) as caught:
        materialize_post_json_case(spec, inventory, answers, review, config)

    assert SENTINEL not in str(caught.value)


def test_false_to_zero_nested_review_edit_is_type_sensitive(tmp_path, monkeypatch):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    material = resolve_post_json_review(spec, inventory, answers)
    resolved_report = {**material.report, "type_probe": {"confirmed": False}}
    supplied_report = {**material.report, "type_probe": {"confirmed": 0}}
    review.write_text(json.dumps(supplied_report), encoding="utf-8")
    monkeypatch.setattr(
        "vintar.regression.post_json_case_materialization.resolve_post_json_review",
        lambda *_args: PostJsonReviewMaterial(
            resolved_report, material.body, material.pointer
        ),
    )

    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_review_mismatch"
    ) as caught:
        materialize_post_json_case(spec, inventory, answers, review, config)

    assert SENTINEL not in str(caught.value)


def test_path_parameter_candidate_is_rejected_with_stable_diagnostic(tmp_path):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    document = json.loads(spec.read_text(encoding="utf-8"))
    document["paths"]["/items/{item_id}"] = document["paths"].pop("/items")
    spec.write_text(json.dumps(document), encoding="utf-8")
    answer = json.loads(answers.read_text(encoding="utf-8"))
    refresh_inventory_and_answer(spec, inventory, answers, answer)
    write_answer(answers, answer)
    material = resolve_post_json_review(spec, inventory, answers)
    review.write_text(serialize_post_json_review(material.report), encoding="utf-8")

    with pytest.raises(
        PostJsonCaseMaterializationError,
        match="post_json_path_parameter_unsupported",
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


def test_cli_writes_valid_case_and_redacted_summary(tmp_path):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    output = tmp_path / "case.toml"
    result = CliRunner().invoke(
        app,
        [
            "materialize-post-json-case",
            "--spec",
            str(spec),
            "--inventory",
            str(inventory),
            "--answers",
            str(answers),
            "--review",
            str(review),
            "--config",
            str(config),
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0 and result.stderr == ""
    assert SENTINEL not in result.stdout
    assert isinstance(load_regression_case(output), PostJsonRegressionCase)
    completed = subprocess.run(
        [sys.executable, "scripts/validate_regression_case_v2.py", str(output)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0 and completed.stderr == ""


def test_schema_and_semantics_both_reject_unknown_or_changed_values(tmp_path):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    case = materialize_post_json_case(spec, inventory, answers, review, config)
    source = case.content.decode("utf-8")

    with pytest.raises(ValueError, match="post_json_case_schema_invalid"):
        parse_regression_case(source.replace("[request]", "[request]\nunknown = 1"))
    with pytest.raises(ValueError, match="post_json_baseline_digest_mismatch"):
        parse_regression_case(source.replace(SENTINEL, "changed-baseline"))


def test_runner_and_batch_require_policy_before_resource_or_transport_construction(
    tmp_path, monkeypatch
):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    case = parse_regression_case(
        materialize_post_json_case(
            spec, inventory, answers, review, config
        ).content.decode()
    )
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("constructed")
        raise AssertionError

    monkeypatch.setattr(runner, "ExecutionContext", forbidden)
    monkeypatch.setattr(runner, "RateLimiter", forbidden)
    monkeypatch.setattr(batch, "RateLimiter", forbidden)

    policy = runner.TrustedExecutionPolicy(scope=case.scope)
    with pytest.raises(ValueError, match="authenticated_execution_unavailable"):
        runner.run_regression_case(case, policy=policy)
    with pytest.raises(ValueError, match="authenticated_execution_unavailable"):
        batch.run_regression_batch([case], policy=policy)
    with pytest.raises(TypeError, match="TrustedExecutionPolicy"):
        runner.run_regression_case(case, policy=object())
    with pytest.raises(TypeError, match="TrustedExecutionPolicy"):
        batch.run_regression_batch([case], policy=object())
    assert calls == []


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda text: text.replace("config_version = 1", "config_version = 2"),
            "post_json_config_invalid",
        ),
        (
            lambda text: text.replace("[limits]", "[limits]\nunknown = 1"),
            "post_json_config_invalid",
        ),
        (
            lambda text: text.replace(
                'url = "https://materialize.invalid/items"',
                'url = "https://materialize.invalid/other"',
            ),
            "post_json_target_operation_mismatch",
        ),
        (
            lambda text: text.replace("max_requests = 6", "max_requests = true"),
            "post_json_limits_invalid",
        ),
        (
            lambda text: text.replace('type = "sqli.boolean"', 'type = "unknown"'),
            "post_json_probe_config_invalid",
        ),
    ],
)
def test_config_rejections_are_stable_and_redacted(tmp_path, mutation, code):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    config.write_text(mutation(config.read_text(encoding="utf-8")), encoding="utf-8")

    with pytest.raises(PostJsonCaseMaterializationError, match=code) as caught:
        materialize_post_json_case(spec, inventory, answers, review, config)

    assert SENTINEL not in str(caught.value)


@pytest.mark.parametrize("content", [b"[]", b'{"duplicate":1,"duplicate":2}'])
def test_invalid_review_artifacts_are_rejected_without_values(tmp_path, content):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    review.write_bytes(content)
    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_review_schema_invalid"
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


@pytest.mark.parametrize(
    ("mutation", "code"),
    [
        (
            lambda answer: answer.update(operation_approved=False),
            "post_json_operation_not_approved",
        ),
        (
            lambda answer: answer["side_effect"].update(confirmed=False),
            "post_json_side_effect_not_approved",
        ),
        (
            lambda answer: answer["environment"].update(confirmed=False),
            "post_json_environment_not_confirmed",
        ),
        (
            lambda answer: answer["baseline"].update(body_sha256="0" * 64),
            "post_json_baseline_digest_mismatch",
        ),
        (
            lambda answer: answer.update(concrete_pointer="/missing"),
            "post_json_pointer_invalid",
        ),
    ],
)
def test_re_resolved_review_rejections_have_stable_codes(tmp_path, mutation, code):
    spec, inventory, answers, review, config, answer = _materialization_inputs(tmp_path)
    mutation(answer)
    write_answer(answers, answer)
    with pytest.raises(PostJsonCaseMaterializationError, match=code) as caught:
        materialize_post_json_case(spec, inventory, answers, review, config)
    assert SENTINEL not in str(caught.value)


def test_operation_definition_drift_is_rejected(tmp_path):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    document = json.loads(spec.read_text())
    document["paths"]["/items"]["post"]["description"] = "changed"
    spec.write_text(json.dumps(document))
    with pytest.raises(
        PostJsonCaseMaterializationError,
        match="post_json_operation_definition_mismatch",
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


def test_schema_provenance_drift_is_rejected(tmp_path):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)
    inventory_value = json.loads(inventory.read_text())
    inventory_value["operations"][0]["fields"][0]["schema_definition_pointer"] = (
        "/changed"
    )
    inventory.write_text(json.dumps(inventory_value))
    with pytest.raises(
        PostJsonCaseMaterializationError,
        match="post_json_schema_provenance_mismatch",
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


@pytest.mark.parametrize(
    "pointer", ["/orders/*/sku", "/orders/01/sku", "/orders/-1/sku"]
)
def test_wildcard_and_noncanonical_array_indexes_are_rejected(tmp_path, pointer):
    spec, inventory, answers, review, config, answer = _materialization_inputs(
        tmp_path, nested=True
    )
    answer["concrete_pointer"] = pointer
    write_answer(answers, answer)
    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_pointer_invalid"
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


def test_missing_array_target_and_non_string_target_are_rejected(tmp_path):
    missing = tmp_path / "missing"
    missing.mkdir()
    spec, inventory, answers, review, config, answer = _materialization_inputs(
        missing, nested=True
    )
    answer["concrete_pointer"] = "/orders/1/sku"
    write_answer(answers, answer)
    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_pointer_target_missing"
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)

    typed = tmp_path / "typed"
    typed.mkdir()
    spec, inventory, answers, review, config, answer = _materialization_inputs(typed)
    answer["baseline"]["value"] = {"name": 1}
    answer["baseline"]["body_sha256"] = hashlib.sha256(b'{"name":1}').hexdigest()
    write_answer(answers, answer)
    with pytest.raises(
        PostJsonCaseMaterializationError,
        match="post_json_pointer_target_not_string",
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


def test_probe_distinctness_and_semantic_limits_are_rejected(tmp_path):
    source = Path("tests/golden/cases/post-json-boolean-v2.toml").read_text()
    with pytest.raises(ValueError, match="post_json_probe_not_distinct"):
        parse_regression_case(source.replace("false-probe", "true-probe"))
    with pytest.raises(ValueError, match="post_json_case_semantic_invalid"):
        parse_regression_case(source.replace("max_requests = 6", "max_requests = 7"))


def test_credentials_output_paths_size_and_network_are_rejected(tmp_path, monkeypatch):
    spec, inventory, answers, review, config, answer = _materialization_inputs(tmp_path)
    config.write_text(
        config.read_text().replace(
            f'allowed_origin = "{ORIGIN}"',
            f'allowed_origin = "{ORIGIN}"\nauthorization = "forbidden"',
        )
    )
    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_credentials_forbidden"
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)

    case = MaterializedPostJsonCase(b"case", "case", "sqli.boolean", "candidate")
    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_output_invalid"
    ):
        write_materialized_post_json_case(tmp_path / "case.json", case, ())
    output = tmp_path / "case.toml"
    output.write_text("existing")
    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_output_conflict"
    ):
        write_materialized_post_json_case(output, case, ())

    def deny(*args, **kwargs):
        raise AssertionError("materialization attempted network access")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    _config(config)
    materialize_post_json_case(spec, inventory, answers, review, config)

    answer["baseline"]["value"] = {"name": "x" * 66_000}
    canonical = json.dumps(
        answer["baseline"]["value"], sort_keys=True, separators=(",", ":")
    ).encode()
    answer["baseline"]["body_sha256"] = hashlib.sha256(canonical).hexdigest()
    write_answer(answers, answer)
    material = resolve_post_json_review(spec, inventory, answers)
    review.write_text(serialize_post_json_review(material.report))
    with pytest.raises(
        PostJsonCaseMaterializationError, match="post_json_case_too_large"
    ):
        materialize_post_json_case(spec, inventory, answers, review, config)


def test_non_string_leaf_and_path_mismatch_are_semantically_rejected():
    source = Path("tests/golden/cases/post-json-boolean-v2.toml").read_text()
    numeric = source.replace(
        'json_body = "{\\"name\\":\\"baseline\\"}"',
        'json_body = "{\\"name\\":1}"',
    ).replace(
        "5e5c0546e15bd689be19e8e151d0517b1ae9f6c96edfda7fbf930a72ae99056d",
        "2bfd14f43d17fc7cea24e0917a8879b4b2f880b8baeec1b9d90fbaad655e71bd",
    )
    with pytest.raises(ValueError, match="post_json_pointer_target_not_string"):
        parse_regression_case(numeric)
    with pytest.raises(ValueError, match="post_json_target_operation_mismatch"):
        parse_regression_case(source.replace('path = "/items"', 'path = "/other"'))


@pytest.mark.parametrize(
    ("failure", "code", "diagnostic"),
    [
        (OSError("failure"), 2, "post_json_materialization_failed"),
        (KeyboardInterrupt(), 130, "post_json_materialization_interrupted"),
    ],
)
def test_cli_public_failures_are_bounded(
    tmp_path, monkeypatch, failure, code, diagnostic
):
    spec, inventory, answers, review, config, _ = _materialization_inputs(tmp_path)

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(
        "vintar.materialize_post_json_case_cli.materialize_post_json_case", fail
    )
    result = CliRunner().invoke(
        app,
        [
            "materialize-post-json-case",
            "--spec",
            str(spec),
            "--inventory",
            str(inventory),
            "--answers",
            str(answers),
            "--review",
            str(review),
            "--config",
            str(config),
            "--output",
            str(tmp_path / "case.toml"),
        ],
    )
    assert result.exit_code == code
    assert diagnostic in result.stderr
    assert SENTINEL not in result.stderr


def test_case_v2_validator_reads_at_most_limit_plus_one():
    validator = runpy.run_path("scripts/validate_regression_case_v2.py")

    class BoundedStream:
        def read(self, size: int) -> bytes:
            assert size == MAX_CASE_BYTES + 1
            return b""

    assert validator["_read_bounded"](BoundedStream()) == b""


@pytest.mark.parametrize("extra", [0, 1])
def test_case_v2_validator_exact_limit_and_one_byte_over(tmp_path, extra):
    source = Path("tests/golden/cases/post-json-boolean-v2.toml").read_bytes()
    path = tmp_path / "case.toml"
    path.write_bytes(source + b" " * (MAX_CASE_BYTES + extra - len(source)))

    completed = subprocess.run(
        [sys.executable, "scripts/validate_regression_case_v2.py", str(path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == (0 if extra == 0 else 2)
    assert completed.stdout == ""
    if extra:
        assert "Re-materialize the case" in completed.stderr
    else:
        assert completed.stderr == ""
