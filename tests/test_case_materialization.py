"""Materialize reviewed discovery decisions into Schema v1 cases."""

import json
import socket
import tomllib
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from typer.testing import CliRunner

from vintar.cli import app
from vintar.core import executor
from vintar.regression.case_materialization import (
    CaseMaterializationError,
    materialize_case,
    write_materialized_case,
)
from vintar.regression.cases import TimeRegressionCase, load_regression_case
from vintar.regression.discovery import input_id, load_inventory
from vintar.regression.discovery_drafts import draft_files
from vintar.regression.discovery_review import build_review

ORIGIN = "http://materialize-fixture.invalid"
TRUE_PAYLOAD = "true-payload-sentinel"
FALSE_PAYLOAD = "false-payload-sentinel"
DELAY_PAYLOAD = "' AND vintar_delay(0.35)=1-- "
CONTROL_PAYLOAD = "' AND vintar_delay(0)=1-- "


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def make_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    value: object = "baseline-value-sentinel",
    *,
    q_required: bool = True,
    q_type: str = "string",
    extra: object = None,
) -> dict[str, Path]:
    monkeypatch.chdir(tmp_path)
    spec = Path("openapi.json")
    document = {
        "openapi": "3.1.2",
        "paths": {
            "/sample": {
                "get": {
                    "parameters": [
                        {
                            "name": "q",
                            "in": "query",
                            "required": q_required,
                            "schema": {"type": q_type},
                        },
                        {
                            "name": "extra",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                    ]
                }
            }
        },
    }
    spec.write_text(json.dumps(document), encoding="utf-8")
    inventory = load_inventory(spec)
    [operation] = inventory.operations
    selected = next(item for item in operation.inputs if item.name == "q")
    identifier = input_id(operation, selected)
    [(draft_name, draft_content)] = draft_files(
        inventory, frozenset({identifier}), spec
    ).items()
    draft = Path(draft_name)
    draft.write_bytes(draft_content)

    answers = Path("answers.json")
    parameters = {
        "q": {"value": value},
        "extra": {"omit": True} if extra is None else {"value": extra},
    }
    answers.write_text(
        json.dumps(
            {
                "version": 1,
                "expected_verdict": "not_detected",
                "parameters": parameters,
            }
        ),
        encoding="utf-8",
    )
    review = Path("review.json")
    review.write_text(
        json.dumps(build_review(spec, draft, answers), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    config = Path("case-config.toml")
    config.write_text(
        "\n".join(
            (
                "config_version = 1",
                f"input_id = {_toml_string(identifier)}",
                "",
                "[target]",
                f"url = {_toml_string(ORIGIN + '/fixture-route')}",
                f"allowed_origin = {_toml_string(ORIGIN)}",
                "",
                "[injection]",
                'location = "query"',
                'name = "q"',
                "occurrence = 0",
                'mode = "append"',
                "",
                "[probes]",
                'selection = "explicit"',
                f"true_payload = {_toml_string(TRUE_PAYLOAD)}",
                f"false_payload = {_toml_string(FALSE_PAYLOAD)}",
                "",
                "[limits]",
                "max_requests = 6",
                "requests_per_second = 10.0",
                "timeout_seconds = 5.0",
                "",
            )
        ),
        encoding="utf-8",
    )
    return {
        "spec": spec,
        "draft": draft,
        "answers": answers,
        "review": review,
        "config": config,
        "output": Path("case.toml"),
    }


def build(inputs: dict[str, Path]):
    return materialize_case(
        inputs["spec"],
        inputs["draft"],
        inputs["answers"],
        inputs["review"],
        inputs["config"],
    )


def invoke(inputs: dict[str, Path]):
    return CliRunner().invoke(
        app,
        [
            "materialize-case",
            "--spec",
            str(inputs["spec"]),
            "--draft",
            str(inputs["draft"]),
            "--answers",
            str(inputs["answers"]),
            "--review",
            str(inputs["review"]),
            "--config",
            str(inputs["config"]),
            "--output",
            str(inputs["output"]),
        ],
    )


def replace_probes(inputs: dict[str, Path], replacement: str) -> None:
    source = inputs["config"].read_text(encoding="utf-8")
    start = source.index("[probes]")
    end = source.index("[limits]")
    inputs["config"].write_text(
        source[:start] + replacement + "\n\n" + source[end:], encoding="utf-8"
    )


def make_time_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    value: object = "Pets",
    q_type: str = "string",
) -> dict[str, Path]:
    inputs = make_inputs(
        tmp_path,
        monkeypatch,
        value,
        q_type=q_type,
    )
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace(
        "config_version = 1",
        'config_version = 1\ntype = "sqli.time"',
        1,
    )
    source = source.replace(
        '[probes]\nselection = "explicit"\n'
        f"true_payload = {_toml_string(TRUE_PAYLOAD)}\n"
        f"false_payload = {_toml_string(FALSE_PAYLOAD)}",
        '[probes]\nselection = "explicit"\n'
        f"delay_payload = {_toml_string(DELAY_PAYLOAD)}\n"
        f"control_payload = {_toml_string(CONTROL_PAYLOAD)}\n"
        "expected_delay_seconds = 0.25",
    )
    source = source.replace("max_requests = 6", "max_requests = 9")
    source = source.replace("timeout_seconds = 5.0", "timeout_seconds = 3.0")
    inputs["config"].write_text(source, encoding="utf-8")
    return inputs


def test_materializes_loadable_case_and_is_idempotent(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    result = invoke(inputs)
    assert result.exit_code == 0 and result.stderr == ""
    summary = json.loads(result.stdout)
    case = load_regression_case(inputs["output"])
    assert summary == {
        "case_id": case.case_id,
        "report_type": "regression_case_materialization_summary",
        "schema_version": 1,
        "confirmation": "not configured",
        "max_requests": 6,
    }
    assert case.template.url == ORIGIN + "/fixture-route"
    assert case.template.params == (("q", "baseline-value-sentinel"),)
    before = inputs["output"].stat()
    assert invoke(inputs).exit_code == 0
    after = inputs["output"].stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


def test_materializes_explicit_time_case_and_round_trips_loader(tmp_path, monkeypatch):
    inputs = make_time_inputs(tmp_path, monkeypatch)

    result = invoke(inputs)

    assert result.exit_code == 0 and result.stderr == ""
    case = load_regression_case(inputs["output"])
    assert isinstance(case, TimeRegressionCase)
    assert case.check_type == "sqli.time"
    assert case.delay_payload == DELAY_PAYLOAD
    assert case.control_payload == CONTROL_PAYLOAD
    assert case.expected_delay_seconds == 0.25
    assert case.max_requests == 9
    assert case.requests_per_second == 10.0
    assert case.timeout_seconds == 3.0
    assert json.loads(result.stdout) == {
        "case_id": case.case_id,
        "confirmation": "not configured",
        "max_requests": 9,
        "report_type": "regression_case_materialization_summary",
        "schema_version": 1,
    }
    parsed = tomllib.loads(inputs["output"].read_text(encoding="utf-8"))
    assert parsed["probes"] == {
        "delay_payload": DELAY_PAYLOAD,
        "control_payload": CONTROL_PAYLOAD,
        "expected_delay_seconds": 0.25,
    }
    assert "selection" not in parsed["probes"]


def test_time_selection_is_explicit_even_for_integer_openapi_parameter(
    tmp_path, monkeypatch
):
    inputs = make_time_inputs(tmp_path, monkeypatch, value=1, q_type="integer")

    result = invoke(inputs)

    assert result.exit_code == 0 and result.stderr == ""
    case = load_regression_case(inputs["output"])
    assert isinstance(case, TimeRegressionCase)
    assert case.template.params == (("q", "1"),)


def test_integer_openapi_parameter_does_not_infer_time_case(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch, 1, q_type="integer")
    replace_probes(
        inputs,
        '[probes]\nselection = "explicit"\n'
        f"delay_payload = {_toml_string(DELAY_PAYLOAD)}\n"
        f"control_payload = {_toml_string(CONTROL_PAYLOAD)}\n"
        "expected_delay_seconds = 0.25",
    )

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert "Invalid explicit probes config" in result.stderr


@pytest.mark.parametrize("case_type", ['"unknown"', "true", "[]"])
def test_materialization_type_rejects_unknown_and_wrong_types(
    tmp_path, monkeypatch, case_type
):
    inputs = make_time_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    inputs["config"].write_text(
        source.replace('type = "sqli.time"', f"type = {case_type}"),
        encoding="utf-8",
    )

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert 'type = "sqli.time"' in result.stderr


def test_time_config_rejects_unknown_top_level_key_redacted(tmp_path, monkeypatch):
    inputs = make_time_inputs(tmp_path, monkeypatch, value="private-baseline")
    source = inputs["config"].read_text(encoding="utf-8")
    inputs["config"].write_text(
        source.replace(
            'type = "sqli.time"',
            'type = "sqli.time"\nprivate_key = "private-config-value"',
        ),
        encoding="utf-8",
    )

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert "Invalid materialization config keys" in result.stderr
    assert "private-config-value" not in result.stderr
    assert "private-baseline" not in result.stderr


def test_time_limits_accept_upper_delay_and_minimum_rate_boundaries(
    tmp_path, monkeypatch
):
    inputs = make_time_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace(
        "expected_delay_seconds = 0.25", "expected_delay_seconds = 2.0"
    )
    source = source.replace("requests_per_second = 10.0", "requests_per_second = 0.1")
    source = source.replace("timeout_seconds = 3.0", "timeout_seconds = 2.5")
    inputs["config"].write_text(source, encoding="utf-8")

    result = invoke(inputs)

    assert result.exit_code == 0 and result.stderr == ""
    case = load_regression_case(inputs["output"])
    assert isinstance(case, TimeRegressionCase)
    assert case.expected_delay_seconds == 2.0
    assert case.requests_per_second == 0.1
    assert case.timeout_seconds == 2.5


@pytest.mark.parametrize(
    ("original", "replacement", "message"),
    [
        (
            "expected_delay_seconds = 0.25",
            "expected_delay_seconds = 0.24",
            "expected_delay_seconds",
        ),
        (
            "expected_delay_seconds = 0.25",
            "expected_delay_seconds = 2.01",
            "expected_delay_seconds",
        ),
        ("max_requests = 9", "max_requests = 8", "max_requests = 9"),
        (
            "requests_per_second = 10.0",
            "requests_per_second = 0.09",
            "requests_per_second",
        ),
        (
            "requests_per_second = 10.0",
            "requests_per_second = 10.01",
            "requests_per_second",
        ),
        ("timeout_seconds = 3.0", "timeout_seconds = 0.74", "timeout_seconds"),
        ("timeout_seconds = 3.0", "timeout_seconds = 8.01", "timeout_seconds"),
    ],
)
def test_time_limits_reject_values_outside_schema_v1_bounds(
    tmp_path, monkeypatch, original, replacement, message
):
    inputs = make_time_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    inputs["config"].write_text(source.replace(original, replacement), encoding="utf-8")

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert message in result.stderr


def test_identical_invalid_output_is_still_schema_validated(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace("timeout_seconds = 5.0", "timeout_seconds = -1")
    inputs["config"].write_text(source, encoding="utf-8")
    invalid_case = build(inputs)
    inputs["output"].write_bytes(invalid_case.content)
    before = inputs["output"].stat()

    result = invoke(inputs)

    after = inputs["output"].stat()
    assert result.exit_code == 2 and result.stdout == ""
    assert "failed Schema v1 validation" in result.stderr
    assert inputs["output"].read_bytes() == invalid_case.content
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        (True, "true"),
        (False, "false"),
        (17, "17"),
        (1.25, "1.25"),
    ],
)
def test_scalar_conversion_preserves_empty_and_uses_canonical_json(
    tmp_path, monkeypatch, value, expected
):
    inputs = make_inputs(tmp_path, monkeypatch, value, extra="kept")
    case = build(inputs)
    write_materialized_case(inputs["output"], case, tuple(inputs.values())[:-1])
    loaded = load_regression_case(inputs["output"])
    assert loaded.template.params == (("extra", "kept"), ("q", expected))


def test_supplementary_unicode_round_trips_through_toml(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch, "Pets 😀")

    result = invoke(inputs)

    assert result.exit_code == 0 and result.stderr == ""
    loaded = load_regression_case(inputs["output"])
    assert loaded.template.params == (("q", "Pets 😀"),)


def test_generated_case_is_accepted_by_offline_verify(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    case = build(inputs)
    write_materialized_case(inputs["output"], case, tuple(inputs.values())[:-1])
    requests = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        assert request.url.host == "materialize-fixture.invalid"
        return httpx.Response(200, content=b"stable")

    with patch.object(
        executor.httpx,
        "HTTPTransport",
        side_effect=lambda **_: httpx.MockTransport(handle),
    ):
        result = CliRunner().invoke(
            app,
            [
                "verify",
                "--cases",
                str(inputs["output"]),
                "--max-requests",
                "6",
                "--authorized",
            ],
            env={
                "VINTAR_TARGET_ORIGIN": ORIGIN,
                "VINTAR_ALLOWED_ORIGIN": ORIGIN,
            },
        )
    assert result.exit_code == 0 and result.stderr == ""
    assert json.loads(result.stdout)["status"] == "pass"
    assert requests == 6


def test_rejects_stale_review_without_disclosing_value(tmp_path, monkeypatch):
    secret = "changed-secret-baseline"
    inputs = make_inputs(tmp_path, monkeypatch)
    answers = json.loads(inputs["answers"].read_text(encoding="utf-8"))
    answers["parameters"]["q"]["value"] = secret
    inputs["answers"].write_text(json.dumps(answers), encoding="utf-8")
    result = invoke(inputs)
    assert result.exit_code == 2 and result.stdout == ""
    assert "Rerun review-draft" in result.stderr
    assert secret not in result.stderr
    assert not inputs["output"].exists()


@pytest.mark.parametrize("selection", ["unknown", 1, []])
def test_rejects_unsupported_probe_selection(tmp_path, monkeypatch, selection):
    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace(
        'selection = "explicit"', f"selection = {json.dumps(selection)}"
    )
    inputs["config"].write_text(source, encoding="utf-8")
    result = invoke(inputs)
    assert result.exit_code == 2 and result.stdout == ""
    assert 'selection = "explicit" or selection = "preset"' in result.stderr


@pytest.mark.parametrize("selection", ['"preset"', '"unknown"', "1", "[]"])
def test_time_rejects_non_explicit_selection_with_actionable_redacted_error(
    tmp_path, monkeypatch, selection
):
    inputs = make_time_inputs(tmp_path, monkeypatch, value="private-baseline")
    replace_probes(
        inputs,
        f'[probes]\nselection = {selection}\npreset = "private-preset"',
    )

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert 'selection = "explicit"' in result.stderr
    assert "presets are not available for time cases" in result.stderr
    assert "private-preset" not in result.stderr
    assert "private-baseline" not in result.stderr
    assert ORIGIN not in result.stderr


@pytest.mark.parametrize(
    "replacement",
    [
        (
            '[probes]\nselection = "explicit"\n'
            f"delay_payload = {_toml_string(DELAY_PAYLOAD)}\n"
            f"control_payload = {_toml_string(CONTROL_PAYLOAD)}"
        ),
        (
            '[probes]\nselection = "explicit"\n'
            f"delay_payload = {_toml_string(DELAY_PAYLOAD)}\n"
            f"control_payload = {_toml_string(CONTROL_PAYLOAD)}\n"
            'expected_delay_seconds = 0.25\ntrue_payload = "mixed-secret"'
        ),
        (
            '[probes]\nselection = "explicit"\n'
            f"delay_payload = {_toml_string(DELAY_PAYLOAD)}\n"
            f"control_payload = {_toml_string(CONTROL_PAYLOAD)}\n"
            'expected_delay_seconds = 0.25\nunknown = "private-value"'
        ),
    ],
)
def test_time_rejects_missing_mixed_and_unknown_probe_keys_redacted(
    tmp_path, monkeypatch, replacement
):
    inputs = make_time_inputs(tmp_path, monkeypatch, value="private-baseline")
    replace_probes(inputs, replacement)

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert "Invalid time probes config" in result.stderr
    assert "mixed-secret" not in result.stderr
    assert "private-value" not in result.stderr
    assert "private-baseline" not in result.stderr
    assert ORIGIN not in result.stderr


@pytest.mark.parametrize(
    ("original", "replacement", "message"),
    [
        (
            "expected_delay_seconds = 0.25",
            "expected_delay_seconds = true",
            "expected_delay_seconds",
        ),
        ("max_requests = 9", "max_requests = true", "request limit"),
        (
            "requests_per_second = 10.0",
            "requests_per_second = true",
            "requests_per_second",
        ),
        ("timeout_seconds = 3.0", "timeout_seconds = true", "timeout_seconds"),
    ],
)
def test_time_config_numeric_fields_reject_booleans(
    tmp_path, monkeypatch, original, replacement, message
):
    inputs = make_time_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    inputs["config"].write_text(source.replace(original, replacement), encoding="utf-8")

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert message in result.stderr


def test_time_config_rejects_non_query_injection_before_output(tmp_path, monkeypatch):
    inputs = make_time_inputs(tmp_path, monkeypatch, value="private-baseline")
    source = inputs["config"].read_text(encoding="utf-8")
    inputs["config"].write_text(
        source.replace('location = "query"', 'location = "header"'),
        encoding="utf-8",
    )

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert 'Use location = "query"' in result.stderr
    assert "private-baseline" not in result.stderr
    assert ORIGIN not in result.stderr
    assert not inputs["output"].exists()


@pytest.mark.parametrize(
    ("name", "true_payload", "false_payload"),
    [
        ("string-quoted", "' AND 1=1-- ", "' AND 1=2-- "),
        ("numeric", " AND 1=1-- ", " AND 1=2-- "),
    ],
)
def test_named_probe_preset_expands_to_schema_v1_payloads(
    tmp_path, monkeypatch, name, true_payload, false_payload
):
    inputs = make_inputs(tmp_path, monkeypatch)
    replace_probes(
        inputs,
        f'[probes]\nselection = "preset"\npreset = "{name}"',
    )
    inputs["config"].write_text(
        inputs["config"].read_text().replace("max_requests = 6", "max_requests = 18")
    )

    result = invoke(inputs)

    assert result.exit_code == 0 and result.stderr == ""
    case = load_regression_case(inputs["output"])
    assert (case.true_payload, case.false_payload) == (true_payload, false_payload)
    parsed = tomllib.loads(inputs["output"].read_text(encoding="utf-8"))
    assert parsed["probes"] == {
        "true_payload": true_payload,
        "false_payload": false_payload,
        "confirmation": {
            "true_payload": true_payload.replace("1=1", "2<3"),
            "false_payload": false_payload.replace("1=2", "2>3"),
            "baseline_preserving_control": true_payload.replace("1=1", "7=7"),
        },
    }
    assert case.confirmation is not None
    assert case.max_requests == 18


def test_explicit_confirmation_is_materialized_without_inference(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    replace_probes(
        inputs,
        '[probes]\nselection = "explicit"\n'
        'true_payload = "true-one"\nfalse_payload = "false-one"\n\n'
        '[probes.confirmation]\ntrue_payload = "true-two"\n'
        'false_payload = "false-two"\n'
        'baseline_preserving_control = "control"',
    )
    inputs["config"].write_text(
        inputs["config"].read_text().replace("max_requests = 6", "max_requests = 18")
    )

    result = invoke(inputs)

    assert result.exit_code == 0 and result.stderr == ""
    case = load_regression_case(inputs["output"])
    assert case.confirmation is not None
    assert case.confirmation.true_payload == "true-two"
    assert json.loads(result.stdout)["confirmation"] == "configured"


@pytest.mark.parametrize(
    "probes",
    [
        '[probes]\nselection = "explicit"\ntrue_payload = "a"\nfalse_payload = "b"\n\n[probes.confirmation]\ntrue_payload = "c"\nfalse_payload = "d"',
        '[probes]\nselection = "explicit"\ntrue_payload = "a"\nfalse_payload = "b"\n\n[probes.confirmation]\ntrue_payload = "a"\nfalse_payload = "d"\nbaseline_preserving_control = "e"',
        '[probes]\nselection = "preset"\npreset = "numeric"\ntrue_payload = "mixed"',
    ],
)
def test_invalid_confirmation_configs_are_actionable_and_redacted(
    tmp_path, monkeypatch, probes
):
    inputs = make_inputs(tmp_path, monkeypatch)
    replace_probes(inputs, probes)

    result = invoke(inputs)

    assert result.exit_code == 2
    assert "confirmation" in result.stderr.lower() or "probes config" in result.stderr
    assert 'true_payload = "a"' not in result.stderr


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        (
            '[probes]\nselection = "explicit"\ntrue_payload = "only-true"',
            "Invalid explicit probes config",
        ),
        (
            '[probes]\nselection = "preset"',
            "Invalid preset probes config",
        ),
        (
            (
                '[probes]\nselection = "explicit"\ntrue_payload = "true-sentinel"\n'
                'false_payload = "false-sentinel"\npreset = "numeric"'
            ),
            "Invalid explicit probes config",
        ),
        (
            (
                '[probes]\nselection = "preset"\npreset = "numeric"\n'
                'true_payload = "true-sentinel"\nfalse_payload = "false-sentinel"'
            ),
            "Invalid preset probes config",
        ),
    ],
)
def test_probe_config_rejects_missing_and_mixed_fields_redacted(
    tmp_path, monkeypatch, replacement, message
):
    inputs = make_inputs(tmp_path, monkeypatch)
    replace_probes(inputs, replacement)

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert message in result.stderr
    assert "true-sentinel" not in result.stderr
    assert "false-sentinel" not in result.stderr
    assert ORIGIN not in result.stderr


@pytest.mark.parametrize("preset", ['"unknown"', "1", "[]"])
def test_probe_config_rejects_unknown_or_non_string_preset(
    tmp_path, monkeypatch, preset
):
    inputs = make_inputs(tmp_path, monkeypatch, value="private-baseline-sentinel")
    replace_probes(
        inputs,
        f'[probes]\nselection = "preset"\npreset = {preset}',
    )

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert "Use one of: numeric, string-quoted" in result.stderr
    assert "private-baseline-sentinel" not in result.stderr
    assert ORIGIN not in result.stderr


@pytest.mark.parametrize(
    ("true_payload", "false_payload", "message"),
    [("", "false", "nonempty"), ("same", "same", "identical")],
)
def test_explicit_probe_config_rejects_invalid_payloads(
    tmp_path, monkeypatch, true_payload, false_payload, message
):
    inputs = make_inputs(tmp_path, monkeypatch)
    replace_probes(
        inputs,
        "\n".join(
            (
                "[probes]",
                'selection = "explicit"',
                f"true_payload = {json.dumps(true_payload)}",
                f"false_payload = {json.dumps(false_payload)}",
            )
        ),
    )

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert message in result.stderr


def test_preset_selection_is_not_inferred_from_openapi_integer_type(
    tmp_path, monkeypatch
):
    inputs = make_inputs(tmp_path, monkeypatch, value=1, q_type="integer")
    replace_probes(
        inputs,
        '[probes]\nselection = "preset"\npreset = "string-quoted"',
    )
    inputs["config"].write_text(
        inputs["config"].read_text().replace("max_requests = 6", "max_requests = 18")
    )

    result = invoke(inputs)

    assert result.exit_code == 0 and result.stderr == ""
    case = load_regression_case(inputs["output"])
    assert case.template.params == (("q", "1"),)
    assert (case.true_payload, case.false_payload) == (
        "' AND 1=1-- ",
        "' AND 1=2-- ",
    )


def test_rejects_omitted_injection_parameter(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch, q_required=False)
    answers = json.loads(inputs["answers"].read_text(encoding="utf-8"))
    answers["parameters"]["q"] = {"omit": True}
    inputs["answers"].write_text(json.dumps(answers), encoding="utf-8")
    inputs["review"].write_text(
        json.dumps(
            build_review(inputs["spec"], inputs["draft"], inputs["answers"]),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    result = invoke(inputs)
    assert result.exit_code == 2 and result.stdout == ""
    assert "Supply a concrete value" in result.stderr


def test_conflict_is_preserved_and_diagnostics_are_redacted(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    inputs["output"].write_bytes(b"existing case notes\n")
    before = inputs["output"].read_bytes()
    result = invoke(inputs)
    assert result.exit_code == 2 and result.stdout == ""
    assert "already has different content" in result.stderr
    assert TRUE_PAYLOAD not in result.stderr
    assert ORIGIN not in result.stderr
    assert inputs["output"].read_bytes() == before


def test_materialization_is_offline(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)

    def deny_network(*args, **kwargs):
        pytest.fail("Materialization attempted network access.")

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)
    result = invoke(inputs)
    assert result.exit_code == 0 and result.stderr == ""


def test_invalid_injection_and_limits_are_actionable(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace('name = "q"', 'name = "other"', 1)
    inputs["config"].write_text(source, encoding="utf-8")
    with pytest.raises(CaseMaterializationError, match="reviewed input"):
        build(inputs)

    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace("max_requests = 6", "max_requests = 7")
    inputs["config"].write_text(source, encoding="utf-8")
    with pytest.raises(CaseMaterializationError, match="max_requests = 6"):
        build(inputs)


def test_review_report_and_config_binding_are_strict(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    review = json.loads(inputs["review"].read_text(encoding="utf-8"))
    review["expected_verdict"] = "vulnerable"
    inputs["review"].write_text(json.dumps(review), encoding="utf-8")
    with pytest.raises(CaseMaterializationError, match="no longer matches"):
        build(inputs)

    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace("input-", "input-0000", 1)
    inputs["config"].write_text(source, encoding="utf-8")
    with pytest.raises(CaseMaterializationError, match="input ID"):
        build(inputs)


def test_review_schema_version_rejects_boolean(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    review = json.loads(inputs["review"].read_text(encoding="utf-8"))
    review["schema_version"] = True
    inputs["review"].write_text(json.dumps(review), encoding="utf-8")

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert "review schema version" in result.stderr
    assert "version 1 JSON output" in result.stderr


@pytest.mark.parametrize(
    ("original", "replacement", "message"),
    [
        ("config_version = 1", "config_version = true", "config version"),
        ("occurrence = 0", "occurrence = true", "injection occurrence"),
        ("max_requests = 6", "max_requests = true", "request limit"),
        (
            "requests_per_second = 10.0",
            "requests_per_second = true",
            "requests_per_second",
        ),
        ("timeout_seconds = 5.0", "timeout_seconds = true", "timeout_seconds"),
    ],
)
def test_config_numeric_fields_reject_boolean(
    tmp_path, monkeypatch, original, replacement, message
):
    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    inputs["config"].write_text(source.replace(original, replacement), encoding="utf-8")

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert message in result.stderr


@pytest.mark.parametrize(
    ("original", "replacement", "message"),
    [
        ('location = "query"', "location = []", "injection location"),
        ('mode = "append"', "mode = []", "injection mode"),
        ('selection = "explicit"', "selection = []", "probe selection"),
    ],
)
def test_config_enum_fields_reject_unhashable_values(
    tmp_path, monkeypatch, original, replacement, message
):
    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    inputs["config"].write_text(source.replace(original, replacement), encoding="utf-8")

    result = invoke(inputs)

    assert result.exit_code == 2 and result.stdout == ""
    assert message in result.stderr
    assert "TypeError" not in result.stderr


@pytest.mark.parametrize("field", ["headers", "cookies", "credentials"])
def test_target_config_rejects_credentials(tmp_path, monkeypatch, field):
    inputs = make_inputs(tmp_path, monkeypatch)
    source = inputs["config"].read_text(encoding="utf-8")
    source = source.replace(
        "[injection]", f'{field} = "unsupported-sensitive-value"\n\n[injection]'
    )
    inputs["config"].write_text(source, encoding="utf-8")
    result = invoke(inputs)
    assert result.exit_code == 2 and result.stdout == ""
    assert "Supply only explicit url and allowed_origin" in result.stderr
    assert "unsupported-sensitive-value" not in result.stderr


def test_output_rejects_alias_and_wrong_extension(tmp_path, monkeypatch):
    inputs = make_inputs(tmp_path, monkeypatch)
    case = build(inputs)
    with pytest.raises(CaseMaterializationError, match="aliases an input"):
        write_materialized_case(inputs["config"], case, tuple(inputs.values())[:-1])
    with pytest.raises(CaseMaterializationError, match=r"requires a \.toml"):
        write_materialized_case(Path("case.json"), case, tuple(inputs.values())[:-1])


def test_toml_is_deterministic_and_contains_no_selection_metadata(
    tmp_path, monkeypatch
):
    inputs = make_inputs(tmp_path, monkeypatch)
    first = build(inputs).content
    second = build(inputs).content
    assert first == second
    parsed = tomllib.loads(first.decode("utf-8"))
    assert parsed["version"] == 1
    assert "selection" not in parsed["probes"]
    assert first.endswith(b"\n")
