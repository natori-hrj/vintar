"""Exercise the complete OpenAPI-to-verify pipeline on loopback twins."""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from probe_examples import (
    get_boolean_confirmation_preset,
    get_boolean_probe_preset,
)
from test_sqli_http_e2e import (
    LoopbackShutdownError,
    LoopbackStartupError,
    _Server,
    running_server,
)
from typer.testing import CliRunner

from vintar.cli import app
from vintar.regression.cases import load_regression_case

FIXTURES = Path(__file__).parent / "fixtures" / "pipeline"


class PipelineLoopbackError(RuntimeError):
    """An actionable failure to create or run the pipeline fixture."""


@contextmanager
def pipeline_server(
    endpoint: str,
    binder: Callable[[], _Server] = _Server,
) -> Iterator[tuple[_Server, str]]:
    try:
        server = binder()
    except OSError as exc:
        raise PipelineLoopbackError(
            f"Cannot bind the {endpoint} pipeline fixture. Check that the runner permits IPv4 loopback sockets."
        ) from exc

    try:
        with running_server(server) as running:
            yield running
    except LoopbackStartupError as exc:
        raise PipelineLoopbackError(
            f"The {endpoint} pipeline fixture did not start. Check thread scheduling and loopback transport setup."
        ) from exc
    except LoopbackShutdownError as exc:
        raise PipelineLoopbackError(
            f"The {endpoint} pipeline fixture did not stop. Check server shutdown and outstanding requests."
        ) from exc


def invoke_success(runner: CliRunner, args: list[str]):
    result = runner.invoke(app, args)
    assert result.exit_code == 0, (
        f"CLI stage {args[0]} failed. Check its inputs and output path. {result.stderr}"
    )
    assert result.stderr == ""
    return json.loads(result.stdout)


def write_pipeline_inputs(
    folder: Path,
    *,
    input_id: str,
    expected_verdict: str,
    endpoint: str,
    origin: str,
    parameter_name: str,
    example_pointer: str,
    preset_name: str | None,
) -> tuple[Path, Path]:
    answers = folder / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "version": 1,
                "expected_verdict": expected_verdict,
                "parameters": {
                    parameter_name: {"pointer": example_pointer},
                    "view": {"omit": True},
                },
            }
        ),
        encoding="utf-8",
    )
    config = folder / "case-config.toml"
    probe_lines = (
        ('selection = "preset"', f"preset = {json.dumps(preset_name)}")
        if preset_name is not None
        else (
            'selection = "explicit"',
            'true_payload = "\' AND 1=1-- "',
            'false_payload = "\' AND 1=2-- "',
        )
    )
    max_requests = 18 if preset_name is not None else 6
    config.write_text(
        "\n".join(
            (
                "config_version = 1",
                f"input_id = {json.dumps(input_id)}",
                "",
                "[target]",
                f"url = {json.dumps(origin + endpoint)}",
                f"allowed_origin = {json.dumps(origin)}",
                "",
                "[injection]",
                'location = "query"',
                f"name = {json.dumps(parameter_name)}",
                "occurrence = 0",
                'mode = "append"',
                "",
                "[probes]",
                *probe_lines,
                "",
                "[limits]",
                f"max_requests = {max_requests}",
                "requests_per_second = 10.0",
                "timeout_seconds = 5.0",
                "",
            )
        ),
        encoding="utf-8",
    )
    return answers, config


def run_pipeline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    endpoint: str,
    expected_verdict: str,
    expected_exit: int,
    expected_status: str,
    expectation_match: bool,
    spec_fixture: str,
    operation_path: str,
    parameter_name: str,
    example_pointer: str,
    baseline: str,
    preset_name: str | None,
) -> None:
    monkeypatch.chdir(tmp_path)
    spec = Path("openapi.json")
    spec.write_bytes((FIXTURES / spec_fixture).read_bytes())
    runner = CliRunner()

    with pipeline_server(endpoint) as (server, origin):
        inventory_path = Path("inventory.json")
        summary = invoke_success(
            runner,
            ["discover", "--spec", str(spec), "--output", str(inventory_path)],
        )
        assert summary == {
            "held": 0,
            "ignored": 0,
            "operations": 1,
            "report_type": "discovery_summary",
            "schema_version": 1,
            "selected": 0,
        }
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        selected = [
            item
            for operation in inventory["operations"]
            if operation["method"] == "GET" and operation["path"] == operation_path
            for item in operation["inputs"]
            if item["location"] == "query" and item["name"] == parameter_name
        ]
        assert len(selected) == 1, (
            "Discovery did not identify exactly one selected query input. Check the pipeline OpenAPI fixture."
        )
        input_id = selected[0]["id"]
        selection = Path("selection.toml")
        selection.write_text(
            f"version = 1\napproved = [{json.dumps(input_id)}]\n",
            encoding="utf-8",
        )

        draft_summary = invoke_success(
            runner,
            [
                "discover",
                "--spec",
                str(spec),
                "--selection",
                str(selection),
                "--drafts-dir",
                "drafts",
            ],
        )
        assert draft_summary["report_type"] == "discovery_draft_summary"
        assert draft_summary["schema_version"] == 1
        assert len(draft_summary["drafts"]) == 1
        draft = Path("drafts") / draft_summary["drafts"][0]
        assert draft.is_file()

        answers, config = write_pipeline_inputs(
            tmp_path,
            input_id=input_id,
            expected_verdict=expected_verdict,
            endpoint=endpoint,
            origin=origin,
            parameter_name=parameter_name,
            example_pointer=example_pointer,
            preset_name=preset_name,
        )
        review = Path("review.json")
        review_summary = invoke_success(
            runner,
            [
                "review-draft",
                "--spec",
                str(spec),
                "--draft",
                str(draft),
                "--answers",
                str(answers),
                "--output",
                str(review),
            ],
        )
        assert review_summary == {
            "input_id": input_id,
            "report_type": "discovery_draft_review_summary",
            "schema_version": 1,
        }
        review_report = json.loads(review.read_text(encoding="utf-8"))
        decision = review_report["parameters"][parameter_name]
        assert decision["status"] == "resolved"
        assert "value" not in decision

        case_path = Path("generated-case.toml")
        assert not case_path.exists()
        materialized = invoke_success(
            runner,
            [
                "materialize-case",
                "--spec",
                str(spec),
                "--draft",
                str(draft),
                "--answers",
                str(answers),
                "--review",
                str(review),
                "--config",
                str(config),
                "--output",
                str(case_path),
            ],
        )
        case = load_regression_case(case_path)
        confirmation_configured = preset_name is not None
        assert materialized == {
            "case_id": case.case_id,
            "confirmation": (
                "configured" if confirmation_configured else "not configured"
            ),
            "max_requests": 18 if confirmation_configured else 6,
            "report_type": "regression_case_materialization_summary",
            "schema_version": 1,
        }
        assert case.case_id == "case-" + input_id.removeprefix("input-")
        assert case.template.url == origin + endpoint
        assert case.template.params == ((parameter_name, baseline),)
        preset = get_boolean_probe_preset(preset_name or "string-quoted")
        assert case.true_payload == preset.true_payload
        assert case.false_payload == preset.false_payload
        confirmation = (
            get_boolean_confirmation_preset(preset_name)
            if preset_name is not None
            else None
        )
        assert case.confirmation == confirmation

        assert server.total_requests == 0, (
            "An offline pipeline stage sent HTTP. Check discover, review-draft, and materialize-case transport boundaries."
        )
        assert server.received == []
        verified = runner.invoke(
            app,
            [
                "verify",
                "--cases",
                str(case_path),
                "--max-requests",
                "18" if confirmation_configured else "6",
                "--rps",
                "10",
                "--timeout",
                "5",
                "--authorized",
            ],
            env={
                "VINTAR_TARGET_ORIGIN": origin,
                "VINTAR_ALLOWED_ORIGIN": origin,
            },
        )
        assert verified.exit_code == expected_exit, (
            f"Verification for {endpoint} returned {verified.exit_code}. Check the fixture label, response stability, or transport setup."
        )
        assert verified.stderr == ""
        report = json.loads(verified.stdout)
        assert report["exit_code"] == expected_exit
        assert report["status"] == expected_status
        assert report["complete"] is True
        expected_requests = (
            18 if confirmation_configured and not endpoint.endswith("safe") else 6
        )
        assert report["requests_used"] == expected_requests
        assert report["counts"][expected_status] == 1
        [outcome] = report["outcomes"]
        assert outcome["expected_verdict"] == expected_verdict
        assert outcome["actual_verdict"] == (
            "not_detected" if endpoint.endswith("safe") else "inconclusive"
        )
        assert outcome["expectation_match"] is expectation_match
        assert outcome["status"] == expected_status
        assert outcome["verification"]["reason_code"] == (
            "no_boolean_difference_literal_input"
            if endpoint.endswith("safe")
            else "boolean_candidate"
        )
        assert outcome["verification"]["request_count"] == 6
        assert outcome["verification"]["failures"] == []
        assert outcome["request_count"] == expected_requests
        assert outcome["actual_reason_code"] == (
            "no_boolean_difference_literal_input"
            if endpoint.endswith("safe")
            else "boolean_candidate"
        )
        expected_confirmation = (
            {
                "configured": True,
                "status": "not_eligible",
                "reason_code": "initial_not_eligible",
                "request_count": 0,
            }
            if confirmation_configured and endpoint.endswith("safe")
            else {
                "configured": True,
                "status": "matched",
                "reason_code": "confirmation_pattern_matched",
                "request_count": 12,
            }
            if confirmation_configured
            else {
                "configured": False,
                "status": "not_configured",
                "reason_code": None,
                "request_count": 0,
            }
        )
        assert outcome["confirmation"] == expected_confirmation

        assert server.total_requests == expected_requests
        assert len(server.received) == expected_requests
        received = server.received
        expected_values = [
            baseline,
            baseline + preset.true_payload,
            baseline + preset.false_payload,
            baseline,
            baseline + preset.false_payload,
            baseline + preset.true_payload,
        ]
        if expected_requests == 18 and confirmation is not None:
            expected_values.extend(
                baseline if payload is None else baseline + payload
                for payload in (
                    None,
                    preset.true_payload,
                    preset.false_payload,
                    confirmation.baseline_preserving_control,
                    confirmation.true_payload,
                    confirmation.false_payload,
                    None,
                    confirmation.false_payload,
                    confirmation.true_payload,
                    confirmation.baseline_preserving_control,
                    preset.false_payload,
                    preset.true_payload,
                )
            )
        assert [path for path, _, _ in received] == [endpoint] * expected_requests
        assert [value for _, value, _ in received] == expected_values
        assert all(
            parse_qs(raw_query, keep_blank_values=True) == {parameter_name: [value]}
            for _, value, raw_query in received
        )
        assert server.query_errors == 0
        assert server.handler_failed is False


def test_openapi_pipeline_safe_matches_not_detected(tmp_path, monkeypatch):
    run_pipeline(
        tmp_path,
        monkeypatch,
        endpoint="/safe",
        expected_verdict="not_detected",
        expected_exit=0,
        expected_status="pass",
        expectation_match=True,
        spec_fixture="openapi.json",
        operation_path="/products",
        parameter_name="category",
        example_pointer="/paths/~1products/get/parameters/0/schema/example",
        baseline="Pets",
        preset_name="string-quoted",
    )


def test_openapi_pipeline_vulnerable_matches_inconclusive(tmp_path, monkeypatch):
    run_pipeline(
        tmp_path,
        monkeypatch,
        endpoint="/vulnerable",
        expected_verdict="inconclusive",
        expected_exit=3,
        expected_status="inconclusive",
        expectation_match=True,
        spec_fixture="openapi.json",
        operation_path="/products",
        parameter_name="category",
        example_pointer="/paths/~1products/get/parameters/0/schema/example",
        baseline="Pets",
        preset_name="string-quoted",
    )


def test_openapi_pipeline_vulnerable_detects_expectation_regression(
    tmp_path, monkeypatch
):
    run_pipeline(
        tmp_path,
        monkeypatch,
        endpoint="/vulnerable",
        expected_verdict="not_detected",
        expected_exit=3,
        expected_status="inconclusive",
        expectation_match=False,
        spec_fixture="openapi.json",
        operation_path="/products",
        parameter_name="category",
        example_pointer="/paths/~1products/get/parameters/0/schema/example",
        baseline="Pets",
        preset_name="string-quoted",
    )


def test_openapi_pipeline_explicit_case_without_confirmation(tmp_path, monkeypatch):
    run_pipeline(
        tmp_path,
        monkeypatch,
        endpoint="/vulnerable",
        expected_verdict="inconclusive",
        expected_exit=3,
        expected_status="inconclusive",
        expectation_match=True,
        spec_fixture="openapi.json",
        operation_path="/products",
        parameter_name="category",
        example_pointer="/paths/~1products/get/parameters/0/schema/example",
        baseline="Pets",
        preset_name=None,
    )


def test_openapi_pipeline_numeric_safe_matches_not_detected(tmp_path, monkeypatch):
    run_pipeline(
        tmp_path,
        monkeypatch,
        endpoint="/numeric-safe",
        expected_verdict="not_detected",
        expected_exit=0,
        expected_status="pass",
        expectation_match=True,
        spec_fixture="openapi-numeric.json",
        operation_path="/product",
        parameter_name="product_id",
        example_pointer="/paths/~1product/get/parameters/0/schema/example",
        baseline="1",
        preset_name="numeric",
    )


def test_openapi_pipeline_numeric_vulnerable_matches_inconclusive(
    tmp_path, monkeypatch
):
    run_pipeline(
        tmp_path,
        monkeypatch,
        endpoint="/numeric-vulnerable",
        expected_verdict="inconclusive",
        expected_exit=3,
        expected_status="inconclusive",
        expectation_match=True,
        spec_fixture="openapi-numeric.json",
        operation_path="/product",
        parameter_name="product_id",
        example_pointer="/paths/~1product/get/parameters/0/schema/example",
        baseline="1",
        preset_name="numeric",
    )


def test_pipeline_loopback_bind_failure_is_actionable():
    def unavailable() -> _Server:
        raise OSError("simulated loopback denial")

    with (
        pytest.raises(
            PipelineLoopbackError,
            match=(
                r"Cannot bind the /safe pipeline fixture\. "
                r"Check that the runner permits IPv4 loopback sockets\."
            ),
        ),
        pipeline_server("/safe", binder=unavailable),
    ):
        pytest.fail("The simulated bind failure unexpectedly produced a server.")
