"""Exercise the complete OpenAPI-to-verify pipeline on loopback twins."""

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qs

import pytest
from test_sqli_http_e2e import (
    FALSE_1,
    TRUE_1,
    LoopbackShutdownError,
    LoopbackStartupError,
    _Server,
    running_server,
)
from typer.testing import CliRunner

from vintar.cli import app
from vintar.regression.cases import load_regression_case

SPEC = Path(__file__).parent / "fixtures" / "pipeline" / "openapi.json"
BASELINE = "Pets"


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
) -> tuple[Path, Path]:
    answers = folder / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "version": 1,
                "expected_verdict": expected_verdict,
                "parameters": {
                    "category": {
                        "pointer": "/paths/~1products/get/parameters/0/schema/example"
                    },
                    "view": {"omit": True},
                },
            }
        ),
        encoding="utf-8",
    )
    config = folder / "case-config.toml"
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
                'name = "category"',
                "occurrence = 0",
                'mode = "append"',
                "",
                "[probes]",
                'selection = "explicit"',
                f"true_payload = {json.dumps(TRUE_1)}",
                f"false_payload = {json.dumps(FALSE_1)}",
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
) -> None:
    monkeypatch.chdir(tmp_path)
    spec = Path("openapi.json")
    spec.write_bytes(SPEC.read_bytes())
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
            if operation["method"] == "GET" and operation["path"] == "/products"
            for item in operation["inputs"]
            if item["location"] == "query" and item["name"] == "category"
        ]
        assert len(selected) == 1, (
            "Discovery did not identify exactly one category query input. Check the pipeline OpenAPI fixture."
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
        assert BASELINE not in review.read_text(encoding="utf-8")

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
        assert materialized == {
            "case_id": case.case_id,
            "report_type": "regression_case_materialization_summary",
            "schema_version": 1,
        }
        assert case.case_id == "case-" + input_id.removeprefix("input-")
        assert case.template.url == origin + endpoint
        assert case.template.params == (("category", BASELINE),)
        assert case.true_payload == TRUE_1
        assert case.false_payload == FALSE_1

        before = len(server.received)
        verified = runner.invoke(
            app,
            [
                "verify",
                "--cases",
                str(case_path),
                "--max-requests",
                "6",
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
        assert report["requests_used"] == 6
        assert report["counts"][expected_status] == 1
        [outcome] = report["outcomes"]
        assert outcome["expected_verdict"] == expected_verdict
        assert outcome["actual_verdict"] == (
            "not_detected" if endpoint == "/safe" else "inconclusive"
        )
        assert outcome["expectation_match"] is expectation_match
        assert outcome["status"] == expected_status
        assert outcome["verification"]["reason_code"] == (
            "no_boolean_difference_literal_input"
            if endpoint == "/safe"
            else "boolean_candidate"
        )
        assert outcome["verification"]["request_count"] == 6
        assert outcome["verification"]["failures"] == []

        received = server.received[before:]
        expected_values = [
            BASELINE,
            BASELINE + TRUE_1,
            BASELINE + FALSE_1,
            BASELINE,
            BASELINE + FALSE_1,
            BASELINE + TRUE_1,
        ]
        assert [path for path, _, _ in received] == [endpoint] * 6
        assert [value for _, value, _ in received] == expected_values
        assert all(
            parse_qs(raw_query, keep_blank_values=True) == {"category": [value]}
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
