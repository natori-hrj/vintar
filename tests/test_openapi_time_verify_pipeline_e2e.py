"""Exercise OpenAPI-to-verify materialization for explicit time SQLi cases."""

import json
import runpy
import socket
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response
from typer.testing import CliRunner

from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.time_analyzer import (
    TimeAnalysisStatus,
    TimeObservation,
    TimeProbeOutcome,
    analyze_time_probes,
)
from vintar.checks.sqli.time_contract import time_product_result
from vintar.checks.sqli.time_plan import (
    TIME_PROBE_ORDER,
    TimePayloads,
    prepare_time_plan,
)
from vintar.cli import app
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression.cases import TimeRegressionCase, load_regression_case

DELAY_SECONDS = 0.35
DELAY_PAYLOAD = "' AND vintar_delay(0.35)=1-- "
CONTROL_PAYLOAD = "' AND vintar_delay(0)=1-- "
EXPECTED_ORDER = (
    "Pets",
    "Pets" + CONTROL_PAYLOAD,
    "Pets" + DELAY_PAYLOAD,
    "Pets" + CONTROL_PAYLOAD,
    "Pets" + DELAY_PAYLOAD,
    "Pets",
    "Pets" + DELAY_PAYLOAD,
    "Pets",
    "Pets" + CONTROL_PAYLOAD,
)
_VALIDATE = runpy.run_path("scripts/validate_ci_report.py")["_validate"]
VULNERABLE_LOOPBACK_REASONS = frozenset({"timing_pattern_matched", "unstable_timing"})
SAFE_LOOPBACK_REASONS = frozenset({"timing_pattern_not_matched", "unstable_timing"})


class PipelineServer(uvicorn.Server):
    """Expose event-based startup synchronization for the pipeline fixture."""

    def __init__(self, config: uvicorn.Config, ready: threading.Event) -> None:
        super().__init__(config)
        self._ready = ready

    async def startup(self, sockets=None) -> None:
        await super().startup(sockets=sockets)
        self._ready.set()


@dataclass(repr=False)
class PipelineState:
    received: list[str] = field(default_factory=list)
    statuses: list[int] = field(default_factory=list)
    sql_calls: int = 0
    delay_calls: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def reset(self) -> None:
        with self.lock:
            self.received.clear()
            self.statuses.clear()
            self.sql_calls = 0
            self.delay_calls = 0

    def record_request(self, value: str) -> None:
        with self.lock:
            self.received.append(value)

    def record_status(self, status: int) -> None:
        with self.lock:
            self.statuses.append(status)

    def record_sql(self) -> None:
        with self.lock:
            self.sql_calls += 1

    def record_delay(self) -> None:
        with self.lock:
            self.delay_calls += 1

    def snapshot(self) -> tuple[tuple[str, ...], tuple[int, ...], int, int]:
        with self.lock:
            return (
                tuple(self.received),
                tuple(self.statuses),
                self.sql_calls,
                self.delay_calls,
            )


def create_app(state: PipelineState) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/{mode}")
    def endpoint(mode: str, request: Request) -> Response:
        values = request.query_params.getlist("category")
        if mode not in {"vulnerable", "safe"} or len(values) != 1:
            state.record_status(400)
            return Response(status_code=400)
        category = values[0]
        state.record_request(category)
        try:
            with closing(sqlite3.connect(":memory:")) as connection:

                def delay_function(seconds: float) -> int:
                    state.record_delay()
                    time.sleep(seconds)
                    return 1

                connection.create_function("vintar_delay", 1, delay_function)
                connection.execute("CREATE TABLE products (category TEXT NOT NULL)")
                connection.execute("INSERT INTO products VALUES (?)", ("Pets",))
                state.record_sql()
                if mode == "vulnerable":
                    connection.execute(
                        f"SELECT category FROM products WHERE category = '{category}'"
                    ).fetchall()
                else:
                    connection.execute(
                        "SELECT category FROM products WHERE category = ?", (category,)
                    ).fetchall()
        except sqlite3.Error:
            state.record_status(500)
            return Response(b"query-error", status_code=500)
        state.record_status(200)
        return Response(b"fixture-response", status_code=200)

    return app


@contextmanager
def running_pipeline_server(mode: str) -> Iterator[tuple[PipelineState, str]]:
    state = PipelineState()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
        except OSError as exc:
            pytest.fail(
                f"Cannot bind the {mode} time pipeline fixture. Check that the runner permits ephemeral IPv4 loopback sockets. {type(exc).__name__}"
            )
        port = listener.getsockname()[1]
        ready = threading.Event()
        server = PipelineServer(
            uvicorn.Config(
                create_app(state),
                host="127.0.0.1",
                port=port,
                lifespan="off",
                access_log=False,
                log_level="critical",
                server_header=False,
            ),
            ready,
        )
        worker = threading.Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            daemon=True,
        )
        worker.start()
        if not ready.wait(timeout=5.0) or not worker.is_alive():
            pytest.fail(
                f"The {mode} time pipeline fixture did not start. Check event synchronization and loopback transport setup."
            )
        try:
            yield state, f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            worker.join(timeout=5.0)
            if worker.is_alive():
                server.force_exit = True
                worker.join(timeout=5.0)
            assert not worker.is_alive(), (
                f"The {mode} time pipeline fixture did not stop. Check shutdown signaling and outstanding requests."
            )
    finally:
        listener.close()


def invoke_success(runner: CliRunner, args: list[str]) -> dict[str, object]:
    result = runner.invoke(app, args)
    assert result.exit_code == 0, (
        f"CLI stage {args[0]} failed. Check its local inputs and output path. {result.stderr}"
    )
    assert result.stderr == ""
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, dict)
    return parsed


def write_spec(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "openapi": "3.1.0",
                "paths": {
                    "/products": {
                        "get": {
                            "parameters": [
                                {
                                    "name": "category",
                                    "in": "query",
                                    "required": True,
                                    "schema": {"type": "string", "example": "Pets"},
                                }
                            ]
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.parametrize(
    ("mode", "expected_verdict"),
    [
        ("vulnerable", "inconclusive"),
        ("safe", "not_detected"),
    ],
)
def test_openapi_time_pipeline_materializes_and_verifies_sqlite_twins(
    tmp_path,
    monkeypatch,
    mode,
    expected_verdict,
):
    from vintar.checks.sqli import time_runner

    captured_observations: list[tuple[TimeObservation, ...]] = []
    production_analyzer = time_runner.analyze_time_probes

    def capture_analysis(*, plan, observations):
        captured_observations.append(observations)
        return production_analyzer(plan=plan, observations=observations)

    monkeypatch.setattr(time_runner, "analyze_time_probes", capture_analysis)
    monkeypatch.chdir(tmp_path)
    spec = Path("openapi.json")
    write_spec(spec)
    runner = CliRunner()

    with running_pipeline_server(mode) as (state, origin):
        inventory = Path("inventory.json")
        invoke_success(
            runner,
            ["discover", "--spec", str(spec), "--output", str(inventory)],
        )
        inventory_data = json.loads(inventory.read_text(encoding="utf-8"))
        [operation] = inventory_data["operations"]
        [selected] = operation["inputs"]
        input_id = selected["id"]
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
        [draft_name] = draft_summary["drafts"]
        draft = Path("drafts") / draft_name
        answers = Path("answers.json")
        answers.write_text(
            json.dumps(
                {
                    "version": 1,
                    "expected_verdict": expected_verdict,
                    "parameters": {
                        "category": {
                            "pointer": "/paths/~1products/get/parameters/0/schema/example"
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        review = Path("review.json")
        invoke_success(
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
        config = Path("case-config.toml")
        config.write_text(
            f"""config_version = 1
type = "sqli.time"
input_id = {json.dumps(input_id)}

[target]
url = {json.dumps(origin + "/" + mode)}
allowed_origin = {json.dumps(origin)}

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
selection = "explicit"
delay_payload = {json.dumps(DELAY_PAYLOAD)}
control_payload = {json.dumps(CONTROL_PAYLOAD)}
expected_delay_seconds = 0.25

[limits]
max_requests = 9
requests_per_second = 10.0
timeout_seconds = 3.0
""",
            encoding="utf-8",
        )
        case_path = Path("time-case.toml")
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
        assert isinstance(case, TimeRegressionCase)
        assert materialized["max_requests"] == 9
        assert state.snapshot() == ((), (), 0, 0), (
            "An offline pipeline stage sent HTTP. Check discover, review-draft, and materialize-case transport boundaries."
        )

        verified = runner.invoke(
            app,
            [
                "verify",
                "--cases",
                str(case_path),
                "--max-requests",
                "9",
                "--rps",
                "10",
                "--timeout",
                "3",
                "--time-deadline",
                "30",
                "--authorized",
            ],
            env={
                "VINTAR_TARGET_ORIGIN": origin,
                "VINTAR_ALLOWED_ORIGIN": origin,
            },
        )
        assert verified.stderr == ""
        report = json.loads(verified.stdout)
        [observations] = captured_observations
        elapsed_values = tuple(item.elapsed_seconds for item in observations)
        [outcome] = report["outcomes"]
        reason = outcome["actual_reason_code"]
        diagnostic = (
            f"reason_code={reason!r}, elapsed_seconds={elapsed_values!r}. "
            "Check fixture SQL behavior, host scheduling, and loopback transport setup."
        )
        allowed_reasons = (
            VULNERABLE_LOOPBACK_REASONS
            if mode == "vulnerable"
            else SAFE_LOOPBACK_REASONS
        )
        assert reason in allowed_reasons, diagnostic
        unstable = reason == "unstable_timing"
        actual_verdict = (
            "inconclusive" if mode == "vulnerable" or unstable else "not_detected"
        )
        expected_exit = 3 if actual_verdict == "inconclusive" else 0
        expected_status = "inconclusive" if expected_exit == 3 else "pass"
        timing_status = (
            "inconclusive"
            if unstable
            else "candidate"
            if mode == "vulnerable"
            else "not_confirmed"
        )
        assert verified.exit_code == expected_exit, diagnostic
        report_path = Path("report.json")
        report_path.write_text(json.dumps(report), encoding="utf-8")
        _VALIDATE(report_path, expected_exit)
        assert report["requests_used"] == 9, diagnostic
        assert report["status"] == expected_status, diagnostic
        assert outcome == {
            "case_id": case.case_id,
            "check_type": "sqli.time",
            "expected_verdict": expected_verdict,
            "actual_verdict": actual_verdict,
            "actual_reason_code": reason,
            "request_count": 9,
            "expectation_match": actual_verdict == expected_verdict,
            "status": expected_status,
            "timing": {
                "status": timing_status,
                "reason_code": reason,
                "request_count": 9,
            },
        }, diagnostic
        received, statuses, sql_calls, delay_calls = state.snapshot()
        assert received == EXPECTED_ORDER, diagnostic
        assert statuses == (200,) * 9, diagnostic
        assert sql_calls == 9, diagnostic
        assert delay_calls == (6 if mode == "vulnerable" else 0), diagnostic

        if mode == "safe":
            batch_dir = Path("batch")
            batch_dir.mkdir()
            time_batch_case = batch_dir / "time.toml"
            time_summary = invoke_success(
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
                    str(time_batch_case),
                ],
            )
            boolean_config = Path("boolean-config.toml")
            boolean_config.write_text(
                f"""config_version = 1
input_id = {json.dumps(input_id)}

[target]
url = {json.dumps(origin + "/safe")}
allowed_origin = {json.dumps(origin)}

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
selection = "explicit"
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 3.0
""",
                encoding="utf-8",
            )
            boolean_batch_case = batch_dir / "boolean.toml"
            boolean_summary = invoke_success(
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
                    str(boolean_config),
                    "--output",
                    str(boolean_batch_case),
                ],
            )
            time_batch = load_regression_case(time_batch_case)
            boolean_batch = load_regression_case(boolean_batch_case)
            assert isinstance(time_batch, TimeRegressionCase)
            assert time_batch.case_id == case.case_id
            assert time_summary["case_id"] == time_batch.case_id
            assert boolean_summary["case_id"] == boolean_batch.case_id
            assert boolean_batch.case_id == case.case_id.removesuffix("-time")
            assert time_batch.case_id == boolean_batch.case_id + "-time"

            state.reset()
            mixed = runner.invoke(
                app,
                [
                    "verify",
                    "--cases",
                    str(batch_dir),
                    "--max-requests",
                    "15",
                    "--rps",
                    "10",
                    "--timeout",
                    "3",
                    "--time-deadline",
                    "30",
                    "--authorized",
                ],
                env={
                    "VINTAR_TARGET_ORIGIN": origin,
                    "VINTAR_ALLOWED_ORIGIN": origin,
                },
            )
            assert mixed.stderr == ""
            mixed_report = json.loads(mixed.stdout)
            _, mixed_observations = captured_observations
            mixed_elapsed = tuple(item.elapsed_seconds for item in mixed_observations)
            boolean_outcome, time_outcome = mixed_report["outcomes"]
            mixed_reason = time_outcome["actual_reason_code"]
            boolean_status = boolean_outcome["status"]
            boolean_verdict = boolean_outcome["actual_verdict"]
            boolean_reason = boolean_outcome["actual_reason_code"]
            mixed_diagnostic = (
                f"Boolean status={boolean_status!r}, verdict={boolean_verdict!r}, "
                f"reason_code={boolean_reason!r}; Time reason_code={mixed_reason!r}, "
                f"elapsed_seconds={mixed_elapsed!r}. "
                "Check fixture SQL behavior, host scheduling, and loopback transport setup."
            )
            assert boolean_status == "pass", mixed_diagnostic
            assert boolean_verdict == "not_detected", mixed_diagnostic
            assert mixed_reason in SAFE_LOOPBACK_REASONS, mixed_diagnostic
            time_is_inconclusive = time_outcome["actual_verdict"] == "inconclusive"
            assert time_is_inconclusive == (mixed_reason == "unstable_timing"), (
                mixed_diagnostic
            )
            mixed_expected_exit = 3 if time_is_inconclusive else 0
            assert mixed.exit_code == mixed_expected_exit, mixed_diagnostic
            mixed_path = Path("mixed-report.json")
            mixed_path.write_text(json.dumps(mixed_report), encoding="utf-8")
            _VALIDATE(mixed_path, mixed_expected_exit)
            assert mixed_report["requests_used"] == 15, mixed_diagnostic
            assert mixed_report["executed_case_ids"] == [
                boolean_batch.case_id,
                time_batch.case_id,
            ], mixed_diagnostic
            assert len(set(mixed_report["executed_case_ids"])) == 2, mixed_diagnostic
            assert "check_type" not in boolean_outcome, mixed_diagnostic
            assert boolean_outcome["verification"]["check_type"] == "sqli_boolean", (
                mixed_diagnostic
            )
            assert time_outcome["check_type"] == "sqli.time", mixed_diagnostic
            mixed_received, mixed_statuses, mixed_sql_calls, mixed_delay_calls = (
                state.snapshot()
            )
            assert mixed_received == (
                "Pets",
                "Petstrue-probe",
                "Petsfalse-probe",
                "Pets",
                "Petsfalse-probe",
                "Petstrue-probe",
                *EXPECTED_ORDER,
            ), mixed_diagnostic
            assert mixed_statuses == (200,) * 15, mixed_diagnostic
            assert mixed_sql_calls == 15, mixed_diagnostic
            assert mixed_delay_calls == 0, mixed_diagnostic


def test_fixture_time_relation_is_exact_candidate_with_fixed_observations():
    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", 18083)})
        ),
        budget=RequestBudget(9),
        timeout=3.0,
        rate_limiter=RateLimiter(requests_per_second=10.0),
    )
    plan = prepare_time_plan(
        template=RequestTemplate(
            method="GET",
            url="http://127.0.0.1:18083/vulnerable",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=TimePayloads(delay=DELAY_PAYLOAD, control=CONTROL_PAYLOAD),
        expected_delay_seconds=0.25,
        context=context,
    )
    elapsed_values = (
        0.007061,
        0.004588,
        0.352533,
        0.001884,
        0.353464,
        0.001846,
        0.353944,
        0.003003,
        0.001503,
    )
    observations = tuple(
        TimeObservation(
            kind=kind,
            sequence=sequence,
            outcome=TimeProbeOutcome.COMPLETED,
            elapsed_seconds=elapsed,
            status_code=200,
        )
        for sequence, (kind, elapsed) in enumerate(
            zip(TIME_PROBE_ORDER, elapsed_values, strict=True), start=1
        )
    )

    analysis = analyze_time_probes(plan=plan, observations=observations)
    product = time_product_result(analysis)

    assert analysis.status is TimeAnalysisStatus.CANDIDATE
    assert analysis.reason_code == "timing_pattern_matched"
    assert product.verdict is Verdict.INCONCLUSIVE
    assert product.reason_code == "timing_pattern_matched"
    assert product.request_count == 9
