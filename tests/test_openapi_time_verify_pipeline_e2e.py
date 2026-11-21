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

from vintar.cli import app
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
    ("mode", "expected_verdict", "expected_exit", "expected_status", "reason"),
    [
        (
            "vulnerable",
            "inconclusive",
            3,
            "inconclusive",
            "timing_pattern_matched",
        ),
        (
            "safe",
            "not_detected",
            0,
            "pass",
            "timing_pattern_not_matched",
        ),
    ],
)
def test_openapi_time_pipeline_materializes_and_verifies_sqlite_twins(
    tmp_path,
    monkeypatch,
    mode,
    expected_verdict,
    expected_exit,
    expected_status,
    reason,
):
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
        assert verified.exit_code == expected_exit, (
            f"Time verification for {mode} returned {verified.exit_code}. Check fixture SQL behavior, response status, and loopback transport setup. {verified.stderr}"
        )
        assert verified.stderr == ""
        report = json.loads(verified.stdout)
        report_path = Path("report.json")
        report_path.write_text(json.dumps(report), encoding="utf-8")
        _VALIDATE(report_path, expected_exit)
        assert report["requests_used"] == 9
        assert report["status"] == expected_status
        [outcome] = report["outcomes"]
        assert outcome == {
            "case_id": case.case_id,
            "check_type": "sqli.time",
            "expected_verdict": expected_verdict,
            "actual_verdict": expected_verdict,
            "actual_reason_code": reason,
            "request_count": 9,
            "expectation_match": True,
            "status": expected_status,
            "timing": {
                "status": "candidate" if mode == "vulnerable" else "not_confirmed",
                "reason_code": reason,
                "request_count": 9,
            },
        }
        received, statuses, sql_calls, delay_calls = state.snapshot()
        assert received == EXPECTED_ORDER
        assert statuses == (200,) * 9
        assert sql_calls == 9
        assert delay_calls == (6 if mode == "vulnerable" else 0)
