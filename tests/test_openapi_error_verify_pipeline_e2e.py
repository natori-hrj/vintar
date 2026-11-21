"""Exercise OpenAPI-to-verify materialization for explicit Error SQLi cases."""

import json
import runpy
import socket
import sqlite3
import threading
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
from vintar.regression.cases import ErrorRegressionCase, load_regression_case

ERROR_PAYLOAD = "'"
EXPECTED_ORDER = ("Pets", "Pets'", "Pets", "Pets'")
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
    sql_errors: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, value: str, status: int, *, sql_error: bool) -> None:
        with self.lock:
            self.received.append(value)
            self.statuses.append(status)
            self.sql_errors += int(sql_error)

    def snapshot(self) -> tuple[tuple[str, ...], tuple[int, ...], int]:
        with self.lock:
            return tuple(self.received), tuple(self.statuses), self.sql_errors


def create_app(state: PipelineState) -> FastAPI:
    fixture = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @fixture.get("/{mode}")
    def endpoint(mode: str, request: Request) -> Response:
        values = request.query_params.getlist("category")
        if mode not in {"vulnerable", "safe"} or len(values) != 1:
            state.record("invalid-request", 400, sql_error=False)
            return Response(status_code=400)
        category = values[0]
        try:
            with closing(sqlite3.connect(":memory:")) as connection:
                connection.execute("CREATE TABLE products (category TEXT NOT NULL)")
                connection.execute("INSERT INTO products VALUES (?)", ("Pets",))
                if mode == "vulnerable":
                    connection.execute(
                        f"SELECT category FROM products WHERE category = '{category}'"
                    ).fetchall()
                else:
                    connection.execute(
                        "SELECT category FROM products WHERE category = ?", (category,)
                    ).fetchall()
        except sqlite3.Error as error:
            state.record(category, 200, sql_error=True)
            return Response(
                f"sqlite3.OperationalError: {error}".encode(),
                status_code=200,
            )
        state.record(category, 200, sql_error=False)
        return Response(b"fixture-response", status_code=200)

    return fixture


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
                f"Cannot bind the {mode} Error pipeline fixture. Check that the runner permits ephemeral IPv4 loopback sockets. {type(exc).__name__}"
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
                f"The {mode} Error pipeline fixture did not start. Check event synchronization and loopback transport setup."
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
                f"The {mode} Error pipeline fixture did not stop. Check shutdown signaling and outstanding requests."
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
    ("mode", "expected_verdict", "expected_exit", "status", "reason"),
    [
        (
            "vulnerable",
            "inconclusive",
            3,
            "inconclusive",
            "dbms_error_disclosed",
        ),
        ("safe", "not_detected", 0, "pass", "dbms_error_not_observed"),
    ],
)
def test_openapi_error_pipeline_materializes_and_verifies_sqlite_twins(
    tmp_path,
    monkeypatch,
    mode,
    expected_verdict,
    expected_exit,
    status,
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
type = "sqli.error"
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
error_payload = {json.dumps(ERROR_PAYLOAD)}

[limits]
max_requests = 4
requests_per_second = 10.0
timeout_seconds = 3.0
""",
            encoding="utf-8",
        )
        case_path = Path("error-case.toml")
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
        assert isinstance(case, ErrorRegressionCase)
        assert case.case_id == "case-" + input_id.removeprefix("input-") + "-error"
        assert materialized == {
            "case_id": case.case_id,
            "confirmation": "not configured",
            "max_requests": 4,
            "report_type": "regression_case_materialization_summary",
            "schema_version": 1,
        }
        assert state.snapshot() == ((), (), 0), (
            "An offline pipeline stage sent HTTP. Check discover, review-draft, and materialize-case transport boundaries."
        )

        verified = runner.invoke(
            app,
            [
                "verify",
                "--cases",
                str(case_path),
                "--max-requests",
                "4",
                "--rps",
                "10",
                "--timeout",
                "3",
                "--authorized",
            ],
            env={
                "VINTAR_TARGET_ORIGIN": origin,
                "VINTAR_ALLOWED_ORIGIN": origin,
            },
        )
        assert verified.exit_code == expected_exit, (
            f"Error verification for {mode} returned {verified.exit_code}. Check fixture SQL behavior, response stability, and loopback transport setup. {verified.stderr}"
        )
        assert verified.stderr == ""
        report = json.loads(verified.stdout)
        report_path = Path("report.json")
        report_path.write_text(json.dumps(report), encoding="utf-8")
        _VALIDATE(report_path, expected_exit)
        assert report["requests_used"] == 4
        assert report["status"] == status
        [outcome] = report["outcomes"]
        assert outcome["case_id"] == case.case_id
        assert outcome["check_type"] == "sqli.error"
        assert outcome["expected_verdict"] == expected_verdict
        assert outcome["actual_verdict"] == expected_verdict
        assert outcome["actual_reason_code"] == reason
        assert outcome["request_count"] == 4
        assert outcome["expectation_match"] is True
        assert outcome["status"] == status
        assert outcome["error"]["reason_code"] == reason
        assert outcome["error"]["request_count"] == 4
        if mode == "vulnerable":
            assert outcome["error"] == {
                "status": "matched",
                "reason_code": reason,
                "request_count": 4,
                "dbms": "sqlite",
                "signature_id": "sqlite_operational_syntax",
            }
        else:
            assert outcome["error"] == {
                "status": "not_matched",
                "reason_code": reason,
                "request_count": 4,
            }
        received, statuses, sql_errors = state.snapshot()
        assert received == EXPECTED_ORDER
        assert statuses == (200,) * 4
        assert sql_errors == (2 if mode == "vulnerable" else 0)
