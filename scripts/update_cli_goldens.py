"""Capture deterministic CLI results and regenerate their golden files."""

import argparse
import hashlib
import json
import runpy
from contextlib import chdir
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

import httpx
from typer.testing import CliRunner

from vintar import sqli_cli
from vintar.checks.sqli.time_analyzer import (
    TimeObservation,
    TimeProbeOutcome,
    analyze_time_probes,
)
from vintar.checks.sqli.time_plan import TIME_PROBE_ORDER, prepare_time_plan
from vintar.checks.sqli.time_runner import TimeRunReport
from vintar.cli import app
from vintar.core import executor, http
from vintar.core.rate_limit import RateLimiter
from vintar.regression import batch
from vintar.regression import runner as regression_runner
from vintar.regression.cases import load_regression_case
from vintar.regression.post_json_inventory import analyze_post_json, serialize_report

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_DIR = ROOT / "tests" / "golden" / "cli"
UPDATE_COMMAND = "uv run python scripts/update_cli_goldens.py --write"
ORIGIN = "http://cli-fixture.invalid"
CASE_TEMPLATE = runpy.run_path(str(ROOT / "scripts" / "run_ci_e2e.py"))["CASE_TEMPLATE"]
TIME_CASE_TEMPLATE = """version = 1
id = "time-case"
type = "sqli.time"
expected_verdict = "{expected}"

[target]
url = "http://cli-fixture.invalid/time"
allowed_origin = "http://cli-fixture.invalid"

[[target.params]]
name = "id"
value = "1"

[injection]
location = "query"
name = "id"
occurrence = 0
mode = "append"

[probes]
delay_payload = "-delay"
control_payload = "-control"
expected_delay_seconds = 0.25

[limits]
max_requests = 9
requests_per_second = 10.0
timeout_seconds = 3.0
"""
ERROR_CASE_TEMPLATE = """version = 1
id = "{case_id}"
type = "sqli.error"
expected_verdict = "{expected}"

[target]
url = "http://cli-fixture.invalid/{path}"
allowed_origin = "http://cli-fixture.invalid"

[[target.params]]
name = "id"
value = "1"

[injection]
location = "query"
name = "id"
occurrence = 0
mode = "append"

[probes]
error_payload = "'"

[limits]
max_requests = 4
requests_per_second = 10.0
timeout_seconds = 3.0
"""


@dataclass(frozen=True)
class Scenario:
    exit_code: int
    requests: int
    expected_verdict: str = "not_detected"
    rate_limited: bool = False
    timeout_on_second_request: bool = False
    time_result: str | None = None
    mixed: bool = False
    error_result: str | None = None
    mixed_error: bool = False


SCENARIOS = {
    "sqli-verify/normal.json": Scenario(0, 6),
    "sqli-verify/probe-failure.json": Scenario(0, 2, timeout_on_second_request=True),
    "sqli-verify/authorization-required.json": Scenario(2, 0),
    "verify/pass.json": Scenario(0, 6),
    "verify/fail.json": Scenario(1, 6, expected_verdict="vulnerable"),
    "verify/partial-inconclusive.json": Scenario(3, 1, rate_limited=True),
    "verify/authorization-required.json": Scenario(2, 0),
    "verify/time-not-detected.json": Scenario(
        0, 0, time_result="timing_pattern_not_matched"
    ),
    "verify/time-candidate.json": Scenario(
        3,
        0,
        expected_verdict="inconclusive",
        time_result="timing_pattern_matched",
    ),
    "verify/mixed-boolean-time.json": Scenario(
        3,
        6,
        time_result="timing_pattern_matched",
        mixed=True,
    ),
    "verify/error-not-detected.json": Scenario(
        0, 4, error_result="dbms_error_not_observed"
    ),
    "verify/error-disclosed.json": Scenario(
        3,
        4,
        expected_verdict="inconclusive",
        error_result="dbms_error_disclosed",
    ),
    "verify/mixed-boolean-time-error.json": Scenario(
        3,
        10,
        time_result="timing_pattern_matched",
        mixed=True,
        error_result="dbms_error_not_observed",
        mixed_error=True,
    ),
    "discover/success.json": Scenario(0, 0),
    "review-draft/success.json": Scenario(0, 0),
    "review-draft/null-baseline.json": Scenario(2, 0),
    "materialize-case/success.json": Scenario(0, 0),
    "materialize-case/conflict.json": Scenario(2, 0),
    "materialize-case/stale-review.json": Scenario(2, 0),
    "discover/drafts.json": Scenario(0, 0),
    "discover/drafts-conflict.json": Scenario(2, 0),
    "discover/stale-selection.json": Scenario(2, 0),
    "discover/invalid-selection.json": Scenario(2, 0),
    "discover/invalid-spec.json": Scenario(2, 0),
    "discover/output-spec-conflict.json": Scenario(2, 0),
    "discover/output-selection-conflict.json": Scenario(2, 0),
    "inventory-post-json/success.json": Scenario(0, 0),
    "inventory-post-json/empty.json": Scenario(0, 0),
    "inventory-post-json/invalid-spec.json": Scenario(2, 0),
    "inventory-post-json/unreadable-spec.json": Scenario(2, 0),
    "inventory-post-json/external-ref.json": Scenario(0, 0),
    "inventory-post-json/cyclic-ref.json": Scenario(0, 0),
    "inventory-post-json/output-spec-conflict.json": Scenario(2, 0),
    "inventory-post-json/unwritable-output.json": Scenario(2, 0),
    "inventory-post-json/interrupt.json": Scenario(130, 0),
    "review-post-json/success.json": Scenario(0, 0),
    "review-post-json/digest-mismatch.json": Scenario(2, 0),
    "review-post-json/operation-unconfirmed.json": Scenario(2, 0),
    "review-post-json/side-effect-unconfirmed.json": Scenario(2, 0),
    "review-post-json/environment-unconfirmed.json": Scenario(2, 0),
    "review-post-json/wildcard-pointer.json": Scenario(2, 0),
}


def cli_args(name: str, scenario: Scenario, folder: Path) -> list[str]:
    if name.startswith("sqli-verify/"):
        args = [
            "sqli",
            "verify",
            "--url",
            f"{ORIGIN}/ok",
            "--allow-origin",
            ORIGIN,
            "--param",
            "id=1",
            "--inject-param",
            "id",
            "--true-payload",
            "true-probe",
            "--false-payload",
            "false-probe",
        ]
    else:
        if scenario.time_result is not None:
            time_expected = (
                "inconclusive"
                if scenario.time_result == "timing_pattern_matched"
                else "not_detected"
            )
            (folder / "time-case.toml").write_text(
                TIME_CASE_TEMPLATE.format(expected=time_expected),
                encoding="utf-8",
            )
            if scenario.mixed:
                source = CASE_TEMPLATE.format(expected="not_detected", path="/ok")
                source = source.replace('id = "fixture-case"', 'id = "boolean-case"')
                (folder / "boolean-case.toml").write_text(source, encoding="utf-8")
            if scenario.mixed_error:
                (folder / "error-case.toml").write_text(
                    ERROR_CASE_TEMPLATE.format(
                        case_id="error-case",
                        expected="not_detected",
                        path="error-not-detected",
                    ),
                    encoding="utf-8",
                )
            budget = 19 if scenario.mixed_error else 15 if scenario.mixed else 9
            args = ["verify", "--cases", str(folder), "--max-requests", str(budget)]
        elif scenario.error_result is not None:
            path = (
                "error-disclosed"
                if scenario.error_result == "dbms_error_disclosed"
                else "error-not-detected"
            )
            (folder / "error-case.toml").write_text(
                ERROR_CASE_TEMPLATE.format(
                    case_id="error-case",
                    expected=scenario.expected_verdict,
                    path=path,
                ),
                encoding="utf-8",
            )
            args = ["verify", "--cases", str(folder), "--max-requests", "4"]
        else:
            cases = (
                (("a-case", "/limited"), ("b-case", "/ok"))
                if scenario.rate_limited
                else (("a-case", "/ok"),)
            )
            for case_id, path in cases:
                source = CASE_TEMPLATE.format(
                    expected=scenario.expected_verdict, path=path
                )
                source = source.replace('id = "fixture-case"', f'id = "{case_id}"')
                (folder / f"{case_id}.toml").write_text(source, encoding="utf-8")
            args = [
                "verify",
                "--cases",
                str(folder),
                "--max-requests",
                str(6 * len(cases)),
            ]
    if scenario.exit_code != 2:
        args.append("--authorized")
    return args


DISCOVERY_SELECTION = (
    'version = 1\napproved = ["input-24a9c3cf0c3d01709121ac0d09079903"]\n'
)


def capture_discovery(name, scenario, folder, args, env):
    spec = folder / "openapi.json"
    selection = folder / "review.toml"
    if name == "discover/invalid-spec.json":
        spec.write_text("{", encoding="utf-8")
    else:
        spec.write_bytes(
            (ROOT / "tests/fixtures/discovery/openapi30.json").read_bytes()
        )
    if not selection.exists():
        selection_text = DISCOVERY_SELECTION
        if name == "discover/stale-selection.json":
            selection_text = f'version = 1\napproved = ["input-{"0" * 32}"]\n'
        elif name == "discover/invalid-selection.json":
            selection_text = "version = 2\napproved = []\n"
        selection.write_text(selection_text, encoding="utf-8")
    output = {
        "discover/output-spec-conflict.json": spec.name,
        "discover/output-selection-conflict.json": selection.name,
    }.get(name, "inventory.json")
    drafting = name in {"discover/drafts.json", "discover/drafts-conflict.json"}
    destination = folder / "drafts"
    conflict = destination / "case-24a9c3cf0c3d01709121ac0d09079903.draft.toml"
    if name == "discover/drafts-conflict.json":
        destination.mkdir()
        conflict.write_text("Existing review notes.\n", encoding="utf-8")
    if args is None:
        args = ["discover", "--spec", spec.name, "--selection", selection.name]
        args.extend(
            ["--drafts-dir", destination.name] if drafting else ["--output", output]
        )
    before = (spec.read_bytes(), selection.read_bytes())
    with (
        chdir(folder),
        patch(
            "socket.socket", side_effect=AssertionError("Discovery opened a socket.")
        ),
        patch(
            "socket.getaddrinfo", side_effect=AssertionError("Discovery resolved DNS.")
        ),
    ):
        result = CliRunner().invoke(app, args, env=env)
    if (spec.read_bytes(), selection.read_bytes()) != before:
        raise ValueError("Discovery modified an input file.")
    if result.exit_code != scenario.exit_code:
        raise ValueError(
            f"Expected exit code {scenario.exit_code}, got {result.exit_code}. "
            f"CLI stderr: {result.stderr.strip()}"
        )
    if drafting:
        if result.exit_code == 0:
            if not result.stdout.endswith("\n") or result.stderr:
                raise ValueError(
                    "Expected a newline-terminated draft summary with empty stderr."
                )
            summary = json.loads(result.stdout)
            drafts = {
                path.name: path.read_text(encoding="utf-8")
                for path in sorted(destination.iterdir())
            }
            if sorted(drafts) != summary["drafts"]:
                raise ValueError("Draft summary differs from the files written.")
        else:
            if (
                result.stdout
                or not result.stderr
                or sorted(destination.iterdir()) != [conflict]
            ):
                raise ValueError(
                    "Expected only a diagnostic and the original conflicting file."
                )
            if conflict.read_text(encoding="utf-8") != "Existing review notes.\n":
                raise ValueError("Discovery changed the conflicting draft.")
            summary = drafts = None
        return {
            "exit_code": result.exit_code,
            "stdout_json": summary,
            "stderr": result.stderr,
            "draft_files": drafts,
        }
    report_path = folder / "inventory.json"
    if result.exit_code == 0:
        if (
            not result.stdout.endswith("\n")
            or result.stderr
            or not report_path.is_file()
        ):
            raise ValueError("Expected JSON summary and report with empty stderr.")
        summary = json.loads(result.stdout)
        report = json.loads(report_path.read_text(encoding="utf-8"))
    else:
        if result.stdout or not result.stderr or report_path.exists():
            raise ValueError("Expected a diagnostic on stderr and no discovery report.")
        summary = report = None
    return {
        "exit_code": result.exit_code,
        "stdout_json": summary,
        "stderr": result.stderr,
        "report_json": report,
    }


def capture_post_json(name, scenario, folder, args, env):
    spec = folder / "openapi.json"
    operation = {
        "operationId": "createItem",
        "requestBody": {
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {"name": {"type": "string"}},
                    }
                }
            }
        },
    }
    document = {"openapi": "3.1.2", "paths": {"/items": {"post": operation}}}
    if name == "inventory-post-json/empty.json":
        document["paths"] = {}
    elif name == "inventory-post-json/invalid-spec.json":
        spec.write_text("{", encoding="utf-8")
    elif name == "inventory-post-json/unreadable-spec.json":
        spec = folder / "missing.json"
    elif name == "inventory-post-json/external-ref.json":
        operation["requestBody"]["content"]["application/json"]["schema"] = {
            "$ref": "external.json#/Item"
        }
    elif name == "inventory-post-json/cyclic-ref.json":
        operation["requestBody"]["content"]["application/json"]["schema"] = {
            "$ref": "#/components/schemas/Node"
        }
        document["components"] = {
            "schemas": {
                "Node": {
                    "type": "object",
                    "properties": {"child": {"$ref": "#/components/schemas/Node"}},
                }
            }
        }
    if not spec.exists() and name not in {
        "inventory-post-json/invalid-spec.json",
        "inventory-post-json/unreadable-spec.json",
    }:
        spec.write_text(json.dumps(document), encoding="utf-8")
    output = (
        spec.name
        if name == "inventory-post-json/output-spec-conflict.json"
        else "missing/report.json"
        if name == "inventory-post-json/unwritable-output.json"
        else "post-json-inventory.json"
    )
    if args is None:
        args = ["inventory-post-json", "--spec", spec.name, "--output", output]
    patches = []
    if name == "inventory-post-json/interrupt.json":
        patches.append(
            patch(
                "vintar.post_json_inventory_cli.analyze_post_json",
                side_effect=KeyboardInterrupt,
            )
        )
    with (
        chdir(folder),
        patch(
            "socket.socket", side_effect=AssertionError("Inventory opened a socket.")
        ),
        patch(
            "socket.getaddrinfo", side_effect=AssertionError("Inventory resolved DNS.")
        ),
    ):
        for context in patches:
            context.start()
        try:
            result = CliRunner().invoke(app, args, env=env)
        finally:
            for context in reversed(patches):
                context.stop()
    report_path = folder / "post-json-inventory.json"
    if result.exit_code != scenario.exit_code:
        raise ValueError(
            f"Expected exit code {scenario.exit_code}, got {result.exit_code}. "
            f"CLI stderr: {result.stderr.strip()}"
        )
    if result.exit_code == 0:
        if (
            not result.stdout.endswith("\n")
            or result.stderr
            or not report_path.is_file()
        ):
            raise ValueError("Expected a human summary, report, and empty stderr.")
        report = json.loads(report_path.read_text(encoding="utf-8"))
    else:
        if result.stdout or not result.stderr or report_path.exists():
            raise ValueError("Expected only a diagnostic and no report.")
        report = None
    return {
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "report_json": report,
    }


def capture_review(name, scenario, folder, args, env):
    export = capture_discovery(
        "discover/drafts.json", Scenario(0, 0), folder, None, env
    )
    draft = next(iter(export["draft_files"]))
    answers = folder / "answers.json"
    if not answers.exists():
        value = (
            None if name == "review-draft/null-baseline.json" else "fixture-baseline"
        )
        answers.write_text(
            json.dumps(
                {
                    "version": 1,
                    "expected_verdict": "not_detected",
                    "parameters": {"q": {"value": value}},
                }
            ),
            encoding="utf-8",
        )
    if args is None:
        args = [
            "review-draft",
            "--spec",
            "openapi.json",
            "--draft",
            f"drafts/{draft}",
            "--answers",
            "answers.json",
            "--output",
            "review.json",
        ]
    with (
        chdir(folder),
        patch("socket.socket", side_effect=AssertionError("Review opened a socket.")),
        patch("socket.getaddrinfo", side_effect=AssertionError("Review resolved DNS.")),
    ):
        result = CliRunner().invoke(app, args, env=env)
    report = folder / "review.json"
    if result.exit_code != scenario.exit_code:
        raise ValueError(
            f"Expected exit {scenario.exit_code}, got {result.exit_code}. Check the review inputs and flags. {result.stderr}"
        )
    if result.exit_code == 0:
        if not result.stdout.endswith("\n") or result.stderr or not report.is_file():
            raise ValueError(
                "Expected a JSON summary and review report. Check the review output path."
            )
        summary = json.loads(result.stdout)
        payload = json.loads(report.read_text(encoding="utf-8"))
    else:
        if result.stdout or not result.stderr or report.exists():
            raise ValueError(
                "Expected a review diagnostic and no output file. Check the error path."
            )
        summary = payload = None
    return {
        "exit_code": result.exit_code,
        "stdout_json": summary,
        "stderr": result.stderr,
        "report_json": payload,
    }


def capture_post_review(name, scenario, folder, args, env):
    sentinel = "PRIVATE-BODY-SENTINEL-74d9"
    body = {"orders": [{"sku": sentinel}]}
    document = {
        "openapi": "3.1.2",
        "paths": {
            "/items": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "orders": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "sku": {"type": "string"}
                                                },
                                            },
                                        }
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }
    spec = folder / "openapi.json"
    spec.write_text(json.dumps(document), encoding="utf-8")
    inventory = folder / "inventory.json"
    report = analyze_post_json(spec)
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
        "concrete_pointer": "/orders/0/sku",
        "operation_approved": True,
        "side_effect": {"class": "no_side_effect", "confirmed": True},
        "environment": {"class": "isolated_test", "confirmed": True},
    }
    if name.endswith("digest-mismatch.json"):
        answer["baseline"]["body_sha256"] = "0" * 64
    elif name.endswith("operation-unconfirmed.json"):
        answer["operation_approved"] = False
    elif name.endswith("side-effect-unconfirmed.json"):
        answer["side_effect"]["confirmed"] = False
    elif name.endswith("environment-unconfirmed.json"):
        answer["environment"]["confirmed"] = False
    elif name.endswith("wildcard-pointer.json"):
        answer["concrete_pointer"] = "/orders/*/sku"
    answers = folder / "answers.json"
    answers.write_text(json.dumps(answer), encoding="utf-8")
    output = folder / "review.json"
    with (
        chdir(folder),
        patch("socket.socket", side_effect=AssertionError("Review opened a socket.")),
        patch("socket.getaddrinfo", side_effect=AssertionError("Review resolved DNS.")),
    ):
        result = CliRunner().invoke(
            app,
            [
                "review-post-json",
                "--spec",
                spec.name,
                "--inventory",
                inventory.name,
                "--answers",
                answers.name,
                "--output",
                output.name,
            ],
            env=env,
        )
    if result.exit_code != scenario.exit_code:
        raise ValueError(result.stderr)
    artifact = (
        json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
    )
    serialized = result.stdout + result.stderr + json.dumps(artifact)
    if sentinel in serialized:
        raise ValueError("POST review golden disclosed its baseline body.")
    return {
        "exit_code": result.exit_code,
        "stdout_json": json.loads(result.stdout) if result.stdout else None,
        "stderr": result.stderr,
        "review_json": artifact,
    }


def capture_materialization(name, scenario, folder, args, env):
    capture_review("review-draft/success.json", Scenario(0, 0), folder, None, env)
    draft = next((folder / "drafts").iterdir())
    config = folder / "case-config.toml"
    if not config.exists():
        config.write_text(
            """config_version = 1
input_id = "input-24a9c3cf0c3d01709121ac0d09079903"

[target]
url = "http://cli-fixture.invalid/fixture-route"
allowed_origin = "http://cli-fixture.invalid"

[injection]
location = "query"
name = "q"
occurrence = 0
mode = "append"

[probes]
selection = "explicit"
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 5.0
""",
            encoding="utf-8",
        )
    output = folder / "security/cases/case-24a9c3cf0c3d01709121ac0d09079903.toml"
    if name == "materialize-case/conflict.json":
        output.parent.mkdir(parents=True)
        output.write_text("Existing review notes.\n", encoding="utf-8")
    if name == "materialize-case/stale-review.json":
        (folder / "answers.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "expected_verdict": "not_detected",
                    "parameters": {"q": {"value": "changed-baseline"}},
                }
            ),
            encoding="utf-8",
        )
    if args is None:
        args = [
            "materialize-case",
            "--spec",
            "openapi.json",
            "--draft",
            str(draft.relative_to(folder)),
            "--answers",
            "answers.json",
            "--review",
            "review.json",
            "--config",
            "case-config.toml",
            "--output",
            str(output.relative_to(folder)),
        ]
    with (
        chdir(folder),
        patch(
            "socket.socket",
            side_effect=AssertionError("Materialization opened a socket."),
        ),
        patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("Materialization resolved DNS."),
        ),
    ):
        result = CliRunner().invoke(app, args, env=env)
    if result.exit_code != scenario.exit_code:
        raise ValueError(
            f"Expected exit {scenario.exit_code}, got {result.exit_code}. "
            f"Check the materialization inputs and flags. {result.stderr}"
        )
    if result.exit_code == 0:
        if not result.stdout.endswith("\n") or result.stderr or not output.is_file():
            raise ValueError(
                "Expected a JSON summary and Schema v1 case. Check the output path."
            )
        summary = json.loads(result.stdout)
        case = load_regression_case(output)
        if summary["case_id"] != case.case_id:
            raise ValueError("Materialization summary differs from the generated case.")
        case_valid = True
    else:
        if result.stdout or not result.stderr:
            raise ValueError(
                "Expected a materialization diagnostic on stderr and empty stdout."
            )
        if name == "materialize-case/conflict.json":
            if output.read_text(encoding="utf-8") != "Existing review notes.\n":
                raise ValueError("Materialization changed the conflicting output.")
        elif output.exists():
            raise ValueError(
                "Materialization wrote a case after rejecting stale input."
            )
        summary = None
        case_valid = False
    return {
        "case_valid": case_valid,
        "exit_code": result.exit_code,
        "stdout_json": summary,
        "stderr": result.stderr,
    }


def capture(
    name: str,
    scenario: Scenario,
    folder: Path,
    *,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    if name.startswith(
        (
            "discover/",
            "review-draft/",
            "materialize-case/",
            "inventory-post-json/",
            "review-post-json/",
        )
    ):
        if name.startswith("review-draft/"):
            offline_capture = capture_review
        elif name.startswith("review-post-json/"):
            offline_capture = capture_post_review
        elif name.startswith("materialize-case/"):
            offline_capture = capture_materialization
        elif name.startswith("discover/"):
            offline_capture = capture_discovery
        else:
            offline_capture = capture_post_json
        return (
            json.dumps(
                offline_capture(name, scenario, folder, args, env),
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )

    request_count = 0

    def handle(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        sleep(0.125)
        if scenario.timeout_on_second_request and request_count == 2:
            raise httpx.ReadTimeout("Fixture probe timed out.", request=request)
        if request.url.path == "/limited":
            return httpx.Response(429, content=b"rate-limited")
        if request.url.path == "/error-disclosed" and request.url.params["id"] != "1":
            return httpx.Response(
                200,
                content=b'sqlite3.OperationalError: near "fixture": syntax error',
            )
        return httpx.Response(200, content=b"fixed-response")

    now = 0.0

    def clock() -> float:
        return now

    def sleep(seconds: float) -> None:
        nonlocal now
        now += seconds

    def virtual_limiter(*, requests_per_second):
        return RateLimiter(
            requests_per_second=requests_per_second, _clock=clock, _sleep=sleep
        )

    def fixed_time_run(**kwargs):
        reason = scenario.time_result
        if reason is None:
            raise ValueError("A time golden requires an explicit fixed result.")
        context = kwargs["context"]
        plan = prepare_time_plan(
            template=kwargs["template"],
            point=kwargs["point"],
            payloads=kwargs["payloads"],
            expected_delay_seconds=kwargs["expected_delay_seconds"],
            context=context,
        )
        groups = {
            "baseline": iter((0.10, 0.11, 0.12)),
            "control": iter((0.11, 0.12, 0.13)),
            "delay": iter(
                (0.10, 0.11, 0.12)
                if reason == "timing_pattern_not_matched"
                else (1.11, 1.12, 1.13)
            ),
        }
        observations = []
        for sequence, kind in enumerate(TIME_PROBE_ORDER, start=1):
            context.budget.consume()
            observations.append(
                TimeObservation(
                    kind=kind,
                    sequence=sequence,
                    outcome=TimeProbeOutcome.COMPLETED,
                    elapsed_seconds=next(groups[kind.value]),
                    status_code=200,
                )
            )
        analysis = analyze_time_probes(plan=plan, observations=tuple(observations))
        if analysis.reason_code != reason:
            raise ValueError("Fixed time golden produced an unexpected result.")
        return TimeRunReport(
            analysis=analysis,
            budget_used=9,
            transport_attempts=9,
            total_elapsed_seconds=0.0,
            deadline_exceeded=False,
        )

    with (
        patch.object(
            executor.httpx,
            "HTTPTransport",
            side_effect=lambda **_: httpx.MockTransport(handle),
        ),
        patch.object(http, "time", SimpleNamespace(perf_counter=clock)),
        patch.object(sqli_cli, "RateLimiter", virtual_limiter),
        patch.object(batch, "RateLimiter", virtual_limiter),
        patch.object(regression_runner, "verify_time_based_sqli", fixed_time_run),
    ):
        result = CliRunner().invoke(
            app,
            cli_args(name, scenario, folder) if args is None else args,
            env=(
                {"VINTAR_TARGET_ORIGIN": ORIGIN, "VINTAR_ALLOWED_ORIGIN": ORIGIN}
                if env is None
                else env
            ),
        )

    if result.exit_code != scenario.exit_code:
        raise ValueError(
            f"Expected exit code {scenario.exit_code}, got {result.exit_code}. "
            f"CLI stderr: {result.stderr.strip()}"
        )
    if request_count != scenario.requests:
        raise ValueError(f"Expected {scenario.requests} requests, got {request_count}.")
    if scenario.exit_code == 2:
        if result.stdout != "":
            raise ValueError("Expected empty stdout for a preflight error.")
        report = None
    else:
        if not result.stdout.endswith("\n") or result.stderr:
            raise ValueError(
                "Expected newline-terminated JSON on stdout and empty stderr."
            )
        report = json.loads(result.stdout)
        if not isinstance(report, dict):
            raise ValueError("Expected one JSON report object on stdout.")

    return (
        json.dumps(
            {
                "exit_code": result.exit_code,
                "stdout_json": report,
                "stderr": result.stderr,
            },
            ensure_ascii=False,
            allow_nan=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="Write the CLI golden files."
    )
    if not parser.parse_args().write:
        parser.print_help()
        return

    with TemporaryDirectory() as temporary:
        captures = {}
        for index, (name, scenario) in enumerate(SCENARIOS.items()):
            folder = Path(temporary) / str(index)
            folder.mkdir()
            captures[name] = capture(name, scenario, folder)

    for name, contents in captures.items():
        path = GOLDEN_DIR / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")


if __name__ == "__main__":
    main()
