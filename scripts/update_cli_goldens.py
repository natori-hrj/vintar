"""Capture deterministic CLI results and regenerate their golden files."""

import argparse
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
from vintar.cli import app
from vintar.core import executor, http
from vintar.core.rate_limit import RateLimiter
from vintar.regression import batch

ROOT = Path(__file__).resolve().parents[1]
GOLDEN_DIR = ROOT / "tests" / "golden" / "cli"
UPDATE_COMMAND = "uv run python scripts/update_cli_goldens.py --write"
ORIGIN = "http://cli-fixture.invalid"
CASE_TEMPLATE = runpy.run_path(str(ROOT / "scripts" / "run_ci_e2e.py"))["CASE_TEMPLATE"]


@dataclass(frozen=True)
class Scenario:
    exit_code: int
    requests: int
    expected_verdict: str = "not_detected"
    rate_limited: bool = False
    timeout_on_second_request: bool = False


SCENARIOS = {
    "sqli-verify/normal.json": Scenario(0, 6),
    "sqli-verify/probe-failure.json": Scenario(0, 2, timeout_on_second_request=True),
    "sqli-verify/authorization-required.json": Scenario(2, 0),
    "verify/pass.json": Scenario(0, 6),
    "verify/fail.json": Scenario(1, 6, expected_verdict="vulnerable"),
    "verify/partial-inconclusive.json": Scenario(3, 1, rate_limited=True),
    "verify/authorization-required.json": Scenario(2, 0),
    "discover/success.json": Scenario(0, 0),
    "discover/stale-selection.json": Scenario(2, 0),
    "discover/invalid-selection.json": Scenario(2, 0),
    "discover/invalid-spec.json": Scenario(2, 0),
    "discover/output-spec-conflict.json": Scenario(2, 0),
    "discover/output-selection-conflict.json": Scenario(2, 0),
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
        cases = (
            (("a-case", "/limited"), ("b-case", "/ok"))
            if scenario.rate_limited
            else (("a-case", "/ok"),)
        )
        for case_id, path in cases:
            source = CASE_TEMPLATE.format(expected=scenario.expected_verdict, path=path)
            source = source.replace('id = "fixture-case"', f'id = "{case_id}"')
            (folder / f"{case_id}.toml").write_text(source, encoding="utf-8")
        args = ["verify", "--cases", str(folder), "--max-requests", str(6 * len(cases))]
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
        result = CliRunner().invoke(
            app,
            [
                "discover",
                "--spec",
                spec.name,
                "--selection",
                selection.name,
                "--output",
                output,
            ]
            if args is None
            else args,
            env=env,
        )
    if (spec.read_bytes(), selection.read_bytes()) != before:
        raise ValueError("Discovery modified an input file.")
    if result.exit_code != scenario.exit_code:
        raise ValueError(
            f"Expected exit code {scenario.exit_code}, got {result.exit_code}. "
            f"CLI stderr: {result.stderr.strip()}"
        )
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


def capture(
    name: str,
    scenario: Scenario,
    folder: Path,
    *,
    args: list[str] | None = None,
    env: dict[str, str] | None = None,
) -> str:
    if name.startswith("discover/"):
        return (
            json.dumps(
                capture_discovery(name, scenario, folder, args, env),
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

    with (
        patch.object(
            executor.httpx,
            "HTTPTransport",
            side_effect=lambda **_: httpx.MockTransport(handle),
        ),
        patch.object(http, "time", SimpleNamespace(perf_counter=clock)),
        patch.object(sqli_cli, "RateLimiter", virtual_limiter),
        patch.object(batch, "RateLimiter", virtual_limiter),
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
