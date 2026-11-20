"""Run the reviewed DSVW OpenAPI-to-verify measurement locally."""

import argparse
import hashlib
import json
import os
import select
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import tomllib
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "third_party" / "sqli"
DECLARATIONS = THIRD_PARTY / "targets.toml"
COMPOSE = THIRD_PARTY / "dsvw" / "compose.yaml"
SPEC = THIRD_PARTY / "dsvw" / "openapi.json"
CONFIGS = THIRD_PARTY / "dsvw" / "configs"
DOCS = ROOT / "docs" / "sqli-third-party-evaluation.md"
STATE_NAME = "prepared-target.json"
SUMMARY_START = "<!-- third-party-measurement:start -->"
SUMMARY_END = "<!-- third-party-measurement:end -->"
CLASSIFICATIONS = ("tp", "fn", "fp", "tn", "non_decision")


class MeasurementError(RuntimeError):
    """An actionable third-party measurement failure."""


class _BridgeServer(socketserver.ThreadingTCPServer):
    """Byte-transparent loopback bridge to one private container address."""

    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, upstream: tuple[str, int]) -> None:
        self.upstream = upstream
        self.handler_failed = False
        super().__init__(("127.0.0.1", 0), _BridgeHandler)

    def handle_error(self, request: object, client_address: tuple[str, int]) -> None:
        self.handler_failed = True


class _BridgeHandler(socketserver.BaseRequestHandler):
    """Forward bytes without parsing or modifying the HTTP exchange."""

    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _BridgeServer):
            raise TypeError("Unexpected loopback bridge server.")
        with socket.create_connection(server.upstream, timeout=5) as upstream:
            peers = (self.request, upstream)
            while True:
                readable, _, _ = select.select(peers, (), (), 10)
                if not readable:
                    raise TimeoutError("Loopback bridge exchange timed out.")
                for source in readable:
                    content = source.recv(65536)
                    if not content:
                        return
                    destination = upstream if source is self.request else self.request
                    destination.sendall(content)


@contextmanager
def loopback_bridge(upstream_host: str) -> Iterator[str]:
    """Expose one private container only through an ephemeral loopback socket."""
    try:
        server = _BridgeServer((upstream_host, 65412))
    except OSError as exc:
        raise MeasurementError(
            "The DSVW loopback bridge could not bind. Check IPv4 loopback permissions instead of using a public address."
        ) from exc
    started = threading.Event()

    def serve() -> None:
        started.set()
        server.serve_forever(poll_interval=0.05)

    thread = threading.Thread(target=serve, name="dsvw-loopback-bridge")
    thread.start()
    if not started.wait(timeout=5):
        server.server_close()
        raise MeasurementError(
            "The DSVW loopback bridge did not start. Check thread scheduling and local socket setup."
        )
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive() or server.handler_failed:
            raise MeasurementError(
                "The DSVW loopback bridge failed or did not stop. Check private-network reachability and outstanding requests."
            )


def classify(expected: str, verdict: str, reason: str) -> str:
    """Apply the existing Boolean candidate-signal evaluation contract."""
    if verdict == "inconclusive" and reason == "boolean_candidate":
        return "tp" if expected == "positive" else "fp"
    if verdict == "not_detected":
        return "fn" if expected == "positive" else "tn"
    return "non_decision"


def sha256_fragment(path: Path, start_line: int, end_line: int) -> str:
    """Hash an inclusive UTF-8 source line range with original line endings."""
    lines = path.read_bytes().splitlines(keepends=True)
    if start_line < 1 or end_line < start_line or end_line > len(lines):
        raise MeasurementError(
            "A reviewed source line range is outside the pinned DSVW source. Check targets.toml against the pinned commit."
        )
    return hashlib.sha256(b"".join(lines[start_line - 1 : end_line])).hexdigest()


def load_document(path: Path) -> dict[str, object]:
    """Load one JSON object with a redacted failure."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MeasurementError(
            "Prepared target metadata is unreadable. Rerun prepare_third_party_sqli.py with a fresh workspace."
        ) from exc
    if type(value) is not dict:
        raise MeasurementError(
            "Prepared target metadata is invalid. Rerun prepare_third_party_sqli.py with a fresh workspace."
        )
    return value


def required_text(mapping: dict[str, object], key: str, source: str) -> str:
    """Read one nonempty string without exposing its value in errors."""
    value = mapping.get(key)
    if type(value) is not str or not value:
        raise MeasurementError(
            f"The {source} has an invalid {key}. Supply the reviewed nonempty value instead."
        )
    return value


def required_int(mapping: dict[str, object], key: str) -> int:
    """Read one strict positive declaration integer."""
    value = mapping.get(key)
    if type(value) is not int or value < 1:
        raise MeasurementError(
            f"The target declaration has an invalid {key}. Supply a positive line number in targets.toml."
        )
    return value


def load_declarations() -> tuple[dict[str, object], list[dict[str, object]]]:
    """Validate the bounded declaration shape used by the runner."""
    with DECLARATIONS.open("rb") as stream:
        document = tomllib.load(stream)
    if (
        document.keys() != {"version", "target", "records"}
        or document.get("version") != 1
    ):
        raise MeasurementError(
            "The third-party declaration shape is invalid. Use version 1 with target and records tables."
        )
    target = document["target"]
    records = document["records"]
    if type(target) is not dict or type(records) is not list or len(records) != 2:
        raise MeasurementError(
            "The third-party declaration must contain the reviewed DSVW target and exactly two records."
        )
    typed_records: list[dict[str, object]] = []
    for record in records:
        if type(record) is not dict:
            raise MeasurementError(
                "A third-party record is invalid. Supply a reviewed TOML table instead."
            )
        typed_records.append(record)
    return target, typed_records


def validate_provenance(
    state: dict[str, object],
    target: dict[str, object],
    records: list[dict[str, object]],
) -> tuple[str, str]:
    """Bind local image and reviewed source evidence to the pinned declaration."""
    commit = required_text(target, "commit", "target declaration")
    if state.get("schema_version") != 1 or state.get("commit") != commit:
        raise MeasurementError(
            "Prepared target metadata does not match the reviewed commit. Rerun preparation in a fresh workspace."
        )
    if state.get("archive_sha256") != target.get("archive_sha256"):
        raise MeasurementError(
            "Prepared archive evidence does not match targets.toml. Rerun preparation with the reviewed archive."
        )
    image_tag = required_text(state, "image_tag", "prepared target metadata")
    image_id = required_text(state, "image_id", "prepared target metadata")
    source_root = Path(required_text(state, "source_root", "prepared target metadata"))
    for record in records:
        source = source_root / required_text(record, "source_path", "record")
        try:
            observed = sha256_fragment(
                source,
                required_int(record, "source_start_line"),
                required_int(record, "source_end_line"),
            )
        except OSError as exc:
            raise MeasurementError(
                "Reviewed DSVW source evidence is missing. Rerun preparation with the pinned archive."
            ) from exc
        if observed != record.get("source_fragment_sha256"):
            raise MeasurementError(
                "A DSVW source fragment SHA-256 does not match its reviewed label. Use the pinned archive or review a declaration update."
            )
    observed_image_id = run_command(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image_tag],
        timeout=30,
        diagnostic=(
            "The prepared DSVW image is unavailable. Run prepare_third_party_sqli.py and keep the recorded local image."
        ),
    ).stdout.strip()
    if observed_image_id != image_id:
        raise MeasurementError(
            "The local DSVW image digest differs from preparation metadata. Rebuild from the pinned archive instead of measuring a changed image."
        )
    return image_tag, image_id


def run_command(
    command: list[str],
    *,
    timeout: int,
    diagnostic: str,
    cwd: Path = ROOT,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a local command and hide potentially sensitive subprocess output."""
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MeasurementError(diagnostic) from exc
    if completed.returncode != 0:
        raise MeasurementError(diagnostic)
    return completed


def cli(
    arguments: list[str],
    *,
    cwd: Path,
    expected_codes: set[int] = frozenset({0}),
    environment: dict[str, str] | None = None,
) -> dict[str, object]:
    """Invoke Vintar and parse its bounded JSON output."""
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "vintar.cli", *arguments],
            cwd=cwd,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise MeasurementError(
            f"The {arguments[0]} stage could not run. Check the local Vintar environment and rerun the reviewed pipeline."
        ) from exc
    if completed.returncode not in expected_codes or completed.stderr:
        raise MeasurementError(
            f"The {arguments[0]} stage failed. Check its reviewed inputs and local transport setup instead of changing the expected label."
        )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise MeasurementError(
            f"The {arguments[0]} stage did not return JSON. Check the installed Vintar version and rerun."
        ) from exc
    if type(report) is not dict:
        raise MeasurementError(
            f"The {arguments[0]} stage returned an invalid report. Check the installed Vintar version and rerun."
        )
    return report


def compose_environment(image_tag: str) -> dict[str, str]:
    """Create the minimal Compose substitution environment."""
    environment = os.environ.copy()
    environment["DSVW_IMAGE"] = image_tag
    return environment


def compose(
    image_tag: str,
    project: str,
    arguments: list[str],
    *,
    timeout: int,
    diagnostic: str,
) -> subprocess.CompletedProcess[str]:
    """Run the reviewed Compose file without pulling images."""
    return run_command(
        [
            "docker",
            "compose",
            "--file",
            str(COMPOSE),
            "--project-name",
            project,
            *arguments,
        ],
        timeout=timeout,
        diagnostic=diagnostic,
        environment=compose_environment(image_tag),
    )


def start_target(image_tag: str, project: str) -> str:
    """Start a fresh target and return its private internal-network address."""
    compose(
        image_tag,
        project,
        ["up", "--detach", "--wait", "--wait-timeout", "30", "--pull", "never"],
        timeout=60,
        diagnostic=(
            "The pinned DSVW container did not become healthy. Check Docker, loopback publishing, and the prepared image instead of retrying the measurement."
        ),
    )
    container = f"{project}-dsvw-1"
    address = run_command(
        [
            "docker",
            "inspect",
            "--format",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container,
        ],
        timeout=30,
        diagnostic=(
            "The DSVW private address could not be resolved. Check the internal Compose network and prepared container."
        ),
    ).stdout.strip()
    try:
        packed = socket.inet_aton(address)
    except OSError as exc:
        raise MeasurementError(
            "Docker returned an invalid DSVW private address. Check the internal network instead of using an external target."
        ) from exc
    if len(packed) != 4 or address.startswith("127."):
        raise MeasurementError(
            "Docker did not assign DSVW a private container address. Check the internal network instead of weakening target isolation."
        )
    return address


def stop_target(image_tag: str, project: str) -> None:
    """Remove the target and its private network with a bounded shutdown."""
    compose(
        image_tag,
        project,
        ["down", "--volumes", "--remove-orphans", "--timeout", "10"],
        timeout=30,
        diagnostic=(
            "The DSVW container did not shut down cleanly. Check Docker state and remove the named measurement project before rerunning."
        ),
    )


def write_text(path: Path, content: str) -> None:
    """Write one private temporary pipeline input."""
    path.write_text(content, encoding="utf-8")


def pipeline_environment(origin: str) -> dict[str, str]:
    """Bind verification to the ephemeral loopback origin without proxy leakage."""
    environment = os.environ.copy()
    for key in tuple(environment):
        if key.lower() in {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
        }:
            del environment[key]
    environment["VINTAR_TARGET_ORIGIN"] = origin
    environment["VINTAR_ALLOWED_ORIGIN"] = origin
    return environment


def run_pipeline_case(
    folder: Path,
    origin: str,
    record: dict[str, object],
    mode: str,
) -> dict[str, object]:
    """Run all four CLI stages for one reviewed record and probe mode."""
    record_id = required_text(record, "id", "record")
    input_id = required_text(record, "input_id", "record")
    parameter = required_text(record, "parameter", "record")
    label = required_text(record, "label", "record")
    expected_verdict = "inconclusive" if label == "positive" else "not_detected"
    local_spec = folder / "openapi.json"
    local_spec.write_bytes(SPEC.read_bytes())

    inventory = folder / "inventory.json"
    discovery = cli(
        ["discover", "--spec", str(local_spec), "--output", str(inventory)],
        cwd=folder,
    )
    if discovery.get("operations") != 1:
        raise MeasurementError(
            "DSVW discovery did not find exactly one operation. Check the reviewed OpenAPI document instead of changing the record."
        )
    inventory_document = load_document(inventory)
    operations = inventory_document.get("operations")
    discovered_ids = (
        {
            item.get("id")
            for operation in operations
            if type(operation) is dict
            for item in operation.get("inputs", [])
            if type(item) is dict and item.get("name") == parameter
        }
        if type(operations) is list
        else set()
    )
    if discovered_ids != {input_id}:
        raise MeasurementError(
            "DSVW discovery input IDs drifted from reviewed declarations. Review the OpenAPI change and regenerate configs instead of measuring it silently."
        )

    selection = folder / "selection.toml"
    write_text(selection, f'version = 1\napproved = ["{input_id}"]\n')
    draft_summary = cli(
        [
            "discover",
            "--spec",
            str(local_spec),
            "--selection",
            str(selection),
            "--drafts-dir",
            str(folder / "drafts"),
        ],
        cwd=folder,
    )
    drafts = draft_summary.get("drafts")
    if type(drafts) is not list or len(drafts) != 1 or type(drafts[0]) is not str:
        raise MeasurementError(
            "DSVW discovery did not emit exactly one draft. Check the reviewed selection and OpenAPI input."
        )
    draft = folder / "drafts" / drafts[0]

    selected_index = 0 if parameter == "id" else 1
    other_parameter = "v" if parameter == "id" else "id"
    answers = folder / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "version": 1,
                "expected_verdict": expected_verdict,
                "parameters": {
                    parameter: {
                        "pointer": f"/paths/~1/get/parameters/{selected_index}/schema/example"
                    },
                    other_parameter: {"omit": True},
                },
            }
        ),
        encoding="utf-8",
    )
    review = folder / "review.json"
    cli(
        [
            "review-draft",
            "--spec",
            str(local_spec),
            "--draft",
            str(draft),
            "--answers",
            str(answers),
            "--output",
            str(review),
        ],
        cwd=folder,
    )

    config_template = CONFIGS / f"{record_id}-{mode}.toml"
    config = folder / "config.toml"
    write_text(
        config,
        config_template.read_text(encoding="utf-8").replace("__ORIGIN__", origin),
    )
    case = folder / "case.toml"
    materialized = cli(
        [
            "materialize-case",
            "--spec",
            str(local_spec),
            "--draft",
            str(draft),
            "--answers",
            str(answers),
            "--review",
            str(review),
            "--config",
            str(config),
            "--output",
            str(case),
        ],
        cwd=folder,
    )
    max_requests = 6 if mode == "six" else 18
    expected_confirmation = "not configured" if mode == "six" else "configured"
    if (
        materialized.get("max_requests") != max_requests
        or materialized.get("confirmation") != expected_confirmation
    ):
        raise MeasurementError(
            "Materialization did not preserve the reviewed probe mode. Check the config and case limits instead of running a different request plan."
        )

    verified = cli(
        [
            "verify",
            "--cases",
            str(case),
            "--max-requests",
            str(max_requests),
            "--rps",
            "10",
            "--timeout",
            "5",
            "--authorized",
        ],
        cwd=folder,
        expected_codes={0, 1, 3},
        environment=pipeline_environment(origin),
    )
    outcomes = verified.get("outcomes")
    if (
        type(outcomes) is not list
        or len(outcomes) != 1
        or type(outcomes[0]) is not dict
    ):
        raise MeasurementError(
            "Verification did not emit exactly one DSVW outcome. Check the generated case and request budget."
        )
    outcome = outcomes[0]
    verdict = required_text(outcome, "actual_verdict", "verification outcome")
    reason = required_text(outcome, "actual_reason_code", "verification outcome")
    request_count = outcome.get("request_count")
    confirmation = outcome.get("confirmation")
    if type(request_count) is not int or type(confirmation) is not dict:
        raise MeasurementError(
            "Verification omitted request or confirmation evidence. Check the installed Vintar report contract."
        )
    return {
        "actual_verdict": verdict,
        "classification": classify(label, verdict, reason),
        "confirmation": confirmation,
        "endpoint_id": record_id,
        "expected_label": label,
        "expected_verdict": expected_verdict,
        "mode": "six_probe" if mode == "six" else "confirmation",
        "reason_code": reason,
        "request_count": request_count,
    }


def counts(records: list[dict[str, object]]) -> dict[str, dict[str, int]]:
    """Count classifications separately for the six- and eighteen-request cases."""
    result: dict[str, dict[str, int]] = {}
    for mode in ("six_probe", "confirmation"):
        phase = Counter(
            record["classification"] for record in records if record["mode"] == mode
        )
        result[mode] = {key: phase[key] for key in CLASSIFICATIONS}
    return result


def render_summary(report: dict[str, object]) -> str:
    """Render the exact reviewed Markdown block checked after every run."""
    records = report["records"]
    if type(records) is not list:
        raise MeasurementError(
            "The measurement report has no records. Check the runner before updating documentation."
        )
    lines = [
        SUMMARY_START,
        "| Record | Mode | Expected label | Actual verdict | Reason | Confirmation | Requests | Classification |",
        "| --- | --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for record in records:
        if type(record) is not dict or type(record.get("confirmation")) is not dict:
            raise MeasurementError(
                "The measurement report contains an invalid record. Check the runner before updating documentation."
            )
        confirmation = record["confirmation"]
        lines.append(
            "| {endpoint_id} | {mode} | {expected_label} | {actual_verdict} | {reason_code} | {status} | {request_count} | {classification} |".format(
                **record,
                status=confirmation.get("status"),
            )
        )
    report_counts = report["counts"]
    if type(report_counts) is not dict:
        raise MeasurementError(
            "The measurement report contains invalid counts. Check the runner before updating documentation."
        )
    lines.extend(
        (
            "",
            "| Mode | TP | TN | FP | FN | Non-decision |",
            "| --- | ---: | ---: | ---: | ---: | ---: |",
        )
    )
    for mode in ("six_probe", "confirmation"):
        values = report_counts.get(mode)
        if type(values) is not dict:
            raise MeasurementError(
                "The measurement report is missing phase counts. Check the runner before updating documentation."
            )
        lines.append(
            f"| {mode} | {values.get('tp')} | {values.get('tn')} | {values.get('fp')} | {values.get('fn')} | {values.get('non_decision')} |"
        )
    lines.append(SUMMARY_END)
    return "\n".join(lines)


def check_documented_summary(
    report: dict[str, object], documentation: Path = DOCS
) -> None:
    """Reject actual results that differ from the committed reviewed summary."""
    expected = render_summary(report)
    try:
        text = documentation.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise MeasurementError(
            "The third-party evaluation document is unreadable. Restore the reviewed summary and rerun."
        ) from exc
    if expected not in text:
        raise MeasurementError(
            "Actual DSVW results differ from docs/sqli-third-party-evaluation.md. Review the saved report and update the documented summary instead of accepting drift silently."
        )


def write_report(path: Path, report: dict[str, object]) -> None:
    """Atomically save an actual report outside the repository."""
    resolved = path.resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise MeasurementError(
            "Measurement JSON must stay outside the repository. Supply an --output path under a separate temporary or artifact directory."
        )
    resolved.parent.mkdir(parents=True, exist_ok=True)
    content = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=resolved.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(resolved)


def measure(workspace: Path, output: Path) -> dict[str, object]:
    """Measure all reviewed records in both modes and save every observation."""
    target, declarations = load_declarations()
    state = load_document(workspace / STATE_NAME)
    image_tag, image_id = validate_provenance(state, target, declarations)
    records: list[dict[str, object]] = []
    run_root = Path(tempfile.mkdtemp(prefix="vintar-dsvw-run-", dir=workspace))
    for index, declaration in enumerate(declarations):
        for mode in ("six", "confirmation"):
            project = f"vintar-dsvw-{index}-{mode}"
            case_folder = run_root / project
            case_folder.mkdir()
            attempted_start = False
            try:
                attempted_start = True
                upstream = start_target(image_tag, project)
                with loopback_bridge(upstream) as origin:
                    records.append(
                        run_pipeline_case(case_folder, origin, declaration, mode)
                    )
            finally:
                if attempted_start:
                    stop_target(image_tag, project)
    records.sort(key=lambda row: (str(row["endpoint_id"]), str(row["mode"])))
    report: dict[str, object] = {
        "counts": counts(records),
        "records": records,
        "schema_version": 1,
        "target": {
            "archive_sha256": target["archive_sha256"],
            "commit": target["commit"],
            "image_id": image_id,
            "license": target["license"],
            "name": target["name"],
        },
    }
    write_report(output, report)
    check_documented_summary(report)
    return report


def main() -> int:
    """Run the manual local-only measurement."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        report = measure(arguments.workspace.resolve(), arguments.output)
    except MeasurementError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    unhealthy = sum(
        values[key]
        for values in report["counts"].values()
        for key in ("fn", "fp", "non_decision")
    )
    print(f"Saved the DSVW measurement report to {arguments.output.resolve()}")
    if unhealthy:
        print(
            "Error: The DSVW measurement contains a false negative, false positive, or non-decision. Review the saved report and the documented limitation instead of treating it as a passing precision result.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
