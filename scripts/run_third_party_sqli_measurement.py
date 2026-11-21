"""Run the reviewed DSVW OpenAPI-to-verify measurement locally."""

import argparse
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
import uuid
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import NamedTuple

from vintar.checks.sqli.error_contract import ERROR_RESULT_RULES
from vintar.checks.sqli.error_signatures import ERROR_SIGNATURES

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
CLASSIFICATIONS = {
    "sqli.boolean": ("tp", "fn", "fp", "tn", "non_decision"),
    "sqli.time": ("tp", "fn", "fp", "tn", "non_decision"),
    "sqli.error": ("candidate", "fn", "fp", "tn", "non_decision"),
}
MEASUREMENT_SCHEMA_VERSION = 3
PROBE_MODES = {
    "sqli.boolean": {"six": "six_probe", "confirmation": "confirmation"},
    "sqli.time": {"time": "nine_probe"},
    "sqli.error": {"error": "error_probe"},
}


class PlannedMeasurement(NamedTuple):
    index: int
    declaration: dict[str, object]
    mode: str
    key: tuple[str, str, str]
    config: Path


class MeasurementError(RuntimeError):
    """An actionable third-party measurement failure."""


def _validate_error_detail(record: dict[str, object]) -> None:
    """Validate one Error detail object from the shared product contracts."""
    endpoint_id = required_text(record, "endpoint_id", "report record")
    detail = record.get("detail")
    if type(detail) is not dict:
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} has no Error detail object. Remeasure the target; do not hand-edit reports."
        )
    reason = record.get("reason_code")
    rule = ERROR_RESULT_RULES.get(reason) if type(reason) is str else None
    if rule is None:
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} has an unsupported top-level reason. Use an ERROR_RESULT_RULES result by remeasuring; do not hand-edit reports."
        )
    required_fields = {"status", "reason_code", "request_count"}
    if rule.requires_evidence:
        required_fields.update(("dbms", "signature_id"))
    if detail.keys() != required_fields:
        missing = sorted(required_fields - detail.keys())
        unexpected = sorted(detail.keys() - required_fields)
        difference = f"missing {missing!r}" if missing else f"unexpected {unexpected!r}"
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} detail fields contradict ERROR_RESULT_RULES: {difference}. Remeasure the target to regenerate the complete Error result; do not hand-edit reports."
        )
    status = detail["status"]
    request_count = detail["request_count"]
    if status != rule.analysis_status.value:
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} detail status {status!r} contradicts reason {reason!r}. Remeasure the target using ERROR_RESULT_RULES; do not hand-edit reports."
        )
    if (
        type(request_count) is not int
        or not rule.minimum_requests <= request_count <= rule.maximum_requests
    ):
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} detail request_count contradicts reason {reason!r}. Remeasure the target using the bounded ERROR_RESULT_RULES request range; do not hand-edit reports."
        )
    if rule.requires_evidence:
        signature_id = detail["signature_id"]
        dbms = detail["dbms"]
        signature = (
            ERROR_SIGNATURES.get(signature_id) if type(signature_id) is str else None
        )
        if signature is None or signature.dbms != dbms:
            raise MeasurementError(
                f"Error measurement record {endpoint_id!r} has an unreviewed DBMS/signature pair. Remeasure the target and use evidence from ERROR_SIGNATURES; do not hand-edit reports."
            )
    if (
        detail.get("reason_code") != reason
        or record.get("request_count") != request_count
        or record.get("actual_verdict") != rule.product_verdict.value
    ):
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} detail contradicts its top-level verdict, reason, or request count. Remeasure the target to regenerate matching fields; do not hand-edit reports."
        )


def validate_measurement_report(report: object) -> dict[str, object]:
    """Accept only the current manual measurement report contract."""
    if type(report) is not dict:
        raise MeasurementError(
            "The third-party measurement report is not a JSON object. This reader supports schema version 3; rerun the measurement to regenerate the report."
        )
    version = report.get("schema_version")
    if type(version) is not int or version != MEASUREMENT_SCHEMA_VERSION:
        found = repr(version) if version is not None else "missing"
        raise MeasurementError(
            f"Unsupported third-party measurement report schema version: found {found}; this reader supports version 3. Rerun the measurement to regenerate the report."
        )
    if report.keys() != {"counts", "records", "schema_version", "target"}:
        raise MeasurementError(
            "Invalid third-party measurement report v3 top-level keys. Use counts grouped by check type, records with detail objects, schema_version, and target; rerun the measurement to regenerate the report."
        )
    records = report["records"]
    counts_value = report["counts"]
    target = report["target"]
    if type(records) is not list or type(target) is not dict:
        raise MeasurementError(
            "Invalid third-party measurement report v3 structure. Use grouped counts, record objects, and target metadata; rerun the measurement to regenerate the report."
        )
    _, declarations = load_declarations()
    planned_measurements = list(plan_measurements(declarations))
    expected_keys = {planned.key for planned in planned_measurements}
    declarations_by_key = {
        planned.key: planned.declaration for planned in planned_measurements
    }
    record_keys: Counter[tuple[str, str, str]] = Counter()
    recomputed_records: list[dict[str, object]] = []
    for record in records:
        if type(record) is not dict:
            raise MeasurementError(
                "The third-party measurement report contains a non-object record. Rerun the measurement to regenerate the report."
            )
        key = (
            required_text(record, "endpoint_id", "report record"),
            required_text(record, "check_type", "report record"),
            required_text(record, "mode", "report record"),
        )
        record_keys[key] += 1

    for key, occurrences in record_keys.items():
        endpoint_id, check_type, mode = key
        description = (
            f"endpoint_id {endpoint_id!r}, check_type {check_type!r}, mode {mode!r}"
        )
        if occurrences > 1:
            raise MeasurementError(
                f"Duplicate measurement record for {description} appears {occurrences} times. Regenerate the report with a full measurement run."
            )
        if key not in expected_keys:
            raise MeasurementError(
                f"Unexpected measurement record for {description} is not in targets.toml. Regenerate the report with a full measurement run."
            )
    if missing := expected_keys.difference(record_keys):
        endpoint_id, check_type, mode = min(missing)
        raise MeasurementError(
            f"The measurement report is incomplete: missing endpoint_id {endpoint_id!r}, check_type {check_type!r}, mode {mode!r}. Regenerate the report with a full measurement run."
        )

    expected_modes = {
        check_type: tuple(modes.values()) for check_type, modes in PROBE_MODES.items()
    }
    if type(counts_value) is not dict:
        raise MeasurementError(
            "Invalid third-party measurement report v3 counts. Use counts grouped by check type and mode; rerun the measurement to regenerate the report."
        )
    if counts_value.keys() != expected_modes.keys():
        changed = min(counts_value.keys() ^ expected_modes.keys(), key=str)
        raise MeasurementError(
            f"Measurement counts disagree with records for check type {changed}, mode all, field count_group. Include exactly sqli.boolean, sqli.time, and sqli.error counts and rerun the measurement to regenerate the report."
        )
    for check_type, modes in expected_modes.items():
        type_counts = counts_value[check_type]
        if type(type_counts) is not dict:
            raise MeasurementError(
                f"Measurement counts disagree with records for check type {check_type}, mode all, field mode_group. Supply a mode-count object and rerun the measurement to regenerate the report."
            )
        if set(type_counts) != set(modes):
            changed = min(set(type_counts) ^ set(modes), key=str)
            raise MeasurementError(
                f"Measurement counts disagree with records for check type {check_type}, mode {changed}, field mode_group. Use exactly the supported mode keys and rerun the measurement to regenerate the report."
            )
        for mode, values in type_counts.items():
            if type(values) is not dict:
                raise MeasurementError(
                    f"Measurement counts disagree with records for check type {check_type}, mode {mode}, field classification_group. Supply classification counts and rerun the measurement to regenerate the report."
                )
            classifications = set(CLASSIFICATIONS[check_type])
            if values.keys() != classifications:
                changed = min(values.keys() ^ classifications, key=str)
                raise MeasurementError(
                    f"Measurement counts disagree with records for check type {check_type}, mode {mode}, field {changed}. Use exactly the classifications defined for that check type and rerun the measurement to regenerate the report."
                )
            if any(type(value) is not int or value < 0 for value in values.values()):
                raise MeasurementError(
                    f"Measurement counts disagree with records for check type {check_type}, mode {mode}, field value. Supply nonnegative integer counts and rerun the measurement to regenerate the report."
                )
    for record in records:
        if type(record.get("detail")) is not dict or "confirmation" in record:
            raise MeasurementError(
                "Invalid third-party measurement report v3 record. Use check_type and the sibling detail object instead of the v1 confirmation field; rerun the measurement to regenerate the report."
            )
        check_type = record.get("check_type")
        if (
            check_type not in CLASSIFICATIONS
            or record.get("classification") not in CLASSIFICATIONS[check_type]
        ):
            raise MeasurementError(
                f"Measurement record for check type {record['check_type']}, mode {record['mode']} has an invalid classification. Use the classifications defined for that check type and rerun the measurement to regenerate the report."
            )
        key = (
            required_text(record, "endpoint_id", "report record"),
            required_text(record, "check_type", "report record"),
            required_text(record, "mode", "report record"),
        )
        declaration = declarations_by_key[key]
        ground_truth = required_text(declaration, "label", "record")
        expected_verdict = expected_verdict_for_label(ground_truth)
        if record.get("expected_label") != ground_truth:
            raise MeasurementError(
                f"Measurement record {key[0]!r} expected_label contradicts reviewed ground truth {ground_truth!r}. Remeasure from targets.toml; do not hand-edit reports."
            )
        if record.get("expected_verdict") != expected_verdict:
            raise MeasurementError(
                f"Measurement record {key[0]!r} stored expected_verdict {record.get('expected_verdict')!r} contradicts ground-truth label {ground_truth!r}; expected {expected_verdict!r}. Remeasure the target; do not hand-edit reports."
            )
        verdict = required_text(record, "actual_verdict", "report record")
        reason = required_text(record, "reason_code", "report record")
        recomputed_classification = classify(
            required_text(record, "check_type", "report record"),
            ground_truth,
            verdict,
            reason,
        )
        stored_classification = record.get("classification")
        if stored_classification != recomputed_classification:
            raise MeasurementError(
                f"Measurement record {key[0]!r} stored classification {stored_classification!r} contradicts ground truth {ground_truth!r} with {verdict}/{reason}; expected {recomputed_classification!r}. Remeasure the target; do not hand-edit reports."
            )
        if check_type == "sqli.error":
            _validate_error_detail(record)
        recomputed_records.append(
            {**record, "classification": recomputed_classification}
        )
    recomputed = counts(recomputed_records)
    for check_type, modes in expected_modes.items():
        for mode in modes:
            for field in CLASSIFICATIONS[check_type]:
                if (
                    counts_value[check_type][mode][field]
                    != recomputed[check_type][mode][field]
                ):
                    raise MeasurementError(
                        f"Measurement counts disagree with records for check type {check_type}, mode {mode}, field {field}. Rerun the measurement to regenerate the report."
                    )
    return report


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


def classify(check_type: str, expected: str, verdict: str, reason: str) -> str:
    """Apply the product decision contract for one reviewed check type."""
    positive_reason = {
        "sqli.boolean": "boolean_candidate",
        "sqli.time": "timing_pattern_matched",
        "sqli.error": "dbms_error_disclosed",
    }.get(check_type)
    if positive_reason is None:
        raise MeasurementError(
            "The record has an unsupported check type. Use sqli.boolean, sqli.time, or sqli.error."
        )
    if verdict == "inconclusive" and reason == positive_reason:
        if check_type == "sqli.error" and expected == "positive":
            return "candidate"
        return "tp" if expected == "positive" else "fp"
    if verdict == "not_detected":
        return "fn" if expected == "positive" else "tn"
    return "non_decision"


def expected_verdict_for_label(label: str) -> str:
    """Map one reviewed ground-truth label to its pipeline expectation."""
    if label == "positive":
        return "inconclusive"
    if label == "negative":
        return "not_detected"
    raise MeasurementError(
        "The record has an unsupported ground-truth label. Use positive or negative in targets.toml and remeasure instead of hand-editing reports."
    )


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
    if type(target) is not dict or type(records) is not list or len(records) != 6:
        raise MeasurementError(
            "The third-party declaration must contain the reviewed DSVW target and exactly six Boolean/Time/Error records."
        )
    typed_records: list[dict[str, object]] = []
    for record in records:
        if type(record) is not dict:
            raise MeasurementError(
                "A third-party record is invalid. Supply a reviewed TOML table instead."
            )
        typed_records.append(record)
    check_types = [
        required_text(record, "check_type", "record") for record in typed_records
    ]
    if any(check_types.count(check_type) != 2 for check_type in PROBE_MODES):
        raise MeasurementError(
            "The third-party declaration must contain exactly two records for each of sqli.boolean, sqli.time, and sqli.error. Review targets.toml instead of changing labels after measurement."
        )
    return target, typed_records


def plan_measurements(
    declarations: list[dict[str, object]],
) -> Iterator[PlannedMeasurement]:
    """Plan one report record per reviewed endpoint and probe config."""
    keys: set[tuple[str, str, str]] = set()
    for index, declaration in enumerate(declarations):
        endpoint_id = required_text(declaration, "id", "record")
        check_type = required_text(declaration, "check_type", "record")
        for mode, report_mode in PROBE_MODES[check_type].items():
            key = (endpoint_id, check_type, report_mode)
            if key in keys:
                raise MeasurementError(
                    f"Duplicate measurement declaration {key!r}. Keep one declaration per endpoint_id, check_type, and mode in targets.toml."
                )
            keys.add(key)
            config = CONFIGS / f"{endpoint_id}-{mode}.toml"
            if not config.is_file():
                raise MeasurementError(
                    f"Missing reviewed configuration {config.name!r} for check type {check_type}. Restore the corresponding TOML config before running or validating measurements."
                )
            yield PlannedMeasurement(index, declaration, mode, key, config)


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
    required_text(state, "source_manifest_sha256", "prepared target metadata")
    source_evidence = state.get("source_evidence")
    if type(source_evidence) is not dict:
        raise MeasurementError(
            "Prepared source evidence is missing. Rerun preparation so the verified archive supplies the build manifest and source fragments."
        )
    for record in records:
        record_id = required_text(record, "id", "record")
        prepared = source_evidence.get(record_id)
        if type(prepared) is not dict:
            raise MeasurementError(
                f"Prepared source evidence for {record_id} differs at field record. The prepared evidence no longer matches the declaration. Rerun prepare; if the referenced lines changed, review and update source_fragment_sha256."
            )
        for field in (
            "source_path",
            "source_start_line",
            "source_end_line",
            "source_fragment_sha256",
        ):
            if prepared.get(field) != record.get(field) or type(
                prepared.get(field)
            ) is not type(record.get(field)):
                raise MeasurementError(
                    f"Prepared source evidence for {record_id} differs at field {field}. The prepared evidence no longer matches the declaration. Rerun prepare; if the referenced lines changed, review and update source_fragment_sha256."
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


def new_run_id() -> str:
    """Return a short lowercase identifier unique to one measurement invocation."""
    return uuid.uuid4().hex[:12]


def compose_project_name(run_id: str, case_index: int, mode: str) -> str:
    """Build one bounded Compose namespace for a case in a specific run."""
    if (
        len(run_id) != 12
        or any(character not in "0123456789abcdef" for character in run_id)
        or type(case_index) is not int
        or case_index < 0
        or mode not in {"six", "confirmation", "time", "error"}
    ):
        raise MeasurementError(
            "The measurement project identity is invalid. Use the generated run ID, nonnegative case index, and supported probe mode instead."
        )
    return f"vintar-dsvw-{run_id}-{case_index}-{mode}"


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
    planned: PlannedMeasurement,
) -> dict[str, object]:
    """Run all four CLI stages for one reviewed record and probe mode."""
    record = planned.declaration
    mode = planned.mode
    record_id, check_type, report_mode = planned.key
    input_id = required_text(record, "input_id", "record")
    parameter = required_text(record, "parameter", "record")
    label = required_text(record, "label", "record")
    expected_verdict = expected_verdict_for_label(label)
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

    config = folder / "config.toml"
    write_text(
        config,
        planned.config.read_text(encoding="utf-8").replace("__ORIGIN__", origin),
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
    max_requests = {"six": 6, "confirmation": 18, "time": 9, "error": 4}[mode]
    expected_confirmation = "configured" if mode == "confirmation" else "not configured"
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
            "--time-deadline",
            "60",
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
    detail_key = {
        "sqli.boolean": "confirmation",
        "sqli.time": "timing",
        "sqli.error": "error",
    }[check_type]
    detail = outcome.get(detail_key)
    if type(request_count) is not int or type(detail) is not dict:
        raise MeasurementError(
            "Verification omitted request or check evidence. Check the installed Vintar report contract."
        )
    return {
        "actual_verdict": verdict,
        "check_type": check_type,
        "classification": classify(check_type, label, verdict, reason),
        "detail": detail,
        "endpoint_id": record_id,
        "expected_label": label,
        "expected_verdict": expected_verdict,
        "mode": report_mode,
        "reason_code": reason,
        "request_count": request_count,
    }


def counts(
    records: list[dict[str, object]],
) -> dict[str, dict[str, dict[str, int]]]:
    """Count classifications separately by check type and request mode."""
    result: dict[str, dict[str, dict[str, int]]] = {}
    for check_type, check_modes in PROBE_MODES.items():
        result[check_type] = {}
        for mode in check_modes.values():
            phase = Counter(
                record["classification"]
                for record in records
                if record["check_type"] == check_type and record["mode"] == mode
            )
            result[check_type][mode] = {
                key: phase[key] for key in CLASSIFICATIONS[check_type]
            }
    return result


def render_summary(report: dict[str, object]) -> str:
    """Render the exact reviewed Markdown block checked after every run."""
    validate_measurement_report(report)
    records = report["records"]
    if type(records) is not list:
        raise MeasurementError(
            "The measurement report has no records. Check the runner before updating documentation."
        )
    lines = [
        SUMMARY_START,
        "| Check type | Record | Mode | Expected label | Actual verdict | Reason | Detail status | Requests | Classification |",
        "| --- | --- | --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for record in records:
        if type(record) is not dict or type(record.get("detail")) is not dict:
            raise MeasurementError(
                "The measurement report contains an invalid record. Check the runner before updating documentation."
            )
        detail = record["detail"]
        lines.append(
            "| {check_type} | {endpoint_id} | {mode} | {expected_label} | {actual_verdict} | {reason_code} | {status} | {request_count} | {classification} |".format(
                **record,
                status=detail.get("status"),
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
            "| Check type | Mode | Candidate | TP | TN | FP | FN | Non-decision |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        )
    )
    for check_type, modes in (
        ("sqli.boolean", ("six_probe", "confirmation")),
        ("sqli.time", ("nine_probe",)),
        ("sqli.error", ("error_probe",)),
    ):
        type_counts = report_counts.get(check_type)
        if type(type_counts) is not dict:
            raise MeasurementError(
                "The measurement report is missing check-type counts. Check the runner before updating documentation."
            )
        for mode in modes:
            values = type_counts.get(mode)
            if type(values) is not dict:
                raise MeasurementError(
                    "The measurement report is missing phase counts. Check the runner before updating documentation."
                )
            lines.append(
                f"| {check_type} | {mode} | {values.get('candidate', '-')} | {values.get('tp', '-')} | {values.get('tn')} | {values.get('fp')} | {values.get('fn')} | {values.get('non_decision')} |"
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
    validate_measurement_report(report)
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
    plan = list(plan_measurements(declarations))
    state = load_document(workspace / STATE_NAME)
    image_tag, image_id = validate_provenance(state, target, declarations)
    records: list[dict[str, object]] = []
    run_id = new_run_id()
    run_root = Path(tempfile.mkdtemp(prefix="vintar-dsvw-run-", dir=workspace))
    for planned in plan:
        project = compose_project_name(run_id, planned.index, planned.mode)
        case_folder = run_root / project
        case_folder.mkdir()
        try:
            upstream = start_target(image_tag, project)
            with loopback_bridge(upstream) as origin:
                records.append(run_pipeline_case(case_folder, origin, planned))
        finally:
            stop_target(image_tag, project)
    records.sort(key=lambda row: (str(row["endpoint_id"]), str(row["mode"])))
    report: dict[str, object] = {
        "counts": counts(records),
        "records": records,
        "schema_version": MEASUREMENT_SCHEMA_VERSION,
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


def unhealthy_count(report: dict[str, object]) -> int:
    """Count every false decision or abstention across isolated check types."""
    validate_measurement_report(report)
    records = report["records"]
    if type(records) is not list:
        raise MeasurementError(
            "The validated measurement report lost its records. Rerun the measurement to regenerate the report."
        )
    return sum(
        1
        for record in records
        if type(record) is dict
        and record.get("classification") in {"fn", "fp", "non_decision"}
    )


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
    unhealthy = unhealthy_count(report)
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
