"""Run reviewed third-party SQLi OpenAPI-to-verify measurements locally."""

import argparse
import hashlib
import json
import os
import re
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

from third_party_sqli_contract import (
    ServiceImageMismatch,
    is_image_digest,
    is_sha256,
    pinned_image_digest,
    validate_service_image_mapping,
)

from vintar.checks.sqli.error_contract import ERROR_RESULT_RULES
from vintar.checks.sqli.error_signatures import ERROR_SIGNATURES

ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "third_party" / "sqli"
DECLARATIONS = THIRD_PARTY / "targets.toml"
DOCS = ROOT / "docs" / "sqli-third-party-evaluation.md"
STATE_NAME = "prepared-targets.json"
SUMMARY_START = "<!-- third-party-measurement:start -->"
SUMMARY_END = "<!-- third-party-measurement:end -->"
CLASSIFICATIONS = {
    "sqli.boolean": ("tp", "fn", "fp", "tn", "non_decision"),
    "sqli.time": ("tp", "fn", "fp", "tn", "non_decision"),
    "sqli.error": ("candidate", "fn", "fp", "tn", "non_decision"),
}
MEASUREMENT_SCHEMA_VERSION = 4
PROBE_MODES = {
    "sqli.boolean": {"six": "six_probe", "confirmation": "confirmation"},
    "sqli.time": {"time": "nine_probe"},
    "sqli.error": {"error": "error_probe"},
}


class PlannedMeasurement(NamedTuple):
    index: int
    target: "TargetAdapter"
    declaration: dict[str, object]
    mode: str
    key: tuple[str, str, str, str]
    config: Path


class TargetAdapter(NamedTuple):
    """Declaration-driven paths and runtime identity for one target."""

    target_id: str
    declaration: dict[str, object]
    compose: Path
    spec: Path
    configs: Path
    service_name: str
    service_port: int
    image_environment: str
    parameter_names: tuple[str, ...]
    startup_timeout_seconds: int


_TARGET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")


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


def _first_difference(
    actual: object, expected: object, path: tuple[str, ...] = ()
) -> tuple[str, ...] | None:
    if type(actual) is not type(expected):
        return path
    if type(expected) is dict:
        if actual.keys() != expected.keys():
            return (*path, min(actual.keys() ^ expected.keys(), key=str))
        for key in expected:
            difference = _first_difference(actual[key], expected[key], (*path, key))
            if difference is not None:
                return difference
        return None
    return path if actual != expected else None


def validate_measurement_report(report: object) -> dict[str, object]:
    """Accept only the current multi-target measurement report contract."""
    if type(report) is not dict:
        raise MeasurementError(
            "The third-party measurement report is not a JSON object. This reader supports schema version 4; rerun the measurement to regenerate the report."
        )
    version = report.get("schema_version")
    if type(version) is not int or version != MEASUREMENT_SCHEMA_VERSION:
        found = repr(version) if version is not None else "missing"
        raise MeasurementError(
            f"Unsupported third-party measurement report schema version: found {found}; this reader supports version 4. The multi-target shape cannot be inferred from an older report; rerun the measurement to regenerate it."
        )
    if report.keys() != {"counts", "records", "schema_version", "targets"}:
        raise MeasurementError(
            "Invalid third-party measurement report v4 top-level keys. Use targets, records, counts.overall, counts.by_target, and schema_version; rerun the current measurement instead of mixing v3 and v4 keys."
        )
    records = report["records"]
    counts_value = report["counts"]
    metadata = report["targets"]
    if type(records) is not list or type(metadata) is not dict:
        raise MeasurementError(
            "Invalid third-party measurement report v4 structure. Use target-keyed metadata, record objects, and both count trees; rerun the measurement."
        )
    targets, declarations = load_declarations()
    if metadata.keys() != targets.keys():
        changed = min(metadata.keys() ^ targets.keys(), key=str)
        raise MeasurementError(
            f"Measurement target metadata differs for target {changed!r}. Regenerate the report from prepared provenance instead of hand-editing it."
        )
    for target_id, target in targets.items():
        value = metadata[target_id]
        required = {
            "archive_sha256",
            "commit",
            "dbms",
            "image_ids",
            "license",
            "name",
            "repository",
            "service_images",
            "source_manifest_sha256",
        }
        if type(value) is not dict or value.keys() != required:
            raise MeasurementError(
                f"Measurement target metadata differs for target {target_id!r}. Use complete v4 prepared provenance and rerun the measurement."
            )
        for field in (
            "archive_sha256",
            "commit",
            "dbms",
            "license",
            "name",
            "repository",
        ):
            if value.get(field) != target.get(field):
                raise MeasurementError(
                    f"Measurement target metadata for {target_id!r} differs from prepared provenance at field {field}. Rerun preparation and measurement instead of hand-editing the report."
                )
        manifest = value.get("source_manifest_sha256")
        image_ids = value.get("image_ids")
        service_images = value.get("service_images")
        declared_images = target.get("service_images")
        if (
            type(manifest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", manifest) is None
            or type(image_ids) is not dict
            or image_ids.keys() != {"app"}
            or not is_image_digest(image_ids.get("app"))
        ):
            raise MeasurementError(
                f"Measurement target metadata for {target_id!r} is not content-addressed or its resolved service images differ from the declaration, so the measured images cannot be identified. Rerun prepare and measurement after making targets.toml and Compose agree."
            )
        try:
            validate_service_image_mapping(target_id, service_images, declared_images)
        except ServiceImageMismatch as exc:
            raise MeasurementError(str(exc)) from exc

    planned = list(plan_measurements(targets, declarations))
    expected_keys = {item.key for item in planned}
    declarations_by_key = {item.key: item.declaration for item in planned}
    record_keys: Counter[tuple[str, str, str, str]] = Counter()
    for record in records:
        if type(record) is not dict:
            raise MeasurementError(
                "The third-party measurement report contains a non-object record. Rerun the measurement to regenerate it."
            )
        key = (
            required_text(record, "target_id", "report record"),
            required_text(record, "endpoint_id", "report record"),
            required_text(record, "check_type", "report record"),
            required_text(record, "mode", "report record"),
        )
        record_keys[key] += 1
    for key, occurrences in record_keys.items():
        description = (
            f"target_id {key[0]!r}, endpoint_id {key[1]!r}, "
            f"check_type {key[2]!r}, mode {key[3]!r}"
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
        target_id, endpoint_id, check_type, mode = min(missing)
        raise MeasurementError(
            f"The measurement report is incomplete: missing target_id {target_id!r}, endpoint_id {endpoint_id!r}, check_type {check_type!r}, mode {mode!r}. Regenerate the report with a full measurement run."
        )

    recomputed_records: list[dict[str, object]] = []
    for record in records:
        if type(record.get("detail")) is not dict or "confirmation" in record:
            raise MeasurementError(
                "Invalid third-party measurement report v4 record. Use target_id, check_type, and the sibling detail object; rerun instead of mixing an older record shape."
            )
        check_type = record.get("check_type")
        if (
            check_type not in CLASSIFICATIONS
            or record.get("classification") not in CLASSIFICATIONS[check_type]
        ):
            raise MeasurementError(
                f"Measurement record for check type {record.get('check_type')}, mode {record.get('mode')} has an invalid classification. Use the classifications defined for that check type and rerun the measurement."
            )
        key = (
            required_text(record, "target_id", "report record"),
            required_text(record, "endpoint_id", "report record"),
            required_text(record, "check_type", "report record"),
            required_text(record, "mode", "report record"),
        )
        declaration = declarations_by_key[key]
        ground_truth = required_text(declaration, "label", "record")
        expected_verdict = expected_verdict_for_label(ground_truth)
        if record.get("expected_label") != ground_truth:
            raise MeasurementError(
                f"Measurement record {key[1]!r} expected_label contradicts reviewed ground truth {ground_truth!r}. Remeasure from targets.toml; do not hand-edit reports."
            )
        if record.get("expected_verdict") != expected_verdict:
            raise MeasurementError(
                f"Measurement record {key[1]!r} stored expected_verdict {record.get('expected_verdict')!r} contradicts ground-truth label {ground_truth!r}; expected {expected_verdict!r}. Remeasure the target; do not hand-edit reports."
            )
        verdict = required_text(record, "actual_verdict", "report record")
        reason = required_text(record, "reason_code", "report record")
        classification = classify(key[2], ground_truth, verdict, reason)
        if record.get("classification") != classification:
            raise MeasurementError(
                f"Measurement record {key[1]!r} stored classification {record.get('classification')!r} contradicts ground truth {ground_truth!r} with {verdict}/{reason}; expected {classification!r}. Remeasure the target; do not hand-edit reports."
            )
        if check_type == "sqli.error":
            _validate_error_detail(record)
        recomputed_records.append({**record, "classification": classification})

    recomputed = counts(recomputed_records)
    if type(counts_value) is not dict or counts_value.keys() != {
        "overall",
        "by_target",
    }:
        raise MeasurementError(
            "Invalid third-party measurement report v4 counts. Supply exactly counts.overall and counts.by_target, then rerun the measurement."
        )
    difference = _first_difference(counts_value, recomputed)
    if difference is not None:
        location = ".".join(("counts", *difference))
        raise MeasurementError(
            f"Measurement counts disagree with records at {location}. Rerun the measurement to regenerate the report instead of correcting counts by hand."
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
def loopback_bridge(upstream_host: str, target: TargetAdapter) -> Iterator[str]:
    """Expose one private container only through an ephemeral loopback socket."""
    try:
        server = _BridgeServer((upstream_host, target.service_port))
    except OSError as exc:
        raise MeasurementError(
            f"The {target.target_id} loopback bridge could not bind. Check IPv4 loopback permissions instead of using a public address."
        ) from exc
    started = threading.Event()

    def serve() -> None:
        started.set()
        server.serve_forever(poll_interval=0.05)

    thread = threading.Thread(target=serve, name=f"{target.target_id}-loopback-bridge")
    thread.start()
    if not started.wait(timeout=5):
        server.server_close()
        raise MeasurementError(
            f"The {target.target_id} loopback bridge did not start. Check thread scheduling and local socket setup."
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
                f"The {target.target_id} loopback bridge failed or did not stop. Check private-network reachability and outstanding requests."
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


def _relative_path(target_id: str, target: dict[str, object], key: str) -> Path:
    value = required_text(target, key, f"target {target_id!r}")
    candidate = (THIRD_PARTY / value).resolve()
    if candidate == THIRD_PARTY or THIRD_PARTY not in candidate.parents:
        raise MeasurementError(
            f"Target {target_id!r} has an invalid {key}. Use a relative path inside third_party/sqli instead."
        )
    return candidate


def load_declarations() -> tuple[dict[str, dict[str, object]], list[dict[str, object]]]:
    """Validate declaration v2 and its per-target ground-truth balance."""
    with DECLARATIONS.open("rb") as stream:
        document = tomllib.load(stream)
    if (
        document.keys() != {"version", "targets", "records"}
        or document.get("version") != 2
    ):
        raise MeasurementError(
            "The third-party declaration shape is invalid. Use declaration version 2 with targets and records tables."
        )
    raw_targets = document["targets"]
    records = document["records"]
    if type(raw_targets) is not list or not raw_targets or type(records) is not list:
        raise MeasurementError(
            "The third-party declaration must contain at least one reviewed target and its records."
        )
    targets: dict[str, dict[str, object]] = {}
    for target in raw_targets:
        if type(target) is not dict:
            raise MeasurementError(
                "A third-party target declaration is invalid. Supply a reviewed target table instead."
            )
        target_id = required_text(target, "id", "target declaration")
        if _TARGET_ID.fullmatch(target_id) is None or target_id in targets:
            raise MeasurementError(
                "A third-party target id is invalid or duplicated. Use a unique lowercase id containing letters, digits, or hyphens."
            )
        for field in (
            "name",
            "repository",
            "license",
            "dbms",
            "commit",
            "archive_url",
            "archive_sha256",
            "compose_path",
            "spec_path",
            "configs_path",
            "service_name",
            "image_environment",
            "operation_path",
        ):
            required_text(target, field, f"target {target_id!r}")
        if not required_text(
            target, "operation_path", f"target {target_id!r}"
        ).startswith("/"):
            raise MeasurementError(
                f"Target {target_id!r} has an invalid operation_path. Supply the reviewed absolute OpenAPI path beginning with '/'."
            )
        for key in ("compose_path", "spec_path", "configs_path"):
            path = _relative_path(target_id, target, key)
            if not path.exists():
                raise MeasurementError(
                    f"Target {target_id!r} {key} does not exist. Restore the reviewed target asset before measuring."
                )
        dockerfile = target.get("dockerfile_path")
        if dockerfile is not None:
            path = _relative_path(target_id, target, "dockerfile_path")
            if not path.is_file():
                raise MeasurementError(
                    f"Target {target_id!r} dockerfile_path does not exist. Restore the reviewed build recipe before measuring."
                )
        service_port = target.get("service_port")
        if type(service_port) is not int or not 1 <= service_port <= 65535:
            raise MeasurementError(
                f"Target {target_id!r} has an invalid service_port. Supply the reviewed integer port from 1 through 65535."
            )
        startup_timeout = target.get("startup_timeout_seconds")
        if type(startup_timeout) is not int or not 1 <= startup_timeout <= 300:
            raise MeasurementError(
                f"Target {target_id!r} has an invalid startup_timeout_seconds. Supply one bounded integer from 1 through 300."
            )
        names = target.get("parameter_names")
        if (
            type(names) is not list
            or not names
            or any(type(name) is not str or not name for name in names)
            or len(set(names)) != len(names)
        ):
            raise MeasurementError(
                f"Target {target_id!r} has invalid parameter_names. Supply unique nonempty OpenAPI query parameter names."
            )
        images = target.get("service_images")
        if type(images) is not list or any(
            pinned_image_digest(image) is None for image in images
        ):
            raise MeasurementError(
                f"Target {target_id!r} has an unpinned service image. Use image@sha256:<64 lowercase hex characters>, not a mutable tag."
            )
        volumes = target.get("fresh_volumes")
        if type(volumes) is not list or any(
            type(volume) is not str or _TARGET_ID.fullmatch(volume) is None
            for volume in volumes
        ):
            raise MeasurementError(
                f"Target {target_id!r} has invalid fresh volumes. Use lowercase names with letters, digits, or hyphens."
            )
        targets[target_id] = target
    typed_records: list[dict[str, object]] = []
    labels: dict[tuple[str, str], set[str]] = {}
    for record in records:
        if type(record) is not dict:
            raise MeasurementError(
                "A third-party record is invalid. Supply a reviewed TOML table instead."
            )
        target_id = required_text(record, "target_id", "record")
        check_type = required_text(record, "check_type", "record")
        label = required_text(record, "label", "record")
        if target_id not in targets:
            raise MeasurementError(
                f"Record {record.get('id')!r} references unknown target_id {target_id!r}. Bind it to a reviewed target."
            )
        if check_type not in PROBE_MODES or label not in {"positive", "negative"}:
            raise MeasurementError(
                f"Record {record.get('id')!r} has an unsupported check type or label. Use a supported SQLi check and positive or negative ground truth."
            )
        operation_path = record.get("operation_path")
        if operation_path is not None and (
            type(operation_path) is not str or not operation_path.startswith("/")
        ):
            raise MeasurementError(
                f"Record {record.get('id')!r} has an invalid operation_path. Supply the reviewed absolute OpenAPI path beginning with '/'."
            )
        labels.setdefault((target_id, check_type), set()).add(label)
        typed_records.append(record)
    for (target_id, check_type), observed in labels.items():
        if observed != {"positive", "negative"}:
            raise MeasurementError(
                f"Target {target_id!r} check type {check_type!r} lacks a positive or negative record. Supply both reviewed ground-truth labels before measuring."
            )
    unused_targets = targets.keys() - {target_id for target_id, _ in labels}
    if unused_targets:
        target_id = min(unused_targets)
        raise MeasurementError(
            f"Target {target_id!r} has no measurement records. Supply a reviewed check type with both positive and negative ground truth before measuring."
        )
    return targets, typed_records


def target_adapter(target_id: str, target: dict[str, object]) -> TargetAdapter:
    """Resolve one validated declaration into runtime paths and names."""
    names = target["parameter_names"]
    service_port = target.get("service_port")
    startup_timeout = target.get("startup_timeout_seconds")
    if (
        type(names) is not list
        or type(service_port) is not int
        or type(startup_timeout) is not int
    ):
        raise MeasurementError(
            f"Target {target_id!r} lost its runtime settings. Reload the validated declarations."
        )
    return TargetAdapter(
        target_id,
        target,
        _relative_path(target_id, target, "compose_path"),
        _relative_path(target_id, target, "spec_path"),
        _relative_path(target_id, target, "configs_path"),
        required_text(target, "service_name", f"target {target_id!r}"),
        service_port,
        required_text(target, "image_environment", f"target {target_id!r}"),
        tuple(names),
        startup_timeout,
    )


def plan_measurements(
    targets: dict[str, dict[str, object]],
    declarations: list[dict[str, object]],
) -> Iterator[PlannedMeasurement]:
    """Plan one report record per reviewed endpoint and probe config."""
    keys: set[tuple[str, str, str, str]] = set()
    for index, declaration in enumerate(declarations):
        target_id = required_text(declaration, "target_id", "record")
        adapter = target_adapter(target_id, targets[target_id])
        endpoint_id = required_text(declaration, "id", "record")
        check_type = required_text(declaration, "check_type", "record")
        for mode, report_mode in PROBE_MODES[check_type].items():
            key = (target_id, endpoint_id, check_type, report_mode)
            if key in keys:
                raise MeasurementError(
                    f"Duplicate measurement declaration {key!r}. Keep one declaration per endpoint_id, check_type, and mode in targets.toml."
                )
            keys.add(key)
            config = adapter.configs / f"{endpoint_id}-{mode}.toml"
            if not config.is_file():
                raise MeasurementError(
                    f"Missing reviewed configuration {config.name!r} for check type {check_type}. Restore the corresponding TOML config before running or validating measurements."
                )
            yield PlannedMeasurement(index, adapter, declaration, mode, key, config)


def validate_provenance(
    state: dict[str, object],
    target: dict[str, object],
    records: list[dict[str, object]],
) -> tuple[str, str]:
    """Bind local image and reviewed source evidence to the pinned declaration."""
    target_id = required_text(target, "id", "target declaration")
    commit = required_text(target, "commit", "target declaration")
    if state.get("commit") != commit:
        raise MeasurementError(
            f"Prepared {target_id} metadata does not match the reviewed commit. Rerun preparation in a fresh workspace."
        )
    if state.get("archive_sha256") != target.get("archive_sha256"):
        raise MeasurementError(
            f"Prepared {target_id} archive evidence does not match targets.toml. Rerun preparation with the reviewed archive."
        )
    dockerfile = target.get("dockerfile_path")
    recipe = state.get("build_recipe")
    if dockerfile is None:
        if "build_recipe" in state:
            raise MeasurementError(
                f"Prepared build recipe metadata exists for target {target_id!r}, but the target has no dockerfile_path. Rerun scripts/prepare_third_party_sqli.py for that target so prepared provenance matches its build inputs."
            )
    else:
        if (
            type(dockerfile) is not str
            or type(recipe) is not dict
            or recipe.keys() != {"path", "sha256"}
            or recipe.get("path") != dockerfile
            or not is_sha256(recipe.get("sha256"))
        ):
            raise MeasurementError(
                f"Prepared build recipe metadata for target {target_id!r} is missing or invalid. The recipe may have changed since prepare and the image may be stale; rerun scripts/prepare_third_party_sqli.py for that target."
            )
        recipe_path = _relative_path(target_id, target, "dockerfile_path")
        current_sha256 = hashlib.sha256(recipe_path.read_bytes()).hexdigest()
        if current_sha256 != recipe["sha256"]:
            raise MeasurementError(
                f"The build recipe for target {target_id!r} changed since prepare, so the prepared image may be stale. Rerun scripts/prepare_third_party_sqli.py for that target before measurement."
            )
    image_tag = required_text(state, "image_tag", "prepared target metadata")
    image_id = required_text(state, "image_id", "prepared target metadata")
    if not is_image_digest(image_id):
        raise MeasurementError(
            f"Prepared image ID for target {target_id!r} is not exactly sha256 plus 64 lowercase hexadecimal characters, so the measured image cannot be identified. Rerun prepare to regenerate trusted metadata."
        )
    required_text(state, "source_manifest_sha256", "prepared target metadata")
    source_evidence = state.get("source_evidence")
    if type(source_evidence) is not dict:
        raise MeasurementError(
            f"Prepared {target_id} source evidence is missing. Rerun preparation so the verified archive supplies the build manifest and source fragments."
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
            f"The prepared {target_id} image is unavailable. Run prepare_third_party_sqli.py and keep the recorded local image."
        ),
    ).stdout.strip()
    if observed_image_id != image_id:
        raise MeasurementError(
            f"The local {target_id} image digest differs from preparation metadata. Rebuild from the pinned archive instead of measuring a changed image."
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


def compose_environment(target: TargetAdapter, image_tag: str) -> dict[str, str]:
    """Create the minimal Compose substitution environment."""
    environment = os.environ.copy()
    environment[target.image_environment] = image_tag
    return environment


def compose(
    target: TargetAdapter,
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
            str(target.compose),
            "--project-name",
            project,
            *arguments,
        ],
        timeout=timeout,
        diagnostic=diagnostic,
        environment=compose_environment(target, image_tag),
    )


def validate_resolved_service_images(
    target: TargetAdapter,
    image_tag: str,
    configuration: object,
) -> dict[str, str]:
    """Bind every resolved Compose service image to reviewed identity."""
    if (
        type(configuration) is not dict
        or type(configuration.get("services")) is not dict
    ):
        raise MeasurementError(
            f"Resolved Compose configuration for {target.target_id!r} has no service image map. Check the Compose file before starting the target."
        )
    services = configuration["services"]
    resolved: dict[str, str] = {}
    for service, settings in services.items():
        if (
            type(service) is not str
            or type(settings) is not dict
            or type(settings.get("image")) is not str
        ):
            raise MeasurementError(
                f"Resolved Compose service identity for target {target.target_id!r} is incomplete. Give every service an explicit image and update targets.toml to match."
            )
        resolved[service] = settings["image"]
    app_image = resolved.get(target.service_name)
    if app_image != image_tag:
        raise MeasurementError(
            f"Compose image mismatch for target {target.target_id!r}, service {target.service_name!r}: declared prepared app image {image_tag!r}, resolved {app_image!r}. Update targets.toml or the Compose file so they agree before starting the target."
        )
    declared = target.declaration.get("service_images")
    if type(declared) is not list:
        raise MeasurementError(
            f"Target {target.target_id!r} lost its declared service images. Reload targets.toml before starting the target."
        )
    auxiliaries = {
        service: image
        for service, image in resolved.items()
        if service != target.service_name
    }
    try:
        return validate_service_image_mapping(target.target_id, auxiliaries, declared)
    except ServiceImageMismatch as exc:
        raise MeasurementError(str(exc)) from exc


def resolve_service_images(
    target: TargetAdapter, image_tag: str, project: str
) -> dict[str, str]:
    """Resolve Compose substitutions and validate images before ``up``."""
    completed = compose(
        target,
        image_tag,
        project,
        ["config", "--format", "json"],
        timeout=30,
        diagnostic=(
            f"The {target.target_id} Compose configuration could not be resolved. Check the reviewed file and prepared image before starting it."
        ),
    )
    try:
        configuration = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise MeasurementError(
            f"The {target.target_id} Compose configuration was not JSON. Check the installed Docker Compose version before starting it."
        ) from exc
    return validate_resolved_service_images(target, image_tag, configuration)


def new_run_id() -> str:
    """Return a short lowercase identifier unique to one measurement invocation."""
    return uuid.uuid4().hex[:12]


def compose_project_name(
    target_id: str, run_id: str, case_index: int, mode: str
) -> str:
    """Build one bounded Compose namespace for a case in a specific run."""
    if (
        _TARGET_ID.fullmatch(target_id) is None
        or len(run_id) != 12
        or any(character not in "0123456789abcdef" for character in run_id)
        or type(case_index) is not int
        or case_index < 0
        or mode not in {"six", "confirmation", "time", "error"}
    ):
        raise MeasurementError(
            "The measurement project identity is invalid. Use the generated run ID, nonnegative case index, and supported probe mode instead."
        )
    return f"vintar-{target_id}-{run_id}-{case_index}-{mode}"


def start_target(
    target: TargetAdapter, image_tag: str, project: str
) -> tuple[str, dict[str, str]]:
    """Start a fresh target and return its private internal-network address."""
    service_images = resolve_service_images(target, image_tag, project)
    compose(
        target,
        image_tag,
        project,
        [
            "up",
            "--detach",
            "--wait",
            "--wait-timeout",
            str(target.startup_timeout_seconds),
            "--pull",
            "never",
        ],
        timeout=target.startup_timeout_seconds + 30,
        diagnostic=(
            f"The pinned {target.target_id} container did not become healthy. Check Docker, loopback publishing, and the prepared image instead of retrying the measurement."
        ),
    )
    container = f"{project}-{target.service_name}-1"
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
            f"The {target.target_id} private address could not be resolved. Check the internal Compose network and prepared container."
        ),
    ).stdout.strip()
    try:
        packed = socket.inet_aton(address)
    except OSError as exc:
        raise MeasurementError(
            f"Docker returned an invalid {target.target_id} private address. Check the internal network instead of using an external target."
        ) from exc
    if len(packed) != 4 or address.startswith("127."):
        raise MeasurementError(
            f"Docker did not assign {target.target_id} a private container address. Check the internal network instead of weakening target isolation."
        )
    return address, service_images


def stop_target(target: TargetAdapter, image_tag: str, project: str) -> None:
    """Remove the target and its private network with a bounded shutdown."""
    compose(
        target,
        image_tag,
        project,
        ["down", "--volumes", "--remove-orphans", "--timeout", "10"],
        timeout=30,
        diagnostic=(
            f"The {target.target_id} container did not shut down cleanly. Check Docker state and remove the named measurement project before rerunning."
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
    target_id, record_id, check_type, report_mode = planned.key
    input_id = required_text(record, "input_id", "record")
    parameter = required_text(record, "parameter", "record")
    label = required_text(record, "label", "record")
    expected_verdict = expected_verdict_for_label(label)
    local_spec = folder / "openapi.json"
    local_spec.write_bytes(planned.target.spec.read_bytes())

    inventory = folder / "inventory.json"
    cli(
        ["discover", "--spec", str(local_spec), "--output", str(inventory)],
        cwd=folder,
    )
    inventory_document = load_document(inventory)
    operations = inventory_document.get("operations")
    operation_path = record.get("operation_path")
    if operation_path is None:
        operation_path = required_text(
            planned.target.declaration,
            "operation_path",
            f"target {target_id!r}",
        )
    if type(operations) is not list:
        raise MeasurementError(
            f"Target {target_id!r} discovery omitted its operation list. Check the reviewed OpenAPI document instead of changing the record."
        )
    matching_operations = [
        operation
        for operation in operations
        if type(operation) is dict
        and operation.get("path") == operation_path
        and operation.get("method") == "GET"
    ]
    if len(matching_operations) != 1:
        raise MeasurementError(
            f"Record {record_id!r} did not bind to exactly one reviewed GET operation. Check its operation_path and OpenAPI document instead of changing the ground truth."
        )
    operation = matching_operations[0]
    operation_inputs = operation.get("inputs")
    if type(operation_inputs) is not list:
        raise MeasurementError(
            f"Record {record_id!r} discovery operation omitted its inputs. Restore the reviewed OpenAPI query parameters before measuring."
        )
    selected_inputs = [
        item
        for item in operation_inputs
        if type(item) is dict and item.get("name") == parameter
    ]
    discovered_ids = {item.get("id") for item in selected_inputs}
    if len(selected_inputs) != 1 or discovered_ids != {input_id}:
        raise MeasurementError(
            f"Target {target_id!r} discovery input IDs drifted from reviewed declarations. Review the OpenAPI change and regenerate configs instead of measuring it silently."
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
            f"Target {target_id!r} discovery did not emit exactly one draft. Check the reviewed selection and OpenAPI input."
        )
    draft = folder / "drafts" / drafts[0]

    if parameter not in planned.target.parameter_names:
        raise MeasurementError(
            f"Record {record_id!r} uses a parameter absent from target {target_id!r}. Update the reviewed target declaration before measuring."
        )
    parameter_answers: dict[str, object] = {}
    for item in operation_inputs:
        if type(item) is not dict or type(item.get("name")) is not str:
            raise MeasurementError(
                f"Record {record_id!r} has an invalid discovered input. Restore the reviewed OpenAPI query parameters before measuring."
            )
        parameter_answers[item["name"]] = {"omit": True}
    selected = selected_inputs[0]
    source = selected.get("source")
    pointer = source.get("pointer") if type(source) is dict else None
    if type(pointer) is not str or not pointer:
        raise MeasurementError(
            f"Record {record_id!r} discovery input omitted its source pointer. Restore the reviewed OpenAPI document before measuring."
        )
    parameter_answers[parameter] = {"pointer": f"{pointer}/schema/example"}
    answers = folder / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "version": 1,
                "expected_verdict": expected_verdict,
                "parameters": parameter_answers,
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
            f"Verification did not emit exactly one {target_id} outcome. Check the generated case and request budget."
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
        "target_id": target_id,
    }


def _count_tree(records: list[dict[str, object]]) -> dict[str, object]:
    """Build one complete check-type/mode aggregate."""
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


def counts(records: list[dict[str, object]]) -> dict[str, object]:
    """Count records overall and independently for each declared target."""
    target_ids = sorted(
        {required_text(record, "target_id", "measurement record") for record in records}
    )
    return {
        "overall": _count_tree(records),
        "by_target": {
            target_id: _count_tree(
                [record for record in records if record.get("target_id") == target_id]
            )
            for target_id in target_ids
        },
    }


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
        "| Target | Check type | Record | Mode | Expected label | Actual verdict | Reason | Detail status | Requests | Classification |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- |",
    ]
    for record in records:
        if type(record) is not dict or type(record.get("detail")) is not dict:
            raise MeasurementError(
                "The measurement report contains an invalid record. Check the runner before updating documentation."
            )
        detail = record["detail"]
        lines.append(
            "| {target_id} | {check_type} | {endpoint_id} | {mode} | {expected_label} | {actual_verdict} | {reason_code} | {status} | {request_count} | {classification} |".format(
                **record,
                status=detail.get("status"),
            )
        )
    count_trees = report["counts"]
    if type(count_trees) is not dict or type(count_trees.get("overall")) is not dict:
        raise MeasurementError(
            "The measurement report contains invalid counts. Check the runner before updating documentation."
        )
    report_counts = count_trees["overall"]
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
    by_target = count_trees.get("by_target")
    if type(by_target) is not dict:
        raise MeasurementError(
            "The measurement report is missing per-target counts. Check the runner before updating documentation."
        )
    lines.extend(
        (
            "",
            "### Cross-target results",
            "",
            (
                "Cells list TP/TN/FP/FN/non-decision. Error cells append candidate. "
                "A dash means the technique does not use TP."
            ),
            "",
            "| Target (DBMS) | Boolean six_probe | Boolean confirmation | Time nine_probe | Error error_probe |",
            "| --- | --- | --- | --- | --- |",
        )
    )
    for target_id, target_counts in sorted(by_target.items()):
        cells = []
        for check_type, mode in (
            ("sqli.boolean", "six_probe"),
            ("sqli.boolean", "confirmation"),
            ("sqli.time", "nine_probe"),
            ("sqli.error", "error_probe"),
        ):
            values = target_counts[check_type][mode]
            fields = ("tp", "tn", "fp", "fn", "non_decision")
            if check_type == "sqli.error":
                fields += ("candidate",)
            cells.append("/".join(str(values.get(field, "—")) for field in fields))
        dbms = report["targets"][target_id]["dbms"]
        lines.append(f"| {target_id} ({dbms}) | " + " | ".join(cells) + " |")
    lines.extend(("", "### Known non-decisions", ""))
    non_decisions = sorted(
        (
            row["target_id"],
            row["endpoint_id"],
            row["check_type"],
            row["mode"],
            row["reason_code"],
        )
        for row in records
        if row["classification"] == "non_decision"
    )
    lines.extend(
        f"- `{target_id}` / `{endpoint_id}` / `{check_type}` / `{mode}`: `{reason}`."
        for target_id, endpoint_id, check_type, mode, reason in non_decisions
    )
    if not non_decisions:
        lines.append("None recorded.")
    lines.append(SUMMARY_END)
    return "\n".join(lines)


def render_measurement_input_revisions(
    revisions_path: Path = THIRD_PARTY / "measurement-input-revisions.toml",
) -> str:
    """Render the review history for every explicit confirmation config."""
    with revisions_path.open("rb") as stream:
        revisions = tomllib.load(stream)["confirmation"]
    history = {}
    for entry in revisions:
        target = required_text(entry, "target", "confirmation revision")
        endpoint = required_text(entry, "endpoint", "confirmation revision")
        key = (target, endpoint, "confirmation")
        if key in history:
            raise MeasurementError(
                f"Duplicate confirmation history for {target}/{endpoint}. "
                "Keep one entry per endpoint in measurement-input-revisions.toml."
            )
        history[key] = required_text(entry, "history", "confirmation revision")

    targets, records = load_declarations()
    explicit_keys = set()
    preset_keys = set()
    for planned in plan_measurements(targets, records):
        target, endpoint, _, mode = planned.key
        if mode != "confirmation":
            continue
        key = (target, endpoint, mode)
        with planned.config.open("rb") as stream:
            probes = tomllib.load(stream)["probes"]
        selection = probes.get("selection")
        if selection == "preset":
            preset_keys.add(key)
        if selection != "explicit":
            continue
        explicit_keys.add(key)
        if key not in history:
            raise MeasurementError(
                f"{target}/{endpoint} uses explicit confirmation inputs without "
                "documented history. Add a confirmation entry to "
                "measurement-input-revisions.toml and regenerate the revisions section."
            )
    if stale_keys := history.keys() - explicit_keys:
        key = min(stale_keys)
        target, endpoint, mode = key
        reason = (
            "describe a preset config as explicit"
            if key in preset_keys
            else "present a removed config as current"
        )
        raise MeasurementError(
            f"Stale measurement revision for {target}/{endpoint}/{mode}: the docs "
            f"would {reason}. Remove the entry from "
            "measurement-input-revisions.toml and regenerate the revisions section."
        )

    lines = [
        "## Measurement input revisions",
        "",
        "Inputs are fixed for each measurement. The entries below identify explicit",
        "confirmation configurations and record any earlier measurements.",
        "",
    ]
    lines.extend(
        f"- `{target}` / `{endpoint}` / {mode}. {text}"
        for (target, endpoint, mode), text in sorted(history.items())
    )
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
            "Actual third-party results differ from docs/sqli-third-party-evaluation.md. Review the saved report and update the documented summary instead of accepting drift silently."
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
    targets, declarations = load_declarations()
    plan = list(plan_measurements(targets, declarations))
    state = load_document(workspace / STATE_NAME)
    prepared_targets = state.get("targets")
    if state.get("schema_version") != 2 or type(prepared_targets) is not dict:
        raise MeasurementError(
            "Prepared metadata is not multi-target schema version 2. Rerun prepare_third_party_sqli.py before measuring."
        )
    if prepared_targets.keys() != targets.keys():
        raise MeasurementError(
            "Prepared target IDs differ from targets.toml. Rerun preparation so every reviewed target has current provenance."
        )
    prepared: dict[str, tuple[str, str, dict[str, object]]] = {}
    for target_id, target in targets.items():
        target_state = prepared_targets[target_id]
        if type(target_state) is not dict:
            raise MeasurementError(
                f"Prepared metadata for target {target_id!r} is invalid. Rerun preparation before measuring."
            )
        image_tag, image_id = validate_provenance(
            target_state,
            target,
            [row for row in declarations if row.get("target_id") == target_id],
        )
        prepared[target_id] = (image_tag, image_id, target_state)
    records: list[dict[str, object]] = []
    resolved_images: dict[str, dict[str, str]] = {}
    run_id = new_run_id()
    run_root = Path(tempfile.mkdtemp(prefix="vintar-third-party-run-", dir=workspace))
    for planned in plan:
        target_id = planned.target.target_id
        image_tag = prepared[target_id][0]
        project = compose_project_name(target_id, run_id, planned.index, planned.mode)
        case_folder = run_root / project
        case_folder.mkdir()
        try:
            upstream, service_images = start_target(planned.target, image_tag, project)
            previous_images = resolved_images.setdefault(target_id, service_images)
            if previous_images != service_images:
                raise MeasurementError(
                    f"Resolved service images changed between cases for target {target_id!r}. Stop and make the Compose configuration deterministic before measuring."
                )
            with loopback_bridge(upstream, planned.target) as origin:
                records.append(run_pipeline_case(case_folder, origin, planned))
        finally:
            stop_target(planned.target, image_tag, project)
    records.sort(
        key=lambda row: (
            str(row["target_id"]),
            str(row["endpoint_id"]),
            str(row["mode"]),
        )
    )
    report: dict[str, object] = {
        "counts": counts(records),
        "records": records,
        "schema_version": MEASUREMENT_SCHEMA_VERSION,
        "targets": {
            target_id: {
                "archive_sha256": target["archive_sha256"],
                "commit": target["commit"],
                "dbms": target["dbms"],
                "image_ids": {"app": prepared[target_id][1]},
                "license": target["license"],
                "name": target["name"],
                "repository": target["repository"],
                "service_images": resolved_images[target_id],
                "source_manifest_sha256": prepared[target_id][2][
                    "source_manifest_sha256"
                ],
            }
            for target_id, target in targets.items()
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
    print(f"Saved the third-party measurement report to {arguments.output.resolve()}")
    if unhealthy:
        print(
            "Error: The third-party measurement contains a false negative, false positive, or non-decision. Review the saved report and the documented limitation instead of treating it as a passing precision result.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
