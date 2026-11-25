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

import httpx
from third_party_sqli_contract import (
    ServiceImageMismatch,
    is_image_digest,
    is_sha256,
    pinned_image_digest,
    validate_service_image_mapping,
)

from vintar.checks.sqli.analyzer import (
    BooleanRepeatComparison,
    BooleanResponseSignature,
    DynamicRegion,
    classify_boolean_signatures,
)
from vintar.checks.sqli.confirmation import CONFIRMATION_ORDER, ConfirmationKind
from vintar.checks.sqli.confirmation_runner import (
    ConfirmationObservation,
    ConfirmationStatus,
    classify_confirmation_observations,
)
from vintar.checks.sqli.cross_phase import (
    CrossPhaseStatus,
    assess_cross_phase_observations,
)
from vintar.checks.sqli.decision_facts import (
    ConfirmationRelationDecisionFacts,
    OperationalCondition,
)
from vintar.checks.sqli.error_analyzer import (
    ERROR_PROBE_ORDER,
    ErrorMatch,
    ErrorObservation,
    ErrorProbeKind,
    classify_error_observations,
    error_operational_decision_facts,
    operational_stop_reason,
)
from vintar.checks.sqli.error_contract import ERROR_RESULT_RULES
from vintar.checks.sqli.error_signatures import ERROR_SIGNATURES
from vintar.checks.sqli.models import Observation, ProbeKind
from vintar.checks.sqli.observation_sink import AttemptOutcome, RecordedSqliObservation
from vintar.checks.sqli.orchestrator import BOOLEAN_PROBE_ORDER
from vintar.checks.sqli.time_analyzer import (
    TimeAnalysisStatus,
    TimeDecisionInputs,
    TimeProbeOutcome,
    TimeResponseSignature,
    classify_time_decision_inputs,
    time_decision_inputs,
)
from vintar.checks.sqli.time_plan import TIME_PROBE_ORDER
from vintar.regression import (
    TimeRegressionOutcome,
    TrustedExecutionPolicy,
    load_regression_case,
    regression_batch_report_dict,
    run_regression_batch,
)
from vintar.regression.report import decision_facts_report_dict

ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "third_party" / "sqli"
DECLARATIONS = THIRD_PARTY / "targets.toml"
DOCS = ROOT / "docs" / "sqli-third-party-evaluation.md"
STATE_NAME = "prepared-targets.json"
SUMMARY_START = "<!-- third-party-measurement:start -->"
SUMMARY_END = "<!-- third-party-measurement:end -->"
REVIEWED_SCHEMA_PATTERN = re.compile(r"Reviewed report schema version: `([0-9]+)`\.")
CLASSIFICATIONS = {
    "sqli.boolean": ("tp", "fn", "fp", "tn", "non_decision"),
    "sqli.time": ("tp", "fn", "fp", "tn", "non_decision"),
    "sqli.error": ("candidate", "fn", "fp", "tn", "non_decision"),
}
MEASUREMENT_SCHEMA_VERSION = 10
PROBE_MODES = {
    "sqli.boolean": {"six": "six_probe", "confirmation": "confirmation"},
    "sqli.time": {"time": "nine_probe"},
    "sqli.error": {"error": "error_probe"},
}
TIME_PROBE_OUTCOMES = frozenset(outcome.value for outcome in TimeProbeOutcome)


class PlannedMeasurement(NamedTuple):
    index: int
    target: "TargetAdapter"
    declaration: dict[str, object]
    mode: str
    key: tuple[str, str, str, str]
    config: Path


def _json_type(value: object) -> str:
    """Name the JSON type without formatting the value."""
    return {
        dict: "object",
        list: "array",
        str: "string",
        bool: "boolean",
        int: "number",
        float: "number",
        type(None): "null",
    }.get(type(value), "non-JSON value")


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


class RecordedResponse(NamedTuple):
    """Wire-level response provenance, with no retained body bytes."""

    status_code: int
    body_size: int
    body_sha256: str


class BridgeHandlerFailure(NamedTuple):
    """One redacted bridge failure and its request-order context."""

    sequence: int | None
    exception_type: str
    cause: str
    accepted_sequences: tuple[int, ...]
    completed_sequences: tuple[int, ...]


_TARGET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")

_POOLED_CONNECTION_ERROR = (
    "The loopback bridge records one HTTP response per TCP connection, but a "
    "pooled or keep-alive client sent multiple HTTP exchanges on one connection. "
    "Use measurement_http_transport() with keep-alive disabled."
)
_PROTOCOL_UPGRADE_ERROR = (
    "The loopback bridge does not support HTTP 101 protocol upgrades. "
    "Use an HTTP endpoint that returns a final non-upgrade response."
)
_WIRE_RESPONSE_WAIT_SECONDS = 5.0
_WIRE_RESPONSE_WAIT_ERROR = (
    "The trusted bridge did not finish every expected wire response because a "
    "handler failed or the bounded wait expired. Check bridge response framing "
    "and handler completion, then rerun the measurement."
)
_WIRE_RESPONSE_SET_ERROR = (
    "The trusted bridge wire response sequences differ from the completed "
    "analyzer attempts. Check bridge request sequencing and rerun the measurement."
)


class MeasurementError(RuntimeError):
    """An actionable third-party measurement failure."""


class ObservationCollector:
    """Collect one trusted runner's exact observations by request sequence."""

    def __init__(self) -> None:
        self._observations: dict[int, RecordedSqliObservation] = {}

    def __call__(self, recorded: RecordedSqliObservation) -> None:
        if recorded.sequence in self._observations:
            raise MeasurementError(
                f"The analyzer observation sink produced duplicate sequence number {recorded.sequence}. Check runner emission and rerun the measurement."
            )
        self._observations[recorded.sequence] = recorded

    def ordered(self, expected: int) -> tuple[RecordedSqliObservation, ...]:
        expected_sequences = set(range(1, expected + 1))
        observed_sequences = set(self._observations)
        if observed_sequences != expected_sequences:
            raise MeasurementError(
                f"The analyzer observation sink has sequence gaps: expected {sorted(expected_sequences)!r}, observed {sorted(observed_sequences)!r}. Check runner emission and rerun the measurement."
            )
        return tuple(self._observations[index] for index in range(1, expected + 1))

    def attempts(self) -> tuple[RecordedSqliObservation, ...]:
        """Return the complete contiguous attempt prefix, including a stop."""
        if not self._observations:
            raise MeasurementError(
                "The trusted observation sink emitted no attempts. Check runner "
                "emission and rerun the measurement."
            )
        expected = set(range(1, max(self._observations) + 1))
        if set(self._observations) != expected:
            raise MeasurementError(
                "The trusted observation sink contains a sequence gap. Check runner "
                "emission and rerun the measurement."
            )
        return tuple(self._observations[index] for index in sorted(expected))


def _confirmation_role(kind: ConfirmationKind) -> str:
    if kind is ConfirmationKind.TRUE_1:
        return "true"
    if kind is ConfirmationKind.FALSE_1:
        return "false"
    if kind is ConfirmationKind.BASELINE_PRESERVING_CONTROL:
        return "control"
    return kind.value.replace("_", "")


def _error_role(kind: ErrorProbeKind) -> str:
    return "error" if kind is ErrorProbeKind.PROBE else kind.value


BOOLEAN_REPORT_ROLES = tuple(kind.value for kind in BOOLEAN_PROBE_ORDER)
CONFIRMATION_REPORT_ROLES = BOOLEAN_REPORT_ROLES + tuple(
    _confirmation_role(kind) for kind in CONFIRMATION_ORDER
)
TIME_REPORT_ROLES = tuple(kind.value for kind in TIME_PROBE_ORDER)
ERROR_REPORT_ROLES = tuple(_error_role(kind) for kind in ERROR_PROBE_ORDER)

PROBE_ROLE_ORDERS = {
    ("sqli.boolean", "six_probe"): BOOLEAN_REPORT_ROLES,
    ("sqli.boolean", "confirmation"): CONFIRMATION_REPORT_ROLES,
    ("sqli.time", "nine_probe"): TIME_REPORT_ROLES,
    ("sqli.error", "error_probe"): ERROR_REPORT_ROLES,
}
OBSERVATION_KIND_ORDERS = {
    ("sqli.boolean", "six_probe"): tuple(kind.value for kind in BOOLEAN_PROBE_ORDER),
    ("sqli.boolean", "confirmation"): tuple(kind.value for kind in BOOLEAN_PROBE_ORDER)
    + tuple(kind.value for kind in CONFIRMATION_ORDER),
    ("sqli.time", "nine_probe"): tuple(kind.value for kind in TIME_PROBE_ORDER),
    ("sqli.error", "error_probe"): tuple(kind.value for kind in ERROR_PROBE_ORDER),
}


def _repeat_comparison_dict(
    first: dict[str, object],
    second: dict[str, object],
    facts: object,
) -> dict[str, object]:
    signature_fields = ("status_code", "body_size", "body_sha256")
    if all(first.get(field) == second.get(field) for field in signature_fields):
        return {"equal": True}
    if type(facts) is dict and facts.get("category") == "response_dynamics":
        pairs = facts.get("unstable_pairs")
        if type(pairs) is list:
            for pair in pairs:
                if (
                    type(pair) is dict
                    and pair.get("probe_kind") == second["probe_kind"]
                ):
                    if pair.get("localization") == "localized":
                        return {
                            "equal": False,
                            "localization": "localized",
                            "prefix_size": pair["prefix_size"],
                            "suffix_size": pair["suffix_size"],
                            "first_changed_size": pair["first_changed_size"],
                            "second_changed_size": pair["second_changed_size"],
                        }
                    return {"equal": False, "localization": "unlocalized"}
    return {"equal": False, "localization": "unlocalized"}


def sanitized_attempts(
    observations: tuple[RecordedSqliObservation, ...],
    wire_responses: dict[int, RecordedResponse],
    *,
    decision_facts: object,
) -> list[dict[str, object]]:
    """Serialize only trusted attempts and bounded wire provenance."""
    attempts: list[dict[str, object]] = []
    prior_by_identity: dict[tuple[str, str], dict[str, object]] = {}
    for recorded in observations:
        item: dict[str, object] = {
            "sequence": recorded.sequence,
            "stage": recorded.family,
            "probe_kind": recorded.kind,
            "outcome": recorded.outcome.value,
        }
        if recorded.outcome is not AttemptOutcome.RESPONSE:
            if recorded.failure is None:
                raise MeasurementError(
                    "A response-less trusted attempt omitted its failure kind. Check "
                    "runner emission and rerun the measurement."
                )
            item["failure_kind"] = recorded.failure.value
            if recorded.sequence in wire_responses:
                raise MeasurementError(
                    "A response-less analyzer attempt has completed wire evidence. "
                    "Check terminal request handling and rerun the measurement."
                )
            attempts.append(item)
            continue
        wire = wire_responses.get(recorded.sequence)
        if wire is None:
            raise MeasurementError(
                "A completed analyzer attempt has no matching wire response. Check "
                "bridge sequencing and rerun the measurement."
            )
        observation = recorded.observation
        status = getattr(observation, "status_code", None)
        truncated = getattr(observation, "truncated", None)
        if status != wire.status_code or type(truncated) is not bool:
            raise MeasurementError(
                "Wire and analyzer response facts disagree. Check the bridge and "
                "trusted observation sink, then rerun the measurement."
            )
        item.update(
            status_code=status,
            truncated=truncated,
            wire_status_code=wire.status_code,
            wire_body_size=wire.body_size,
            wire_body_sha256=wire.body_sha256,
        )
        if isinstance(
            observation,
            (
                Observation,
                BooleanResponseSignature,
                ConfirmationObservation,
                ErrorObservation,
                TimeResponseSignature,
            ),
        ):
            item.update(
                body_size=observation.body_size,
                body_sha256=observation.body_digest,
            )
        if isinstance(
            observation,
            (Observation, BooleanResponseSignature, ConfirmationObservation),
        ):
            item.update(
                normalization_applied=observation.normalization_applied,
                normalized_echo_count=observation.normalized_echo_count,
            )
            identity = (recorded.family, recorded.kind)
            first = prior_by_identity.get(identity)
            if first is None:
                prior_by_identity[identity] = item
            else:
                item["repeat_comparison"] = _repeat_comparison_dict(
                    first, item, decision_facts
                )
        if isinstance(observation, ErrorObservation):
            item["matches"] = [
                {"dbms": match.dbms, "signature_id": match.signature_id}
                for match in observation.matches
            ]
        attempts.append(item)
    unused_wire = set(wire_responses) - {
        item["sequence"] for item in attempts if item["outcome"] == "response"
    }
    if unused_wire:
        raise MeasurementError(
            "The bridge recorded wire responses without matching analyzer attempts. "
            "Check request sequencing and rerun the measurement."
        )
    return attempts


def _validate_error_detail(record: dict[str, object], record_index: int) -> None:
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
        difference = (
            f"missing {missing!r}"
            if missing
            else f"unexpected keys in object; expected only {sorted(required_fields)!r}"
        )
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} (records[{record_index}]) "
            f"detail fields contradict ERROR_RESULT_RULES: {difference}. "
            "Remeasure the target to regenerate the complete Error result; do not hand-edit reports."
        )
    status = detail["status"]
    request_count = detail["request_count"]
    if status != rule.analysis_status.value:
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} (records[{record_index}]) "
            f"detail status observed JSON type {_json_type(status)}. "
            f"Expected string {rule.analysis_status.value!r} for the validated reason. "
            "Remeasure the target using ERROR_RESULT_RULES; do not hand-edit reports."
        )
    if (
        type(request_count) is not int
        or not rule.minimum_requests <= request_count <= rule.maximum_requests
    ):
        raise MeasurementError(
            f"Error measurement record {endpoint_id!r} (records[{record_index}]) "
            f"detail request_count contradicts the reason. Observed JSON type {_json_type(request_count)}. "
            f"Expected a JSON integer from {rule.minimum_requests} through {rule.maximum_requests}. "
            "Remeasure the target using the bounded ERROR_RESULT_RULES request range; do not hand-edit reports."
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
) -> tuple[tuple[str, ...], str] | None:
    if type(actual) is not type(expected):
        return (
            path,
            f"Observed JSON type {_json_type(actual)}. Expected {_json_type(expected)}.",
        )
    if type(expected) is dict:
        if missing := expected.keys() - actual.keys():
            key = min(missing)
            return (
                *path,
                key,
            ), f"Missing field. Expected JSON type {_json_type(expected[key])}."
        if actual.keys() - expected.keys():
            return (
                path,
                "Observed an object with unexpected keys. Expected only the declared count fields.",
            )
        for key in expected:
            difference = _first_difference(actual[key], expected[key], (*path, key))
            if difference is not None:
                return difference
        return None
    if actual != expected:
        return (
            path,
            f"Observed JSON type {_json_type(actual)}. Expected the recomputed JSON {_json_type(expected)}.",
        )
    return None


_NON_OBJECT_REPORT_MESSAGE = (
    "The third-party measurement report is not a JSON object. "
    "Pass a report produced by scripts/run_third_party_sqli_measurement.py."
)


def _v10_error(message: str) -> MeasurementError:
    return MeasurementError(
        f"{message} Rerun scripts/run_third_party_sqli_measurement.py with the "
        "current tooling; do not hand-edit report evidence."
    )


def _strict_int(value: object, field: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise _v10_error(
            f"Invalid v10 {field}: expected a JSON integer of at least {minimum}."
        )
    return value


def _strict_digest(value: object, field: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise _v10_error(f"Invalid v10 {field}: expected a lowercase SHA-256 digest.")
    return value


def _attempt_plan(check_type: str, mode: str) -> tuple[tuple[str, str], ...]:
    kinds = OBSERVATION_KIND_ORDERS[(check_type, mode)]
    if check_type == "sqli.boolean":
        return tuple(
            ("boolean" if index <= 6 else "confirmation", kind)
            for index, kind in enumerate(kinds, start=1)
        )
    return tuple((check_type.removeprefix("sqli."), kind) for kind in kinds)


def _parse_v10_attempts(
    record: dict[str, object], check_type: str, mode: str
) -> list[dict[str, object]]:
    attempts = record.get("attempts")
    if type(attempts) is not list or not attempts:
        raise _v10_error("Invalid v10 attempts: expected a nonempty attempt array.")
    plan = _attempt_plan(check_type, mode)
    seen_terminal = False
    response_count = 0
    counted = 0
    prior: dict[tuple[str, str], dict[str, object]] = {}
    for index, item in enumerate(attempts, start=1):
        if type(item) is not dict:
            raise _v10_error(f"Invalid v10 attempts[{index - 1}]: expected an object.")
        if seen_terminal:
            raise _v10_error(
                "Invalid v10 attempts: no attempt may follow a terminal no_response or not_dispatched entry."
            )
        if index > len(plan):
            raise _v10_error(
                "Invalid v10 attempts: entries exceed the fixed production plan."
            )
        stage, kind = plan[index - 1]
        if (
            _strict_int(item.get("sequence"), "attempt sequence", minimum=1) != index
            or item.get("stage") != stage
            or item.get("probe_kind") != kind
        ):
            raise _v10_error(
                f"Invalid v10 attempt identity at sequence {index}: expected the fixed production stage and probe kind."
            )
        outcome = item.get("outcome")
        common = {"sequence", "stage", "probe_kind", "outcome"}
        if outcome == "no_response" or outcome == "not_dispatched":
            if (
                item.keys() != common | {"failure_kind"}
                or type(item.get("failure_kind")) is not str
            ):
                raise _v10_error(
                    f"Invalid v10 {outcome} attempt fields: store only the fixed failure_kind and request identity."
                )
            seen_terminal = True
            if outcome == "no_response":
                counted += 1
            continue
        if outcome != "response":
            raise _v10_error(
                "Invalid v10 attempt outcome: use response, no_response, or not_dispatched."
            )
        response_count += 1
        counted += 1
        base = common | {
            "status_code",
            "truncated",
            "wire_status_code",
            "wire_body_size",
            "wire_body_sha256",
        }
        family_fields: set[str] = {"body_size", "body_sha256"}
        if stage in {"boolean", "confirmation"}:
            family_fields |= {"normalization_applied", "normalized_echo_count"}
        if stage == "error":
            family_fields.add("matches")
        identity = (stage, kind)
        repeated = identity in prior and stage in {"boolean", "confirmation"}
        if repeated:
            family_fields.add("repeat_comparison")
        expected_fields = base | family_fields
        if item.keys() != expected_fields:
            raise _v10_error(
                f"Invalid v10 response fields at sequence {index}: fields do not match its check family and repeat position."
            )
        status = _strict_int(item.get("status_code"), "status_code", minimum=100)
        if status > 599 or item.get("wire_status_code") != status:
            raise _v10_error(
                f"Invalid v10 status evidence at sequence {index}: wire and analyzer status must agree."
            )
        if type(item.get("truncated")) is not bool:
            raise _v10_error("Invalid v10 truncated field: expected a JSON boolean.")
        _strict_int(item.get("wire_body_size"), "wire_body_size")
        _strict_digest(item.get("wire_body_sha256"), "wire_body_sha256")
        size = _strict_int(item.get("body_size"), "body_size")
        _strict_digest(item.get("body_sha256"), "body_sha256")
        if stage in {"boolean", "confirmation"}:
            applied = item.get("normalization_applied")
            echo_count = item.get("normalized_echo_count")
            if (
                type(applied) is not bool
                or type(echo_count) is not int
                or echo_count < 0
            ):
                raise _v10_error(
                    "Invalid v10 Boolean normalization evidence: expected a boolean and nonnegative integer."
                )
            if applied != (echo_count > 0):
                raise _v10_error(
                    "Invalid v10 Boolean normalization evidence: applied must equal whether the echo count is positive."
                )
        if repeated:
            comparison = item.get("repeat_comparison")
            if (
                type(comparison) is not dict
                or type(comparison.get("equal")) is not bool
            ):
                raise _v10_error(
                    f"Invalid v10 repeat comparison at sequence {index}: expected a discriminated comparison object."
                )
            if comparison["equal"]:
                if comparison.keys() != {"equal"}:
                    raise _v10_error(
                        "Equal repeat comparisons cannot contain localization sizes."
                    )
            elif comparison.get("localization") == "unlocalized":
                if comparison.keys() != {"equal", "localization"}:
                    raise _v10_error(
                        "Unlocalized repeat comparisons cannot contain sizes."
                    )
            elif comparison.get("localization") == "localized":
                required = {
                    "equal",
                    "localization",
                    "prefix_size",
                    "suffix_size",
                    "first_changed_size",
                    "second_changed_size",
                }
                if comparison.keys() != required:
                    raise _v10_error(
                        "Localized repeat comparisons require all four sizes."
                    )
                prefix = _strict_int(comparison["prefix_size"], "prefix_size")
                suffix = _strict_int(comparison["suffix_size"], "suffix_size")
                first_changed = _strict_int(
                    comparison["first_changed_size"], "first_changed_size"
                )
                second_changed = _strict_int(
                    comparison["second_changed_size"], "second_changed_size"
                )
                first = prior[identity]
                if prefix + suffix + first_changed != first["body_size"] or (
                    prefix + suffix + second_changed != size
                ):
                    raise _v10_error(
                        "Localized repeat comparison sizes do not sum to both analyzer body sizes."
                    )
            else:
                raise _v10_error(
                    "Invalid v10 repeat localization: use localized or unlocalized."
                )
            equal = all(
                prior[identity][field] == item[field]
                for field in ("status_code", "body_size", "body_sha256")
            )
            if comparison["equal"] != equal:
                raise _v10_error(
                    "The stored repeat comparison contradicts analyzer response signatures."
                )
        else:
            prior[identity] = item
        if stage == "error":
            matches = item.get("matches")
            if type(matches) is not list:
                raise _v10_error("Invalid v10 Error matches: expected a sorted array.")
            for match in matches:
                if type(match) is not dict or match.keys() != {"dbms", "signature_id"}:
                    raise _v10_error("Invalid v10 Error match fields.")
                signature_id = match["signature_id"]
                signature = (
                    ERROR_SIGNATURES.get(signature_id)
                    if type(signature_id) is str
                    else None
                )
                if signature is None or signature.dbms != match.get("dbms"):
                    raise _v10_error("Invalid v10 Error DBMS/signature pair.")
        prior.setdefault(identity, item)
    request_count = _strict_int(record.get("request_count"), "request_count")
    if counted != request_count:
        raise _v10_error(
            "v10 request_count disagrees with response and no_response attempts; not_dispatched is not counted."
        )
    if response_count != len(
        [item for item in attempts if item.get("outcome") == "response"]
    ):
        raise _v10_error("Invalid v10 response accounting.")
    return attempts


def _comparison_object(
    item: dict[str, object], kind: ProbeKind
) -> BooleanRepeatComparison:
    value = item["repeat_comparison"]
    if type(value) is not dict:
        raise _v10_error("Invalid Boolean repeat comparison object.")
    region = None
    if value.get("localization") == "localized":
        region = DynamicRegion(
            value["prefix_size"],
            value["suffix_size"],
            value["first_changed_size"],
            value["second_changed_size"],
        )
    return BooleanRepeatComparison(kind, value["equal"], region)


def _derive_complete_v10_record(
    record: dict[str, object], attempts: list[dict[str, object]]
) -> tuple[str, str, object | None]:
    check_type = record["check_type"]
    mode = record["mode"]
    terminal = attempts[-1]
    response_condition = None
    if terminal["outcome"] == "response":
        response_condition = (
            "rate_limited"
            if terminal["status_code"] == 429
            else "truncated"
            if terminal["truncated"]
            else "non_success_status"
            if terminal["stage"] != "error" and not 200 <= terminal["status_code"] < 300
            else None
        )
    if terminal["outcome"] != "response" or response_condition is not None:
        condition = (
            terminal["failure_kind"]
            if terminal["outcome"] != "response"
            else response_condition
        )
        stage = terminal["stage"]
        if stage == "time":
            reason = {
                "deadline": "incomplete_probes"
                if terminal["outcome"] == "not_dispatched"
                else "probe_interrupted",
                "timeout": "probe_timeout",
                "request_failed": "probe_failed",
                "interrupted": "probe_interrupted",
                "rate_limited": "rate_limited",
                "truncated": "truncated_response",
                "non_success_status": "non_success_status",
            }.get(condition)
        elif stage == "error":
            reason = {
                "timeout": "probe_timeout",
                "connection": "probe_failed",
                "response_read": "probe_failed",
                "unknown": "probe_failed",
                "rate_limit": "probe_interrupted",
                "cancelled": "probe_interrupted",
                "rate_limited": "rate_limited",
                "truncated": "truncated_response",
                "non_success_status": "non_success_status",
            }.get(condition)
        elif stage == "confirmation":
            reason = {
                "budget_unavailable": "confirmation_budget_unavailable",
                "preflight_failed": "confirmation_preflight_failed",
                "budget_exceeded": "confirmation_budget_exceeded",
                "rate_limit_interrupted": "confirmation_rate_limit_interrupted",
                "timeout": "confirmation_timeout",
                "connection": "confirmation_request_failed",
                "response_read": "confirmation_request_failed",
                "unknown": "confirmation_request_failed",
                "rate_limited": "confirmation_rate_limited",
                "truncated": "confirmation_truncated",
                "non_success_status": "confirmation_non_success_status",
            }.get(condition)
        else:
            reason = (
                "budget_unavailable"
                if condition == "budget_unavailable"
                else "rate_limited"
                if condition == "rate_limited"
                else "truncated_response"
                if condition == "truncated"
                else "non_success_status"
                if condition == "non_success_status"
                else "probe_failed"
            )
        if reason is None:
            raise _v10_error("Unsupported terminal failure kind in v10 attempts.")
        probe_kind = terminal["probe_kind"]
        if stage == "error" and probe_kind == "probe":
            probe_kind = "error"
        facts: dict[str, object] = {
            "category": "operational",
            "stage": "initial" if stage == "boolean" else stage,
            "sequence": terminal["sequence"],
            "probe_kind": probe_kind,
            "condition": condition,
        }
        if terminal["outcome"] == "response":
            facts["status_code"] = terminal["status_code"]
        return "inconclusive", reason, facts
    if check_type == "sqli.boolean":
        initial = attempts[:6]
        signatures = tuple(
            BooleanResponseSignature(
                ProbeKind(item["probe_kind"]),
                item["status_code"],
                item["body_size"],
                item["body_sha256"],
                item["truncated"],
                item["normalization_applied"],
                item["normalized_echo_count"],
            )
            for item in initial
        )
        second_by_kind = {
            kind: next(
                item for item in reversed(initial) if item["probe_kind"] == kind.value
            )
            for kind in ProbeKind
        }
        comparison = tuple(
            _comparison_object(second_by_kind[kind], kind) for kind in ProbeKind
        )
        classification = classify_boolean_signatures(
            signatures=signatures,
            repeat_comparisons=comparison,
            normalization_applied=any(
                item["normalization_applied"] for item in initial
            ),
            normalized_echo_count=sum(
                item["normalized_echo_count"] for item in initial
            ),
        )
        facts = classification.decision_facts
        if mode == "six_probe" or classification.reason_code != "boolean_candidate":
            return (
                classification.verdict.value,
                classification.reason_code,
                None if facts is None else decision_facts_report_dict(facts),
            )
        confirmation_attempts = attempts[6:]
        confirmation = tuple(
            ConfirmationObservation(
                ConfirmationKind(item["probe_kind"]),
                item["status_code"],
                item["body_size"],
                item["body_sha256"],
                item["truncated"],
                item["normalization_applied"],
                item["normalized_echo_count"],
            )
            for item in confirmation_attempts
        )
        status, evidence, confirmation_facts = classify_confirmation_observations(
            confirmation
        )
        if status is ConfirmationStatus.CANDIDATE and evidence is not None:
            initial_observations = tuple(
                Observation(
                    ProbeKind(item["probe_kind"]),
                    item["status_code"],
                    item["body_size"],
                    0.0,
                    item["body_sha256"],
                    item["truncated"],
                    item["normalization_applied"],
                    item["normalized_echo_count"],
                )
                for item in initial
            )
            cross = assess_cross_phase_observations(
                initial=initial_observations, confirmation=confirmation
            )
            if cross.status is CrossPhaseStatus.MATCH:
                return "inconclusive", "boolean_candidate", None
            cross_facts = ConfirmationRelationDecisionFacts(
                reason_code="confirmation_cross_phase_mismatch",
                cross_phase_mismatched_kinds=cross.mismatched_kinds,
            )
            return (
                "inconclusive",
                "confirmation_cross_phase_mismatch",
                decision_facts_report_dict(cross_facts),
            )
        return (
            "inconclusive",
            "confirmation_unstable"
            if status is ConfirmationStatus.INCONCLUSIVE
            else "candidate_confirmation_mismatch",
            None
            if confirmation_facts is None
            else decision_facts_report_dict(confirmation_facts),
        )
    if check_type == "sqli.time":
        predicates = record.get("time_predicates")
        if type(predicates) is not dict or predicates.keys() != set(
            TimeDecisionInputs.__dataclass_fields__
        ):
            raise _v10_error(
                "Complete Time records require exactly the eight production decision predicates."
            )
        inputs = TimeDecisionInputs(**predicates)
        status, reason, facts = classify_time_decision_inputs(inputs)
        verdict = (
            "not_detected"
            if status is TimeAnalysisStatus.NOT_CONFIRMED
            else "inconclusive"
        )
        return (
            verdict,
            reason,
            None if facts is None else decision_facts_report_dict(facts),
        )
    try:
        observations = tuple(
            ErrorObservation(
                ErrorProbeKind(item["probe_kind"]),
                item["sequence"],
                item["status_code"],
                item["body_size"],
                item["body_sha256"],
                item["truncated"],
                tuple(
                    ErrorMatch(match["dbms"], match["signature_id"])
                    for match in item["matches"]
                ),
            )
            for item in attempts
        )
        _, reason, _ = classify_error_observations(observations)
    except (TypeError, ValueError):
        raise _v10_error(
            "Invalid v10 Error attempts: expected a valid ordered analyzer sequence."
        ) from None
    verdict = ERROR_RESULT_RULES[reason].product_verdict.value
    facts = None
    for observation in observations:
        stop_reason = operational_stop_reason(observation)
        if stop_reason is not None:
            condition = (
                OperationalCondition.RATE_LIMITED
                if stop_reason == "rate_limited"
                else OperationalCondition.TRUNCATED
                if stop_reason == "truncated_response"
                else OperationalCondition.NON_SUCCESS_STATUS
            )
            facts = decision_facts_report_dict(
                error_operational_decision_facts(
                    reason_code=stop_reason,
                    sequence=observation.sequence,
                    kind=observation.kind,
                    condition=condition,
                    status_code=observation.status_code,
                )
            )
            break
    if facts is None and reason == "non_success_status":
        observation = next(
            item for item in observations if not 200 <= item.status_code < 300
        )
        facts = decision_facts_report_dict(
            error_operational_decision_facts(
                reason_code=reason,
                sequence=observation.sequence,
                kind=observation.kind,
                condition=OperationalCondition.NON_SUCCESS_STATUS,
                status_code=observation.status_code,
            )
        )
    return verdict, reason, facts


def _validate_v10_measurement_report(report: object) -> dict[str, object]:
    if type(report) is not dict:
        raise MeasurementError(_NON_OBJECT_REPORT_MESSAGE)
    if report.keys() != {"counts", "records", "schema_version", "targets"}:
        raise _v10_error("Invalid v10 top-level fields.")
    if report.get("schema_version") != 10:
        raise _v10_error("Invalid v10 schema version.")
    records = report.get("records")
    if type(records) is not list:
        raise _v10_error("Invalid v10 records array.")
    targets, declarations = load_declarations()
    planned = list(plan_measurements(targets, declarations))
    declaration_by_key = {item.key: item.declaration for item in planned}
    expected_keys = set(declaration_by_key)
    observed_keys: set[tuple[str, str, str, str]] = set()
    recomputed_records: list[dict[str, object]] = []
    for record in records:
        if type(record) is not dict:
            raise _v10_error("Invalid v10 record: expected an object.")
        base_fields = {
            "actual_verdict",
            "attempts",
            "check_type",
            "classification",
            "detail",
            "endpoint_id",
            "expected_label",
            "expected_verdict",
            "mode",
            "reason_code",
            "request_count",
            "target_id",
        }
        allowed = base_fields | {"decision_facts", "time_predicates"}
        if not base_fields <= record.keys() or record.keys() - allowed:
            raise _v10_error("Invalid v10 record fields.")
        key = tuple(
            record[field]
            for field in ("target_id", "endpoint_id", "check_type", "mode")
        )
        if any(type(part) is not str for part in key):
            raise _v10_error("Invalid v10 record identity: expected declared strings.")
        if key not in expected_keys or key in observed_keys:
            raise _v10_error("A v10 record is undeclared or duplicated.")
        observed_keys.add(key)
        declaration = declaration_by_key[key]
        label = required_text(declaration, "label", "record declaration")
        if record.get("expected_label") != label or record.get(
            "expected_verdict"
        ) != expected_verdict_for_label(label):
            raise _v10_error("A v10 record contradicts reviewed ground truth.")
        attempts = _parse_v10_attempts(record, key[2], key[3])
        verdict, reason, facts = _derive_complete_v10_record(record, attempts)
        if (
            record.get("actual_verdict") != verdict
            or record.get("reason_code") != reason
        ):
            raise _v10_error(
                "The stored v10 verdict or reason contradicts classifier-derived attempt evidence."
            )
        if record.get("decision_facts") != facts:
            raise _v10_error(
                "Stored v10 decision_facts contradict classifier-derived attempt evidence."
            )
        detail = record.get("detail")
        if type(detail) is not dict:
            raise _v10_error("A v10 record requires its product detail object.")
        if key[2] in {"sqli.time", "sqli.error"} and (
            detail.get("reason_code") != reason
            or detail.get("request_count") != record.get("request_count")
        ):
            raise _v10_error(
                "The v10 product detail contradicts the derived reason or request count."
            )
        if key[2] == "sqli.error":
            _validate_error_detail(record, records.index(record))
        classification = classify(key[2], label, verdict, reason)
        if classification == "non_decision" and facts is None:
            raise _v10_error(
                "A v10 non-decision lacks classifier-derived structured decision_facts."
            )
        if record.get("classification") != classification:
            raise _v10_error(
                "Stored v10 classification contradicts ground truth and result."
            )
        recomputed_records.append({**record, "classification": classification})
    if observed_keys != expected_keys:
        raise _v10_error("The v10 measurement plan is incomplete.")
    if _first_difference(report.get("counts"), counts(recomputed_records)) is not None:
        raise _v10_error("v10 aggregate counts disagree with records.")
    metadata = report.get("targets")
    if type(metadata) is not dict or metadata.keys() != targets.keys():
        raise _v10_error("v10 target metadata does not match declared targets.")
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
            raise _v10_error(f"v10 target metadata for {target_id!r} is incomplete.")
        for field in (
            "archive_sha256",
            "commit",
            "dbms",
            "license",
            "name",
            "repository",
        ):
            if value[field] != target[field]:
                raise _v10_error(
                    f"v10 target metadata for {target_id!r} differs from prepared provenance at field {field}. Rerun preparation and measurement."
                )
        image_ids = value["image_ids"]
        if (
            type(image_ids) is not dict
            or image_ids.keys() != {"app"}
            or not is_image_digest(image_ids.get("app"))
            or not is_sha256(value["source_manifest_sha256"])
        ):
            raise _v10_error(
                f"v10 target metadata for {target_id!r} cannot be identified. Rerun prepare before measurement."
            )
        try:
            validate_service_image_mapping(
                target_id, value["service_images"], target.get("service_images")
            )
        except ServiceImageMismatch:
            raise _v10_error(
                f"targets.{target_id}.service_images observed JSON type object with invalid entries. Expected only declared digest-pinned images. Rerun preparation."
            ) from None
    return report


_V9_REMEASURE_MESSAGE = (
    "Schema v9 lacks per-attempt evidence and structured decision facts required "
    "by schema v10. Re-run: uv run --locked python "
    "scripts/run_third_party_sqli_measurement.py --workspace "
    "/tmp/vintar-third-party-sqli --output "
    "/tmp/vintar-third-party-sqli-report.json"
)


def validate_measurement_report(report: object) -> dict[str, object]:
    """Accept only current schema v10 output."""
    if (
        type(report) is dict
        and type(report.get("schema_version")) is int
        and report.get("schema_version") <= 9
    ):
        raise MeasurementError(_V9_REMEASURE_MESSAGE)
    return _validate_v10_measurement_report(report)


class _ResponseRecorder:
    """Order sanitized responses by request acceptance, never thread completion."""

    def __init__(self) -> None:
        self.responses: dict[int, RecordedResponse] = {}
        self.response_condition = threading.Condition()
        self.next_sequence = 0
        self.terminal_states: dict[int, str] = {}
        self.recording_error: str | None = None
        self.failure: BridgeHandlerFailure | None = None

    def accept(self) -> int:
        with self.response_condition:
            sequence = self.next_sequence
            self.next_sequence += 1
            self.terminal_states[sequence] = "active"
            return sequence

    def record_response(self, sequence: int, response: RecordedResponse) -> None:
        with self.response_condition:
            if sequence in self.responses:
                self.recording_error = (
                    f"The loopback recorder produced duplicate sequence number {sequence}. "
                    "Check the bridge recorder and rerun the measurement instead of assigning one probe twice."
                )
                self.failure = BridgeHandlerFailure(
                    sequence=sequence,
                    exception_type="MeasurementError",
                    cause=self.recording_error,
                    accepted_sequences=tuple(range(self.next_sequence)),
                    completed_sequences=tuple(sorted(self.responses)),
                )
                self.response_condition.notify_all()
                raise MeasurementError(self.recording_error)
            self.responses[sequence] = response
            if sequence in self.terminal_states:
                self.terminal_states[sequence] = "response"
            self.response_condition.notify_all()

    def complete_without_response(self, sequence: int) -> None:
        with self.response_condition:
            if self.terminal_states.get(sequence) == "active":
                self.terminal_states[sequence] = "no_response"
            self.response_condition.notify_all()

    def synchronized_response_map(
        self,
        expected_sequences: frozenset[int],
        *,
        timeout_seconds: float = _WIRE_RESPONSE_WAIT_SECONDS,
    ) -> dict[int, RecordedResponse]:
        """After acceptance stops, settle handlers and match one-based wire responses."""
        if any(
            type(sequence) is not int or sequence < 1 for sequence in expected_sequences
        ):
            raise ValueError(
                "Expected wire response sequences must be positive integers."
            )
        with self.response_condition:
            complete = self.response_condition.wait_for(
                lambda: (
                    self.handler_failed or "active" not in self.terminal_states.values()
                ),
                timeout=timeout_seconds,
            )
            if not complete or self.handler_failed:
                raise MeasurementError(_WIRE_RESPONSE_WAIT_ERROR)
            responses = {
                sequence + 1: response for sequence, response in self.responses.items()
            }
            if responses.keys() != expected_sequences:
                raise MeasurementError(_WIRE_RESPONSE_SET_ERROR)
            return responses

    def record_failure(
        self, sequence: int | None, exception_type: str, cause: str
    ) -> None:
        with self.response_condition:
            if self.failure is None:
                self.failure = BridgeHandlerFailure(
                    sequence=sequence,
                    exception_type=exception_type,
                    cause=cause,
                    accepted_sequences=tuple(range(self.next_sequence)),
                    completed_sequences=tuple(sorted(self.responses)),
                )
            if sequence is not None and sequence in self.terminal_states:
                self.terminal_states[sequence] = "failed"
            self.response_condition.notify_all()

    @property
    def handler_failed(self) -> bool:
        return self.failure is not None


def _redacted_bridge_cause(exception: BaseException) -> str:
    if isinstance(exception, MeasurementError) and str(exception) in {
        _POOLED_CONNECTION_ERROR,
        _PROTOCOL_UPGRADE_ERROR,
    }:
        return str(exception)
    if isinstance(exception, MeasurementError):
        return (
            "The loopback bridge rejected invalid HTTP framing or request sequencing."
        )
    if isinstance(exception, TimeoutError):
        return "The loopback bridge exchange timed out."
    if isinstance(exception, OSError):
        return "The loopback bridge encountered a socket error."
    return "The loopback bridge handler raised an unexpected exception."


class _BridgeServer(socketserver.ThreadingTCPServer):
    """Byte-transparent loopback bridge to one private container address."""

    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, upstream: tuple[str, int]) -> None:
        self.upstream = upstream
        self.recorder = _ResponseRecorder()
        self.accepted_sequences: dict[int, int] = {}
        super().__init__(("127.0.0.1", 0), _BridgeHandler)

    def process_request(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        sequence = self.recorder.accept()
        with self.recorder.response_condition:
            self.accepted_sequences[id(request)] = sequence
        super().process_request(request, client_address)

    def claim_sequence(self, request: socket.socket) -> int:
        with self.recorder.response_condition:
            sequence = self.accepted_sequences.get(id(request))
            if sequence is None:
                raise MeasurementError(
                    "The loopback recorder lost an accepted request sequence. Check the bridge lifecycle and rerun the measurement."
                )
            return sequence

    def complete_sequence(self, request: socket.socket) -> None:
        with self.recorder.response_condition:
            sequence = self.accepted_sequences.pop(id(request), None)
        if sequence is not None:
            self.recorder.complete_without_response(sequence)

    def record_response(self, sequence: int, response: RecordedResponse) -> None:
        self.recorder.record_response(sequence, response)

    def synchronized_response_map(
        self,
        expected_sequences: frozenset[int],
        *,
        timeout_seconds: float = _WIRE_RESPONSE_WAIT_SECONDS,
    ) -> dict[int, RecordedResponse]:
        self.shutdown()
        self.server_close()
        return self.recorder.synchronized_response_map(
            expected_sequences,
            timeout_seconds=timeout_seconds,
        )

    @property
    def handler_failed(self) -> bool:
        return self.recorder.handler_failed

    def handle_error(self, request: object, client_address: tuple[str, int]) -> None:
        exception = sys.exception()
        if exception is None:
            exception = RuntimeError("The bridge handler failed without an exception.")
        with self.recorder.response_condition:
            sequence = self.accepted_sequences.get(id(request))
        self.recorder.record_failure(
            sequence,
            type(exception).__name__,
            _redacted_bridge_cause(exception),
        )


class _BridgeHandler(socketserver.BaseRequestHandler):
    """Forward bytes without parsing or modifying the HTTP exchange."""

    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _BridgeServer):
            raise TypeError("Unexpected loopback bridge server.")
        sequence = server.claim_sequence(self.request)
        response = bytearray()
        request = bytearray()
        request_complete = False
        with socket.create_connection(server.upstream, timeout=5) as upstream:
            peers = (self.request, upstream)
            while True:
                readable, _, _ = select.select(peers, (), (), 10)
                if not readable:
                    raise TimeoutError("Loopback bridge exchange timed out.")
                finished = False
                for source in readable:
                    content = source.recv(65536)
                    if not content:
                        finished = True
                        break
                    destination = upstream if source is self.request else self.request
                    if source is self.request:
                        if request_complete:
                            raise MeasurementError(_POOLED_CONNECTION_ERROR)
                        request.extend(content)
                        marker = request.find(b"\r\n\r\n")
                        if marker >= 0:
                            request_complete = True
                            if request[marker + 4 :]:
                                raise MeasurementError(_POOLED_CONNECTION_ERROR)
                    if source is upstream:
                        response.extend(content)
                    destination.sendall(content)
                if finished:
                    break
        if response:
            recorded = _parse_http_response(bytes(response))
            server.record_response(sequence, recorded)

    def finish(self) -> None:
        server = self.server
        if isinstance(server, _BridgeServer) and sys.exception() is None:
            server.complete_sequence(self.request)


def _chunked_body_chunks(body: bytes) -> tuple[tuple[bytes, ...], bytes]:
    remaining = body
    chunks: list[bytes] = []
    while True:
        line, separator, remaining = remaining.partition(b"\r\n")
        if not separator:
            raise MeasurementError(
                "The loopback recorder received an incomplete chunked response. Check the target HTTP framing and rerun the measurement."
            )
        try:
            size = int(line.split(b";", 1)[0], 16)
        except ValueError as exc:
            raise MeasurementError(
                "The loopback recorder received invalid chunk framing. Check the target HTTP response and rerun the measurement."
            ) from exc
        if size == 0:
            if remaining.startswith(b"\r\n"):
                return tuple(chunks), remaining[2:]
            trailer_end = remaining.find(b"\r\n\r\n")
            if trailer_end < 0:
                raise MeasurementError(
                    "The loopback recorder received incomplete chunk trailers. Check the target HTTP framing and rerun the measurement."
                )
            return tuple(chunks), remaining[trailer_end + 4 :]
        if len(remaining) < size + 2 or remaining[size : size + 2] != b"\r\n":
            raise MeasurementError(
                "The loopback recorder received a truncated chunk. Check the target HTTP response and rerun the measurement."
            )
        chunks.append(remaining[:size])
        remaining = remaining[size + 2 :]


def _recorded_response(status_code: int, chunks: Iterator[bytes]) -> RecordedResponse:
    digest = hashlib.sha256()
    body_size = 0
    for chunk in chunks:
        body_size += len(chunk)
        digest.update(chunk)
    return RecordedResponse(status_code, body_size, digest.hexdigest())


def _parse_http_response(response: bytes) -> RecordedResponse:
    remaining = response
    while True:
        headers, separator, body = remaining.partition(b"\r\n\r\n")
        lines = headers.split(b"\r\n")
        if not separator or not lines:
            raise MeasurementError(
                "The loopback recorder could not parse a complete HTTP response header. Check the target transport and rerun the measurement."
            )
        status = lines[0].split(b" ", 2)
        try:
            status_code = int(status[1])
        except (IndexError, ValueError) as exc:
            raise MeasurementError(
                "The loopback recorder received an invalid HTTP status line. Check the target transport and rerun the measurement."
            ) from exc
        if not 100 <= status_code <= 599:
            raise MeasurementError(
                "The loopback recorder received an out-of-range HTTP status. Check the target transport and rerun the measurement."
            )
        if status_code == 101:
            raise MeasurementError(_PROTOCOL_UPGRADE_ERROR)
        if 100 <= status_code < 200:
            remaining = body
            if not remaining:
                raise MeasurementError(
                    "The loopback recorder received an interim HTTP response without a final response. Check the target response and rerun the measurement."
                )
            continue
        break

    header_values: dict[bytes, bytes] = {}
    for line in lines[1:]:
        name, marker, value = line.partition(b":")
        if marker:
            header_values[name.strip().lower()] = value.strip().lower()
    if status_code in {204, 304}:
        if body:
            raise MeasurementError(_POOLED_CONNECTION_ERROR)
        chunks: Iterator[bytes] | tuple[bytes, ...] = ()
    elif b"chunked" in header_values.get(b"transfer-encoding", b""):
        chunks, extra = _chunked_body_chunks(body)
        if extra:
            raise MeasurementError(_POOLED_CONNECTION_ERROR)
    elif b"content-length" in header_values:
        try:
            length = int(header_values[b"content-length"])
        except ValueError as exc:
            raise MeasurementError(
                "The loopback recorder received an invalid Content-Length. Check the target response and rerun the measurement."
            ) from exc
        if len(body) > length:
            raise MeasurementError(_POOLED_CONNECTION_ERROR)
        if len(body) < length:
            raise MeasurementError(
                "The loopback recorder body length disagrees with Content-Length. Check the target response and rerun the measurement."
            )
        chunks = iter((body,))
    else:
        chunks = iter((body,))
    return _recorded_response(status_code, chunks)


def measurement_http_transport() -> httpx.HTTPTransport:
    """Build the trusted maintainer transport with connection reuse disabled."""
    return httpx.HTTPTransport(
        limits=httpx.Limits(max_keepalive_connections=0),
    )


@contextmanager
def loopback_bridge(
    upstream_host: str, target: TargetAdapter
) -> Iterator[tuple[str, _BridgeServer]]:
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
        yield f"http://127.0.0.1:{port}", server
    finally:
        pending_error = sys.exception()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        preserving_wire_wait_error = (
            isinstance(pending_error, MeasurementError)
            and str(pending_error) == _WIRE_RESPONSE_WAIT_ERROR
        )
        if server.recorder.failure is not None and not preserving_wire_wait_error:
            failure = server.recorder.failure
            sequence = "unknown" if failure.sequence is None else str(failure.sequence)
            raise MeasurementError(
                f"The {target.target_id} loopback bridge handler failed at sequence {sequence} "
                f"with {failure.exception_type}: {failure.cause} "
                f"Accepted sequences: {list(failure.accepted_sequences)!r}; completed sequences: {list(failure.completed_sequences)!r}. "
                "Fix the bridge transport or response framing, then rerun the measurement."
            ) from None
        if thread.is_alive():
            raise MeasurementError(
                f"The {target.target_id} loopback bridge serve thread did not stop. Check outstanding handler lifecycle before rerunning the measurement."
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
    recorder: _BridgeServer,
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

    loaded_case = load_regression_case(case)
    collector = ObservationCollector()
    policy = TrustedExecutionPolicy(
        scope=loaded_case.scope,
        max_requests=max_requests,
        max_requests_per_second=10,
        max_timeout_seconds=5,
        max_time_execution_seconds=60,
        max_response_size=loaded_case.max_response_size,
    )
    with measurement_http_transport() as transport:
        result = run_regression_batch(
            [loaded_case],
            policy=policy,
            transport=transport,
            observation_sink=collector,
        )
    verified = regression_batch_report_dict(result)
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
    runtime_outcome = result.outcomes[0]
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
    decision_facts = outcome.get("decision_facts")
    collected = collector.attempts()
    counted_attempts = sum(
        item.outcome is not AttemptOutcome.NOT_DISPATCHED for item in collected
    )
    if counted_attempts != request_count:
        raise MeasurementError(
            "Trusted attempt accounting contradicts the product request count. "
            "Check terminal runner emission and rerun the measurement."
        )
    expected_wire_sequences = frozenset(
        item.sequence for item in collected if item.outcome is AttemptOutcome.RESPONSE
    )
    attempts = sanitized_attempts(
        collected,
        recorder.synchronized_response_map(expected_wire_sequences),
        decision_facts=decision_facts,
    )
    classification = classify(check_type, label, verdict, reason)
    if classification == "non_decision" and decision_facts is None:
        raise MeasurementError(
            "A measured non-decision omitted production decision_facts. Add the "
            "bounded facts where the check chooses its reason, then rerun instead "
            "of deriving facts in the report layer."
        )
    report_record: dict[str, object] = {
        "actual_verdict": verdict,
        "attempts": attempts,
        "check_type": check_type,
        "classification": classification,
        "detail": detail,
        "endpoint_id": record_id,
        "expected_label": label,
        "expected_verdict": expected_verdict,
        "mode": report_mode,
        "reason_code": reason,
        "request_count": request_count,
        "target_id": target_id,
    }
    if decision_facts is not None:
        report_record["decision_facts"] = decision_facts
    if type(runtime_outcome) is TimeRegressionOutcome:
        evidence = runtime_outcome.time_run.analysis.evidence
        if evidence is not None:
            predicates = time_decision_inputs(
                evidence, runtime_outcome.time_run.analysis.expected_delay_seconds
            )
            report_record["time_predicates"] = {
                name: getattr(predicates, name)
                for name in TimeDecisionInputs.__dataclass_fields__
            }
    return report_record


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
    return _render_summary(report)


def _render_summary(report: dict[str, object]) -> str:
    """Render a report after its caller selected the applicable contract."""
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


def check_documented_summary(report: object, documentation: Path = DOCS) -> str:
    """Reject actual results that differ from the committed reviewed summary."""
    if type(report) is not dict:
        raise MeasurementError(_NON_OBJECT_REPORT_MESSAGE)
    validate_measurement_report(report)
    try:
        text = documentation.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise MeasurementError(
            "The third-party evaluation document is unreadable. Restore the reviewed summary and rerun."
        ) from exc
    reviewed_version = REVIEWED_SCHEMA_PATTERN.search(text)
    report_version = report.get("schema_version")
    if reviewed_version is None or int(reviewed_version.group(1)) != report_version:
        found = reviewed_version.group(1) if reviewed_version is not None else "missing"
        raise MeasurementError(
            f"The reviewed documentation is bound to report schema version {found}, but fixture schema_version has JSON type {_json_type(report_version)} outside the bound version. Expected the integer specified by the docs binding. After a real measurement, update the documented schema binding and fixture together; do not fabricate or silently upgrade evidence."
        )
    expected = _render_summary(report)
    if expected not in text:
        raise MeasurementError(
            "Actual third-party results differ from docs/sqli-third-party-evaluation.md. Review the saved report and update the documented summary instead of accepting drift silently."
        )
    return expected


def write_report(path: Path, report: dict[str, object]) -> None:
    """Atomically save an actual report outside the repository."""
    validate_measurement_report(report)
    if report.get("schema_version") != MEASUREMENT_SCHEMA_VERSION:
        raise MeasurementError(
            "New measurement output requires schema version 10 with per-attempt "
            "evidence and structured decision facts. Re-run "
            "scripts/run_third_party_sqli_measurement.py on current main instead "
            "of writing a legacy fixture."
        )
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
            with loopback_bridge(upstream, planned.target) as (origin, recorder):
                records.append(
                    run_pipeline_case(case_folder, origin, planned, recorder)
                )
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
