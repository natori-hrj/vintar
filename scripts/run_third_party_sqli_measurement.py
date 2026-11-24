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
from enum import Enum
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

from vintar.checks.sqli.confirmation import CONFIRMATION_ORDER, ConfirmationKind
from vintar.checks.sqli.confirmation_runner import ConfirmationObservation
from vintar.checks.sqli.error_analyzer import (
    ERROR_PROBE_ORDER,
    ErrorMatch,
    ErrorObservation,
    ErrorProbeKind,
    classify_error_observations,
)
from vintar.checks.sqli.error_contract import ERROR_RESULT_RULES
from vintar.checks.sqli.error_signatures import ERROR_SIGNATURES
from vintar.checks.sqli.models import Observation
from vintar.checks.sqli.observation_sink import RecordedSqliObservation
from vintar.checks.sqli.orchestrator import BOOLEAN_PROBE_ORDER
from vintar.checks.sqli.time_analyzer import TimeObservation, TimeProbeOutcome
from vintar.checks.sqli.time_plan import TIME_PROBE_ORDER
from vintar.regression import (
    TrustedExecutionPolicy,
    load_regression_case,
    regression_batch_report_dict,
    run_regression_batch,
)

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
MEASUREMENT_SCHEMA_VERSION = 9
UNRELIABLE_EVIDENCE_SCHEMA_VERSIONS = frozenset({5, 6, 7, 8})
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


def derive_relations(evidence: list[dict[str, object]]) -> dict[str, bool]:
    """Derive analyzer response relations from decoded observation evidence."""
    signatures = _boolean_role_signatures(evidence)
    relations = {
        f"{role}_stable": len(set(values)) == 1
        for role, values in sorted(signatures.items())
    }
    for left, right in (
        ("baseline", "true"),
        ("baseline", "false"),
        ("true", "false"),
        ("baseline", "control"),
        ("baseline", "true2"),
        ("false", "false2"),
        ("baseline", "error"),
    ):
        if left in signatures and right in signatures:
            relations[f"{left}_equals_{right}"] = (
                len(set(signatures[left])) == 1
                and len(set(signatures[right])) == 1
                and signatures[left][0] == signatures[right][0]
            )
    return relations


def sanitized_probe_evidence(
    roles: tuple[str, ...],
    responses: tuple[RecordedResponse, ...],
    observations: tuple[RecordedSqliObservation, ...],
    *,
    check_type: str,
    expected_kinds: tuple[str, ...] | None = None,
) -> tuple[list[dict[str, object]], dict[str, bool]]:
    """Discard bodies after deriving bounded, non-sensitive response evidence."""
    if len(roles) != len(responses) or len(roles) != len(observations):
        raise MeasurementError(
            "Wire responses and analyzer observations differ from the fixed request plan. Check the trusted observation sink and loopback recorder, then rerun instead of pairing incomplete evidence."
        )
    evidence: list[dict[str, object]] = []
    for sequence, (role, response, recorded) in enumerate(
        zip(roles, responses, observations, strict=True), start=1
    ):
        expected_kind = role if expected_kinds is None else expected_kinds[sequence - 1]
        expected_family = check_type.removeprefix("sqli.")
        if check_type == "sqli.boolean" and sequence > len(BOOLEAN_PROBE_ORDER):
            expected_family = "confirmation"
        if (
            recorded.sequence != sequence
            or recorded.kind != expected_kind
            or recorded.family != expected_family
        ):
            raise MeasurementError(
                f"Analyzer observation sequence, family, or role mismatch at request {sequence}: expected {expected_family}/{expected_kind}, observed sequence {recorded.sequence} {recorded.family}/{recorded.kind}. Check runner observation emission and rerun the measurement."
            )
        observation = recorded.observation
        status = getattr(observation, "status_code", None)
        if status != response.status_code:
            raise MeasurementError(
                f"Wire and analyzer status disagree at request {sequence}: wire {response.status_code}, analyzer {status!r}. Check the bridge and trusted observation sink, then rerun the measurement."
            )
        item: dict[str, object] = {
            "role": role,
            "sequence": sequence,
            "wire_status_code": response.status_code,
            "wire_body_size": response.body_size,
            "wire_body_sha256": response.body_sha256,
        }
        if isinstance(
            observation, (Observation, ConfirmationObservation, ErrorObservation)
        ):
            item.update(
                analyzer_status_code=observation.status_code,
                analyzer_body_size=observation.body_size,
                analyzer_body_sha256=observation.body_digest,
                truncated=observation.truncated,
            )
            if isinstance(observation, (Observation, ConfirmationObservation)):
                item.update(
                    normalization_applied=observation.normalization_applied,
                    normalized_echo_count=observation.normalized_echo_count,
                )
        elif type(observation) is TimeObservation:
            item.update(
                analyzer_status_code=observation.status_code,
                outcome=observation.outcome.value,
                truncated=observation.truncated,
            )
        else:
            raise MeasurementError(
                f"Analyzer observation at request {sequence} has an unsupported type. Check the production runner sink and rerun the measurement."
            )
        if check_type == "sqli.error" and type(observation) is ErrorObservation:
            item.update(
                matches=[
                    {"dbms": match.dbms, "signature_id": match.signature_id}
                    for match in observation.matches
                ],
            )
        evidence.append(item)
    return evidence, derive_relations(evidence)


def _boolean_relation_is_stable(relations: dict[str, object]) -> bool:
    return all(
        relations.get(f"{role}_stable") is True
        for role in ("baseline", "true", "false")
    )


def _boolean_role_signatures(
    evidence: list[dict[str, object]],
) -> dict[str, list[tuple[object, object, object]]]:
    signatures: dict[str, list[tuple[object, object, object]]] = {}
    for item in evidence:
        role = item.get("role")
        digest = item.get("analyzer_body_sha256")
        if type(role) is str and type(digest) is str:
            signatures.setdefault(role, []).append(
                (
                    item.get("analyzer_status_code"),
                    item.get("analyzer_body_size"),
                    digest,
                )
            )
    return signatures


def _confirmation_pair_state(
    evidence: list[dict[str, object]],
) -> tuple[bool, bool]:
    """Return per-kind stability and cross-predicate reproduction."""
    signatures = _boolean_role_signatures(evidence)
    roles = ("baseline", "true", "false", "control", "true2", "false2")
    per_kind_stable = all(
        len(signatures.get(role, ())) == 2 and len(set(signatures[role])) == 1
        for role in roles
    )
    pairs_reproduced = (
        per_kind_stable
        and signatures["true"][0] == signatures["true2"][0]
        and signatures["false"][0] == signatures["false2"][0]
    )
    return per_kind_stable, pairs_reproduced


def _confirmation_remaining_relation_matches(
    evidence: list[dict[str, object]],
) -> bool:
    signatures = _boolean_role_signatures(evidence)
    return (
        signatures["baseline"][0] == signatures["true"][0]
        and signatures["baseline"][0] == signatures["control"][0]
        and signatures["baseline"][0] != signatures["false"][0]
    )


class _ConfirmationReasonRules(Enum):
    REVIEWED_V8 = 8
    CURRENT_V9 = 9


def _validate_reason_evidence(
    record: dict[str, object],
    evidence: list[dict[str, object]],
    relations: dict[str, object],
    *,
    confirmation_rules: _ConfirmationReasonRules,
) -> None:
    endpoint = required_text(record, "endpoint_id", "report record")
    check_type = required_text(record, "check_type", "report record")
    reason = required_text(record, "reason_code", "report record")
    statuses = [item["analyzer_status_code"] for item in evidence]
    all_success = all(type(value) is int and 200 <= value < 300 for value in statuses)
    stable = _boolean_relation_is_stable(relations)
    if check_type == "sqli.boolean" and reason == "unexpected_difference":
        expected = (
            all_success
            and stable
            and relations.get("baseline_equals_true") is False
            and relations.get("baseline_equals_false") is False
            and relations.get("true_equals_false") is False
        )
        if not expected:
            raise MeasurementError(
                f"Probe evidence for {endpoint!r} contradicts unexpected_difference: it requires all 2xx responses, stable repeated baseline/true/false pairs, and three pairwise-distinct digests. Remeasure the target and fix the recorder or reason instead of hand-editing evidence."
            )
    if check_type == "sqli.boolean" and reason == "boolean_candidate":
        initial_candidate = (
            all_success
            and stable
            and relations.get("baseline_equals_true") is True
            and relations.get("baseline_equals_false") is False
            and relations.get("true_equals_false") is False
        )
        if not initial_candidate:
            raise MeasurementError(
                f"Probe evidence for {endpoint!r} contradicts boolean_candidate: it requires stable 2xx baseline/true/false pairs with baseline equal to true and different from false. Remeasure the target and fix the recorder or reason instead of hand-editing evidence."
            )
        detail = record.get("detail")
        if type(detail) is dict and detail.get("status") == "matched":
            confirmation_match = all(
                relations.get(name) is True
                for name in (
                    "control_stable",
                    "true2_stable",
                    "false2_stable",
                    "baseline_equals_control",
                    "baseline_equals_true2",
                    "false_equals_false2",
                )
            )
            if not confirmation_match:
                raise MeasurementError(
                    f"Probe evidence for {endpoint!r} contradicts confirmation_pattern_matched. Remeasure the target so both confirmation pairs and the baseline-preserving control reproduce the declared relation."
                )
    if check_type == "sqli.boolean" and reason in {
        "candidate_confirmation_mismatch",
        "confirmation_unstable",
    }:
        if confirmation_rules is _ConfirmationReasonRules.REVIEWED_V8:
            if reason == "candidate_confirmation_mismatch" and not (
                all_success
                and stable
                and relations.get("baseline_equals_true") is True
                and relations.get("baseline_equals_false") is False
                and relations.get("true_equals_false") is False
                and not all(
                    relations.get(name) is True
                    for name in (
                        "baseline_equals_control",
                        "baseline_equals_true2",
                        "false_equals_false2",
                    )
                )
            ):
                raise MeasurementError(
                    f"Probe evidence for {endpoint!r} contradicts the reviewed v8 "
                    "candidate_confirmation_mismatch rule. Restore the reviewed stable "
                    "2xx evidence of an initial candidate and a mismatching confirmation "
                    "relation, or remeasure with the current runner."
                )
            return
        initial_evidence = evidence[: len(BOOLEAN_PROBE_ORDER)]
        confirmation_evidence = evidence[len(BOOLEAN_PROBE_ORDER) :]
        initial_relations = derive_relations(initial_evidence)
        initial_candidate = (
            len(initial_evidence) == len(BOOLEAN_PROBE_ORDER)
            and _boolean_relation_is_stable(initial_relations)
            and initial_relations.get("baseline_equals_true") is True
            and initial_relations.get("baseline_equals_false") is False
            and initial_relations.get("true_equals_false") is False
        )
        complete_confirmation = len(confirmation_evidence) == len(CONFIRMATION_ORDER)
        per_kind_stable, pairs_reproduced = _confirmation_pair_state(
            confirmation_evidence
        )
        remaining_relation_matches = (
            per_kind_stable
            and _confirmation_remaining_relation_matches(confirmation_evidence)
        )
        if reason == "candidate_confirmation_mismatch" and not (
            all_success
            and initial_candidate
            and complete_confirmation
            and pairs_reproduced
            and not remaining_relation_matches
        ):
            raise MeasurementError(
                f"Probe evidence for {endpoint!r} contradicts candidate_confirmation_mismatch: both confirmation predicate pairs must be stable and reproduced before the remaining relation can mismatch. Remeasure the target with the current runner instead of hand-editing the reason."
            )
        if reason == "confirmation_unstable" and not (
            all_success
            and initial_candidate
            and complete_confirmation
            and (not per_kind_stable or not pairs_reproduced)
        ):
            raise MeasurementError(
                f"Probe evidence for {endpoint!r} contradicts confirmation_unstable: an eligible initial candidate must complete all confirmation requests and show an unstable repeated kind or unreproduced TRUE/FALSE predicate pair. Remeasure the target with the current runner instead of hand-editing the reason."
            )
    if (
        check_type == "sqli.boolean"
        and reason == "no_boolean_difference"
        and not (
            all_success
            and stable
            and relations.get("baseline_equals_true") is True
            and relations.get("baseline_equals_false") is True
            and relations.get("true_equals_false") is True
        )
    ):
        raise MeasurementError(
            f"Probe evidence for {endpoint!r} contradicts no_boolean_difference. Remeasure the target so stable 2xx baseline, true, and false digests all match."
        )
    if (
        check_type == "sqli.boolean"
        and reason == "no_boolean_difference_literal_input"
        and not (
            all_success
            and stable
            and relations.get("baseline_equals_true") is False
            and relations.get("baseline_equals_false") is False
            and relations.get("true_equals_false") is True
        )
    ):
        raise MeasurementError(
            f"Probe evidence for {endpoint!r} contradicts no_boolean_difference_literal_input. Remeasure the target so stable 2xx true and false digests match each other but differ from baseline."
        )
    if (
        check_type == "sqli.time"
        and reason
        in {
            "timing_pattern_matched",
            "timing_pattern_not_matched",
            "unstable_timing",
            "ambiguous_timing",
        }
        and not all_success
    ):
        raise MeasurementError(
            f"Probe evidence for {endpoint!r} contradicts {reason}: timing analysis requires completed 2xx responses. Remeasure the target and preserve a transport reason for non-2xx evidence."
        )


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


def _validate_error_probe_evidence(
    record: dict[str, object], evidence: list[dict[str, object]], record_index: int
) -> None:
    """Reclassify sanitized Error observations through the product analyzer."""
    endpoint = required_text(record, "endpoint_id", "report record")
    observations: list[ErrorObservation] = []
    for sequence, item in enumerate(evidence, start=1):
        role = item["role"]
        kind = ErrorProbeKind.BASELINE if role == "baseline" else ErrorProbeKind.PROBE
        raw_matches = item["matches"]
        if type(raw_matches) is not list:
            raise MeasurementError(
                f"Error probe evidence for {endpoint!r} has invalid signature matches. Remeasure the target so reviewed DBMS/signature facts are recorded instead of hand-edited."
            )
        try:
            matches = tuple(
                ErrorMatch(match["dbms"], match["signature_id"])
                for match in raw_matches
                if type(match) is dict and match.keys() == {"dbms", "signature_id"}
            )
            if len(matches) != len(raw_matches):
                raise ValueError
            observation = ErrorObservation(
                kind=kind,
                sequence=sequence,
                status_code=item["analyzer_status_code"],
                body_size=item["analyzer_body_size"],
                body_digest=item["analyzer_body_sha256"],
                truncated=item["truncated"],
                matches=matches,
            )
        except (KeyError, TypeError, ValueError):
            raise MeasurementError(
                f"Error probe evidence for {endpoint!r} has invalid analyzer facts. Remeasure the target so truncation and sorted reviewed signature matches are recorded mechanically."
            ) from None
        observations.append(observation)
    try:
        status, reason, classified_evidence = classify_error_observations(
            tuple(observations)
        )
    except (TypeError, ValueError):
        raise MeasurementError(
            f"Error probe evidence for {endpoint!r} at records[{record_index}].evidence "
            "is an array that cannot form the bounded analyzer sequence. Expected an "
            "array of analyzer facts in the fixed request order. Remeasure the target "
            "instead of hand-editing evidence."
        ) from None
    detail = record.get("detail")
    expected_evidence = (
        None
        if classified_evidence is None
        else (classified_evidence.dbms, classified_evidence.signature_id)
    )
    stored_evidence = (
        (detail.get("dbms"), detail.get("signature_id"))
        if type(detail) is dict and "dbms" in detail and "signature_id" in detail
        else None
    )
    if (
        record.get("reason_code") != reason
        or type(detail) is not dict
        or detail.get("status") != status.value
        or stored_evidence != expected_evidence
    ):
        raise MeasurementError(
            f"Error probe evidence for {endpoint!r} classifies as {status.value}/{reason} with evidence {expected_evidence!r}, which contradicts the stored Error result. Remeasure the target so the report is produced by classify_error_observations instead of hand-editing it."
        )


def _validate_probe_evidence(
    record: dict[str, object],
    record_index: int,
    *,
    require_normalization_evidence: bool,
    confirmation_rules: _ConfirmationReasonRules,
) -> None:
    """Validate strict wire provenance and analyzer observation evidence."""
    endpoint = required_text(record, "endpoint_id", "report record")
    location = f"Measurement record {endpoint!r} (records[{record_index}])"
    evidence = record.get("evidence")
    relations = record.get("relations")
    if type(evidence) is not list or type(relations) is not dict:
        raise MeasurementError(
            f"{location} lacks strict request evidence or derived relations. Remeasure with the current runner instead of fabricating probe evidence."
        )
    planned_roles = PROBE_ROLE_ORDERS.get(
        (record.get("check_type"), record.get("mode"))
    )
    request_count = record.get("request_count")
    if type(request_count) is not int or request_count < 0:
        raise MeasurementError(
            f"{location} request_count observed JSON type {_json_type(request_count)}. Expected a nonnegative JSON integer. Remeasure the target instead of hand-editing request accounting."
        )
    expected_roles = (
        planned_roles[:request_count]
        if planned_roles is not None and type(request_count) is int
        else None
    )
    if record.get("request_count") != len(evidence):
        raise MeasurementError(
            f"{location} request_count differs from its evidence entry count. Remeasure the target so every request has exactly one sanitized evidence entry."
        )
    if (
        expected_roles is None
        or tuple(item.get("role") if type(item) is dict else None for item in evidence)
        != expected_roles
    ):
        raise MeasurementError(
            f"{location} evidence roles do not match the fixed request order. Remeasure the target and fix the recorder instead of reordering evidence."
        )
    expected_fields = {
        "sequence",
        "role",
        "wire_status_code",
        "wire_body_size",
        "wire_body_sha256",
        "analyzer_status_code",
        "truncated",
    }
    if record.get("check_type") == "sqli.time":
        expected_fields.add("outcome")
    else:
        expected_fields.update(("analyzer_body_size", "analyzer_body_sha256"))
    if record.get("check_type") == "sqli.error":
        expected_fields.add("matches")
    boolean_normalization_fields = {
        "normalization_applied",
        "normalized_echo_count",
    }
    if record.get("check_type") == "sqli.boolean" and require_normalization_evidence:
        expected_fields.update(boolean_normalization_fields)
    for index, item in enumerate(evidence, start=1):
        if type(item) is not dict or item.keys() != expected_fields:
            fields = ", ".join(sorted(expected_fields))
            raise MeasurementError(
                f"{location} evidence entry {index} has invalid fields. "
                f"Expected exactly: {fields}. Remeasure instead of hand-editing the evidence."
            )
        sequence = item["sequence"]
        if type(sequence) is not int or sequence != index:
            raise MeasurementError(
                f"{location} evidence entry {index} sequence observed JSON type {_json_type(sequence)}. Expected JSON integer {index}. Remeasure the target so production request order is recorded exactly."
            )
        if (
            type(item["wire_status_code"]) is not int
            or not 100 <= item["wire_status_code"] <= 599
            or type(item["wire_body_size"]) is not int
            or item["wire_body_size"] < 0
            or type(item["wire_body_sha256"]) is not str
            or not is_sha256(item["wire_body_sha256"])
            or type(item["analyzer_status_code"]) is not int
            or not 100 <= item["analyzer_status_code"] <= 599
            or item["wire_status_code"] != item["analyzer_status_code"]
            or type(item["truncated"]) is not bool
        ):
            raise MeasurementError(
                f"{location} evidence entry {index} has an invalid status, size, or body digest. Remeasure the target to regenerate bounded non-sensitive evidence."
            )
        if record.get("check_type") != "sqli.time" and (
            type(item["analyzer_body_size"]) is not int
            or item["analyzer_body_size"] < 0
            or type(item["analyzer_body_sha256"]) is not str
            or not is_sha256(item["analyzer_body_sha256"])
        ):
            raise MeasurementError(
                f"{location} evidence entry {index} has invalid analyzer body facts. Remeasure the target to record the exact production observation."
            )
        if (
            record.get("check_type") == "sqli.boolean"
            and boolean_normalization_fields <= item.keys()
        ):
            applied = item["normalization_applied"]
            count = item["normalized_echo_count"]
            if (
                type(applied) is not bool
                or type(count) is not int
                or count < 0
                or applied != (count > 0)
            ):
                raise MeasurementError(
                    f"{location} evidence entry {index} has inconsistent Boolean echo-normalization metadata. Expected a JSON boolean and a nonnegative JSON integer that is positive exactly when normalization changed the analyzer body. Remeasure with the production Boolean analyzer instead of hand-editing evidence."
                )
        if record.get("check_type") == "sqli.time":
            outcome = item["outcome"]
            if type(outcome) is not str or outcome not in TIME_PROBE_OUTCOMES:
                allowed = ", ".join(sorted(TIME_PROBE_OUTCOMES))
                membership = " outside the allowed set" if type(outcome) is str else ""
                raise MeasurementError(
                    f"{location} evidence entry {index} outcome observed JSON type {_json_type(outcome)}{membership}. Expected a string emitted by TimeProbeOutcome. Allowed values: {allowed}. Remeasure the target instead of hand-editing analyzer evidence."
                )
    derived = derive_relations(evidence)
    if relations != derived:
        raise MeasurementError(
            f"{location} relations disagree with its body digests. Remeasure the target so relations are derived mechanically instead of hand-edited."
        )
    _validate_reason_evidence(
        record, evidence, relations, confirmation_rules=confirmation_rules
    )
    if record.get("check_type") == "sqli.error":
        _validate_error_probe_evidence(record, evidence, record_index)


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


def _validate_measurement_report(
    report: object,
    *,
    reviewed_schema_version: int | None,
) -> dict[str, object]:
    """Validate current output or one explicitly docs-bound reviewed fixture."""
    if type(report) is not dict:
        raise MeasurementError(_NON_OBJECT_REPORT_MESSAGE)
    version = report.get("schema_version")
    reviewed_v8 = version == 8 and reviewed_schema_version == 8
    if (
        type(version) is int
        and version in UNRELIABLE_EVIDENCE_SCHEMA_VERSIONS
        and not reviewed_v8
    ):
        detail = (
            "v8 used the previous confirmation reason rules and cannot be interpreted under the v9 predicate-pair stability precedence"
            if version == 8
            else (
                "v7 lacks the required Boolean normalization_applied and normalized_echo_count evidence"
                if version == 7
                else "v5/v6 analytical facts were derived from wire bytes and are unreliable under HTTP content encoding"
            )
        )
        raise MeasurementError(
            f"Unsupported third-party measurement report schema version {version}: {detail}. Re-run scripts/run_third_party_sqli_measurement.py on current main to produce schema version 9 with the current confirmation reason contract."
        )
    if type(version) is not int or (
        version != MEASUREMENT_SCHEMA_VERSION and not reviewed_v8
    ):
        raise MeasurementError(
            f"Unsupported third-party measurement report schema_version: observed JSON type {_json_type(version)}. Expected the integer 9. Older report reason rules and shapes cannot be reinterpreted; re-run scripts/run_third_party_sqli_measurement.py on current main."
        )
    confirmation_rules = (
        _ConfirmationReasonRules.REVIEWED_V8
        if reviewed_v8
        else _ConfirmationReasonRules.CURRENT_V9
    )
    if report.keys() != {"counts", "records", "schema_version", "targets"}:
        raise MeasurementError(
            f"Invalid third-party measurement report v{version} top-level keys. Use targets, records, counts.overall, counts.by_target, and schema_version; rerun the current measurement instead of mixing report versions."
        )
    records = report["records"]
    counts_value = report["counts"]
    metadata = report["targets"]
    if type(records) is not list or type(metadata) is not dict:
        raise MeasurementError(
            f"Invalid third-party measurement report v{version} structure. Use target-keyed metadata, record objects, and both count trees; rerun the measurement."
        )
    targets, declarations = load_declarations()
    if metadata.keys() != targets.keys():
        raise MeasurementError(
            "Measurement target metadata differs at targets. Observed an object with missing or unexpected keys. Expected exactly the target IDs declared in targets.toml. Regenerate the report from prepared provenance instead of hand-editing it."
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
                f"Measurement target metadata differs for target {target_id!r}. Use complete prepared provenance and rerun the measurement."
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
        except ServiceImageMismatch:
            raise MeasurementError(
                f"Measurement target metadata at targets.{target_id}.service_images "
                f"observed JSON type {_json_type(service_images)} with invalid shape or image entries. "
                "Expected an object mapping service names to the digest-pinned images declared in "
                "targets.toml. Rerun preparation and measurement with matching Compose configuration."
            ) from None

    planned = list(plan_measurements(targets, declarations))
    expected_keys = {item.key for item in planned}
    declarations_by_key = {item.key: item.declaration for item in planned}
    record_keys: Counter[tuple[str, str, str, str]] = Counter()
    for record_index, record in enumerate(records):
        if type(record) is not dict:
            raise MeasurementError(
                "The third-party measurement report contains a non-object record. Rerun the measurement to regenerate it."
            )
        key_fields = ("target_id", "endpoint_id", "check_type", "mode")
        for field in key_fields:
            value = record.get(field)
            if type(value) is not str or not value:
                raise MeasurementError(
                    f"Measurement records[{record_index}].{field} observed JSON type "
                    f"{_json_type(value)}. Expected a reviewed nonempty string declared in "
                    "targets.toml. Regenerate the report with a full measurement run."
                )
        key = (
            record["target_id"],
            record["endpoint_id"],
            record["check_type"],
            record["mode"],
        )
        if key not in expected_keys:
            prefix_length = next(
                length
                for length in range(1, len(key) + 1)
                if not any(
                    expected[:length] == key[:length] for expected in expected_keys
                )
            )
            field = key_fields[prefix_length - 1]
            raise MeasurementError(
                f"Unexpected measurement record at records[{record_index}].{field}. "
                "Observed JSON type string outside the allowed set. Expected a string "
                "matching a planned record in targets.toml. Regenerate the report with a full measurement run."
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
    if missing := expected_keys.difference(record_keys):
        target_id, endpoint_id, check_type, mode = min(missing)
        raise MeasurementError(
            f"The measurement report is incomplete: missing target_id {target_id!r}, endpoint_id {endpoint_id!r}, check_type {check_type!r}, mode {mode!r}. Regenerate the report with a full measurement run."
        )

    recomputed_records: list[dict[str, object]] = []
    for record_index, record in enumerate(records):
        if version in {7, 8, MEASUREMENT_SCHEMA_VERSION} and record.keys() != {
            "actual_verdict",
            "check_type",
            "classification",
            "detail",
            "endpoint_id",
            "evidence",
            "expected_label",
            "expected_verdict",
            "mode",
            "reason_code",
            "relations",
            "request_count",
            "target_id",
        }:
            raise MeasurementError(
                f"Invalid v{version} fields for measurement record {record.get('endpoint_id')!r}. Store only the reviewed result, sanitized evidence, and derived relations; remove payloads, bodies, headers, cookies, and URLs by remeasuring with the current runner."
            )
        if type(record.get("detail")) is not dict or "confirmation" in record:
            raise MeasurementError(
                f"Invalid third-party measurement report v{version} record. Use target_id, check_type, and the sibling detail object; rerun instead of mixing an older record shape."
            )
        check_type = record.get("check_type")
        if (
            check_type not in CLASSIFICATIONS
            or record.get("classification") not in CLASSIFICATIONS[check_type]
        ):
            raise MeasurementError(
                f"Measurement record for check type {record.get('check_type')}, mode {record.get('mode')} has an invalid records[{record_index}].classification. Observed JSON type {_json_type(record.get('classification'))} outside the allowed set. Expected a string in {CLASSIFICATIONS[check_type]}. Rerun the measurement."
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
                f"Measurement record {key[1]!r} records[{record_index}].expected_verdict contradicts ground-truth label {ground_truth!r}. Observed JSON type {_json_type(record.get('expected_verdict'))}. Expected string {expected_verdict!r}. Remeasure the target; do not hand-edit reports."
            )
        verdict = required_text(record, "actual_verdict", "report record")
        reason = required_text(record, "reason_code", "report record")
        classification = classify(key[2], ground_truth, verdict, reason)
        if record.get("classification") != classification:
            raise MeasurementError(
                f"Measurement record {key[1]!r} records[{record_index}].classification contradicts ground truth {ground_truth!r} and the reported verdict/reason. Observed JSON type {_json_type(record.get('classification'))}. Expected string {classification!r}. Remeasure the target; do not hand-edit reports."
            )
        if check_type == "sqli.error":
            _validate_error_detail(record, record_index)
        if version in {7, 8, MEASUREMENT_SCHEMA_VERSION}:
            _validate_probe_evidence(
                record,
                record_index,
                require_normalization_evidence=version
                in {8, MEASUREMENT_SCHEMA_VERSION},
                confirmation_rules=confirmation_rules,
            )
        elif "evidence" in record or "relations" in record:
            raise MeasurementError(
                f"Legacy v4 measurement record {key[1]!r} contains v6 probe evidence. Rerun the measurement instead of mixing report versions."
            )
        recomputed_records.append({**record, "classification": classification})

    recomputed = counts(recomputed_records)
    if type(counts_value) is not dict or counts_value.keys() != {
        "overall",
        "by_target",
    }:
        raise MeasurementError(
            f"Invalid third-party measurement report v{version} counts. Supply exactly counts.overall and counts.by_target, then rerun the measurement."
        )
    difference = _first_difference(counts_value, recomputed)
    if difference is not None:
        path, diagnostic = difference
        location = ".".join(("counts", *path))
        raise MeasurementError(
            f"Measurement counts disagree with records at {location}. {diagnostic} Rerun the measurement to regenerate the report instead of correcting counts by hand."
        )
    return report


def validate_measurement_report(report: object) -> dict[str, object]:
    """Accept only current schema v9 output."""
    return _validate_measurement_report(report, reviewed_schema_version=None)


class _ResponseRecorder:
    """Order sanitized responses by request acceptance, never thread completion."""

    def __init__(self) -> None:
        self.responses: dict[int, RecordedResponse] = {}
        self.response_condition = threading.Condition()
        self.next_sequence = 0
        self.recording_error: str | None = None
        self.failure: BridgeHandlerFailure | None = None

    def accept(self) -> int:
        with self.response_condition:
            sequence = self.next_sequence
            self.next_sequence += 1
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
            self.response_condition.notify_all()

    def recorded_responses(self, expected: int) -> tuple[RecordedResponse, ...]:
        with self.response_condition:
            complete = self.response_condition.wait_for(
                lambda: len(self.responses) >= expected or self.handler_failed,
                timeout=5,
            )
            expected_sequences = set(range(expected))
            observed_sequences = set(self.responses)
            if self.recording_error is not None:
                raise MeasurementError(self.recording_error)
            if (
                not complete
                or len(self.responses) != expected
                or observed_sequences != expected_sequences
            ):
                raise MeasurementError(
                    f"The loopback recorder has sequence gaps: expected {sorted(expected_sequences)!r}, observed {sorted(observed_sequences)!r}. Check response framing and handler completion, then rerun the measurement instead of pairing roles by completion order."
                )
            return tuple(self.responses[index] for index in range(expected))

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
            self.accepted_sequences.pop(id(request), None)

    def record_response(self, sequence: int, response: RecordedResponse) -> None:
        self.recorder.record_response(sequence, response)

    def recorded_responses(self, expected: int) -> tuple[RecordedResponse, ...]:
        return self.recorder.recorded_responses(expected)

    @property
    def handler_failed(self) -> bool:
        return self.recorder.handler_failed

    def handle_error(self, request: object, client_address: tuple[str, int]) -> None:
        exception = sys.exception()
        if exception is None:
            exception = RuntimeError("The bridge handler failed without an exception.")
        with self.recorder.response_condition:
            sequence = self.accepted_sequences.pop(id(request), None)
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
        recorded = _parse_http_response(bytes(response))
        server.record_response(sequence, recorded)
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
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if server.recorder.failure is not None:
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
    roles = PROBE_ROLE_ORDERS[(check_type, report_mode)][:request_count]
    kinds = OBSERVATION_KIND_ORDERS[(check_type, report_mode)][:request_count]
    evidence, relations = sanitized_probe_evidence(
        roles,
        recorder.recorded_responses(request_count),
        collector.ordered(request_count),
        check_type=check_type,
        expected_kinds=kinds,
    )
    return {
        "actual_verdict": verdict,
        "check_type": check_type,
        "classification": classify(check_type, label, verdict, reason),
        "detail": detail,
        "endpoint_id": record_id,
        "evidence": evidence,
        "expected_label": label,
        "expected_verdict": expected_verdict,
        "mode": report_mode,
        "reason_code": reason,
        "relations": relations,
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
    _validate_measurement_report(
        report,
        reviewed_schema_version=int(reviewed_version.group(1)),
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
            "New measurement output requires schema version 9 with the current confirmation predicate-pair stability precedence and exact analyzer evidence. Re-run scripts/run_third_party_sqli_measurement.py on current main instead of writing a legacy v4 through v8 fixture."
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
