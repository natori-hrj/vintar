"""Keep the offline third-party declaration and reviewed summary deterministic."""

import copy
import hashlib
import importlib.util
import json
import re
import socketserver
import sys
import tarfile
import threading
import tomllib
import traceback
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from types import ModuleType, SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import yaml
from test_sqli_candidate_reliability import classify as reliability_classify
from typer.testing import CliRunner

from vintar.checks.sqli.confirmation import CONFIRMATION_ORDER
from vintar.checks.sqli.confirmation_runner import (
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.error_analyzer import (
    ERROR_PROBE_ORDER,
    ErrorMatch,
    ErrorObservation,
    ErrorProbeKind,
)
from vintar.checks.sqli.models import Observation, ProbeKind, Verdict
from vintar.checks.sqli.observation_sink import RecordedSqliObservation
from vintar.checks.sqli.orchestrator import BOOLEAN_PROBE_ORDER, verify_boolean_sqli
from vintar.checks.sqli.presets import get_boolean_confirmation_preset
from vintar.checks.sqli.time_plan import TIME_PROBE_ORDER
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
from vintar.regression.cases import (
    ErrorRegressionCase,
    RegressionCase,
    TimeRegressionCase,
    load_regression_case,
)

ROOT = Path(__file__).resolve().parents[1]
THIRD_PARTY = ROOT / "third_party" / "sqli"
TARGETS = THIRD_PARTY / "targets.toml"
CONFIGS = THIRD_PARTY / "dsvw" / "configs"
DOJO_CONFIGS = THIRD_PARTY / "sqli-dojo" / "configs"
OWASP_CONFIGS = THIRD_PARTY / "owasp-lab" / "configs"
RUNNER = ROOT / "scripts" / "run_third_party_sqli_measurement.py"
PREPARER = ROOT / "scripts" / "prepare_third_party_sqli.py"
IMAGE_CONTRACT = ROOT / "scripts" / "third_party_sqli_contract.py"
REVIEWED_REPORT = ROOT / "tests" / "fixtures" / "third-party-sqli-measurement.json"


def load_script(path: Path, name: str) -> ModuleType:
    """Load a standalone script without executing its command-line entry point."""
    if path in {RUNNER, PREPARER} and "third_party_sqli_contract" not in sys.modules:
        contract_specification = importlib.util.spec_from_file_location(
            "third_party_sqli_contract", IMAGE_CONTRACT
        )
        assert contract_specification is not None
        assert contract_specification.loader is not None
        contract = importlib.util.module_from_spec(contract_specification)
        sys.modules["third_party_sqli_contract"] = contract
        contract_specification.loader.exec_module(contract)
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification is not None
    assert specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def load_runner() -> ModuleType:
    return load_script(RUNNER, "third_party_sqli_measurement")


def load_preparer() -> ModuleType:
    return load_script(PREPARER, "third_party_sqli_preparation")


def declarations() -> dict[str, object]:
    with TARGETS.open("rb") as stream:
        return tomllib.load(stream)


def expected_report() -> dict[str, object]:
    """Load the byte-for-byte reviewed live measurement fixture."""
    value = json.loads(REVIEWED_REPORT.read_text(encoding="utf-8"))
    assert type(value) is dict
    return value


def _report_record(report, endpoint_id):
    return next(
        item for item in report["records"] if item["endpoint_id"] == endpoint_id
    )


def legacy_v4_report() -> dict[str, object]:
    """Retain the former reviewed shape only for compatibility tests."""
    records = [
        {
            "actual_verdict": "inconclusive",
            "classification": "tp",
            "check_type": "sqli.boolean",
            "detail": {
                "configured": True,
                "reason_code": "confirmation_pattern_matched",
                "request_count": 12,
                "status": "matched",
            },
            "endpoint_id": "dsvw-blind-boolean-id",
            "expected_label": "positive",
            "expected_verdict": "inconclusive",
            "mode": "confirmation",
            "reason_code": "boolean_candidate",
            "request_count": 18,
        },
        {
            "actual_verdict": "inconclusive",
            "classification": "tp",
            "check_type": "sqli.boolean",
            "detail": {
                "configured": False,
                "reason_code": None,
                "request_count": 0,
                "status": "not_configured",
            },
            "endpoint_id": "dsvw-blind-boolean-id",
            "expected_label": "positive",
            "expected_verdict": "inconclusive",
            "mode": "six_probe",
            "reason_code": "boolean_candidate",
            "request_count": 6,
        },
        {
            "actual_verdict": "inconclusive",
            "check_type": "sqli.time",
            "classification": "tp",
            "detail": {
                "reason_code": "timing_pattern_matched",
                "request_count": 9,
                "status": "candidate",
            },
            "endpoint_id": "dsvw-time-id",
            "expected_label": "positive",
            "expected_verdict": "inconclusive",
            "mode": "nine_probe",
            "reason_code": "timing_pattern_matched",
            "request_count": 9,
        },
        {
            "actual_verdict": "not_detected",
            "check_type": "sqli.time",
            "classification": "tn",
            "detail": {
                "reason_code": "timing_pattern_not_matched",
                "request_count": 9,
                "status": "not_confirmed",
            },
            "endpoint_id": "dsvw-time-version-query",
            "expected_label": "negative",
            "expected_verdict": "not_detected",
            "mode": "nine_probe",
            "reason_code": "timing_pattern_not_matched",
            "request_count": 9,
        },
        {
            "actual_verdict": "inconclusive",
            "classification": "non_decision",
            "check_type": "sqli.boolean",
            "detail": {
                "configured": True,
                "reason_code": "initial_not_eligible",
                "request_count": 0,
                "status": "not_eligible",
            },
            "endpoint_id": "dsvw-version-query",
            "expected_label": "negative",
            "expected_verdict": "not_detected",
            "mode": "confirmation",
            "reason_code": "unexpected_difference",
            "request_count": 6,
        },
        {
            "actual_verdict": "inconclusive",
            "classification": "non_decision",
            "check_type": "sqli.boolean",
            "detail": {
                "configured": False,
                "reason_code": None,
                "request_count": 0,
                "status": "not_configured",
            },
            "endpoint_id": "dsvw-version-query",
            "expected_label": "negative",
            "expected_verdict": "not_detected",
            "mode": "six_probe",
            "reason_code": "unexpected_difference",
            "request_count": 6,
        },
        {
            "actual_verdict": "inconclusive",
            "classification": "candidate",
            "check_type": "sqli.error",
            "detail": {
                "dbms": "sqlite",
                "reason_code": "dbms_error_disclosed",
                "request_count": 4,
                "signature_id": "sqlite_operational_syntax",
                "status": "matched",
            },
            "endpoint_id": "dsvw-error-id",
            "expected_label": "positive",
            "expected_verdict": "inconclusive",
            "mode": "error_probe",
            "reason_code": "dbms_error_disclosed",
            "request_count": 4,
        },
        {
            "actual_verdict": "not_detected",
            "classification": "tn",
            "check_type": "sqli.error",
            "detail": {
                "reason_code": "dbms_error_not_observed",
                "request_count": 4,
                "status": "not_matched",
            },
            "endpoint_id": "dsvw-error-version-query",
            "expected_label": "negative",
            "expected_verdict": "not_detected",
            "mode": "error_probe",
            "reason_code": "dbms_error_not_observed",
            "request_count": 4,
        },
    ]
    for record in records:
        record["target_id"] = "dsvw"
    records.extend(
        [
            {
                "actual_verdict": "inconclusive",
                "classification": "tp",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": True,
                    "reason_code": "confirmation_pattern_matched",
                    "request_count": 12,
                    "status": "matched",
                },
                "endpoint_id": "sqli-dojo-boolean-id",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "confirmation",
                "reason_code": "boolean_candidate",
                "request_count": 18,
                "target_id": "sqli-dojo",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "tp",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": False,
                    "reason_code": None,
                    "request_count": 0,
                    "status": "not_configured",
                },
                "endpoint_id": "sqli-dojo-boolean-id",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "six_probe",
                "reason_code": "boolean_candidate",
                "request_count": 6,
                "target_id": "sqli-dojo",
            },
            {
                "actual_verdict": "not_detected",
                "classification": "tn",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": True,
                    "reason_code": "initial_not_eligible",
                    "request_count": 0,
                    "status": "not_eligible",
                },
                "endpoint_id": "sqli-dojo-boolean-source",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "confirmation",
                "reason_code": "no_boolean_difference",
                "request_count": 6,
                "target_id": "sqli-dojo",
            },
            {
                "actual_verdict": "not_detected",
                "classification": "tn",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": False,
                    "reason_code": None,
                    "request_count": 0,
                    "status": "not_configured",
                },
                "endpoint_id": "sqli-dojo-boolean-source",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "six_probe",
                "reason_code": "no_boolean_difference",
                "request_count": 6,
                "target_id": "sqli-dojo",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "candidate",
                "check_type": "sqli.error",
                "detail": {
                    "dbms": "mysql",
                    "reason_code": "dbms_error_disclosed",
                    "request_count": 4,
                    "signature_id": "mysql_syntax_error_1064",
                    "status": "matched",
                },
                "endpoint_id": "sqli-dojo-error-id",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "error_probe",
                "reason_code": "dbms_error_disclosed",
                "request_count": 4,
                "target_id": "sqli-dojo",
            },
            {
                "actual_verdict": "not_detected",
                "classification": "tn",
                "check_type": "sqli.error",
                "detail": {
                    "reason_code": "dbms_error_not_observed",
                    "request_count": 4,
                    "status": "not_matched",
                },
                "endpoint_id": "sqli-dojo-error-source",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "error_probe",
                "reason_code": "dbms_error_not_observed",
                "request_count": 4,
                "target_id": "sqli-dojo",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "tp",
                "check_type": "sqli.time",
                "detail": {
                    "reason_code": "timing_pattern_matched",
                    "request_count": 9,
                    "status": "candidate",
                },
                "endpoint_id": "sqli-dojo-time-id",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "nine_probe",
                "reason_code": "timing_pattern_matched",
                "request_count": 9,
                "target_id": "sqli-dojo",
            },
            {
                "actual_verdict": "not_detected",
                "classification": "tn",
                "check_type": "sqli.time",
                "detail": {
                    "reason_code": "timing_pattern_not_matched",
                    "request_count": 9,
                    "status": "not_confirmed",
                },
                "endpoint_id": "sqli-dojo-time-source",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "nine_probe",
                "reason_code": "timing_pattern_not_matched",
                "request_count": 9,
                "target_id": "sqli-dojo",
            },
        ]
    )
    records.extend(
        [
            {
                "actual_verdict": "inconclusive",
                "classification": "non_decision",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": True,
                    "reason_code": "initial_not_eligible",
                    "request_count": 0,
                    "status": "not_eligible",
                },
                "endpoint_id": "owasp-lab-boolean-greet",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "confirmation",
                "reason_code": "unexpected_difference",
                "request_count": 6,
                "target_id": "owasp-lab",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "non_decision",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": False,
                    "reason_code": None,
                    "request_count": 0,
                    "status": "not_configured",
                },
                "endpoint_id": "owasp-lab-boolean-greet",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "six_probe",
                "reason_code": "unexpected_difference",
                "request_count": 6,
                "target_id": "owasp-lab",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "non_decision",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": True,
                    "reason_code": "initial_not_eligible",
                    "request_count": 0,
                    "status": "not_eligible",
                },
                "endpoint_id": "owasp-lab-boolean-search",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "confirmation",
                "reason_code": "unexpected_difference",
                "request_count": 6,
                "target_id": "owasp-lab",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "non_decision",
                "check_type": "sqli.boolean",
                "detail": {
                    "configured": False,
                    "reason_code": None,
                    "request_count": 0,
                    "status": "not_configured",
                },
                "endpoint_id": "owasp-lab-boolean-search",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "six_probe",
                "reason_code": "unexpected_difference",
                "request_count": 6,
                "target_id": "owasp-lab",
            },
            {
                "actual_verdict": "not_detected",
                "classification": "tn",
                "check_type": "sqli.error",
                "detail": {
                    "reason_code": "dbms_error_not_observed",
                    "request_count": 4,
                    "status": "not_matched",
                },
                "endpoint_id": "owasp-lab-error-greet",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "error_probe",
                "reason_code": "dbms_error_not_observed",
                "request_count": 4,
                "target_id": "owasp-lab",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "non_decision",
                "check_type": "sqli.error",
                "detail": {
                    "reason_code": "non_success_status",
                    "request_count": 4,
                    "status": "inconclusive",
                },
                "endpoint_id": "owasp-lab-error-search",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "error_probe",
                "reason_code": "non_success_status",
                "request_count": 4,
                "target_id": "owasp-lab",
            },
            {
                "actual_verdict": "inconclusive",
                "classification": "tp",
                "check_type": "sqli.time",
                "detail": {
                    "reason_code": "timing_pattern_matched",
                    "request_count": 9,
                    "status": "candidate",
                },
                "endpoint_id": "owasp-lab-time-check-username",
                "expected_label": "positive",
                "expected_verdict": "inconclusive",
                "mode": "nine_probe",
                "reason_code": "timing_pattern_matched",
                "request_count": 9,
                "target_id": "owasp-lab",
            },
            {
                "actual_verdict": "not_detected",
                "classification": "tn",
                "check_type": "sqli.time",
                "detail": {
                    "reason_code": "timing_pattern_not_matched",
                    "request_count": 9,
                    "status": "not_confirmed",
                },
                "endpoint_id": "owasp-lab-time-greet",
                "expected_label": "negative",
                "expected_verdict": "not_detected",
                "mode": "nine_probe",
                "reason_code": "timing_pattern_not_matched",
                "request_count": 9,
                "target_id": "owasp-lab",
            },
        ]
    )
    records.sort(
        key=lambda row: (
            str(row["target_id"]),
            str(row["endpoint_id"]),
            str(row["mode"]),
        )
    )
    dsvw_counts = {
        "sqli.boolean": {
            "confirmation": {
                "fn": 0,
                "fp": 0,
                "non_decision": 1,
                "tn": 0,
                "tp": 1,
            },
            "six_probe": {
                "fn": 0,
                "fp": 0,
                "non_decision": 1,
                "tn": 0,
                "tp": 1,
            },
        },
        "sqli.time": {
            "nine_probe": {
                "fn": 0,
                "fp": 0,
                "non_decision": 0,
                "tn": 1,
                "tp": 1,
            }
        },
        "sqli.error": {
            "error_probe": {
                "candidate": 1,
                "fn": 0,
                "fp": 0,
                "non_decision": 0,
                "tn": 1,
            }
        },
    }
    dojo_counts = {
        "sqli.boolean": {
            "confirmation": {
                "fn": 0,
                "fp": 0,
                "non_decision": 0,
                "tn": 1,
                "tp": 1,
            },
            "six_probe": {
                "fn": 0,
                "fp": 0,
                "non_decision": 0,
                "tn": 1,
                "tp": 1,
            },
        },
        "sqli.time": {
            "nine_probe": {
                "fn": 0,
                "fp": 0,
                "non_decision": 0,
                "tn": 1,
                "tp": 1,
            }
        },
        "sqli.error": {
            "error_probe": {
                "candidate": 1,
                "fn": 0,
                "fp": 0,
                "non_decision": 0,
                "tn": 1,
            }
        },
    }
    owasp_counts = {
        "sqli.boolean": {
            "confirmation": {
                "fn": 0,
                "fp": 0,
                "non_decision": 2,
                "tn": 0,
                "tp": 0,
            },
            "six_probe": {
                "fn": 0,
                "fp": 0,
                "non_decision": 2,
                "tn": 0,
                "tp": 0,
            },
        },
        "sqli.time": {
            "nine_probe": {
                "fn": 0,
                "fp": 0,
                "non_decision": 0,
                "tn": 1,
                "tp": 1,
            }
        },
        "sqli.error": {
            "error_probe": {
                "candidate": 0,
                "fn": 0,
                "fp": 0,
                "non_decision": 1,
                "tn": 1,
            }
        },
    }
    overall = json.loads(json.dumps(dsvw_counts))
    for target_counts in (dojo_counts, owasp_counts):
        for check_type, modes in target_counts.items():
            for mode, values in modes.items():
                for field, value in values.items():
                    overall[check_type][mode][field] += value
    return {
        "counts": {
            "overall": overall,
            "by_target": {
                "dsvw": dsvw_counts,
                "owasp-lab": owasp_counts,
                "sqli-dojo": dojo_counts,
            },
        },
        "records": records,
        "schema_version": 4,
        "targets": {
            "dsvw": {
                "archive_sha256": "96690f62ac0fba8a4f0aeac22f2370853bc02b96fb3efd1b8fc3a39398bf302b",
                "commit": "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
                "dbms": "sqlite",
                "image_ids": {
                    "app": "sha256:c14c096299306103dacfd9908376549b3a638f914a6fa0915b2c4779af9be5c8"
                },
                "license": "Unlicense",
                "name": "DSVW",
                "repository": "https://github.com/stamparm/DSVW",
                "service_images": {},
                "source_manifest_sha256": "dd8e307cc1c350f5e2010b0f739ef7e3f92ab2205be7743dc5822802cee28bef",
            },
            "sqli-dojo": {
                "archive_sha256": "6c0218fef749fddec28560af883865eb4178ed998d5cc927a5e3592add50b88f",
                "commit": "81f20037de323376d8a7651377e3a3971efdbae8",
                "dbms": "mysql",
                "image_ids": {
                    "app": "sha256:551add78854168e48ba09a3b6c4638664aa923a84a4a0e0c5f212b9abaa666c9"
                },
                "license": "GPL-3.0",
                "name": "sqli-dojo-docker",
                "repository": "https://github.com/h1pmnh/sqli-dojo-docker",
                "service_images": {
                    "mysql": "mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"
                },
                "source_manifest_sha256": "bff7a572b1f3c3bd1482c8f75ef0f703900f59f9e7f0bb89214edd32eb348416",
            },
            "owasp-lab": {
                "archive_sha256": "5d0c805d86cd6a3ec8d95afdb2fdae99cab5dc765842dac4e6d122c171737db4",
                "commit": "9cb62dd2e30b08a0ddc753247c62b54b90e933ed",
                "dbms": "postgresql",
                "image_ids": {
                    "app": "sha256:cc1157c59138b33e8d3a2a7329004cb2d60925eed0c8cf3c3ba2c03d06c733fc"
                },
                "license": "MIT",
                "name": "OWASP Training Lab",
                "repository": "https://github.com/jozeta/owasp-lab",
                "service_images": {
                    "postgres": "postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
                },
                "source_manifest_sha256": "107dc85a50f94193df257e7ca9890f297c169964376cee35f88b643ee8c51ea9",
            },
        },
    }


def v10_report_from_legacy_v4(runner):
    """Construct deterministic v10 attempts for the current reviewed plan."""
    report = expected_report()
    report["schema_version"] = 10
    raw_bodies = {
        "baseline": b"fixed-baseline-response-body",
        "true": b"fixed-true-response-body",
        "false": b"fixed-false-response-body",
        "control": b"fixed-control-response-body",
        "true2": b"fixed-true2-response-body",
        "false2": b"fixed-false2-response-body",
        "delay": b"fixed-delay-response-body",
        "error": b"fixed-error-response-body",
    }
    for record in report["records"]:
        record.pop("evidence")
        record.pop("relations")
        roles = runner.PROBE_ROLE_ORDERS[(record["check_type"], record["mode"])][
            : record["request_count"]
        ]
        bodies = dict(raw_bodies)
        statuses = {role: 200 for role in set(roles)}
        reason = record["reason_code"]
        if record["check_type"] == "sqli.boolean":
            if reason == "boolean_candidate":
                bodies["true"] = bodies["baseline"]
                if record["detail"]["status"] == "matched":
                    bodies["control"] = bodies["baseline"]
                    bodies["true2"] = bodies["baseline"]
                    bodies["false2"] = bodies["false"]
            elif reason == "candidate_confirmation_mismatch":
                bodies["true"] = bodies["baseline"]
                bodies["control"] = bodies["baseline"]
                bodies["true2"] = b"fixed-mismatching-confirmation-body"
                bodies["false2"] = b"fixed-mismatching-confirmation-body"
            elif reason == "no_boolean_difference_literal_input":
                bodies["false"] = bodies["true"]
            elif reason == "no_boolean_difference":
                bodies["true"] = bodies["baseline"]
                bodies["false"] = bodies["baseline"]
        elif record["check_type"] == "sqli.error":
            if reason == "dbms_error_disclosed":
                bodies["error"] = {
                    "sqlite_operational_syntax": (
                        b"sqlite3.OperationalError: near token syntax error"
                    ),
                    "mysql_syntax_error_1064": (
                        b"You have an error in your SQL syntax; check the manual "
                        b"that corresponds to your MySQL server version"
                    ),
                }[record["detail"]["signature_id"]]
            elif reason == "dbms_error_not_observed":
                bodies["error"] = bodies["baseline"]
            elif reason == "non_success_status":
                statuses["error"] = 500
        responses = tuple(
            runner._recorded_response(statuses[role], iter((bodies[role],)))
            for role in roles
        )
        observations = []
        kinds = runner.OBSERVATION_KIND_ORDERS[(record["check_type"], record["mode"])][
            : record["request_count"]
        ]
        for sequence, (role, kind) in enumerate(
            zip(roles, kinds, strict=True), start=1
        ):
            body = bodies[role]
            digest = hashlib.sha256(body).hexdigest()
            status = statuses[role]
            if record["check_type"] == "sqli.boolean" and sequence <= 6:
                observation = Observation(
                    ProbeKind(kind), status, len(body), 0.01, digest
                )
                family = "boolean"
            elif record["check_type"] == "sqli.boolean":
                observation = runner.ConfirmationObservation(
                    runner.ConfirmationKind(kind), status, len(body), digest, False
                )
                family = "confirmation"
            elif record["check_type"] == "sqli.time":
                observation = runner.TimeResponseSignature(
                    status,
                    False,
                    len(body),
                    digest,
                )
                family = "time"
            else:
                matches = ()
                if role == "error" and reason == "dbms_error_disclosed":
                    matches = (
                        ErrorMatch(
                            record["detail"]["dbms"],
                            record["detail"]["signature_id"],
                        ),
                    )
                observation = ErrorObservation(
                    ErrorProbeKind(kind),
                    sequence,
                    status,
                    len(body),
                    digest,
                    False,
                    matches,
                )
                family = "error"
            observations.append(
                RecordedSqliObservation(family, sequence, kind, observation)
            )
        decision_facts = None
        if record["reason_code"] == "non_success_status":
            stop = next(
                item for item in observations if item.observation.status_code == 500
            )
            decision_facts = {
                "category": "operational",
                "stage": "error",
                "sequence": stop.sequence,
                "probe_kind": "error",
                "condition": "non_success_status",
                "status_code": 500,
            }
            record["decision_facts"] = decision_facts
        record["attempts"] = runner.sanitized_attempts(
            tuple(observations),
            {index: response for index, response in enumerate(responses, start=1)},
            decision_facts=decision_facts,
        )
        if record["check_type"] == "sqli.time":
            positive = record["reason_code"] == "timing_pattern_matched"
            record["time_predicates"] = {
                "baseline_span_exceeded": False,
                "control_span_exceeded": False,
                "baseline_control_difference_exceeded": False,
                "drift_exceeded": False,
                "delay_span_exceeded": False,
                "candidate_median_met": positive,
                "candidate_margin_met": positive,
                "no_delay_condition_met": not positive,
            }
    return report


v9_report_from_legacy_v4 = v10_report_from_legacy_v4


def legacy_v5_report(runner):
    """Build the superseded v5 shape that omitted Error analyzer facts."""
    report = v9_report_from_legacy_v4(runner)
    report["schema_version"] = 5
    for record in report["records"]:
        if record["check_type"] == "sqli.error":
            for item in record["evidence"]:
                item.pop("truncated")
                item.pop("matches")
    return report


def test_reviewed_declarations_are_exact_and_digest_bound():
    document = declarations()
    assert document["version"] == 2
    targets = {target["id"]: target for target in document["targets"]}
    assert targets["dsvw"] == {
        "archive_sha256": "96690f62ac0fba8a4f0aeac22f2370853bc02b96fb3efd1b8fc3a39398bf302b",
        "archive_url": "https://github.com/stamparm/DSVW/archive/9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908.tar.gz",
        "commit": "9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908",
        "compose_path": "dsvw/compose.yaml",
        "configs_path": "dsvw/configs",
        "dbms": "sqlite",
        "fresh_volumes": [],
        "id": "dsvw",
        "image_environment": "DSVW_IMAGE",
        "license": "Unlicense",
        "name": "DSVW",
        "operation_path": "/",
        "parameter_names": ["id", "v"],
        "repository": "https://github.com/stamparm/DSVW",
        "service_images": [],
        "service_name": "dsvw",
        "service_port": 65412,
        "spec_path": "dsvw/openapi.json",
        "startup_timeout_seconds": 30,
    }
    assert targets["sqli-dojo"] == {
        "archive_sha256": "6c0218fef749fddec28560af883865eb4178ed998d5cc927a5e3592add50b88f",
        "archive_url": "https://github.com/h1pmnh/sqli-dojo-docker/archive/81f20037de323376d8a7651377e3a3971efdbae8.tar.gz",
        "commit": "81f20037de323376d8a7651377e3a3971efdbae8",
        "compose_path": "sqli-dojo/compose.yaml",
        "configs_path": "sqli-dojo/configs",
        "dbms": "mysql",
        "dockerfile_path": "sqli-dojo/Dockerfile",
        "fresh_volumes": ["mysql-data"],
        "id": "sqli-dojo",
        "image_environment": "SQLI_DOJO_IMAGE",
        "license": "GPL-3.0",
        "name": "sqli-dojo-docker",
        "operation_path": "/lookup_person.php",
        "parameter_names": ["id", "source"],
        "repository": "https://github.com/h1pmnh/sqli-dojo-docker",
        "service_images": [
            "mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"
        ],
        "service_name": "dojo",
        "service_port": 80,
        "spec_path": "sqli-dojo/openapi.json",
        "startup_timeout_seconds": 120,
    }
    assert targets["owasp-lab"] == {
        "archive_sha256": "5d0c805d86cd6a3ec8d95afdb2fdae99cab5dc765842dac4e6d122c171737db4",
        "archive_url": "https://github.com/jozeta/owasp-lab/archive/9cb62dd2e30b08a0ddc753247c62b54b90e933ed.tar.gz",
        "commit": "9cb62dd2e30b08a0ddc753247c62b54b90e933ed",
        "compose_path": "owasp-lab/compose.yaml",
        "configs_path": "owasp-lab/configs",
        "dbms": "postgresql",
        "dockerfile_path": "owasp-lab/Dockerfile",
        "fresh_volumes": ["postgres-data"],
        "id": "owasp-lab",
        "image_environment": "OWASP_LAB_IMAGE",
        "license": "MIT",
        "name": "OWASP Training Lab",
        "operation_path": "/a03/search",
        "parameter_names": ["q", "username", "name"],
        "repository": "https://github.com/jozeta/owasp-lab",
        "service_images": [
            "postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
        ],
        "service_name": "lab",
        "service_port": 5000,
        "spec_path": "owasp-lab/openapi.json",
        "startup_timeout_seconds": 120,
    }
    records = document["records"]
    assert [record["id"] for record in records if record["target_id"] == "dsvw"] == [
        "dsvw-blind-boolean-id",
        "dsvw-version-query",
        "dsvw-time-id",
        "dsvw-time-version-query",
        "dsvw-error-id",
        "dsvw-error-version-query",
    ]
    assert [
        record["id"] for record in records if record["target_id"] == "sqli-dojo"
    ] == [
        "sqli-dojo-boolean-id",
        "sqli-dojo-boolean-source",
        "sqli-dojo-time-id",
        "sqli-dojo-time-source",
        "sqli-dojo-error-id",
        "sqli-dojo-error-source",
    ]
    assert [
        record["id"] for record in records if record["target_id"] == "owasp-lab"
    ] == [
        "owasp-lab-boolean-search",
        "owasp-lab-boolean-greet",
        "owasp-lab-time-check-username",
        "owasp-lab-time-greet",
        "owasp-lab-error-search",
        "owasp-lab-error-greet",
    ]
    dsvw_records = [record for record in records if record["target_id"] == "dsvw"]
    assert [record["check_type"] for record in dsvw_records] == [
        "sqli.boolean",
        "sqli.boolean",
        "sqli.time",
        "sqli.time",
        "sqli.error",
        "sqli.error",
    ]
    assert [record["label"] for record in dsvw_records] == [
        "positive",
        "negative",
        "positive",
        "negative",
        "positive",
        "negative",
    ]
    assert [record["evidence_type"] for record in dsvw_records] == [
        "non_parameterized_sql_sink",
        "parameter_does_not_reach_sql_sink",
        "non_parameterized_sql_sink",
        "parameter_does_not_reach_sql_sink",
        "non_parameterized_sql_sink_with_exposed_exception",
        "parameter_does_not_reach_sql_sink",
    ]
    assert all(
        record["source_path"] == "dsvw.py"
        for record in records
        if record["target_id"] == "dsvw"
    )
    assert {
        record["source_path"]
        for record in records
        if record["target_id"] == "sqli-dojo"
    } == {"src/lookup_person.php", "src/common/view_source.php"}
    assert all(
        re.fullmatch(r"[0-9a-f]{64}", record["source_fragment_sha256"])
        for record in records
    )
    assert all(record["reviewer_note"] for record in records)


def test_openapi_and_configs_bind_only_the_two_reviewed_inputs():
    spec = json.loads((THIRD_PARTY / "dsvw" / "openapi.json").read_text())
    parameters = spec["paths"]["/"]["get"]["parameters"]
    assert [(item["name"], item["in"]) for item in parameters] == [
        ("id", "query"),
        ("v", "query"),
    ]
    configs = sorted((THIRD_PARTY / "dsvw" / "configs").glob("*.toml"))
    assert [path.name for path in configs] == [
        "dsvw-blind-boolean-id-confirmation.toml",
        "dsvw-blind-boolean-id-six.toml",
        "dsvw-error-id-error.toml",
        "dsvw-error-version-query-error.toml",
        "dsvw-time-id-time.toml",
        "dsvw-time-version-query-time.toml",
        "dsvw-version-query-confirmation.toml",
        "dsvw-version-query-six.toml",
    ]
    parsed = []
    for path in configs:
        with path.open("rb") as stream:
            config = tomllib.load(stream)
        assert config["target"] == {
            "allowed_origin": "__ORIGIN__",
            "url": "__ORIGIN__/",
        }
        assert config["injection"]["location"] == "query"
        parsed.append(config)
    assert sum(config["limits"]["max_requests"] == 6 for config in parsed) == 2
    assert sum(config["limits"]["max_requests"] == 18 for config in parsed) == 2
    assert sum(config["limits"]["max_requests"] == 9 for config in parsed) == 2
    assert sum(config["limits"]["max_requests"] == 4 for config in parsed) == 2
    assert sum(config["probes"]["selection"] == "explicit" for config in parsed) == 6
    assert sum(config["probes"]["selection"] == "preset" for config in parsed) == 2
    time_configs = [config for config in parsed if config.get("type") == "sqli.time"]
    assert len(time_configs) == 2
    assert all(config["injection"]["mode"] == "replace" for config in time_configs)
    assert all(
        config["probes"]["expected_delay_seconds"] == 0.5 for config in time_configs
    )
    error_configs = [config for config in parsed if config.get("type") == "sqli.error"]
    assert len(error_configs) == 2
    assert all(config["probes"]["error_payload"] == "'" for config in error_configs)


def test_sqli_dojo_openapi_configs_and_images_are_reviewed_and_pinned():
    spec = json.loads((THIRD_PARTY / "sqli-dojo" / "openapi.json").read_text())
    parameters = spec["paths"]["/lookup_person.php"]["get"]["parameters"]
    assert [(item["name"], item["in"]) for item in parameters] == [
        ("id", "query"),
        ("source", "query"),
    ]
    configs = sorted(DOJO_CONFIGS.glob("*.toml"))
    assert [path.name for path in configs] == [
        "sqli-dojo-boolean-id-confirmation.toml",
        "sqli-dojo-boolean-id-six.toml",
        "sqli-dojo-boolean-source-confirmation.toml",
        "sqli-dojo-boolean-source-six.toml",
        "sqli-dojo-error-id-error.toml",
        "sqli-dojo-error-source-error.toml",
        "sqli-dojo-time-id-time.toml",
        "sqli-dojo-time-source-time.toml",
    ]
    parsed = []
    for path in configs:
        with path.open("rb") as stream:
            config = tomllib.load(stream)
        assert config["target"] == {
            "allowed_origin": "__ORIGIN__",
            "url": "__ORIGIN__/lookup_person.php",
        }
        assert config["injection"]["location"] == "query"
        parsed.append(config)
    assert sorted(config["limits"]["max_requests"] for config in parsed) == [
        4,
        4,
        6,
        6,
        9,
        9,
        18,
        18,
    ]
    compose = (THIRD_PARTY / "sqli-dojo" / "compose.yaml").read_text()
    mysql = "mysql:8.0@sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b"
    assert mysql in compose
    assert "mysql-data:/var/lib/mysql" in compose
    dockerfile = (THIRD_PARTY / "sqli-dojo" / "Dockerfile").read_text()
    assert (
        "php:8.4-apache@sha256:3550aedd1c7bdfe26283c7b1550ef76509e6c2b1284aef814e6f2e325b7c9688"
        in dockerfile
    )


def _filter_value(value: str, characters: str) -> str:
    return value.translate(str.maketrans("", "", characters))


def _explicit_confirmation_payloads(config: dict[str, object]) -> tuple[str, ...]:
    probes = config.get("probes")
    if type(probes) is not dict or probes.get("selection") != "explicit":
        return ()
    confirmation = probes.get("confirmation")
    if type(confirmation) is not dict:
        return ()
    values = (
        probes.get("true_payload"),
        probes.get("false_payload"),
        confirmation.get("true_payload"),
        confirmation.get("false_payload"),
        confirmation.get("baseline_preserving_control"),
    )
    if any(type(value) is not str for value in values):
        raise AssertionError(
            "Explicit confirmation payloads are incomplete. Supply all five reviewed payloads before checking target filter compatibility."
        )
    return tuple(values)


def _assert_explicit_confirmations_avoid_target_filter(
    compose_path: Path, config_paths: tuple[Path, ...]
) -> None:
    compose = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
    services = compose.get("services") if type(compose) is dict else None
    if type(services) is not dict:
        raise AssertionError(
            "Target Compose services are invalid. Restore the reviewed Compose declaration before checking confirmation payloads."
        )
    filter_characters = "".join(
        str(service.get("environment", {}).get("FILTER_CHARACTERS", ""))
        for service in services.values()
        if type(service) is dict and type(service.get("environment")) is dict
    )
    if not filter_characters:
        return
    for config_path in config_paths:
        with config_path.open("rb") as stream:
            config = tomllib.load(stream)
        for payload in _explicit_confirmation_payloads(config):
            invalid = sorted(set(payload).intersection(filter_characters))
            assert not invalid, (
                f"Explicit confirmation payloads in {config_path.name!r} contain target "
                f"FILTER_CHARACTERS {''.join(invalid)!r}, so the target rewrites the "
                "reviewed Boolean relation. Supply explicit payloads that avoid the "
                "configured filter characters instead."
            )


def test_sqli_dojo_confirmation_payloads_survive_configured_filter():
    old = get_boolean_confirmation_preset("numeric")
    with (DOJO_CONFIGS / "sqli-dojo-boolean-id-confirmation.toml").open("rb") as stream:
        config = tomllib.load(stream)
    payloads = _explicit_confirmation_payloads(config)
    filter_characters = "<>"

    assert _filter_value(old.true_payload, filter_characters) == " AND 23-- "
    assert _filter_value(old.false_payload, filter_characters) == " AND 23-- "
    assert len(set(payloads)) == 5
    assert all(
        _filter_value(payload, filter_characters) == payload for payload in payloads
    )


def test_explicit_confirmations_avoid_declared_compose_filters(tmp_path):
    for compose in sorted(THIRD_PARTY.glob("*/compose.yaml")):
        reviewed = tuple(
            sorted((compose.parent / "configs").glob("*-confirmation.toml"))
        )
        _assert_explicit_confirmations_avoid_target_filter(compose, reviewed)

    incompatible = tmp_path / "incompatible-confirmation.toml"
    incompatible.write_text(
        (DOJO_CONFIGS / "sqli-dojo-boolean-id-confirmation.toml")
        .read_text(encoding="utf-8")
        .replace(" AND 2=2-- ", " AND 2<3-- "),
        encoding="utf-8",
    )
    with pytest.raises(
        AssertionError,
        match=r"contain target FILTER_CHARACTERS.*avoid the configured filter characters",
    ):
        _assert_explicit_confirmations_avoid_target_filter(
            THIRD_PARTY / "sqli-dojo" / "compose.yaml", (incompatible,)
        )


def _fixed_dojo_confirmation(true_2: str, false_2: str):
    origin = "http://localhost:8000"
    filter_characters = "<>"
    row_returning_values = {
        "2",
        "2 AND 1=1-- ",
        "2 AND 2=2-- ",
        "2 AND 7=7-- ",
        "2 AND 23-- ",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        original = request.url.params["id"]
        filtered = _filter_value(original, filter_characters)
        warning = b""
        if original != filtered:
            warning = f"filtered:{original}->{filtered}|".encode()
        rows = b"person-2" if filtered in row_returning_values else b"no-rows"
        return httpx.Response(200, content=warning + rows)

    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        budget=RequestBudget(18),
        rate_limiter=RateLimiter(requests_per_second=10),
    )
    return verify_boolean_sqli_with_confirmation(
        check_id="sqli-dojo-fixed-filter-relation",
        template=RequestTemplate(
            method="GET",
            url=origin + "/lookup_person.php",
            params=(("id", "2"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="id",
            mode=InjectionMode.APPEND,
        ),
        true_1=" AND 1=1-- ",
        false_1=" AND 1=2-- ",
        true_2=true_2,
        false_2=false_2,
        baseline_preserving_control=" AND 7=7-- ",
        context=context,
        transport=httpx.MockTransport(handler),
    )


def test_fixed_dojo_relation_accepts_filter_compatible_confirmation():
    result = _fixed_dojo_confirmation(" AND 2=2-- ", " AND 2=3-- ")

    assert result.status is ConfirmationStatus.CANDIDATE
    assert result.reason_code == "confirmation_pattern_matched"
    assert result.confirmation_requests == 12
    assert result.total_requests == 18


def test_fixed_dojo_relation_rejects_filtered_preset_confirmation():
    old = get_boolean_confirmation_preset("numeric")

    result = _fixed_dojo_confirmation(old.true_payload, old.false_payload)

    assert result.status is ConfirmationStatus.INCONCLUSIVE
    assert result.reason_code == "confirmation_unstable"
    assert result.confirmation_requests == 12
    assert result.total_requests == 18


def test_owasp_lab_openapi_configs_and_images_are_reviewed_and_pinned():
    spec = json.loads((THIRD_PARTY / "owasp-lab" / "openapi.json").read_text())
    assert {
        path: [parameter["name"] for parameter in operation["get"]["parameters"]]
        for path, operation in spec["paths"].items()
    } == {
        "/a03/check-username": ["username"],
        "/a03/greet": ["name"],
        "/a03/search": ["q"],
    }
    assert sorted(path.name for path in OWASP_CONFIGS.glob("*.toml")) == [
        "owasp-lab-boolean-greet-confirmation.toml",
        "owasp-lab-boolean-greet-six.toml",
        "owasp-lab-boolean-search-confirmation.toml",
        "owasp-lab-boolean-search-six.toml",
        "owasp-lab-error-greet-error.toml",
        "owasp-lab-error-search-error.toml",
        "owasp-lab-time-check-username-time.toml",
        "owasp-lab-time-greet-time.toml",
    ]
    compose = (THIRD_PARTY / "owasp-lab" / "compose.yaml").read_text()
    assert (
        "postgres:16-alpine@sha256:f2f98726820d0342055351c6e9d36e705f5bfffb3dd53ff556325114b08afb6d"
        in compose
    )
    assert "postgres-data:/var/lib/postgresql/data" in compose
    assert "/healthz" in compose
    assert "/a03/" not in compose
    dockerfile = (THIRD_PARTY / "owasp-lab" / "Dockerfile").read_text()
    assert (
        "python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b"
        in dockerfile
    )


def test_postgres_compose_healthchecks_require_tcp_readiness():
    for compose_path in sorted(THIRD_PARTY.glob("*/compose.yaml")):
        document = yaml.safe_load(compose_path.read_text(encoding="utf-8"))
        assert isinstance(document, dict)
        services = document.get("services")
        assert isinstance(services, dict)
        for service_name, service in services.items():
            assert isinstance(service, dict)
            image = service.get("image")
            if not isinstance(image, str) or not image.startswith("postgres:"):
                continue
            healthcheck = service.get("healthcheck")
            test = healthcheck.get("test") if isinstance(healthcheck, dict) else None
            command = " ".join(test) if isinstance(test, list) else ""
            has_tcp_host = re.search(
                r"(?:^|\s)-h(?:\s+|=)(?:127\.0\.0\.1|localhost)(?:\s|$)", command
            )
            assert "pg_isready" in command and has_tcp_host is not None, (
                f"{compose_path}:{service_name} does not wait for PostgreSQL TCP readiness; "
                "the image's init server is Unix-socket-only and can make a hostless "
                "pg_isready pass too early. Use pg_isready -h 127.0.0.1 (or -h localhost) instead."
            )


@pytest.mark.parametrize(
    (
        "target_id",
        "record_id",
        "config_mode",
        "input_id",
        "parameter",
        "index",
        "operation_path",
        "expected",
    ),
    [
        (
            "dsvw",
            "dsvw-time-id",
            "time",
            "input-0927742c7a4ae9527f51f8c541502371",
            "id",
            0,
            "/",
            "inconclusive",
        ),
        (
            "dsvw",
            "dsvw-time-version-query",
            "time",
            "input-ffe5bfa38242d9cad17138d92bb38efd",
            "v",
            1,
            "/",
            "not_detected",
        ),
        (
            "dsvw",
            "dsvw-error-id",
            "error",
            "input-0927742c7a4ae9527f51f8c541502371",
            "id",
            0,
            "/",
            "inconclusive",
        ),
        (
            "dsvw",
            "dsvw-error-version-query",
            "error",
            "input-ffe5bfa38242d9cad17138d92bb38efd",
            "v",
            1,
            "/",
            "not_detected",
        ),
        (
            "sqli-dojo",
            "sqli-dojo-boolean-id",
            "confirmation",
            "input-cd830e9d6b74c85da764108226a46c4e",
            "id",
            0,
            "/lookup_person.php",
            "inconclusive",
        ),
        (
            "sqli-dojo",
            "sqli-dojo-time-id",
            "time",
            "input-cd830e9d6b74c85da764108226a46c4e",
            "id",
            0,
            "/lookup_person.php",
            "inconclusive",
        ),
        (
            "sqli-dojo",
            "sqli-dojo-time-source",
            "time",
            "input-ad87295e6521cda804be52b80e0ee734",
            "source",
            1,
            "/lookup_person.php",
            "not_detected",
        ),
        (
            "sqli-dojo",
            "sqli-dojo-error-id",
            "error",
            "input-cd830e9d6b74c85da764108226a46c4e",
            "id",
            0,
            "/lookup_person.php",
            "inconclusive",
        ),
        (
            "sqli-dojo",
            "sqli-dojo-error-source",
            "error",
            "input-ad87295e6521cda804be52b80e0ee734",
            "source",
            1,
            "/lookup_person.php",
            "not_detected",
        ),
        (
            "owasp-lab",
            "owasp-lab-time-check-username",
            "time",
            "input-e394c15608838355cc18b2176fc80222",
            "username",
            0,
            "/a03/check-username",
            "inconclusive",
        ),
        (
            "owasp-lab",
            "owasp-lab-time-greet",
            "time",
            "input-b714f64e50b1e26b75d7ac44596d3b74",
            "name",
            0,
            "/a03/greet",
            "not_detected",
        ),
        (
            "owasp-lab",
            "owasp-lab-error-search",
            "error",
            "input-576bd25c5162489797c44f04125ea3aa",
            "q",
            0,
            "/a03/search",
            "inconclusive",
        ),
        (
            "owasp-lab",
            "owasp-lab-error-greet",
            "error",
            "input-b714f64e50b1e26b75d7ac44596d3b74",
            "name",
            0,
            "/a03/greet",
            "not_detected",
        ),
    ],
)
def test_reviewed_configs_materialize_and_load_offline(
    tmp_path,
    monkeypatch,
    target_id,
    record_id,
    config_mode,
    input_id,
    parameter,
    index,
    operation_path,
    expected,
):
    monkeypatch.chdir(tmp_path)
    spec = tmp_path / "openapi.json"
    spec.write_bytes((THIRD_PARTY / target_id / "openapi.json").read_bytes())
    selection = tmp_path / "selection.toml"
    selection.write_text(f'version = 1\napproved = ["{input_id}"]\n', encoding="utf-8")
    runner = CliRunner()
    discovered = runner.invoke(
        app,
        [
            "discover",
            "--spec",
            str(spec),
            "--selection",
            str(selection),
            "--drafts-dir",
            str(tmp_path / "drafts"),
        ],
    )
    assert discovered.exit_code == 0 and discovered.stderr == ""
    draft_name = json.loads(discovered.stdout)["drafts"][0]
    draft = tmp_path / "drafts" / draft_name
    other = (
        ("v" if parameter == "id" else "id")
        if target_id == "dsvw"
        else ("source" if parameter == "id" else "id")
        if target_id == "sqli-dojo"
        else None
    )
    pointer_path = operation_path.replace("~", "~0").replace("/", "~1")
    parameters = {
        parameter: {
            "pointer": f"/paths/{pointer_path}/get/parameters/{index}/schema/example"
        }
    }
    if other is not None:
        parameters[other] = {"omit": True}
    answers = tmp_path / "answers.json"
    answers.write_text(
        json.dumps(
            {
                "version": 1,
                "expected_verdict": expected,
                "parameters": parameters,
            }
        ),
        encoding="utf-8",
    )
    review = tmp_path / "review.json"
    reviewed = runner.invoke(
        app,
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
    assert reviewed.exit_code == 0 and reviewed.stderr == ""
    config = tmp_path / "config.toml"
    config.write_text(
        (
            {
                "dsvw": CONFIGS,
                "sqli-dojo": DOJO_CONFIGS,
                "owasp-lab": OWASP_CONFIGS,
            }[target_id]
            / f"{record_id}-{config_mode}.toml"
        )
        .read_text(encoding="utf-8")
        .replace(
            "__ORIGIN__",
            "http://127.0.0.1:65412"
            if target_id == "dsvw"
            else "http://127.0.0.1:18080"
            if target_id == "sqli-dojo"
            else "http://127.0.0.1:15000",
        ),
        encoding="utf-8",
    )
    output = tmp_path / "case.toml"
    materialized = runner.invoke(
        app,
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
            str(output),
        ],
    )
    assert materialized.exit_code == 0 and materialized.stderr == ""
    case = load_regression_case(output)
    assert json.loads(materialized.stdout)["case_id"] == case.case_id
    if config_mode == "time":
        assert isinstance(case, TimeRegressionCase)
        assert case.case_id.endswith("-time")
        assert case.max_requests == 9
        assert case.expected_delay_seconds == 0.5
    elif config_mode == "error":
        assert isinstance(case, ErrorRegressionCase)
        assert case.case_id.endswith("-error")
        assert case.max_requests == 4
        assert case.error_payload == "'"
    else:
        assert isinstance(case, RegressionCase)
        assert case.max_requests == 18
        assert case.confirmation is not None
        payloads = (
            case.true_payload,
            case.false_payload,
            case.confirmation.true_payload,
            case.confirmation.false_payload,
            case.confirmation.baseline_preserving_control,
        )
        assert len(set(payloads)) == 5
        assert all(not set(payload).intersection("<>") for payload in payloads)


@pytest.mark.parametrize("label", ["positive", "negative"])
@pytest.mark.parametrize(
    ("verdict", "reason"),
    [
        (Verdict.INCONCLUSIVE, "boolean_candidate"),
        (Verdict.NOT_DETECTED, "no_boolean_difference_literal_input"),
        (Verdict.INCONCLUSIVE, "unexpected_difference"),
    ],
)
def test_runner_reuses_the_reliability_classification(label, verdict, reason):
    runner = load_runner()
    assert runner.classify(
        "sqli.boolean", label, verdict.value, reason
    ) == reliability_classify(label, verdict, reason)


@pytest.mark.parametrize(
    ("label", "verdict", "reason", "expected"),
    [
        ("positive", "inconclusive", "timing_pattern_matched", "tp"),
        ("negative", "inconclusive", "timing_pattern_matched", "fp"),
        ("positive", "not_detected", "timing_pattern_not_matched", "fn"),
        ("negative", "not_detected", "timing_pattern_not_matched", "tn"),
        ("negative", "inconclusive", "unstable_timing", "non_decision"),
    ],
)
def test_time_classification_uses_the_product_contract(
    label, verdict, reason, expected
):
    runner = load_runner()
    assert runner.classify("sqli.time", label, verdict, reason) == expected


@pytest.mark.parametrize(
    ("label", "verdict", "reason", "expected"),
    [
        ("positive", "inconclusive", "dbms_error_disclosed", "candidate"),
        ("negative", "inconclusive", "dbms_error_disclosed", "fp"),
        ("positive", "not_detected", "dbms_error_not_observed", "fn"),
        ("negative", "not_detected", "dbms_error_not_observed", "tn"),
        ("positive", "inconclusive", "unstable_error_signal", "non_decision"),
    ],
)
def test_error_classification_keeps_candidates_distinct_from_tp(
    label, verdict, reason, expected
):
    runner = load_runner()
    assert runner.classify("sqli.error", label, verdict, reason) == expected


def test_aggregation_separates_boolean_time_and_error_results():
    runner = load_runner()
    records = v9_report_from_legacy_v4(runner)["records"]

    assert runner.counts(records) == v9_report_from_legacy_v4(runner)["counts"]
    assert set(runner.counts(records)["overall"]) == {
        "sqli.boolean",
        "sqli.time",
        "sqli.error",
    }


@pytest.mark.doc_drift
def test_reviewed_documentation_matches_the_report_contract():
    runner = load_runner()
    report = expected_report()
    rendered = runner.check_documented_summary(report)
    assert "n=2" not in rendered
    assert rendered.count("| dsvw-blind-boolean-id |") == 2
    assert rendered.count("| dsvw-version-query |") == 2
    assert rendered.count("| sqli-dojo-boolean-id |") == 2
    assert rendered.count("| sqli-dojo-boolean-source |") == 2
    assert "| sqli-dojo (mysql) |" in rendered
    documentation = runner.DOCS.read_text(encoding="utf-8")
    readme = (THIRD_PARTY / "README.md").read_text(encoding="utf-8")
    for field in ("attempts", "response", "no_response", "not_dispatched"):
        assert f"`{field}`" in documentation
        assert f"`{field}`" in readme
    assert "Reviewed report schema version: `9`." in documentation


@pytest.mark.doc_drift
def test_measurement_input_revisions_match_reviewed_configs():
    runner = load_runner()
    source = runner.DOCS.read_text(encoding="utf-8")
    _, heading, section = source.partition("## Measurement input revisions\n")
    assert heading and (heading + section.split("\n## ", 1)[0]).strip() == (
        runner.render_measurement_input_revisions()
    ), (
        "Measurement input revisions differ from the declared history. "
        "Regenerate the section with render_measurement_input_revisions()."
    )


def test_missing_measurement_input_revision_is_rejected(tmp_path):
    runner = load_runner()
    original = THIRD_PARTY / "measurement-input-revisions.toml"
    revisions = tmp_path / original.name
    sections = original.read_text(encoding="utf-8").split("[[confirmation]]")
    revisions.write_text(
        "[[confirmation]]".join(
            section
            for section in sections
            if 'endpoint = "sqli-dojo-boolean-id"' not in section
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        runner.MeasurementError,
        match=r"sqli-dojo/sqli-dojo-boolean-id.*without documented history.*Add a confirmation entry",
    ):
        runner.render_measurement_input_revisions(revisions)


def test_stale_measurement_input_revision_is_rejected(tmp_path):
    runner = load_runner()
    original = THIRD_PARTY / "measurement-input-revisions.toml"
    revisions = tmp_path / original.name
    revisions.write_text(
        original.read_text(encoding="utf-8")
        + '\n[[confirmation]]\ntarget = "sqli-dojo"\nendpoint = "removed-endpoint"\n'
        'history = "This configuration was removed."\n',
        encoding="utf-8",
    )

    with pytest.raises(
        runner.MeasurementError,
        match=r"Stale.*sqli-dojo/removed-endpoint/confirmation.*removed config as current.*Remove the entry",
    ):
        runner.render_measurement_input_revisions(revisions)


def test_preset_confirmation_revision_is_rejected(tmp_path, monkeypatch):
    runner = load_runner()
    plan_measurements = runner.plan_measurements
    preset_config = tmp_path / "owasp-lab-boolean-greet-confirmation.toml"
    source = THIRD_PARTY / "dsvw/configs/dsvw-version-query-confirmation.toml"
    preset_config.write_bytes(source.read_bytes())
    revision_key = (
        "owasp-lab",
        "owasp-lab-boolean-greet",
        "sqli.boolean",
        "confirmation",
    )

    def plan_with_preset(targets, records):
        for planned in plan_measurements(targets, records):
            yield (
                planned._replace(config=preset_config)
                if planned.key == revision_key
                else planned
            )

    monkeypatch.setattr(runner, "plan_measurements", plan_with_preset)
    with pytest.raises(
        runner.MeasurementError,
        match=r"owasp-lab/owasp-lab-boolean-greet/confirmation.*describe a preset config as explicit.*Remove the entry",
    ):
        runner.render_measurement_input_revisions()


@pytest.mark.parametrize("report", [[], "private report text", 42, None])
def test_documented_summary_rejects_non_object_reports(report, tmp_path):
    runner = load_runner()
    message = (
        "The third-party measurement report is not a JSON object. "
        "Pass a report produced by scripts/run_third_party_sqli_measurement.py."
    )

    with pytest.raises(runner.MeasurementError, match=rf"^{re.escape(message)}$"):
        runner.check_documented_summary(report, tmp_path / "missing.md")


def test_observation_collector_rejects_duplicates_and_sequence_gaps():
    runner = load_runner()
    collector = runner.ObservationCollector()
    observation = RecordedSqliObservation("boolean", 1, "baseline", object())
    collector(observation)
    with pytest.raises(
        runner.MeasurementError,
        match=r"duplicate sequence number 1.*runner emission.*rerun",
    ):
        collector(observation)

    gap = runner.ObservationCollector()
    gap(RecordedSqliObservation("boolean", 2, "true", object()))
    with pytest.raises(
        runner.MeasurementError,
        match=r"sequence gaps.*expected \[1, 2\].*observed \[2\].*runner emission",
    ):
        gap.ordered(2)


def test_report_probe_roles_are_derived_from_production_orders():
    runner = load_runner()

    assert runner.BOOLEAN_REPORT_ROLES == tuple(
        kind.value for kind in BOOLEAN_PROBE_ORDER
    )
    assert runner.CONFIRMATION_REPORT_ROLES == runner.BOOLEAN_REPORT_ROLES + tuple(
        runner._confirmation_role(kind) for kind in CONFIRMATION_ORDER
    )
    assert runner.TIME_REPORT_ROLES == tuple(kind.value for kind in TIME_PROBE_ORDER)
    assert runner.ERROR_REPORT_ROLES == tuple(
        runner._error_role(kind) for kind in ERROR_PROBE_ORDER
    )


def test_confirmation_roles_start_with_boolean_order_then_confirmation_order():
    runner = load_runner()
    initial_count = len(BOOLEAN_PROBE_ORDER)

    assert runner.CONFIRMATION_REPORT_ROLES[:initial_count] == tuple(
        kind.value for kind in BOOLEAN_PROBE_ORDER
    )
    assert runner.CONFIRMATION_REPORT_ROLES[initial_count:] == tuple(
        runner._confirmation_role(kind) for kind in CONFIRMATION_ORDER
    )

    runner = load_runner()
    content_length = runner._parse_http_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    )
    chunked = runner._parse_http_response(
        b"HTTP/1.1 500 Error\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\nbody\r\n0\r\n\r\n"
    )

    expected_digest = hashlib.sha256(b"body").hexdigest()
    assert content_length == runner.RecordedResponse(200, 4, expected_digest)
    assert chunked == runner.RecordedResponse(500, 4, expected_digest)
    assert not hasattr(content_length, "body")


def test_bridge_rejects_extra_content_length_and_chunked_frames():
    runner = load_runner()
    message = r"records one HTTP response per TCP connection.*keep-alive client.*measurement_http_transport\(\).*keep-alive disabled"

    with pytest.raises(runner.MeasurementError, match=message):
        runner._parse_http_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nextra"
        )
    with pytest.raises(runner.MeasurementError, match=message):
        runner._parse_http_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"4\r\nbody\r\n0\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nextra"
        )


def test_bridge_skips_one_or_more_interim_responses_before_final_response():
    runner = load_runner()
    expected_digest = hashlib.sha256(b"body").hexdigest()

    one_interim = runner._parse_http_response(
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    )
    multiple_interim = runner._parse_http_response(
        b"HTTP/1.1 100 Continue\r\n\r\n"
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload\r\n\r\n"
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
    )

    expected = runner.RecordedResponse(200, 4, expected_digest)
    assert one_interim == expected
    assert multiple_interim == expected


def test_bridge_rejects_extra_frame_after_interim_and_final_response():
    runner = load_runner()

    with pytest.raises(
        runner.MeasurementError,
        match=r"records one HTTP response per TCP connection.*keep-alive client.*measurement_http_transport",
    ):
        runner._parse_http_response(
            b"HTTP/1.1 103 Early Hints\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nextra"
        )


def test_bridge_rejects_protocol_upgrade_and_truncated_interim_headers():
    runner = load_runner()

    with pytest.raises(
        runner.MeasurementError,
        match=r"does not support HTTP 101 protocol upgrades.*non-upgrade response",
    ):
        runner._parse_http_response(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )
    with pytest.raises(
        runner.MeasurementError,
        match=r"complete HTTP response header.*target transport.*rerun",
    ):
        runner._parse_http_response(
            b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload"
        )


@pytest.mark.parametrize("status_code", [204, 304])
def test_bridge_records_no_body_final_statuses(status_code):
    runner = load_runner()

    response = runner._parse_http_response(
        f"HTTP/1.1 {status_code} No Body\r\nContent-Length: 0\r\n\r\n".encode()
    )

    assert response == runner.RecordedResponse(
        status_code,
        0,
        hashlib.sha256(b"").hexdigest(),
    )


class _KeepAliveUpstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.requests_lock = threading.Lock()
        super().__init__(("127.0.0.1", 0), _KeepAliveHandler)


class _KeepAliveHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        value = parse_qs(urlsplit(self.path).query)["id"][0]
        body = b"false" if "1=2" in value else b"baseline-or-true"
        server = self.server
        if not isinstance(server, _KeepAliveUpstream):
            raise TypeError("Unexpected keep-alive test server.")
        with server.requests_lock:
            server.requests.append(value)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def _run_six_probes_through_bridge(runner, transport):
    upstream = _KeepAliveUpstream()
    started = threading.Event()

    def serve() -> None:
        started.set()
        upstream.serve_forever(poll_interval=0.01)

    thread = threading.Thread(target=serve)
    thread.start()
    assert started.wait(timeout=5), (
        "The keep-alive upstream did not start; check Event synchronization instead of adding a sleep."
    )
    target = SimpleNamespace(
        target_id="fixed-keep-alive",
        service_port=upstream.server_address[1],
    )
    collector = runner.ObservationCollector()
    try:
        with runner.loopback_bridge("127.0.0.1", target) as (origin, bridge):
            context = ExecutionContext(
                scope=ScopePolicy(
                    allowed_origins=frozenset(
                        {
                            AllowedOrigin(
                                "http", "127.0.0.1", int(origin.rsplit(":", 1)[1])
                            )
                        }
                    )
                ),
                budget=RequestBudget(6),
                rate_limiter=RateLimiter(requests_per_second=100),
            )
            result = verify_boolean_sqli(
                check_id="fixed-keep-alive-six-probe",
                template=RequestTemplate(
                    method="GET",
                    url=origin + "/lookup",
                    params=(("id", "2"),),
                ),
                point=InjectionPoint(
                    location=InjectionLocation.QUERY,
                    name="id",
                    mode=InjectionMode.APPEND,
                ),
                true_payload=" AND 1=1-- ",
                false_payload=" AND 1=2-- ",
                context=context,
                transport=transport,
                observation_sink=collector,
            )
            responses = bridge.recorded_responses(6)
            observations = collector.ordered(6)
            return result, bridge, responses, observations, tuple(upstream.requests)
    finally:
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), (
            "The keep-alive upstream did not stop; check handler lifecycle instead of adding a sleep."
        )


def test_measurement_transport_records_one_connection_per_probe():
    runner = load_runner()

    with runner.measurement_http_transport() as transport:
        result, bridge, responses, observations, requests = (
            _run_six_probes_through_bridge(runner, transport)
        )

    assert result.request_count == 6
    assert bridge.recorder.next_sequence == 6
    assert tuple(sorted(bridge.recorder.responses)) == tuple(range(6))
    assert len(responses) == len(observations) == len(requests) == 6
    assert all(
        response.status_code == recorded.observation.status_code
        and response.body_size == recorded.observation.body_size
        and response.body_sha256 == recorded.observation.body_digest
        for response, recorded in zip(responses, observations, strict=True)
    )
    assert tuple(recorded.kind for recorded in observations) == tuple(
        kind.value for kind in BOOLEAN_PROBE_ORDER
    )


def test_keep_alive_transport_fails_closed_on_second_exchange():
    runner = load_runner()

    with (
        pytest.raises(
            runner.MeasurementError,
            match=r"records one HTTP response per TCP connection.*pooled or keep-alive client.*measurement_http_transport\(\).*keep-alive disabled",
        ),
        httpx.HTTPTransport() as transport,
    ):
        _run_six_probes_through_bridge(runner, transport)


def test_measurement_transport_factory_disables_keep_alive(monkeypatch):
    runner = load_runner()
    captured: dict[str, object] = {}
    sentinel = object()

    def fake_transport(**kwargs):
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(runner.httpx, "HTTPTransport", fake_transport)

    assert runner.measurement_http_transport() is sentinel
    limits = captured["limits"]
    assert isinstance(limits, httpx.Limits)
    assert limits.max_keepalive_connections == 0


def test_bridge_handler_parse_failure_preserves_redacted_cause_and_sequence():
    runner = load_runner()
    target = SimpleNamespace(target_id="fixed-diagnostic", service_port=1)
    sentinel = "SENTINEL-SECRET-7f3a"
    malformed = (
        b"HTTP/1.1 200 OK\r\nContent-Length: " + sentinel.encode() + b"\r\n\r\nbody"
    )

    with (
        pytest.raises(
            runner.MeasurementError,
            match=r"handler failed at sequence 0 with MeasurementError.*rejected invalid HTTP framing or request sequencing.*Accepted sequences: \[0\]; completed sequences: \[\]",
        ) as caught,
        runner.loopback_bridge("127.0.0.1", target) as (_, bridge),
    ):
        request = object()
        sequence = bridge.recorder.accept()
        bridge.accepted_sequences[id(request)] = sequence
        try:
            runner._parse_http_response(malformed)
        except runner.MeasurementError:
            bridge.handle_error(request, ("127.0.0.1", 1))

    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert sentinel not in str(caught.value)
    assert sentinel not in "".join(traceback.format_exception(caught.value))


def test_bridge_records_responses_by_acceptance_sequence_not_completion_order():
    runner = load_runner()
    recorder = runner._ResponseRecorder()
    first_waiting = threading.Event()
    second_recorded = threading.Event()
    first = runner._recorded_response(201, iter((b"first-response",)))
    second = runner._recorded_response(202, iter((b"second-response",)))
    first_sequence = recorder.accept()
    second_sequence = recorder.accept()

    def record_first() -> None:
        first_waiting.set()
        if not second_recorded.wait(timeout=5):
            raise RuntimeError(
                "The deterministic ordering barrier did not release. Check the test synchronization instead of adding a sleep."
            )
        recorder.record_response(first_sequence, first)

    def record_second() -> None:
        recorder.record_response(second_sequence, second)
        second_recorded.set()

    first_thread = threading.Thread(target=record_first)
    second_thread = threading.Thread(target=record_second)
    first_thread.start()
    assert first_waiting.wait(timeout=5)
    second_thread.start()
    first_thread.join(timeout=5)
    second_thread.join(timeout=5)
    assert not first_thread.is_alive() and not second_thread.is_alive()

    assert recorder.recorded_responses(2) == (first, second)


def test_bridge_rejects_sequence_gaps_and_duplicates():
    runner = load_runner()
    response = runner._recorded_response(200, iter((b"response",)))
    gap_recorder = runner._ResponseRecorder()
    duplicate_recorder = runner._ResponseRecorder()
    gap_recorder.record_response(0, response)
    gap_recorder.record_response(2, response)
    with pytest.raises(
        runner.MeasurementError,
        match=r"sequence gaps.*expected \[0, 1\], observed \[0, 2\].*rerun.*completion order",
    ):
        gap_recorder.recorded_responses(2)

    duplicate_recorder.record_response(0, response)
    with pytest.raises(
        runner.MeasurementError,
        match=r"duplicate sequence number 0.*rerun.*one probe twice",
    ):
        duplicate_recorder.record_response(0, response)


def test_report_target_metadata_must_match_declaration():
    runner = load_runner()
    report = v9_report_from_legacy_v4(runner)
    report["targets"]["dsvw"]["commit"] = "changed"

    with pytest.raises(
        runner.MeasurementError,
        match=r"dsvw.*prepared provenance at field commit.*Rerun preparation and measurement",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize("missing_label", ["positive", "negative"])
def test_declaration_requires_both_labels_per_target_and_check(
    missing_label, monkeypatch
):
    runner = load_runner()
    document = declarations()
    document["records"] = [
        record
        for record in document["records"]
        if not (
            record["check_type"] == "sqli.error" and record["label"] == missing_label
        )
    ]
    monkeypatch.setattr(runner.tomllib, "load", lambda stream: document)

    with pytest.raises(
        runner.MeasurementError,
        match=r"dsvw.*sqli.error.*lacks a positive or negative record.*Supply both",
    ):
        runner.load_declarations()


def test_record_operation_path_must_be_an_absolute_openapi_path(monkeypatch):
    runner = load_runner()
    document = declarations()
    record = next(row for row in document["records"] if row["target_id"] == "owasp-lab")
    record["operation_path"] = "a03/search"
    monkeypatch.setattr(runner.tomllib, "load", lambda stream: document)

    with pytest.raises(
        runner.MeasurementError,
        match=r"owasp-lab-boolean-search.*invalid operation_path.*absolute OpenAPI path",
    ):
        runner.load_declarations()


def test_tag_only_service_image_is_rejected(monkeypatch, tmp_path):
    runner = load_runner()
    content = TARGETS.read_text(encoding="utf-8").replace(
        "service_images = []", 'service_images = ["postgres:16"]'
    )
    declaration = tmp_path / "targets.toml"
    declaration.write_text(content, encoding="utf-8")
    monkeypatch.setattr(runner, "DECLARATIONS", declaration)

    with pytest.raises(
        runner.MeasurementError,
        match=r"dsvw.*unpinned service image.*image@sha256.*mutable tag",
    ):
        runner.load_declarations()


def test_compose_is_internal_loopback_only_and_never_pulls():
    compose = (THIRD_PARTY / "dsvw" / "compose.yaml").read_text()
    assert "pull_policy: never" in compose
    assert "expose:" in compose
    assert '"65412"' in compose
    assert "ports:" not in compose
    assert "internal: true" in compose
    assert "PEX_ROOT: /tmp/pex" in compose
    assert "/tmp:size=128m" in compose
    assert "0.0.0.0" not in compose


@pytest.mark.parametrize(
    ("value", "valid"),
    [
        ("sha256:", False),
        ("sha256:" + "a" * 63, False),
        ("sha256:" + "A" * 64, False),
        ("sha256:" + "g" * 64, False),
        ("sha512:" + "a" * 64, False),
        ("sha256:" + "a" * 64, True),
    ],
)
def test_image_digest_contract_is_exact(value, valid):
    runner = load_runner()
    assert runner.is_image_digest(value) is valid


@pytest.mark.parametrize(
    "bad_image_id",
    [
        "sha256:",
        "sha256:" + "a" * 8,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
        "digest:" + "a" * 64,
    ],
)
def test_prepare_rejects_unidentifiable_local_image_id(bad_image_id):
    preparer = load_preparer()
    with pytest.raises(
        preparer.PreparationError,
        match=r"cannot be identified.*Rerun prepare",
    ):
        preparer.validate_prepared_image_id(bad_image_id, "dsvw")


def _target_with_service_images(runner, service_images):
    targets, _ = runner.load_declarations()
    declaration = {**targets["dsvw"], "service_images": service_images}
    return runner.target_adapter("dsvw", declaration)


@pytest.mark.parametrize(
    ("declared", "resolved", "message"),
    [
        (
            [],
            {
                "dsvw": {"image": "app:prepared"},
                "db": {"image": "db@sha256:" + "a" * 64},
            },
            r"service 'db'.*declared '<not declared>'.*resolved 'db@sha256:",
        ),
        (
            ["db@sha256:" + "b" * 64],
            {
                "dsvw": {"image": "app:prepared"},
                "db": {"image": "db@sha256:" + "a" * 64},
            },
            r"service 'db'.*declared 'db@sha256:b+.*resolved 'db@sha256:a+",
        ),
        (
            ["db@sha256:" + "a" * 64],
            {"dsvw": {"image": "app:prepared"}},
            r"service '<unused>'.*declared 'db@sha256:a+.*resolved '<not used>'",
        ),
    ],
)
def test_resolved_compose_images_must_exactly_match_declaration(
    declared, resolved, message
):
    runner = load_runner()
    target = _target_with_service_images(runner, declared)

    with pytest.raises(
        runner.MeasurementError,
        match=message + r".*Update targets.toml or the Compose file",
    ):
        runner.validate_resolved_service_images(
            target, "app:prepared", {"services": resolved}
        )


def test_matching_resolved_compose_images_are_recorded():
    runner = load_runner()
    database = "db@sha256:" + "a" * 64
    target = _target_with_service_images(runner, [database])

    assert runner.validate_resolved_service_images(
        target,
        "app:prepared",
        {
            "services": {
                "dsvw": {"image": "app:prepared"},
                "db": {"image": database},
            }
        },
    ) == {"db": database}


@pytest.mark.parametrize("entry_point", ["pre_start", "report"])
@pytest.mark.parametrize(
    ("declared", "mapping", "error"),
    [
        (
            ["shared@sha256:" + "a" * 64],
            {
                "db": "shared@sha256:" + "a" * 64,
                "worker": "shared@sha256:" + "a" * 64,
            },
            None,
        ),
        (
            [],
            {"db": "db@sha256:" + "a" * 64},
            r"service 'db'.*declared '<not declared>'.*resolved 'db@sha256:",
        ),
        (
            ["db@sha256:" + "a" * 64],
            {},
            r"service '<unused>'.*declared 'db@sha256:a+.*resolved '<not used>'",
        ),
        (
            ["db@sha256:" + "b" * 64],
            {"db": "db@sha256:" + "a" * 64},
            r"service 'db'.*declared 'db@sha256:b+.*resolved 'db@sha256:a+",
        ),
    ],
)
def test_pre_start_and_report_use_the_same_service_image_rule(
    entry_point, declared, mapping, error, monkeypatch
):
    runner = load_runner()
    targets, records = runner.load_declarations()
    target_declaration = {**targets["dsvw"], "service_images": declared}
    monkeypatch.setattr(
        runner,
        "load_declarations",
        lambda: ({**targets, "dsvw": target_declaration}, records),
    )

    if entry_point == "pre_start":
        target = runner.target_adapter("dsvw", target_declaration)

        def call_pre_start():
            return runner.validate_resolved_service_images(
                target,
                "app:prepared",
                {
                    "services": {
                        "dsvw": {"image": "app:prepared"},
                        **{
                            service: {"image": image}
                            for service, image in mapping.items()
                        },
                    }
                },
            )

        call = call_pre_start

    else:
        report = v9_report_from_legacy_v4(runner)
        report["targets"]["dsvw"]["service_images"] = mapping

        def call_report():
            return runner.validate_measurement_report(report)

        call = call_report

    if error is None:
        assert call() is not None
    else:
        with pytest.raises(
            runner.MeasurementError,
            match=(
                error + r".*Update targets.toml or the Compose file"
                if entry_point == "pre_start"
                else r"targets.dsvw.service_images.*JSON type object.*digest-pinned.*Rerun preparation"
            ),
        ):
            call()


@pytest.mark.parametrize(
    "bad_image_id",
    [
        "sha256:",
        "sha256:" + "a" * 8,
        "sha256:" + "A" * 64,
        "sha256:" + "g" * 64,
        "digest:" + "a" * 64,
    ],
)
def test_report_rejects_bad_app_image_ids(bad_image_id):
    runner = load_runner()
    report = v9_report_from_legacy_v4(runner)
    report["targets"]["dsvw"]["image_ids"]["app"] = bad_image_id

    with pytest.raises(
        runner.MeasurementError,
        match=r"cannot be identified.*Rerun prepare",
    ):
        runner.validate_measurement_report(report)


def test_prepare_ignores_modified_stale_extraction(tmp_path, monkeypatch):
    preparer = load_preparer()
    commit = "0123456789abcdef0123456789abcdef01234567"
    archive_source = tmp_path / "archive-source" / f"DSVW-{commit}"
    archive_source.mkdir(parents=True)
    (archive_source / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    (archive_source / "dsvw.py").write_text("one\ntwo\nthree\n", encoding="utf-8")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    archive = workspace / f"dsvw-{commit}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(archive_source, arcname=archive_source.name)

    stale = workspace / "source" / archive_source.name
    stale.mkdir(parents=True)
    (stale / "Dockerfile").write_text("MODIFIED STALE FILE\n", encoding="utf-8")
    archive_digest = preparer.sha256_file(archive)
    target = {
        "id": "dsvw",
        "archive_sha256": archive_digest,
        "archive_url": "https://invalid.example/archive",
        "commit": commit,
        "service_images": [],
    }
    records = [
        {
            "id": "reviewed",
            "target_id": "dsvw",
            "source_path": "dsvw.py",
            "source_start_line": 1,
            "source_end_line": 1,
        }
    ]
    monkeypatch.setattr(preparer, "load_declarations", lambda: ([target], records))
    observed: dict[str, object] = {}

    def fake_docker(arguments, target_id):
        if arguments[0] == "build":
            context = Path(arguments[-1])
            observed["context"] = context
            observed["dockerfile"] = (context / "Dockerfile").read_text(
                encoding="utf-8"
            )
            observed["manifest"] = preparer.source_manifest_sha256(context)
            return ""
        return "sha256:" + "a" * 64

    monkeypatch.setattr(preparer, "run_docker", fake_docker)
    state_path = preparer.prepare(workspace)
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert observed["dockerfile"] == "FROM scratch\n"
    target_state = state["targets"]["dsvw"]
    assert state["schema_version"] == 2
    assert "build_recipe" not in target_state
    assert observed["manifest"] == target_state["source_manifest_sha256"]
    assert target_state["source_evidence"] == {
        "reviewed": {
            "source_end_line": 1,
            "source_fragment_sha256": (
                "2c8b08da5ce60398e1f19af0e5dccc744df274b826abe585eaba68c525434806"
            ),
            "source_path": "dsvw.py",
            "source_start_line": 1,
        }
    }
    assert observed["context"] != stale
    assert not Path(observed["context"]).exists()
    assert (stale / "Dockerfile").read_text(encoding="utf-8") == (
        "MODIFIED STALE FILE\n"
    )


def test_compose_projects_are_unique_and_teardown_uses_own_run(monkeypatch, tmp_path):
    runner = load_runner()
    first = runner.compose_project_name("dsvw", runner.new_run_id(), 0, "six")
    second = runner.compose_project_name("dsvw", runner.new_run_id(), 0, "six")
    assert first != second
    assert re.fullmatch(r"vintar-dsvw-[0-9a-f]{12}-0-six", first)
    assert len(first) < 64
    assert runner.compose_project_name("dsvw", "0123456789ab", 2, "time") == (
        "vintar-dsvw-0123456789ab-2-time"
    )
    targets, _ = runner.load_declarations()
    adapter = runner.target_adapter("dsvw", targets["dsvw"])
    stopped: list[str] = []
    monkeypatch.setattr(
        runner,
        "compose",
        lambda target, image, project, arguments, **kwargs: stopped.append(project),
    )
    runner.stop_target(adapter, "image", first)
    runner.stop_target(adapter, "image", second)
    assert stopped == [first, second]


def prepared_provenance():
    record = {
        "id": "dsvw-record",
        "source_end_line": 23,
        "source_fragment_sha256": "a" * 64,
        "source_path": "dsvw.py",
        "source_start_line": 21,
    }
    state = {
        "archive_sha256": "archive",
        "commit": "commit",
        "image_id": "sha256:" + "a" * 64,
        "image_tag": "image:tag",
        "schema_version": 1,
        "source_evidence": {
            "dsvw-record": {key: value for key, value in record.items() if key != "id"}
        },
        "source_manifest_sha256": "b" * 64,
    }
    target = {"archive_sha256": "archive", "commit": "commit", "id": "dsvw"}
    return state, target, record


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("source_path", "changed.py"),
        ("source_start_line", 20),
        ("source_end_line", 24),
    ],
)
def test_changed_source_reference_is_rejected_before_docker(
    field, changed, monkeypatch
):
    runner = load_runner()
    state, target, record = prepared_provenance()
    changed_record = {**record, field: changed}
    docker_calls: list[list[str]] = []
    monkeypatch.setattr(
        runner,
        "run_command",
        lambda command, **kwargs: docker_calls.append(command),
    )

    with pytest.raises(
        runner.MeasurementError,
        match=rf"dsvw-record differs at field {field}.*Rerun prepare.*source_fragment_sha256",
    ):
        runner.validate_provenance(state, target, [changed_record])

    assert docker_calls == []


def test_unchanged_source_reference_passes_before_docker(monkeypatch):
    runner = load_runner()
    state, target, record = prepared_provenance()
    docker_calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        docker_calls.append(command)
        return SimpleNamespace(stdout="sha256:" + "a" * 64 + "\n")

    monkeypatch.setattr(runner, "run_command", fake_run)

    assert runner.validate_provenance(state, target, [record]) == (
        "image:tag",
        "sha256:" + "a" * 64,
    )
    assert docker_calls == [
        ["docker", "image", "inspect", "--format", "{{.Id}}", "image:tag"]
    ]


def prepared_recipe_provenance(tmp_path, monkeypatch, *, mutate_during_build=False):
    preparer = load_preparer()
    commit = "0123456789abcdef0123456789abcdef01234567"
    archive_source = tmp_path / "archive-source" / f"dojo-{commit}"
    archive_source.mkdir(parents=True)
    (archive_source / "upstream.txt").write_text("reviewed\n", encoding="utf-8")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    archive = workspace / f"dojo-{commit}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(archive_source, arcname=archive_source.name)
    recipe_path = tmp_path / "Dockerfile"
    recipe_path.write_text("FROM scratch\n", encoding="utf-8")
    target = {
        "archive_sha256": preparer.sha256_file(archive),
        "archive_url": "https://invalid.example/archive",
        "commit": commit,
        "dockerfile_path": "sqli-dojo/Dockerfile",
        "id": "dojo",
        "service_images": [],
    }
    record = {
        "id": "dojo-record",
        "source_end_line": 1,
        "source_fragment_sha256": (
            "a9f2d25d1f71f8065e2119e538bde8846570fcdad320388236e99d9e225c290d"
        ),
        "source_path": "upstream.txt",
        "source_start_line": 1,
        "target_id": "dojo",
    }
    monkeypatch.setattr(
        preparer,
        "target_asset",
        lambda target_id, declaration, key: recipe_path,
    )
    observed: dict[str, object] = {}

    def fake_docker(arguments, target_id):
        if arguments[0] == "build":
            snapshot = Path(arguments[arguments.index("--file") + 1])
            observed["snapshot_path"] = snapshot
            observed["snapshot_bytes"] = snapshot.read_bytes()
            if mutate_during_build:
                recipe_path.write_text("FROM changed\n", encoding="utf-8")
            observed["build_bytes"] = snapshot.read_bytes()
            return ""
        return "sha256:" + "a" * 64

    monkeypatch.setattr(preparer, "run_docker", fake_docker)
    state = preparer.prepare_target(workspace, target, [record])
    return state, target, record, recipe_path, observed


def test_build_recipe_hash_and_docker_input_share_one_snapshot(tmp_path, monkeypatch):
    state, _, _, recipe_path, observed = prepared_recipe_provenance(
        tmp_path, monkeypatch, mutate_during_build=True
    )
    snapshot_bytes = observed["snapshot_bytes"]
    snapshot_path = observed["snapshot_path"]

    assert isinstance(snapshot_bytes, bytes)
    assert isinstance(snapshot_path, Path)
    assert snapshot_bytes == observed["build_bytes"] == b"FROM scratch\n"
    assert recipe_path.read_bytes() == b"FROM changed\n"
    assert state["build_recipe"] == {
        "path": "sqli-dojo/Dockerfile",
        "sha256": hashlib.sha256(snapshot_bytes).hexdigest(),
    }
    assert snapshot_path != recipe_path
    assert not snapshot_path.exists()


def test_changed_build_recipe_is_rejected_before_docker(tmp_path, monkeypatch):
    runner = load_runner()
    state, target, record, recipe_path, _ = prepared_recipe_provenance(
        tmp_path, monkeypatch
    )
    recipe_path.write_text("FROM changed\n", encoding="utf-8")
    docker_calls: list[list[str]] = []
    monkeypatch.setattr(
        runner,
        "_relative_path",
        lambda target_id, declaration, key: recipe_path,
    )
    monkeypatch.setattr(
        runner,
        "run_command",
        lambda command, **kwargs: docker_calls.append(command),
    )

    with pytest.raises(
        runner.MeasurementError,
        match=r"build recipe.*target 'dojo'.*changed since prepare.*image may be stale.*Rerun scripts/prepare_third_party_sqli.py",
    ):
        runner.validate_provenance(state, target, [record])

    assert docker_calls == []


def test_missing_build_recipe_is_rejected_before_docker(monkeypatch):
    runner = load_runner()
    state, target, record = prepared_provenance()
    target["dockerfile_path"] = "sqli-dojo/Dockerfile"
    docker_calls: list[list[str]] = []
    monkeypatch.setattr(
        runner,
        "run_command",
        lambda command, **kwargs: docker_calls.append(command),
    )

    with pytest.raises(
        runner.MeasurementError,
        match=r"build recipe metadata.*target 'dsvw'.*missing or invalid.*image may be stale.*rerun scripts/prepare_third_party_sqli.py",
    ):
        runner.validate_provenance(state, target, [record])

    assert docker_calls == []


def test_unchanged_build_recipe_passes_before_docker(tmp_path, monkeypatch):
    runner = load_runner()
    state, target, record, recipe_path, _ = prepared_recipe_provenance(
        tmp_path, monkeypatch
    )
    docker_calls: list[list[str]] = []
    monkeypatch.setattr(
        runner,
        "_relative_path",
        lambda target_id, declaration, key: recipe_path,
    )

    def fake_run(command, **kwargs):
        docker_calls.append(command)
        return SimpleNamespace(stdout="sha256:" + "a" * 64 + "\n")

    monkeypatch.setattr(runner, "run_command", fake_run)

    assert runner.validate_provenance(state, target, [record]) == (
        state["image_tag"],
        state["image_id"],
    )
    assert docker_calls == [
        ["docker", "image", "inspect", "--format", "{{.Id}}", state["image_tag"]]
    ]


def test_build_recipe_on_archive_only_target_is_rejected(monkeypatch):
    runner = load_runner()
    state, target, record = prepared_provenance()
    state["build_recipe"] = {
        "path": "unexpected/Dockerfile",
        "sha256": "c" * 64,
    }
    docker_calls: list[list[str]] = []
    monkeypatch.setattr(
        runner,
        "run_command",
        lambda command, **kwargs: docker_calls.append(command),
    )

    with pytest.raises(
        runner.MeasurementError,
        match=r"build recipe metadata exists.*target 'dsvw'.*no dockerfile_path.*Rerun scripts/prepare_third_party_sqli.py",
    ):
        runner.validate_provenance(state, target, [record])

    assert docker_calls == []


def test_v10_writer_shape_round_trips_through_derive_then_compare_validator():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    assert report["schema_version"] == runner.MEASUREMENT_SCHEMA_VERSION == 10
    assert runner.validate_measurement_report(report) is report
    for record in report["records"]:
        assert "evidence" not in record and "relations" not in record
        assert (
            sum(item["outcome"] != "not_dispatched" for item in record["attempts"])
            == record["request_count"]
        )


def test_v10_writer_requires_current_schema_and_round_trips(tmp_path):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    output = tmp_path / "report.json"
    runner.write_report(output, report)
    assert json.loads(output.read_text(encoding="utf-8")) == report
    with pytest.raises(runner.MeasurementError, match="v9 lacks per-attempt evidence"):
        runner.write_report(tmp_path / "legacy.json", expected_report())


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("sequence", True, "JSON integer"),
        ("stage", "error", "fixed production stage"),
        ("probe_kind", "delay", "fixed production stage"),
        ("wire_status_code", 201, "wire and analyzer status"),
        ("wire_body_size", True, "JSON integer"),
        ("wire_body_sha256", "f" * 63, "lowercase SHA-256"),
    ],
)
def test_v10_attempt_identity_and_wire_mutations_fail(field, value, message):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    report["records"][0]["attempts"][0][field] = value
    with pytest.raises(runner.MeasurementError, match=message):
        runner.validate_measurement_report(report)


def test_v10_terminal_no_response_and_not_dispatched_accounting():
    runner = load_runner()
    for outcome, failure_kind, counted in (
        ("no_response", "timeout", 1),
        ("not_dispatched", "budget_unavailable", 0),
    ):
        report = v10_report_from_legacy_v4(runner)
        record = next(
            item
            for item in report["records"]
            if item["check_type"] == "sqli.boolean" and item["mode"] == "six_probe"
        )
        later = record["attempts"][0]
        record["attempts"] = [
            {
                "sequence": 1,
                "stage": "boolean",
                "probe_kind": "baseline",
                "outcome": outcome,
                "failure_kind": failure_kind,
            }
        ]
        record["request_count"] = counted
        record["actual_verdict"] = "inconclusive"
        record["reason_code"] = (
            "probe_failed" if outcome == "no_response" else "budget_unavailable"
        )
        record["classification"] = "non_decision"
        record["decision_facts"] = {
            "category": "operational",
            "stage": "initial",
            "sequence": 1,
            "probe_kind": "baseline",
            "condition": failure_kind,
        }
        record["detail"] = {
            "configured": False,
            "reason_code": None,
            "request_count": 0,
            "status": "not_configured",
        }
        report["counts"] = runner.counts(report["records"])
        assert runner.validate_measurement_report(report) is report
        record["attempts"].append({**later, "sequence": 2, "probe_kind": "true"})
        with pytest.raises(runner.MeasurementError, match="no attempt may follow"):
            runner.validate_measurement_report(report)


def test_v10_repeat_digest_relation_is_rederived():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        item
        for item in report["records"]
        if item["check_type"] == "sqli.boolean"
        and item["mode"] == "six_probe"
        and item["reason_code"] == "boolean_candidate"
    )
    record["attempts"][5]["body_sha256"] = "f" * 64
    with pytest.raises(runner.MeasurementError, match="repeat comparison contradicts"):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize(
    "predicate",
    [
        "baseline_span_exceeded",
        "control_span_exceeded",
        "baseline_control_difference_exceeded",
        "drift_exceeded",
        "candidate_median_met",
        "candidate_margin_met",
    ],
)
def test_v10_time_predicate_mutations_change_the_derived_result(predicate):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        item
        for item in report["records"]
        if item["check_type"] == "sqli.time"
        and item["reason_code"] == "timing_pattern_matched"
    )
    record["time_predicates"][predicate] = not record["time_predicates"][predicate]
    with pytest.raises(runner.MeasurementError, match="verdict or reason contradicts"):
        runner.validate_measurement_report(report)


def test_v10_rejects_relabelled_facts_and_reason():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(item for item in report["records"] if "decision_facts" in item)
    record["decision_facts"]["sequence"] = 1
    with pytest.raises(runner.MeasurementError, match="decision_facts contradict"):
        runner.validate_measurement_report(report)

    report = v10_report_from_legacy_v4(runner)
    record = next(item for item in report["records"] if "decision_facts" in item)
    record.pop("decision_facts")
    with pytest.raises(runner.MeasurementError, match="decision_facts contradict"):
        runner.validate_measurement_report(report)
    report = v10_report_from_legacy_v4(runner)
    report["records"][0]["reason_code"] = "unexpected_difference"
    with pytest.raises(runner.MeasurementError, match="verdict or reason contradicts"):
        runner.validate_measurement_report(report)


def test_v10_boolean_response_dynamics_are_derived_from_repeat_comparison():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        item
        for item in report["records"]
        if item["check_type"] == "sqli.boolean"
        and item["mode"] == "six_probe"
        and item["expected_label"] == "positive"
    )
    repeated = record["attempts"][3]
    repeated["body_sha256"] = "f" * 64
    repeated["repeat_comparison"] = {
        "equal": False,
        "localization": "unlocalized",
    }
    record.update(
        actual_verdict="inconclusive",
        reason_code="unstable_response",
        classification="non_decision",
        decision_facts={
            "category": "response_dynamics",
            "normalization_applied": False,
            "normalized_echo_count": 0,
            "unstable_pairs": [
                {"probe_kind": "baseline", "localization": "unlocalized"}
            ],
        },
    )
    report["counts"] = runner.counts(report["records"])
    assert runner.validate_measurement_report(report) is report


def test_v10_confirmation_relation_facts_are_derived_from_attempts():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        item
        for item in report["records"]
        if item["check_type"] == "sqli.boolean"
        and item["mode"] == "confirmation"
        and item["expected_label"] == "positive"
    )
    repeated = next(
        item
        for item in reversed(record["attempts"])
        if item["stage"] == "confirmation" and item["probe_kind"] == "true_2"
    )
    repeated["body_sha256"] = "e" * 64
    repeated["repeat_comparison"] = {
        "equal": False,
        "localization": "unlocalized",
    }
    record.update(
        actual_verdict="inconclusive",
        reason_code="confirmation_unstable",
        classification="non_decision",
        decision_facts={
            "category": "confirmation_relation",
            "unstable_repeat_kinds": ["true_2"],
            "unreproduced_predicate_pairs": [],
            "mismatched_relations": [],
            "cross_phase_mismatched_kinds": [],
        },
        detail={
            "configured": True,
            "reason_code": "confirmation_unstable",
            "request_count": 12,
            "status": "inconclusive",
        },
    )
    report["counts"] = runner.counts(report["records"])
    assert runner.validate_measurement_report(report) is report


def test_v10_time_dynamics_facts_are_derived_from_predicates():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        item
        for item in report["records"]
        if item["check_type"] == "sqli.time" and item["expected_label"] == "positive"
    )
    record["time_predicates"].update(
        candidate_median_met=False,
        candidate_margin_met=False,
        no_delay_condition_met=False,
    )
    record.update(
        actual_verdict="inconclusive",
        reason_code="ambiguous_timing",
        classification="non_decision",
        decision_facts={
            "category": "timing_dynamics",
            "instability_causes": [],
            "candidate_median_met": False,
            "candidate_margin_met": False,
            "no_delay_condition_met": False,
        },
        detail={
            "reason_code": "ambiguous_timing",
            "request_count": 9,
            "status": "inconclusive",
        },
    )
    report["counts"] = runner.counts(report["records"])
    assert runner.validate_measurement_report(report) is report


@pytest.mark.doc_drift
def test_public_v9_rejection_and_exact_docs_bound_transition():
    runner = load_runner()
    reviewed = expected_report()
    with pytest.raises(
        runner.MeasurementError,
        match=r"v9 lacks per-attempt evidence.*uv run --locked python.*--workspace.*--output",
    ):
        runner.validate_measurement_report(reviewed)
    assert runner.check_documented_summary(reviewed)
    mutated = copy.deepcopy(reviewed)
    mutated["records"][0]["request_count"] += 1
    with pytest.raises(runner.MeasurementError, match="exact hash-pinned reviewed v9"):
        runner.check_documented_summary(mutated)


def test_v10_report_privacy_is_recursive():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    serialized = json.dumps(report, sort_keys=True)
    prohibited = {
        "body",
        "payload",
        "url",
        "headers",
        "cookies",
        "exception",
        "elapsed",
        "rate_wait",
        "median",
        "span",
        "threshold",
        "margin",
        "matched_text",
    }

    def visit(value):
        if type(value) is dict:
            for key, child in value.items():
                assert key not in prohibited
                visit(child)
        elif type(value) is list:
            for child in value:
                visit(child)

    visit(report)
    for secret in (
        "fixed-baseline-response-body",
        "fixed-error-response-body",
        "sqlite3.OperationalError",
        " AND 1=1-- ",
        "SENTINEL-SECRET-7f3a",
    ):
        assert secret not in serialized


@pytest.mark.parametrize("version", [4, 5, 6, 7, 8])
def test_v10_public_read_and_write_require_remeasurement_of_older_reports(
    version, tmp_path
):
    runner = load_runner()
    report = {"schema_version": version}
    with pytest.raises(runner.MeasurementError, match="Re-run: uv run --locked python"):
        runner.validate_measurement_report(report)
    output = tmp_path / "legacy.json"
    with pytest.raises(runner.MeasurementError, match="Re-run: uv run --locked python"):
        runner.write_report(output, report)
    assert not output.exists()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("missing", "measurement plan is incomplete"),
        ("duplicate", "undeclared or duplicated"),
        ("undeclared", "undeclared or duplicated"),
    ],
)
def test_v10_health_requires_the_full_declared_plan(mutation, message):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    records = report["records"]
    if mutation == "missing":
        records[:] = [
            record for record in records if record["classification"] != "non_decision"
        ]
    elif mutation == "duplicate":
        records.append(copy.deepcopy(records[0]))
    else:
        records[0]["endpoint_id"] = "SENTINEL-SECRET-7f3a"
    report["counts"] = runner.counts(records)
    with pytest.raises(runner.MeasurementError, match=message) as exc:
        runner.unhealthy_count(report)
    assert "SENTINEL-SECRET-7f3a" not in str(exc.value)
    assert "Rerun" in str(exc.value)


@pytest.mark.parametrize("scope", ["overall", "by_target"])
@pytest.mark.parametrize(
    "mutation", ["off_by_one", "missing_key", "extra_key", "boolean"]
)
def test_v10_recomputes_each_count_tree(scope, mutation):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    tree = report["counts"][scope]
    if scope == "by_target":
        tree = tree[next(iter(tree))]
    bucket = tree["sqli.boolean"]["six_probe"]
    if mutation == "off_by_one":
        bucket["tp"] += 1
    elif mutation == "missing_key":
        del bucket["tp"]
    elif mutation == "extra_key":
        bucket["SENTINEL-SECRET-7f3a"] = 0
    else:
        key = next(key for key, count in bucket.items() if count in (0, 1))
        bucket[key] = bool(bucket[key])
    with pytest.raises(
        runner.MeasurementError, match="aggregate counts disagree"
    ) as exc:
        runner.validate_measurement_report(report)
    assert "SENTINEL-SECRET-7f3a" not in str(exc.value)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("expected_label", "SENTINEL-SECRET-7f3a", "reviewed ground truth"),
        ("expected_verdict", "SENTINEL-SECRET-7f3a", "reviewed ground truth"),
        ("classification", "tp", "classification contradicts"),
        ("request_count", True, "request_count.*JSON integer"),
        ("request_count", -1, "request_count.*JSON integer"),
        ("request_count", "SENTINEL-SECRET-7f3a", "request_count.*JSON integer"),
        ("endpoint_id", {"value": "SENTINEL-SECRET-7f3a"}, "record identity"),
    ],
)
def test_v10_rejects_invalid_record_fields_without_echoing_input(field, value, message):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        record
        for record in report["records"]
        if record["classification"] == "non_decision"
    )
    record[field] = value
    if field == "classification":
        report["counts"] = runner.counts(report["records"])
    with pytest.raises(runner.MeasurementError, match=message) as exc:
        runner.validate_measurement_report(report)
    assert "SENTINEL-SECRET-7f3a" not in str(exc.value)


INVALID_ATTEMPT_OUTCOME = "invalid attempt outcome"


@pytest.mark.parametrize(
    "value", [INVALID_ATTEMPT_OUTCOME, {"secret": INVALID_ATTEMPT_OUTCOME}]
)
def test_v10_rejects_unknown_attempt_outcomes_without_echoing_input(value):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    report["records"][0]["attempts"][0]["outcome"] = value
    with pytest.raises(
        runner.MeasurementError, match=r"attempt outcome.*use response"
    ) as exc:
        runner.validate_measurement_report(report)
    assert INVALID_ATTEMPT_OUTCOME not in str(exc.value)


def test_v10_non_decisions_keep_the_manual_runner_exit_one(
    tmp_path, monkeypatch, capsys
):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    monkeypatch.setattr(runner, "measure", lambda workspace, output: report)
    monkeypatch.setattr(
        runner.sys,
        "argv",
        [
            "run_third_party_sqli_measurement.py",
            "--workspace",
            str(tmp_path),
            "--output",
            str(tmp_path / "report.json"),
        ],
    )
    non_decisions = [
        record
        for record in report["records"]
        if record["classification"] == "non_decision"
    ]
    assert non_decisions
    assert runner.unhealthy_count(report) == len(non_decisions)
    assert runner.main() == 1
    assert (
        "contains a false negative, false positive, or non-decision"
        in capsys.readouterr().err
    )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("normalization_applied", "SENTINEL-SECRET-7f3a", "normalization evidence"),
        ("normalized_echo_count", True, "normalization evidence"),
        ("normalized_echo_count", 1, "applied must equal"),
        ("status_code", True, "status_code.*JSON integer"),
        ("body_size", True, "body_size.*JSON integer"),
    ],
)
def test_v10_validates_boolean_response_evidence(field, value, message):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        record for record in report["records"] if record["mode"] == "six_probe"
    )
    attempt = record["attempts"][0]
    attempt["normalization_applied"] = False
    attempt["normalized_echo_count"] = 0
    attempt[field] = value
    with pytest.raises(runner.MeasurementError, match=message) as exc:
        runner.validate_measurement_report(report)
    assert "SENTINEL-SECRET-7f3a" not in str(exc.value)


@pytest.mark.parametrize("check_type", ["sqli.boolean", "sqli.error"])
def test_v10_derives_results_from_analyzer_evidence_not_wire_digests(check_type):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        record
        for record in report["records"]
        if record["check_type"] == check_type
        and record["classification"] in {"tp", "candidate"}
    )
    for index, attempt in enumerate(record["attempts"]):
        attempt["wire_body_sha256"] = hashlib.sha256(str(index).encode()).hexdigest()
        attempt["wire_body_size"] = 100 + index
    assert runner.validate_measurement_report(report) is report


@pytest.mark.doc_drift
def test_v10_valid_report_cannot_use_the_reviewed_v9_documentation_binding():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    with pytest.raises(
        runner.MeasurementError,
        match="update the documented schema binding and fixture together",
    ):
        runner.check_documented_summary(report)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("matches", None, "Error matches"),
        (
            "matches",
            [{"dbms": "SENTINEL-SECRET-7f3a", "signature_id": []}],
            "DBMS/signature pair",
        ),
        ("truncated", None, "truncated field"),
    ],
)
def test_v10_error_response_evidence_requires_reviewed_fields(field, value, message):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        record
        for record in report["records"]
        if record["classification"] == "candidate"
    )
    record["attempts"][-1][field] = value
    with pytest.raises(runner.MeasurementError, match=message) as exc:
        runner.validate_measurement_report(report)
    assert "SENTINEL-SECRET-7f3a" not in str(exc.value)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "SENTINEL-SECRET-7f3a"),
        ("request_count", True),
        ("dbms", "SENTINEL-SECRET-7f3a"),
        ("signature_id", "SENTINEL-SECRET-7f3a"),
    ],
)
def test_v10_validates_error_detail_contract(field, value):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    record = next(
        record
        for record in report["records"]
        if record["classification"] == "candidate"
    )
    record["detail"][field] = value
    with pytest.raises(
        runner.MeasurementError, match=r"detail|unreviewed DBMS/signature pair"
    ) as exc:
        runner.validate_measurement_report(report)
    assert "SENTINEL-SECRET-7f3a" not in str(exc.value)


def test_v10_error_attempt_diagnostic_redacts_classifier_exception(monkeypatch):
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)

    def fail_classification(observations):
        raise ValueError("SENTINEL-SECRET-7f3a")

    monkeypatch.setattr(runner, "classify_error_observations", fail_classification)
    with pytest.raises(
        runner.MeasurementError,
        match=r"Error attempts.*valid ordered analyzer sequence.*Rerun",
    ) as exc:
        runner.validate_measurement_report(report)
    assert "SENTINEL-SECRET-7f3a" not in str(exc.value)
    assert exc.value.__suppress_context__


def test_v10_renderer_does_not_depend_on_wire_digest():
    runner = load_runner()
    report = v10_report_from_legacy_v4(runner)
    expected = runner.render_summary(report)
    report["records"][0]["attempts"][0]["wire_body_sha256"] = "f" * 64
    assert runner.render_summary(report) == expected
