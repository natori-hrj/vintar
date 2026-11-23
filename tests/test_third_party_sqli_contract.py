"""Keep the offline third-party declaration and reviewed summary deterministic."""

import hashlib
import importlib.util
import json
import re
import sys
import tarfile
import tomllib
from pathlib import Path
from types import ModuleType, SimpleNamespace

import httpx
import pytest
import yaml
from test_sqli_candidate_reliability import classify as reliability_classify
from typer.testing import CliRunner

from vintar.checks.sqli.confirmation_runner import (
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.presets import get_boolean_confirmation_preset
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
    assert result.reason_code == "candidate_confirmation_mismatch"
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
    records = expected_report()["records"]

    assert runner.counts(records) == expected_report()["counts"]
    assert set(runner.counts(records)["overall"]) == {
        "sqli.boolean",
        "sqli.time",
        "sqli.error",
    }


def test_error_acceptance_contract_keeps_candidate_distinct_from_vulnerability():
    report = expected_report()
    records = {
        record["endpoint_id"]: record
        for record in report["records"]
        if record["check_type"] == "sqli.error"
    }
    assert records["dsvw-error-id"] == {
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
        "target_id": "dsvw",
    }
    assert records["dsvw-error-version-query"]["actual_verdict"] == "not_detected"
    assert records["dsvw-error-version-query"]["reason_code"] == (
        "dbms_error_not_observed"
    )
    assert records["dsvw-error-version-query"]["request_count"] == 4
    assert report["counts"]["by_target"]["dsvw"]["sqli.error"]["error_probe"] == {
        "candidate": 1,
        "fn": 0,
        "fp": 0,
        "non_decision": 0,
        "tn": 1,
    }


def _report_record(report, endpoint_id):
    return next(
        record for record in report["records"] if record["endpoint_id"] == endpoint_id
    )


def test_error_candidate_without_detail_is_rejected_with_regeneration_guidance():
    runner = load_runner()
    report = expected_report()
    _report_record(report, "dsvw-error-id")["detail"] = {}

    with pytest.raises(
        runner.MeasurementError,
        match=r"dsvw-error-id.*detail fields contradict ERROR_RESULT_RULES: missing .*dbms.*reason_code.*request_count.*signature_id.*status.*Remeasure.*do not hand-edit reports",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize(
    "missing_field", ["status", "reason_code", "request_count", "dbms", "signature_id"]
)
def test_error_candidate_requires_every_contract_field(missing_field):
    runner = load_runner()
    report = expected_report()
    del _report_record(report, "dsvw-error-id")["detail"][missing_field]

    with pytest.raises(
        runner.MeasurementError,
        match=rf"dsvw-error-id.*detail fields contradict ERROR_RESULT_RULES: missing \['{missing_field}'\].*Remeasure.*do not hand-edit reports",
    ):
        runner.validate_measurement_report(report)


def test_error_candidate_rejects_unreviewed_dbms_signature_pair():
    runner = load_runner()
    report = expected_report()
    _report_record(report, "dsvw-error-id")["detail"]["dbms"] = "mysql"

    with pytest.raises(
        runner.MeasurementError,
        match=r"dsvw-error-id.*unreviewed DBMS/signature pair.*Remeasure.*ERROR_SIGNATURES.*do not hand-edit reports",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("status", "inconclusive", "status 'inconclusive' contradicts reason"),
        ("reason_code", "unstable_response", "detail contradicts its top-level"),
        ("request_count", 3, "request_count contradicts reason"),
    ],
)
def test_error_candidate_values_follow_error_result_rules(field, value, message):
    runner = load_runner()
    report = expected_report()
    _report_record(report, "dsvw-error-id")["detail"][field] = value

    with pytest.raises(
        runner.MeasurementError,
        match=rf"dsvw-error-id.*{message}.*Remeasure.*do not hand-edit reports",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize("evidence_value", [None, "sqlite"])
def test_error_non_candidate_rejects_forbidden_evidence_fields(evidence_value):
    runner = load_runner()
    report = expected_report()
    detail = _report_record(report, "dsvw-error-version-query")["detail"]
    detail["dbms"] = evidence_value
    detail["signature_id"] = evidence_value

    with pytest.raises(
        runner.MeasurementError,
        match=r"dsvw-error-version-query.*detail fields contradict ERROR_RESULT_RULES: unexpected .*dbms.*signature_id.*Remeasure.*do not hand-edit reports",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize(
    ("endpoint_id", "stored_classification", "ground_truth", "result", "expected"),
    [
        (
            "dsvw-error-version-query",
            "candidate",
            "negative",
            "not_detected/dbms_error_not_observed",
            "tn",
        ),
        (
            "dsvw-error-id",
            "tn",
            "positive",
            "inconclusive/dbms_error_disclosed",
            "candidate",
        ),
        (
            "dsvw-error-id",
            "fn",
            "positive",
            "inconclusive/dbms_error_disclosed",
            "candidate",
        ),
        (
            "dsvw-blind-boolean-id",
            "fn",
            "positive",
            "inconclusive/boolean_candidate",
            "tp",
        ),
        (
            "dsvw-time-id",
            "fn",
            "positive",
            "inconclusive/timing_pattern_matched",
            "tp",
        ),
    ],
)
def test_reaggregated_counts_cannot_hide_classification_relabeling(
    endpoint_id, stored_classification, ground_truth, result, expected
):
    runner = load_runner()
    report = expected_report()
    _report_record(report, endpoint_id)["classification"] = stored_classification
    report["counts"] = runner.counts(report["records"])

    with pytest.raises(
        runner.MeasurementError,
        match=rf"{endpoint_id}.*stored classification '{stored_classification}' contradicts ground truth '{ground_truth}' with {result}; expected '{expected}'.*Remeasure.*do not hand-edit reports",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize(
    ("endpoint_id", "replacement", "ground_truth", "expected"),
    [
        ("dsvw-error-version-query", "vulnerable", "negative", "not_detected"),
        ("dsvw-blind-boolean-id", "not_detected", "positive", "inconclusive"),
    ],
)
def test_expected_verdict_must_follow_declared_ground_truth(
    endpoint_id, replacement, ground_truth, expected
):
    runner = load_runner()
    report = expected_report()
    _report_record(report, endpoint_id)["expected_verdict"] = replacement

    with pytest.raises(
        runner.MeasurementError,
        match=rf"{endpoint_id}.*stored expected_verdict '{replacement}' contradicts ground-truth label '{ground_truth}'; expected '{expected}'.*Remeasure.*do not hand-edit reports",
    ):
        runner.validate_measurement_report(report)


def test_stored_v4_report_fixture_still_validates_unchanged():
    runner = load_runner()
    report = expected_report()

    assert runner.validate_measurement_report(report) is report


def test_non_decisions_keep_the_manual_runner_exit_one(tmp_path, monkeypatch, capsys):
    runner = load_runner()
    report = expected_report()
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

    assert runner.unhealthy_count(report) == 7
    assert runner.main() == 1
    captured = capsys.readouterr()
    assert "contains a false negative, false positive, or non-decision" in (
        captured.err
    )


@pytest.mark.doc_drift
def test_reviewed_documentation_matches_the_report_contract():
    runner = load_runner()
    report = expected_report()
    runner.check_documented_summary(report)
    rendered = runner.render_summary(report)
    assert "n=2" not in rendered
    assert rendered.count("| dsvw-blind-boolean-id |") == 2
    assert rendered.count("| dsvw-version-query |") == 2
    assert rendered.count("| sqli-dojo-boolean-id |") == 2
    assert rendered.count("| sqli-dojo-boolean-source |") == 2
    assert "| sqli-dojo (mysql) |" in rendered


def test_mysql_by_target_counts_are_recomputed_from_records():
    runner = load_runner()
    report = expected_report()
    mysql_records = [
        record for record in report["records"] if record["target_id"] == "sqli-dojo"
    ]

    assert (
        runner.counts(mysql_records)["by_target"]["sqli-dojo"]
        == report["counts"]["by_target"]["sqli-dojo"]
    )
    assert runner.validate_measurement_report(report) is report


def test_measurement_output_declares_schema_version_four():
    runner = load_runner()
    report = expected_report()

    assert report["schema_version"] == runner.MEASUREMENT_SCHEMA_VERSION == 4
    assert runner.validate_measurement_report(report) is report


def test_zeroed_counts_cannot_hide_recorded_non_decisions():
    runner = load_runner()
    report = expected_report()
    for count_tree in (
        report["counts"]["overall"],
        report["counts"]["by_target"]["dsvw"],
    ):
        for check_counts in count_tree.values():
            for mode_counts in check_counts.values():
                for field in mode_counts:
                    mode_counts[field] = 0

    with pytest.raises(
        runner.MeasurementError,
        match=r"(?i)counts disagree with records at counts.overall.sqli.boolean.six_probe.*rerun the measurement",
    ):
        runner.unhealthy_count(report)


def test_single_off_by_one_count_is_rejected():
    runner = load_runner()
    report = expected_report()
    report["counts"]["overall"]["sqli.time"]["nine_probe"]["tn"] += 1

    with pytest.raises(
        runner.MeasurementError,
        match=r"counts disagree with records at counts.overall.sqli.time.nine_probe.*Rerun the measurement",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize("operation", ["extra", "missing"])
def test_extra_or_missing_count_key_is_rejected(operation):
    runner = load_runner()
    report = expected_report()
    counts = report["counts"]["overall"]["sqli.boolean"]["six_probe"]
    if operation == "extra":
        counts["other"] = 0
        field = "other"
    else:
        del counts["non_decision"]
        field = "non_decision"

    with pytest.raises(
        runner.MeasurementError,
        match=rf"(?i)counts disagree with records at counts.overall.sqli.boolean.six_probe.{field}.*rerun the measurement",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize("recompute_counts", [True, False])
def test_removed_non_decisions_are_rejected_before_counts(recompute_counts):
    runner = load_runner()
    saved = expected_report()
    saved["records"] = [
        record
        for record in saved["records"]
        if record["classification"] != "non_decision"
    ]
    if recompute_counts:
        saved["counts"] = runner.counts(saved["records"])
    report = json.loads(json.dumps(saved))

    for reader in (runner.validate_measurement_report, runner.unhealthy_count):
        with pytest.raises(
            runner.MeasurementError,
            match=r"incomplete: missing target_id 'dsvw', endpoint_id 'dsvw-version-query', check_type 'sqli.boolean', mode 'confirmation'.*full measurement run",
        ):
            reader(report)


def test_duplicate_record_is_rejected_with_occurrence_count():
    runner = load_runner()
    report = expected_report()
    report["records"].append(report["records"][0].copy())
    report["counts"] = runner.counts(report["records"])

    with pytest.raises(
        runner.MeasurementError,
        match=r"Duplicate.*endpoint_id 'dsvw-blind-boolean-id', check_type 'sqli.boolean', mode 'confirmation' appears 2 times.*full measurement run",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize(
    ("field", "value"), [("endpoint_id", "undeclared-endpoint"), ("mode", "unknown")]
)
def test_undeclared_record_key_is_rejected(field, value):
    runner = load_runner()
    report = expected_report()
    report["records"][0][field] = value
    report["counts"] = runner.counts(report["records"])

    with pytest.raises(
        runner.MeasurementError,
        match=rf"Unexpected.*{field} '{value}'.*not in targets.toml.*full measurement run",
    ):
        runner.validate_measurement_report(report)


def test_report_keys_follow_reviewed_measurement_plan(monkeypatch, tmp_path):
    runner = load_runner()
    targets, records = runner.load_declarations()
    old_id = records[0]["id"]
    new_id = "renamed-endpoint"
    records[0]["id"] = new_id
    monkeypatch.setattr(runner, "load_declarations", lambda: (targets, records))
    original_adapter = runner.target_adapter

    def temporary_adapter(target_id, target):
        adapter = original_adapter(target_id, target)
        return adapter._replace(configs=tmp_path)

    monkeypatch.setattr(runner, "target_adapter", temporary_adapter)
    for config in CONFIGS.glob("*.toml"):
        (tmp_path / config.name.replace(old_id, new_id)).write_bytes(
            config.read_bytes()
        )
    for config in DOJO_CONFIGS.glob("*.toml"):
        (tmp_path / config.name).write_bytes(config.read_bytes())
    for config in OWASP_CONFIGS.glob("*.toml"):
        (tmp_path / config.name).write_bytes(config.read_bytes())

    planned = list(runner.plan_measurements(targets, records))
    report = expected_report()
    for record in report["records"]:
        if record["endpoint_id"] == old_id:
            record["endpoint_id"] = new_id
    assert {entry.key for entry in planned} == {
        (
            record["target_id"],
            record["endpoint_id"],
            record["check_type"],
            record["mode"],
        )
        for record in report["records"]
    }
    assert runner.validate_measurement_report(report) is report
    planned[0].config.unlink()
    with pytest.raises(runner.MeasurementError, match="Missing reviewed configuration"):
        runner.validate_measurement_report(report)


def test_consistent_counts_and_health_match_records():
    runner = load_runner()
    report = expected_report()
    unhealthy_records = [
        record
        for record in report["records"]
        if record["classification"] in {"fn", "fp", "non_decision"}
    ]

    assert runner.validate_measurement_report(report) is report
    assert runner.unhealthy_count(report) == len(unhealthy_records) == 7


def test_v4_preserves_v3_records_and_aggregate_counts():
    report = expected_report()
    dsvw_records = [
        record for record in report["records"] if record["target_id"] == "dsvw"
    ]
    legacy_records = [
        {key: value for key, value in record.items() if key != "target_id"}
        for record in dsvw_records
    ]

    assert legacy_records == [
        {key: value for key, value in record.items() if key != "target_id"}
        for record in expected_report()["records"]
        if record["target_id"] == "dsvw"
    ]
    assert (
        report["counts"]["by_target"]["dsvw"]
        == expected_report()["counts"]["by_target"]["dsvw"]
    )


def test_unknown_target_id_is_rejected_before_counts():
    runner = load_runner()
    report = expected_report()
    report["records"][0]["target_id"] = "unknown"

    with pytest.raises(
        runner.MeasurementError,
        match=r"Unexpected measurement record.*target_id 'unknown'.*not in targets.toml.*Regenerate",
    ):
        runner.validate_measurement_report(report)


@pytest.mark.parametrize("tree", ["overall", "by_target"])
def test_each_v4_count_tree_is_recomputed(tree):
    runner = load_runner()
    report = expected_report()
    count_tree = (
        report["counts"]["overall"]
        if tree == "overall"
        else report["counts"]["by_target"]["dsvw"]
    )
    count_tree["sqli.time"]["nine_probe"]["tn"] += 1

    with pytest.raises(
        runner.MeasurementError,
        match=rf"counts disagree with records at counts.{tree}.*Rerun",
    ):
        runner.validate_measurement_report(report)


def test_report_target_metadata_must_match_declaration():
    runner = load_runner()
    report = expected_report()
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


@pytest.mark.parametrize("old_version", [1, 2, 3])
def test_old_measurement_report_is_rejected_with_regeneration_guidance(old_version):
    runner = load_runner()
    report = expected_report()
    report["schema_version"] = old_version

    with pytest.raises(
        runner.MeasurementError,
        match=rf"found {old_version}; this reader supports version 4.*rerun the measurement",
    ):
        runner.render_summary(report)


def test_v4_report_with_v3_shape_is_rejected():
    runner = load_runner()
    report = expected_report()
    report["counts"] = report["counts"]["overall"]
    boolean_record = report["records"][0]
    boolean_record["confirmation"] = boolean_record.pop("detail")

    with pytest.raises(
        runner.MeasurementError,
        match=r"v4 record.*sibling detail object.*rerun",
    ):
        runner.check_documented_summary(report)


def test_v3_version_with_v4_shape_is_rejected_before_shape_parsing():
    runner = load_runner()
    report = expected_report()
    report["schema_version"] = 3

    with pytest.raises(
        runner.MeasurementError,
        match=r"found 3; this reader supports version 4.*rerun the measurement",
    ):
        runner.unhealthy_count(report)


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
        report = expected_report()
        report["targets"]["dsvw"]["service_images"] = mapping

        def call_report():
            return runner.validate_measurement_report(report)

        call = call_report

    if error is None:
        assert call() is not None
    else:
        with pytest.raises(
            runner.MeasurementError,
            match=error + r".*Update targets.toml or the Compose file",
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
    report = expected_report()
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
