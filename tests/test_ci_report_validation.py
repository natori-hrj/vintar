"""Tests for the GitHub Actions report validation boundary."""

import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import ValidationError

from vintar.checks.sqli.models import Verdict, VerificationResult
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.report import regression_batch_report_dict
from vintar.regression.runner import RegressionOutcome, RegressionStatus

_validate = runpy.run_path("scripts/validate_ci_report.py")["_validate"]


def make_report():
    verification = VerificationResult(
        check_id="case-one",
        verdict=Verdict.INCONCLUSIVE,
        observations=(),
        request_count=0,
        reason_code="budget_unavailable",
        reason="Internal diagnostic not for publication.",
    )

    outcome = RegressionOutcome(
        case_id="case-one",
        expected_verdict=Verdict.INCONCLUSIVE,
        verification=verification,
        expectation_match=True,
        status=RegressionStatus.INCONCLUSIVE,
    )

    batch = RegressionBatchResult(
        planned_case_ids=("case-one", "case-two"),
        outcomes=(outcome,),
        status=RegressionStatus.INCONCLUSIVE,
        requests_used=0,
    )

    return regression_batch_report_dict(batch)


def write_report(tmp_path, data):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_valid_partial_report(tmp_path):
    path = write_report(tmp_path, make_report())
    _validate(path, 3)


def test_legacy_v1_report_without_confirmation_fields_is_accepted(tmp_path):
    fixture = Path("tests/fixtures/regression-batch-report-v1-legacy.json")
    path = tmp_path / "legacy-report.json"
    path.write_bytes(fixture.read_bytes())

    _validate(path, 3)

    script = Path("scripts/validate_ci_report.py").resolve()
    completed = subprocess.run(
        [sys.executable, str(script), str(path), "3"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""


@pytest.mark.parametrize(
    "missing",
    ["actual_reason_code", "request_count", "confirmation"],
)
def test_extended_outcome_fields_are_all_or_nothing(tmp_path, missing):
    report = make_report()
    del report["outcomes"][0][missing]
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="Supply actual_reason_code"):
        _validate(path, 3)


@pytest.mark.parametrize(
    ("status", "updates"),
    [
        (
            "not_configured",
            {"configured": False, "reason_code": "confirmation_timeout"},
        ),
        (
            "not_eligible",
            {"configured": False, "reason_code": "initial_not_eligible"},
        ),
        (
            "matched",
            {"configured": False, "reason_code": "confirmation_pattern_matched"},
        ),
        (
            "mismatch",
            {"configured": True, "reason_code": "confirmation_timeout"},
        ),
        (
            "operational",
            {
                "configured": True,
                "reason_code": "confirmation_pattern_matched",
            },
        ),
    ],
)
def test_confirmation_status_combinations_are_rejected_by_schema(
    tmp_path, status, updates
):
    report = make_report()
    confirmation = report["outcomes"][0]["confirmation"]
    confirmation.update(status=status, **updates)
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match=f"Invalid {status} confirmation"):
        _validate(path, 3)


def test_not_eligible_rejects_boolean_candidate_initial_result(tmp_path):
    report = make_report()
    outcome = report["outcomes"][0]
    outcome["verification"]["reason_code"] = "boolean_candidate"
    outcome["actual_reason_code"] = "boolean_candidate"
    outcome["confirmation"] = {
        "configured": True,
        "status": "not_eligible",
        "reason_code": "initial_not_eligible",
        "request_count": 0,
    }
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="non-candidate initial result"):
        _validate(path, 3)


@pytest.mark.parametrize(
    ("status", "confirmation_reason", "final_reason"),
    [
        ("matched", "confirmation_pattern_matched", "confirmation_timeout"),
        (
            "mismatch",
            "candidate_confirmation_mismatch",
            "confirmation_timeout",
        ),
    ],
)
def test_completed_confirmation_requires_its_exact_final_reason(
    tmp_path, status, confirmation_reason, final_reason
):
    report = make_report()
    outcome = report["outcomes"][0]
    outcome["actual_reason_code"] = final_reason
    outcome["request_count"] = 18
    outcome["confirmation"] = {
        "configured": True,
        "status": status,
        "reason_code": confirmation_reason,
        "request_count": 12,
    }
    report["requests_used"] = 18
    path = write_report(tmp_path, report)

    with pytest.raises(ValidationError):
        _validate(path, 3)


def test_operational_confirmation_requires_the_same_final_reason(tmp_path):
    report = make_report()
    outcome = report["outcomes"][0]
    outcome["actual_reason_code"] = "confirmation_timeout"
    outcome["request_count"] = 1
    outcome["confirmation"] = {
        "configured": True,
        "status": "operational",
        "reason_code": "confirmation_request_failed",
        "request_count": 1,
    }
    report["requests_used"] = 1
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="same final INCONCLUSIVE reason"):
        _validate(path, 3)


def test_not_configured_timeout_repro_exits_two(tmp_path):
    report = make_report()
    report["outcomes"][0]["confirmation"]["reason_code"] = "confirmation_timeout"
    path = write_report(tmp_path, report)
    script = Path("scripts/validate_ci_report.py").resolve()

    completed = subprocess.run(
        [sys.executable, str(script), str(path), "3"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == "Vintar: CI report validation failed.\n"


def test_exit_code_mismatch(tmp_path):
    path = write_report(tmp_path, make_report())

    with pytest.raises(ValueError, match="exit code"):
        _validate(path, 0)


def test_error_code_not_a_valid_batch_report(tmp_path):
    path = write_report(tmp_path, make_report())

    with pytest.raises(ValueError, match="exit code"):
        _validate(path, 2)


def test_missing_report_rejected(tmp_path):
    with pytest.raises(ValueError, match="missing"):
        _validate(tmp_path / "missing.json", 3)


def test_inconsistent_case_count(tmp_path):
    report = make_report()
    report["planned_count"] = 1
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="planned count"):
        _validate(path, 3)


def test_inconsistent_case_order(tmp_path):
    report = make_report()
    report["not_run_case_ids"] = ["different-case"]
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="ordering"):
        _validate(path, 3)


def test_inconsistent_outcome_count(tmp_path):
    report = make_report()
    report["counts"]["inconclusive"] = 0
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="status count"):
        _validate(path, 3)


def test_unknown_fields_rejected(tmp_path):
    report = make_report()
    report["secret"] = "should never be accepted"
    path = write_report(tmp_path, report)

    with pytest.raises(ValidationError):
        _validate(path, 3)


def test_invalid_json_rejected(tmp_path):
    path = tmp_path / "report.json"
    path.write_text("{invalid json", encoding="utf-8")

    with pytest.raises(ValueError):
        _validate(path, 3)


def test_command_hides_invalid_report_details(tmp_path):
    secret = "secret-target.example.invalid"
    path = tmp_path / f"{secret}.json"
    path.write_text(f'{{"secret":"{secret}"}}', encoding="utf-8")
    script = Path("scripts/validate_ci_report.py").resolve()

    completed = subprocess.run(
        [sys.executable, str(script), str(path), "3"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert completed.stderr == "Vintar: CI report validation failed.\n"
    assert secret not in completed.stderr


def test_oversized_report_rejected(tmp_path):
    path = tmp_path / "report.json"
    path.write_bytes(b"x" * 2_097_153)

    with pytest.raises(ValueError, match="size limit"):
        _validate(path, 3)


def test_schema_does_not_accept_error_exit(tmp_path):
    report = make_report()
    report["exit_code"] = 2
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="exit code"):
        _validate(path, 2)


def test_boolean_exit_code_is_rejected(tmp_path):
    path = write_report(tmp_path, make_report())

    with pytest.raises(ValueError, match="exit code"):
        _validate(path, True)


def test_duplicate_json_member_is_rejected(tmp_path):
    report = json.dumps(make_report())
    path = tmp_path / "report.json"
    path.write_text(report[:-1] + ',"status":"inconclusive"}', encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate"):
        _validate(path, 3)


def test_invalid_utf8_is_rejected(tmp_path):
    path = tmp_path / "report.json"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(UnicodeDecodeError):
        _validate(path, 3)


def test_symlinked_report_is_rejected(tmp_path):
    actual = write_report(tmp_path, make_report())
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(actual)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks unavailable.")

    with pytest.raises(ValueError, match="report file"):
        _validate(link, 3)


def test_schema_location_is_independent_of_working_directory(tmp_path, monkeypatch):
    path = write_report(tmp_path, make_report())
    other = tmp_path / "other"
    other.mkdir()
    monkeypatch.chdir(other)

    _validate(path, 3)


def test_nested_request_accounting_is_validated(tmp_path):
    report = make_report()
    report["outcomes"][0]["verification"]["request_count"] = 1
    report["outcomes"][0]["request_count"] = 1
    report["requests_used"] = 1
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="verification request count"):
        _validate(path, 3)


def test_evidence_requires_all_probe_kinds(tmp_path):
    report = make_report()
    report["outcomes"][0]["verification"]["evidence"] = {
        "baseline_true_similarity": 1.0,
        "baseline_false_similarity": 1.0,
        "true_false_similarity": 1.0,
    }
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="Evidence"):
        _validate(path, 3)


def test_conclusive_verification_requires_observations_and_evidence(tmp_path):
    report = make_report()
    report.update(
        status="pass",
        complete=True,
        exit_code=0,
        planned_case_ids=["case-one"],
        not_run_case_ids=[],
        planned_count=1,
        counts={"pass": 1, "fail": 0, "inconclusive": 0, "not_run": 0},
    )
    outcome = report["outcomes"][0]
    outcome.update(
        expected_verdict="not_detected",
        actual_verdict="not_detected",
        expectation_match=True,
        status="pass",
    )
    outcome["verification"].update(
        verdict="not_detected",
        reason_code="no_boolean_difference",
    )
    outcome["actual_reason_code"] = "no_boolean_difference"
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="lacks observations"):
        _validate(path, 0)


def test_workflow_uses_pinned_actions_and_manual_trigger_only():
    workflow = Path(".github/workflows/vintar-security.yml").read_text(encoding="utf-8")
    action_refs = re.findall(r"uses:\s+[^@\s]+@([^\s#]+)", workflow)

    assert action_refs
    assert all(re.fullmatch(r"[0-9a-f]{40}", ref) for ref in action_refs)
    assert "workflow_dispatch:" in workflow
    assert "pull_request_target" not in workflow
    assert "workflow_run" not in workflow
    assert "secrets." not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "persist-credentials: false" in workflow
    assert "ubuntu-latest" not in workflow
    assert workflow.count("runs-on: ubuntu-24.04") == 2
    assert "environment:\n      name: security-testing" in workflow
    assert "${{ runner.temp }}/vintar-report/vintar-report.json" in workflow
