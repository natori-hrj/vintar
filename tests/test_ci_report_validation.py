"""Tests for the GitHub Actions report validation boundary."""

import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from vintar.checks.sqli import confirmation_runner
from vintar.checks.sqli.models import Verdict, VerificationResult
from vintar.checks.sqli.time_contract import TIME_RESULT_RULES
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.report import regression_batch_report_dict
from vintar.regression.runner import RegressionOutcome, RegressionStatus

_VALIDATOR_MODULE = runpy.run_path("scripts/validate_ci_report.py")
_validate = _VALIDATOR_MODULE["_validate"]
SCHEMA_PATH = Path("schemas/regression-batch-report-v1.schema.json")


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


def make_eligible_report():
    report = make_report()
    outcome = report["outcomes"][0]
    digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    outcome["verification"].update(
        verdict="inconclusive",
        reason_code="boolean_candidate",
        request_count=6,
        observations=[
            {
                "kind": kind,
                "status_code": 200,
                "body_size": 0,
                "elapsed": 0.1,
                "body_digest": digest,
                "truncated": False,
            }
            for kind in ("baseline", "true", "false", "baseline", "false", "true")
        ],
        failures=[],
        evidence={
            "baseline_true_similarity": 1.0,
            "baseline_false_similarity": 0.0,
            "true_false_similarity": 0.0,
        },
    )
    outcome["actual_reason_code"] = "boolean_candidate"
    outcome["request_count"] = 6
    report["requests_used"] = 6
    return report


def make_matched_report():
    report = make_eligible_report()
    outcome = report["outcomes"][0]
    outcome["request_count"] = 18
    outcome["confirmation"] = {
        "configured": True,
        "status": "matched",
        "reason_code": "confirmation_pattern_matched",
        "request_count": 12,
    }
    report["requests_used"] = 18
    return report


def write_report(tmp_path, data):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def make_time_report(reason: str):
    rule = TIME_RESULT_RULES[reason]
    request_count = rule.minimum_requests
    verdict = rule.product_verdict.value
    status = "inconclusive" if verdict == "inconclusive" else "pass"
    return {
        "schema_version": 1,
        "report_type": "regression_batch",
        "status": status,
        "complete": True,
        "exit_code": 3 if status == "inconclusive" else 0,
        "planned_case_ids": ["time-case"],
        "executed_case_ids": ["time-case"],
        "not_run_case_ids": [],
        "planned_count": 1,
        "executed_count": 1,
        "requests_used": request_count,
        "counts": {
            "pass": int(status == "pass"),
            "fail": 0,
            "inconclusive": int(status == "inconclusive"),
            "not_run": 0,
        },
        "outcomes": [
            {
                "case_id": "time-case",
                "check_type": "sqli.time",
                "expected_verdict": verdict,
                "actual_verdict": verdict,
                "actual_reason_code": reason,
                "request_count": request_count,
                "expectation_match": True,
                "status": status,
                "timing": {
                    "status": rule.analysis_status.value,
                    "reason_code": reason,
                    "request_count": request_count,
                },
            }
        ],
    }


def test_time_schema_reason_enum_matches_product_contract():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert set(schema["$defs"]["timing"]["properties"]["reason_code"]["enum"]) == set(
        TIME_RESULT_RULES
    )
    assert _VALIDATOR_MODULE["TIME_RESULT_RULES"] is TIME_RESULT_RULES


@pytest.mark.parametrize("reason", TIME_RESULT_RULES)
def test_every_time_result_rule_is_accepted_by_schema_and_validator(tmp_path, reason):
    report = make_time_report(reason)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)

    _validate(write_report(tmp_path, report), report["exit_code"])


@pytest.mark.parametrize("reason", TIME_RESULT_RULES)
@pytest.mark.parametrize("field", ["verdict", "count", "status"])
def test_time_result_rule_mismatches_are_rejected(tmp_path, reason, field):
    report = make_time_report(reason)
    outcome = report["outcomes"][0]
    if field == "verdict":
        outcome["actual_verdict"] = (
            "not_detected"
            if outcome["actual_verdict"] == "inconclusive"
            else "inconclusive"
        )
    elif field == "count":
        rule = TIME_RESULT_RULES[reason]
        invalid = rule.minimum_requests - 1 if rule.minimum_requests else 9
        outcome["request_count"] = invalid
        outcome["timing"]["request_count"] = invalid
        report["requests_used"] = invalid
    else:
        outcome["timing"]["status"] = (
            "candidate"
            if outcome["timing"]["status"] != "candidate"
            else "inconclusive"
        )

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), report["exit_code"])


@pytest.mark.parametrize("missing", ["check_type", "timing"])
def test_time_outcome_fields_are_all_or_nothing(tmp_path, missing):
    report = make_time_report("timing_pattern_not_matched")
    del report["outcomes"][0][missing]

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 0)


def test_boolean_outcome_rejects_timing_object(tmp_path):
    report = make_report()
    report["outcomes"][0]["timing"] = {
        "status": "inconclusive",
        "reason_code": "incomplete_probes",
        "request_count": 0,
    }

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 3)


def test_valid_partial_report(tmp_path):
    path = write_report(tmp_path, make_report())
    _validate(path, 3)


def test_validator_and_schema_derive_confirmation_request_rules_from_runner():
    assert (
        _VALIDATOR_MODULE["_CONFIRMATION_RULES"]
        is confirmation_runner.CONFIRMATION_RESULT_RULES
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    confirmation_schema = dict(schema["$defs"]["confirmation"])
    confirmation_schema["$defs"] = schema["$defs"]
    validator = Draft202012Validator(confirmation_schema)
    assert set(schema["$defs"]["operational_reason"]["enum"]) == {
        reason
        for reason, rule in confirmation_runner.CONFIRMATION_RESULT_RULES.items()
        if rule.status is confirmation_runner.ConfirmationStatus.INCONCLUSIVE
        and reason != "candidate_confirmation_mismatch"
    }
    status_by_reason = {
        "initial_not_eligible": "not_eligible",
        "confirmation_pattern_matched": "matched",
        "candidate_confirmation_mismatch": "mismatch",
    }
    for reason, rule in confirmation_runner.CONFIRMATION_RESULT_RULES.items():
        status = status_by_reason.get(reason, "operational")
        for count in {rule.minimum_requests, rule.maximum_requests}:
            validator.validate(
                {
                    "configured": True,
                    "status": status,
                    "reason_code": reason,
                    "request_count": count,
                }
            )
        if rule.minimum_requests > 0:
            assert not validator.is_valid(
                {
                    "configured": True,
                    "status": status,
                    "reason_code": reason,
                    "request_count": rule.minimum_requests - 1,
                }
            )
        assert not validator.is_valid(
            {
                "configured": True,
                "status": status,
                "reason_code": reason,
                "request_count": rule.maximum_requests + 1,
            }
        )


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
    report = make_eligible_report()
    outcome = report["outcomes"][0]
    outcome["confirmation"] = {
        "configured": True,
        "status": "not_eligible",
        "reason_code": "initial_not_eligible",
        "request_count": 0,
    }
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="not confirmation-eligible"):
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
    report = make_eligible_report()
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
    report = make_eligible_report()
    outcome = report["outcomes"][0]
    outcome["actual_reason_code"] = "confirmation_timeout"
    outcome["request_count"] = 7
    outcome["confirmation"] = {
        "configured": True,
        "status": "operational",
        "reason_code": "confirmation_request_failed",
        "request_count": 1,
    }
    report["requests_used"] = 7
    path = write_report(tmp_path, report)

    with pytest.raises(
        ValueError,
        match="final INCONCLUSIVE/confirmation_request_failed",
    ):
        _validate(path, 3)


def test_matched_rejects_non_candidate_initial_and_exits_two(tmp_path):
    report = make_matched_report()
    outcome = report["outcomes"][0]
    outcome["verification"].update(
        verdict="not_detected",
        reason_code="no_boolean_difference",
    )
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


@pytest.mark.parametrize(
    "invalid_initial",
    [
        "reason",
        "request_count",
        "failure",
        "missing_evidence",
        "kind_counts",
        "non_success",
        "truncated",
        "unstable_pair",
    ],
)
def test_ran_confirmation_requires_complete_eligible_initial(tmp_path, invalid_initial):
    report = make_matched_report()
    outcome = report["outcomes"][0]
    verification = outcome["verification"]
    if invalid_initial == "reason":
        verification["reason_code"] = "unexpected_difference"
    elif invalid_initial == "request_count":
        verification["observations"].pop()
        verification["request_count"] = 5
        outcome["request_count"] = 17
        report["requests_used"] = 17
    elif invalid_initial == "failure":
        verification["observations"].pop()
        verification["failures"] = [
            {"kind": "true", "error": "timeout", "elapsed": 0.1}
        ]
    elif invalid_initial == "missing_evidence":
        verification["evidence"] = None
    elif invalid_initial == "kind_counts":
        verification["observations"][0]["kind"] = "true"
    elif invalid_initial == "non_success":
        verification["observations"][0]["status_code"] = 500
    elif invalid_initial == "truncated":
        verification["observations"][0]["truncated"] = True
    else:
        verification["observations"][3]["body_size"] = 1
    path = write_report(tmp_path, report)

    with pytest.raises(
        (ValueError, ValidationError),
        match=r"eligible|18 was expected",
    ):
        _validate(path, 3)


def test_mismatch_rejects_zero_confirmation_requests_and_exits_two(tmp_path):
    report = make_eligible_report()
    outcome = report["outcomes"][0]
    outcome["actual_reason_code"] = "candidate_confirmation_mismatch"
    outcome["confirmation"] = {
        "configured": True,
        "status": "mismatch",
        "reason_code": "candidate_confirmation_mismatch",
        "request_count": 0,
    }
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
