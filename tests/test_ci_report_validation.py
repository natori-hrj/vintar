"""Tests for the GitHub Actions report validation boundary."""

import json
import re
import runpy
import subprocess
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from workflow_actions import collect_workflow_uses

from vintar.checks.sqli import confirmation_runner
from vintar.checks.sqli.analyzer import analyze_boolean_responses
from vintar.checks.sqli.decision_facts import (
    DECISION_FACT_CATEGORY_REASONS,
    DecisionStage,
    OperationalCondition,
    OperationalDecisionFacts,
)
from vintar.checks.sqli.error_analyzer import (
    ErrorAnalysis,
    ErrorProbeKind,
    classify_error_observations,
    error_observation,
    error_operational_decision_facts,
)
from vintar.checks.sqli.error_contract import ERROR_RESULT_RULES
from vintar.checks.sqli.error_runner import ErrorRunReport
from vintar.checks.sqli.error_signatures import (
    ERROR_SIGNATURES,
    ErrorSignature,
)
from vintar.checks.sqli.models import (
    ProbeError,
    ProbeFailure,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.checks.sqli.time_contract import TIME_RESULT_RULES
from vintar.core.models import HttpResult
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.report import regression_batch_report_dict
from vintar.regression.runner import (
    ErrorRegressionOutcome,
    RegressionOutcome,
    RegressionStatus,
)

_VALIDATOR_MODULE = runpy.run_path("scripts/validate_ci_report.py")
_SCHEMA_GENERATOR_MODULE = runpy.run_path("scripts/update_error_signature_schema.py")
_validate = _VALIDATOR_MODULE["_validate"]
SCHEMA_PATH = Path("schemas/regression-batch-report-v1.schema.json")


def test_decision_fact_reason_table_matches_python_validator():
    assert _VALIDATOR_MODULE["_DECISION_FACT_CATEGORY_REASONS"] == (
        DECISION_FACT_CATEGORY_REASONS
    )


def make_report():
    verification = VerificationResult(
        check_id="case-one",
        verdict=Verdict.INCONCLUSIVE,
        observations=(),
        request_count=0,
        reason_code="budget_unavailable",
        reason="Internal diagnostic not for publication.",
        decision_facts=OperationalDecisionFacts(
            reason_code="budget_unavailable",
            stage=DecisionStage.INITIAL,
            sequence=1,
            probe_kind=ProbeKind.BASELINE,
            condition=OperationalCondition.BUDGET_UNAVAILABLE,
        ),
    )

    return _report_for_verification(verification)


def _report_for_verification(verification):
    outcome = RegressionOutcome(
        case_id=verification.check_id,
        expected_verdict=Verdict.INCONCLUSIVE,
        verification=verification,
        expectation_match=True,
        status=RegressionStatus.INCONCLUSIVE,
    )

    batch = RegressionBatchResult(
        planned_case_ids=(verification.check_id, "case-two"),
        outcomes=(outcome,),
        status=RegressionStatus.INCONCLUSIVE,
        requests_used=verification.request_count,
    )

    return regression_batch_report_dict(batch)


def test_decision_facts_schema_and_validator_reject_reason_mislabel(tmp_path):
    report = make_report()
    outcome = report["outcomes"][0]
    outcome["decision_facts"] = {
        "category": "response_dynamics",
        "normalization_applied": False,
        "normalized_echo_count": 0,
        "unstable_pairs": [{"probe_kind": "baseline", "localization": "unlocalized"}],
    }
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(report)
    with pytest.raises(ValidationError):
        _validate(write_report(tmp_path, report), report["exit_code"])


def test_python_validator_rejects_operational_fact_condition_mislabel(tmp_path):
    report = make_report()
    report["outcomes"][0]["decision_facts"] = {
        "category": "operational",
        "stage": "initial",
        "sequence": 1,
        "probe_kind": "baseline",
        "condition": "timeout",
    }

    with pytest.raises(ValueError, match="same checks-layer decision"):
        _validate(write_report(tmp_path, report), report["exit_code"])


_OBSERVATION_CONTRADICTION = r"Decision facts contradict recorded observations.*Regenerate the report with Vintar"


@pytest.mark.parametrize(
    "mutation",
    ["reviewer", "wrong_kind", "wrong_status", "non_last", "nonexistent"],
)
def test_initial_rate_limited_facts_must_match_stopping_observation(tmp_path, mutation):
    path = Path("tests/golden/cli/verify/partial-inconclusive.json")
    report = json.loads(path.read_text(encoding="utf-8"))["stdout_json"]
    _validate(write_report(tmp_path, report), 3)
    outcome = report["outcomes"][0]
    facts = outcome["decision_facts"]
    observations = outcome["verification"]["observations"]
    if mutation == "reviewer":
        facts.update(sequence=18, probe_kind="false")
    elif mutation == "wrong_kind":
        facts["probe_kind"] = "false"
    elif mutation == "wrong_status":
        observations[0]["status_code"] = 503
    elif mutation == "non_last":
        observations.append({**observations[0], "kind": "true", "status_code": 200})
        outcome["verification"]["request_count"] = 2
        outcome["request_count"] = report["requests_used"] = 2
    else:
        facts["sequence"] = 2

    with pytest.raises(ValueError, match=_OBSERVATION_CONTRADICTION):
        _validate(write_report(tmp_path, report), 3)


def test_initial_failure_facts_match_recorded_failure(tmp_path):
    verification = VerificationResult(
        check_id="case-one",
        verdict=Verdict.INCONCLUSIVE,
        observations=(),
        failures=(ProbeFailure(kind=ProbeKind.BASELINE, error=ProbeError.TIMEOUT),),
        request_count=1,
        reason_code="probe_failed",
        reason="Test verification.",
        decision_facts=OperationalDecisionFacts(
            reason_code="probe_failed",
            stage=DecisionStage.INITIAL,
            sequence=1,
            probe_kind=ProbeKind.BASELINE,
            condition=ProbeError.TIMEOUT,
        ),
    )
    report = _report_for_verification(verification)
    _validate(write_report(tmp_path, report), 3)
    report["outcomes"][0]["decision_facts"]["condition"] = "connection"
    with pytest.raises(ValueError, match=_OBSERVATION_CONTRADICTION):
        _validate(write_report(tmp_path, report), 3)


def _response(body=b"response", *, status_code=200, truncated=False):
    return HttpResult(
        status_code=status_code, elapsed=0.1, body=body, headers={}, truncated=truncated
    )


@pytest.mark.parametrize(("status", "truncated"), [(503, False), (200, True)])
def test_initial_analysis_facts_use_request_order_for_completed_plan(
    tmp_path, status, truncated
):
    response = _response()
    verification = analyze_boolean_responses(
        "case-one",
        baseline=(response, _response(status_code=status, truncated=truncated)),
        true_responses=(response, response),
        false_responses=(response, response),
    )
    report = _report_for_verification(verification)
    facts = report["outcomes"][0]["decision_facts"]
    assert facts["sequence"] == 4
    _validate(write_report(tmp_path, report), 3)
    facts["status_code"] = 502
    with pytest.raises(ValueError, match=_OBSERVATION_CONTRADICTION):
        _validate(write_report(tmp_path, report), 3)


@pytest.mark.parametrize("last_is_also_rate_limited", [False, True])
def test_completed_boolean_rate_limit_facts_must_match_first_429(
    tmp_path, last_is_also_rate_limited
):
    normal = _response()
    rate_limited = _response(status_code=429, truncated=True)
    verification = analyze_boolean_responses(
        "case-one",
        baseline=(_response(status_code=503), normal),
        true_responses=(
            _response(truncated=True),
            rate_limited if last_is_also_rate_limited else normal,
        ),
        false_responses=(rate_limited, normal),
    )
    report = _report_for_verification(verification)
    facts = report["outcomes"][0]["decision_facts"]
    assert facts == {
        "category": "operational",
        "stage": "initial",
        "sequence": 3,
        "probe_kind": "false",
        "condition": "rate_limited",
        "status_code": 429,
    }
    _validate(write_report(tmp_path, report), 3)

    facts.update(sequence=6, probe_kind="true")
    with pytest.raises(ValueError, match=_OBSERVATION_CONTRADICTION):
        _validate(write_report(tmp_path, report), 3)


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("non_success_status", "rate_limited"),
        ("truncated_response", "rate_limited"),
        ("non_success_status", "truncated_response"),
    ],
)
def test_completed_boolean_facts_must_use_highest_precedence_reason(
    tmp_path, earlier, later
):
    responses = {
        "non_success_status": _response(status_code=503),
        "truncated_response": _response(truncated=True),
        "rate_limited": _response(status_code=429, truncated=True),
    }
    normal = _response()
    verification = analyze_boolean_responses(
        "case-one",
        baseline=(responses[earlier], normal),
        true_responses=(normal, normal),
        false_responses=(responses[later], normal),
    )
    report = _report_for_verification(verification)
    outcome = report["outcomes"][0]
    facts = outcome["decision_facts"]
    assert outcome["actual_reason_code"] == later
    assert facts["sequence"] == 3
    _validate(write_report(tmp_path, report), 3)

    outcome["actual_reason_code"] = outcome["verification"]["reason_code"] = earlier
    facts.update(
        sequence=1,
        probe_kind="baseline",
        condition="truncated" if earlier == "truncated_response" else earlier,
        status_code=responses[earlier].status_code,
    )
    with pytest.raises(
        ValueError,
        match=r"reason and position must follow analyzer precedence.*Regenerate",
    ):
        _validate(write_report(tmp_path, report), 3)


def test_early_stopped_boolean_facts_must_match_last_response_condition(tmp_path):
    path = Path("tests/golden/cli/verify/partial-inconclusive.json")
    report = json.loads(path.read_text(encoding="utf-8"))["stdout_json"]
    outcome = report["outcomes"][0]
    outcome["verification"]["observations"][0].update(status_code=503, truncated=True)
    outcome["actual_reason_code"] = outcome["verification"]["reason_code"] = (
        "non_success_status"
    )
    outcome["decision_facts"].update(condition="non_success_status", status_code=503)

    with pytest.raises(
        ValueError,
        match=r"reason and position must follow analyzer precedence.*Regenerate",
    ):
        _validate(write_report(tmp_path, report), 3)


@pytest.mark.parametrize(("body", "status"), [(b"different", 200), (b"response", 201)])
def test_response_dynamics_facts_reject_a_stable_pair(tmp_path, body, status):
    response = _response()
    verification = analyze_boolean_responses(
        "case-one",
        baseline=(response, _response(body, status_code=status)),
        true_responses=(response, response),
        false_responses=(response, response),
    )
    report = _report_for_verification(verification)
    _validate(write_report(tmp_path, report), 3)
    outcome = report["outcomes"][0]
    outcome["decision_facts"]["unstable_pairs"][0]["probe_kind"] = "true"
    with pytest.raises(ValueError, match=_OBSERVATION_CONTRADICTION):
        _validate(write_report(tmp_path, report), 3)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        (None, None),
        ("prefix_size", 10_000),
        ("suffix_size", 10_000),
        ("second_changed_size", 2),
    ],
)
def test_localized_response_dynamics_must_fit_both_recorded_bodies(
    tmp_path, field, replacement
):
    prefix = b"a" * 80
    suffix = b"z" * 80
    first = _response(prefix + b"x" + suffix)
    second = _response(prefix + b"y" + suffix)
    verification = analyze_boolean_responses(
        "case-one",
        baseline=(first, second),
        true_responses=(first, first),
        false_responses=(first, first),
    )
    report = _report_for_verification(verification)
    pair = report["outcomes"][0]["decision_facts"]["unstable_pairs"][0]
    assert pair == {
        "probe_kind": "baseline",
        "localization": "localized",
        "prefix_size": 80,
        "suffix_size": 80,
        "first_changed_size": 1,
        "second_changed_size": 1,
    }
    if field is None:
        _validate(write_report(tmp_path, report), 3)
        return

    pair[field] = replacement
    with pytest.raises(
        ValueError,
        match=r"^Localized response dynamics facts contradict recorded body sizes\. Regenerate the report with Vintar\.$",
    ):
        _validate(write_report(tmp_path, report), 3)


def make_eligible_report():
    report = make_report()
    outcome = report["outcomes"][0]
    outcome.pop("decision_facts", None)
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


@pytest.mark.parametrize(
    ("field", "replacement"), [("sequence", 8), ("probe_kind", "true_1")]
)
def test_confirmation_operational_facts_match_count_and_plan(
    tmp_path, field, replacement
):
    report = make_eligible_report()
    outcome = report["outcomes"][0]
    outcome["actual_reason_code"] = "confirmation_timeout"
    outcome["request_count"] = report["requests_used"] = 7
    outcome["confirmation"] = {
        "configured": True,
        "status": "operational",
        "reason_code": "confirmation_timeout",
        "request_count": 1,
    }
    facts = {
        "category": "operational",
        "stage": "confirmation",
        "sequence": 7,
        "probe_kind": "baseline",
        "condition": "timeout",
    }
    outcome["decision_facts"] = facts
    _validate(write_report(tmp_path, report), 3)
    facts[field] = replacement
    with pytest.raises(ValueError, match=_OBSERVATION_CONTRADICTION):
        _validate(write_report(tmp_path, report), 3)


_RATE_LIMIT_PRECEDENCE = (
    r"HTTP 429 is classified as rate_limited first.*regenerate the report"
    r".*current Vintar writer"
)


@pytest.mark.parametrize(
    ("reason", "condition"),
    [("non_success_status", "non_success_status"), ("truncated_response", "truncated")],
)
def test_initial_operational_facts_reject_mislabeled_rate_limit(
    tmp_path, reason, condition
):
    path = Path("tests/golden/cli/verify/partial-inconclusive.json")
    report = json.loads(path.read_text(encoding="utf-8"))["stdout_json"]
    outcome = report["outcomes"][0]
    outcome["actual_reason_code"] = reason
    outcome["verification"]["reason_code"] = reason
    outcome["decision_facts"]["condition"] = condition

    with pytest.raises(ValueError, match=_RATE_LIMIT_PRECEDENCE):
        _validate(write_report(tmp_path, report), 3)


@pytest.mark.parametrize(
    ("reason", "condition", "original_status"),
    [
        ("confirmation_non_success_status", "non_success_status", 503),
        ("confirmation_truncated", "truncated", 200),
    ],
)
def test_confirmation_operational_facts_reject_mislabeled_rate_limit(
    tmp_path, reason, condition, original_status
):
    report = make_eligible_report()
    outcome = report["outcomes"][0]
    outcome["actual_reason_code"] = reason
    outcome["request_count"] = report["requests_used"] = 7
    outcome["confirmation"] = {
        "configured": True,
        "status": "operational",
        "reason_code": reason,
        "request_count": 1,
    }
    facts = {
        "category": "operational",
        "stage": "confirmation",
        "sequence": 7,
        "probe_kind": "baseline",
        "condition": condition,
        "status_code": original_status,
    }
    outcome["decision_facts"] = facts
    _validate(write_report(tmp_path, report), 3)
    facts["status_code"] = 429

    with pytest.raises(ValueError, match=_RATE_LIMIT_PRECEDENCE):
        _validate(write_report(tmp_path, report), 3)


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


def time_decision_facts(reason: str, request_count: int) -> dict[str, object]:
    if reason == "unstable_timing":
        return {
            "category": "timing_dynamics",
            "instability_causes": ["control_span"],
        }
    if reason == "ambiguous_timing":
        return {
            "category": "timing_dynamics",
            "instability_causes": [],
            "candidate_median_met": True,
            "candidate_margin_met": False,
            "no_delay_condition_met": False,
        }
    sequence = request_count + 1 if reason == "incomplete_probes" else request_count
    condition = {
        "incomplete_probes": "deadline",
        "probe_timeout": "timeout",
        "probe_failed": "request_failed",
        "probe_interrupted": "interrupted",
        "rate_limited": "rate_limited",
        "non_success_status": "non_success_status",
        "truncated_response": "truncated",
    }[reason]
    result: dict[str, object] = {
        "category": "operational",
        "stage": "time",
        "sequence": sequence,
        "probe_kind": [
            "baseline",
            "control",
            "delay",
            "control",
            "delay",
            "baseline",
            "delay",
            "baseline",
            "control",
        ][sequence - 1],
        "condition": condition,
    }
    if reason == "rate_limited":
        result["status_code"] = 429
    elif reason == "non_success_status":
        result["status_code"] = 403
    elif reason == "truncated_response":
        result["status_code"] = 200
    return result


def make_error_report(reason: str):
    rule = ERROR_RESULT_RULES[reason]
    request_count = rule.minimum_requests
    verdict = rule.product_verdict.value
    status = "inconclusive" if verdict == "inconclusive" else "pass"
    error = {
        "status": rule.analysis_status.value,
        "reason_code": reason,
        "request_count": request_count,
    }
    if rule.requires_evidence:
        error.update(
            dbms="sqlite",
            signature_id="sqlite_operational_syntax",
        )
    return {
        "schema_version": 1,
        "report_type": "regression_batch",
        "status": status,
        "complete": True,
        "exit_code": 3 if status == "inconclusive" else 0,
        "planned_case_ids": ["error-case"],
        "executed_case_ids": ["error-case"],
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
                "case_id": "error-case",
                "check_type": "sqli.error",
                "expected_verdict": verdict,
                "actual_verdict": verdict,
                "actual_reason_code": reason,
                "request_count": request_count,
                "expectation_match": True,
                "status": status,
                "error": error,
            }
        ],
    }


def test_error_schema_and_validator_derive_contract_tables():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert set(schema["$defs"]["error"]["properties"]["reason_code"]["enum"]) == set(
        ERROR_RESULT_RULES
    )
    assert _VALIDATOR_MODULE["ERROR_RESULT_RULES"] is ERROR_RESULT_RULES


@pytest.mark.parametrize(
    ("reason", "condition", "status_code"),
    [
        ("probe_timeout", "timeout", None),
        ("probe_failed", "connection", None),
        ("rate_limited", "rate_limited", 429),
        ("truncated_response", "truncated", 200),
        ("non_success_status", "non_success_status", 503),
    ],
)
def test_error_operational_facts_validate_end_to_end(
    tmp_path, reason, condition, status_code
):
    report = make_error_report(reason)
    facts = {
        "category": "operational",
        "stage": "error",
        "sequence": 1,
        "probe_kind": "baseline",
        "condition": condition,
    }
    if status_code is not None:
        facts["status_code"] = status_code
    report["outcomes"][0]["decision_facts"] = facts

    _validate(write_report(tmp_path, report), report["exit_code"])


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sequence", 2),
        ("probe_kind", "error"),
        ("condition", "non_success_status"),
        ("status_code", 503),
    ],
)
def test_error_operational_fact_mutations_are_rejected(tmp_path, field, value):
    report = make_error_report("rate_limited")
    report["outcomes"][0]["decision_facts"] = {
        "category": "operational",
        "stage": "error",
        "sequence": 1,
        "probe_kind": "baseline",
        "condition": "rate_limited",
        "status_code": 429,
    }
    report["outcomes"][0]["decision_facts"][field] = value

    with pytest.raises((ValueError, ValidationError), match=r"(?i)(decision|fact)"):
        _validate(write_report(tmp_path, report), report["exit_code"])


def test_error_operational_facts_reject_requests_after_rate_limit(tmp_path):
    observation = error_observation(
        ErrorProbeKind.BASELINE, 1, _response(status_code=429)
    )
    status, reason, evidence = classify_error_observations((observation,))
    analysis = ErrorAnalysis(
        status=status,
        reason_code=reason,
        observations=(observation,),
        evidence=evidence,
        decision_facts=error_operational_decision_facts(
            reason_code=reason,
            sequence=observation.sequence,
            kind=observation.kind,
            condition=OperationalCondition.RATE_LIMITED,
            status_code=observation.status_code,
        ),
    )
    outcome = ErrorRegressionOutcome(
        case_id="error-case",
        expected_verdict=Verdict.INCONCLUSIVE,
        error_run=ErrorRunReport(
            analysis=analysis, budget_used=1, transport_attempts=1
        ),
        expectation_match=True,
        status=RegressionStatus.INCONCLUSIVE,
    )
    report = regression_batch_report_dict(
        RegressionBatchResult(
            planned_case_ids=("error-case",),
            outcomes=(outcome,),
            status=RegressionStatus.INCONCLUSIVE,
            requests_used=1,
        )
    )
    assert reason == "rate_limited"
    _validate(write_report(tmp_path, report), 3)

    recorded = report["outcomes"][0]
    recorded["request_count"] = recorded["error"]["request_count"] = report[
        "requests_used"
    ] = 3
    with pytest.raises(
        ValueError,
        match=r"runner stops at this attempt, so no further requests can be recorded\. "
        r"Regenerate the report with the current Vintar writer\.",
    ):
        _validate(write_report(tmp_path, report), 3)


def test_error_signature_schema_pairs_match_registry():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert (
        schema["$defs"]["error_signature_pairs"]
        == _SCHEMA_GENERATOR_MODULE["error_signature_pair_schema"]()
    )
    schema_pairs = {
        (branch["properties"]["dbms"]["const"], signature_id)
        for branch in schema["$defs"]["error_signature_pairs"]["oneOf"]
        for signature_id in branch["properties"]["signature_id"]["enum"]
    }
    registry_pairs = {
        (signature.dbms, signature_id)
        for signature_id, signature in ERROR_SIGNATURES.items()
    }
    assert schema_pairs == registry_pairs


def test_error_allowed_values_exist_only_in_generated_pair_definition():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    constrained_paths = []

    def collect(node, path=()):
        if isinstance(node, dict):
            for key, value in node.items():
                current = (*path, key)
                if (
                    key in {"dbms", "signature_id"}
                    and isinstance(value, dict)
                    and ("enum" in value or "const" in value)
                ):
                    constrained_paths.append(current)
                collect(value, current)
        elif isinstance(node, list):
            for index, value in enumerate(node):
                collect(value, (*path, index))

    collect(schema)

    assert constrained_paths
    assert all(
        path[:2] == ("$defs", "error_signature_pairs") for path in constrained_paths
    )


def test_generated_error_signature_schema_is_current():
    _SCHEMA_GENERATOR_MODULE["check_schema"]()


def test_stale_generated_error_signature_schema_is_rejected(tmp_path):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(SCHEMA_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    stale = schema_path.read_text(encoding="utf-8").replace(
        "sqlite_operational_syntax", "stale_signature", 1
    )
    schema_path.write_text(stale, encoding="utf-8")

    with pytest.raises(ValueError, match=r"schema is stale.*--write"):
        _SCHEMA_GENERATOR_MODULE["check_schema"](schema_path)


def test_added_signature_regenerates_every_schema_constraint(tmp_path, monkeypatch):
    extra_signature = ErrorSignature(
        signature_id="sqlite_extra_syntax",
        dbms="sqlite",
        pattern=re.compile(
            rb"SQLite extra syntax diagnostic", re.ASCII | re.IGNORECASE
        ),
    )
    registry = dict(ERROR_SIGNATURES)
    registry[extra_signature.signature_id] = extra_signature
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(SCHEMA_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    _SCHEMA_GENERATOR_MODULE["update_schema"](schema_path, registry)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    report = make_error_report("dbms_error_disclosed")
    report["outcomes"][0]["error"].update(
        dbms="sqlite",
        signature_id=extra_signature.signature_id,
    )
    report_path = write_report(tmp_path, report)
    monkeypatch.setitem(_validate.__globals__, "ERROR_SIGNATURES", registry)

    Draft202012Validator(schema).validate(report)
    _validate(report_path, 3, schema_path)

    report["outcomes"][0]["error"]["dbms"] = "oracle"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(report)
    with pytest.raises(ValidationError):
        _validate(report_path, 3, schema_path)


@pytest.mark.parametrize(
    ("signature_id", "dbms"),
    [
        (signature_id, signature.dbms)
        for signature_id, signature in ERROR_SIGNATURES.items()
    ],
)
def test_schema_accepts_every_registered_error_signature_pair(signature_id, dbms):
    report = make_error_report("dbms_error_disclosed")
    report["outcomes"][0]["error"].update(
        dbms=dbms,
        signature_id=signature_id,
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    Draft202012Validator(schema).validate(report)


def test_schema_rejects_oracle_dbms_with_sqlite_signature():
    report = make_error_report("dbms_error_disclosed")
    report["outcomes"][0]["error"]["dbms"] = "oracle"
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(report)


@pytest.mark.parametrize(
    ("dbms", "signature_id", "accepted"),
    [
        *(
            (signature.dbms, signature_id, True)
            for signature_id, signature in ERROR_SIGNATURES.items()
        ),
        ("oracle", "sqlite_operational_syntax", False),
    ],
)
def test_schema_and_python_validator_agree_on_error_signature_pairs(
    tmp_path, dbms, signature_id, accepted
):
    report = make_error_report("dbms_error_disclosed")
    report["outcomes"][0]["error"].update(
        dbms=dbms,
        signature_id=signature_id,
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    path = write_report(tmp_path, report)

    if accepted:
        Draft202012Validator(schema).validate(report)
        _validate(path, 3)
    else:
        with pytest.raises(ValidationError):
            Draft202012Validator(schema).validate(report)
        with pytest.raises(ValidationError):
            _validate(path, 3)


@pytest.mark.parametrize("reason", ERROR_RESULT_RULES)
def test_every_error_result_rule_is_accepted_by_schema_and_validator(tmp_path, reason):
    report = make_error_report(reason)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)

    _validate(write_report(tmp_path, report), report["exit_code"])


@pytest.mark.parametrize("reason", ERROR_RESULT_RULES)
@pytest.mark.parametrize(
    "field", ("verdict", "count_below", "count_above", "status", "reason")
)
def test_error_result_rule_mismatches_are_rejected(tmp_path, reason, field):
    report = make_error_report(reason)
    outcome = report["outcomes"][0]
    if field == "verdict":
        outcome["actual_verdict"] = (
            "not_detected"
            if outcome["actual_verdict"] == "inconclusive"
            else "inconclusive"
        )
    elif field in {"count_below", "count_above"}:
        rule = ERROR_RESULT_RULES[reason]
        invalid = (
            rule.minimum_requests - 1
            if field == "count_below"
            else rule.maximum_requests + 1
        )
        outcome["request_count"] = invalid
        outcome["error"]["request_count"] = invalid
        report["requests_used"] = invalid
    elif field == "status":
        outcome["error"]["status"] = (
            "matched" if outcome["error"]["status"] != "matched" else "inconclusive"
        )
    else:
        replacement = next(item for item in ERROR_RESULT_RULES if item != reason)
        outcome["error"]["reason_code"] = replacement

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), report["exit_code"])


@pytest.mark.parametrize("missing", ("check_type", "error"))
def test_error_outcome_fields_are_all_or_nothing(tmp_path, missing):
    report = make_error_report("dbms_error_not_observed")
    del report["outcomes"][0][missing]

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 0)


@pytest.mark.parametrize("field", ("dbms", "signature_id"))
def test_error_evidence_is_all_or_nothing(tmp_path, field):
    report = make_error_report("dbms_error_disclosed")
    del report["outcomes"][0]["error"][field]

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 3)


def test_error_evidence_is_forbidden_when_rule_does_not_require_it(tmp_path):
    report = make_error_report("dbms_error_not_observed")
    report["outcomes"][0]["error"].update(
        dbms="sqlite", signature_id="sqlite_operational_syntax"
    )

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 0)


def test_error_evidence_requires_reviewed_dbms_signature_pair(tmp_path):
    report = make_error_report("dbms_error_disclosed")
    report["outcomes"][0]["error"]["dbms"] = "mysql"

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 3)


def test_boolean_outcome_rejects_error_object(tmp_path):
    report = make_report()
    report["outcomes"][0]["error"] = {
        "status": "inconclusive",
        "reason_code": "probe_timeout",
        "request_count": 1,
    }

    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 3)


def test_time_schema_reason_enum_matches_product_contract():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    assert set(schema["$defs"]["timing"]["properties"]["reason_code"]["enum"]) == set(
        TIME_RESULT_RULES
    )
    assert _VALIDATOR_MODULE["TIME_RESULT_RULES"] is TIME_RESULT_RULES


@pytest.mark.parametrize(
    "reason",
    [
        "incomplete_probes",
        "probe_timeout",
        "probe_failed",
        "probe_interrupted",
        "rate_limited",
        "non_success_status",
        "truncated_response",
        "unstable_timing",
        "ambiguous_timing",
    ],
)
def test_time_decision_facts_are_accepted_by_schema_and_validator(tmp_path, reason):
    report = make_time_report(reason)
    outcome = report["outcomes"][0]
    outcome["decision_facts"] = time_decision_facts(reason, outcome["request_count"])
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    Draft202012Validator(schema).validate(report)
    _validate(write_report(tmp_path, report), report["exit_code"])


@pytest.mark.parametrize(
    ("reason", "mutation"),
    [
        ("probe_timeout", {"sequence": 2}),
        ("probe_timeout", {"probe_kind": "control"}),
        ("rate_limited", {"status_code": 200}),
        ("non_success_status", {"status_code": 200}),
        ("non_success_status", {"status_code": 429}),
        ("truncated_response", {"status_code": 429}),
    ],
)
def test_time_operational_fact_mutations_are_rejected(tmp_path, reason, mutation):
    report = make_time_report(reason)
    outcome = report["outcomes"][0]
    facts = time_decision_facts(reason, outcome["request_count"])
    facts.update(mutation)
    outcome["decision_facts"] = facts

    expected = (
        _RATE_LIMIT_PRECEDENCE
        if mutation.get("status_code") == 429 or reason == "rate_limited"
        else r"facts|status|429"
    )
    with pytest.raises((ValueError, ValidationError), match=expected):
        _validate(write_report(tmp_path, report), report["exit_code"])


def test_time_decision_fact_reason_mislabel_is_rejected(tmp_path):
    report = make_time_report("unstable_timing")
    report["outcomes"][0]["decision_facts"] = time_decision_facts("ambiguous_timing", 9)
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(report)
    with pytest.raises((ValueError, ValidationError)):
        _validate(write_report(tmp_path, report), 3)


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
    outcome.pop("decision_facts", None)
    path = write_report(tmp_path, report)

    with pytest.raises(ValueError, match="lacks observations"):
        _validate(path, 0)


def test_workflow_uses_pinned_actions_and_manual_trigger_only():
    workflow = Path(".github/workflows/vintar-security.yml").read_text(encoding="utf-8")
    action_refs = [
        action.rpartition("@")[2]
        for action in collect_workflow_uses(workflow)
        if not action.startswith("./")
    ]

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
