"""Tests for versioned regression batch reporting."""

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from vintar.checks.sqli import confirmation_runner
from vintar.checks.sqli.models import (
    BooleanEvidence,
    Observation,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.regression import report as regression_report
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.report import (
    BATCH_REPORT_SCHEMA_VERSION,
    BATCH_REPORT_TYPE,
    CIExitCode,
    batch_exit_code,
    regression_batch_report_dict,
    regression_batch_report_json,
)
from vintar.regression.runner import (
    RegressionOutcome,
    RegressionStatus,
)

EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SCHEMA_PATH = (
    Path(__file__).parents[1] / "schemas" / "regression-batch-report-v1.schema.json"
)


@pytest.fixture(scope="module")
def report_validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_confirmation_reason_schema_matches_runner_contract():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    enum = schema["$defs"]["confirmation"]["properties"]["reason_code"]["oneOf"][1][
        "enum"
    ]

    assert frozenset(enum) == regression_report._CONFIRMATION_REASON_CODES
    assert regression_report._CONFIRMATION_REASON_CODES == (
        confirmation_runner._INCONCLUSIVE_REASONS
        | {"initial_not_eligible", "confirmation_pattern_matched"}
    )


def make_verification(
    case_id: str,
    verdict: Verdict,
    *,
    reason_code: str | None = None,
    reason: str = "Internal diagnostic message.",
) -> VerificationResult:
    if verdict is Verdict.INCONCLUSIVE:
        return VerificationResult(
            check_id=case_id,
            verdict=verdict,
            observations=(),
            request_count=0,
            reason_code=reason_code or "budget_unavailable",
            reason=reason,
        )

    observations = tuple(
        Observation(
            kind=kind,
            status_code=200,
            body_size=0,
            elapsed=0.1,
            body_digest=EMPTY_DIGEST,
        )
        for kind in (
            ProbeKind.BASELINE,
            ProbeKind.TRUE,
            ProbeKind.FALSE,
        )
    )

    return VerificationResult(
        check_id=case_id,
        verdict=verdict,
        observations=observations,
        request_count=3,
        reason_code=reason_code
        or (
            "boolean_differential"
            if verdict is Verdict.VULNERABLE
            else "no_boolean_difference"
        ),
        reason=reason,
        evidence=BooleanEvidence(
            baseline_true_similarity=1.0,
            baseline_false_similarity=(0.0 if verdict is Verdict.VULNERABLE else 1.0),
            true_false_similarity=(0.0 if verdict is Verdict.VULNERABLE else 1.0),
        ),
    )


def make_outcome(
    case_id: str,
    *,
    actual: Verdict = Verdict.NOT_DETECTED,
    expected: Verdict = Verdict.NOT_DETECTED,
    reason: str = "Internal diagnostic message.",
) -> RegressionOutcome:
    verification = make_verification(
        case_id,
        actual,
        reason=reason,
    )

    matched = actual is expected

    if actual is Verdict.INCONCLUSIVE:
        status = RegressionStatus.INCONCLUSIVE
    elif actual is Verdict.VULNERABLE:
        status = RegressionStatus.FAIL
    elif matched:
        status = RegressionStatus.PASS
    else:
        status = RegressionStatus.FAIL

    return RegressionOutcome(
        case_id=case_id,
        expected_verdict=expected,
        verification=verification,
        expectation_match=matched,
        status=status,
    )


def make_batch(
    *outcomes: RegressionOutcome,
    planned_ids: tuple[str, ...] | None = None,
) -> RegressionBatchResult:
    if planned_ids is None:
        planned_ids = tuple(item.case_id for item in outcomes)

    complete = len(outcomes) == len(planned_ids)

    if any(item.status is RegressionStatus.FAIL for item in outcomes):
        status = RegressionStatus.FAIL
    elif not complete or any(
        item.status is RegressionStatus.INCONCLUSIVE for item in outcomes
    ):
        status = RegressionStatus.INCONCLUSIVE
    else:
        status = RegressionStatus.PASS

    return RegressionBatchResult(
        planned_case_ids=planned_ids,
        outcomes=tuple(outcomes),
        status=status,
        requests_used=sum(item.verification.request_count for item in outcomes),
    )


def test_complete_passing_report():
    result = make_batch(
        make_outcome("case-one"),
        make_outcome("case-two"),
    )

    report = regression_batch_report_dict(result)

    assert report["schema_version"] == BATCH_REPORT_SCHEMA_VERSION
    assert report["report_type"] == BATCH_REPORT_TYPE
    assert report["status"] == "pass"
    assert report["complete"] is True
    assert report["exit_code"] == 0
    assert report["planned_case_ids"] == ["case-one", "case-two"]
    assert report["executed_case_ids"] == ["case-one", "case-two"]
    assert report["not_run_case_ids"] == []
    assert report["planned_count"] == 2
    assert report["executed_count"] == 2
    assert report["requests_used"] == 6

    assert report["counts"] == {
        "pass": 2,
        "fail": 0,
        "inconclusive": 0,
        "not_run": 0,
    }

    assert len(report["outcomes"]) == 2
    assert report["outcomes"][0]["actual_verdict"] == "not_detected"
    assert report["outcomes"][0]["expectation_match"] is True
    assert report["outcomes"][0]["verification"]["schema_version"] == 1


def test_incomplete_batch_is_not_success():
    result = make_batch(
        make_outcome(
            "case-one",
            actual=Verdict.INCONCLUSIVE,
            expected=Verdict.INCONCLUSIVE,
        ),
        planned_ids=("case-one", "case-two", "case-three"),
    )

    report = regression_batch_report_dict(result)

    assert report["complete"] is False
    assert report["status"] == "inconclusive"
    assert report["exit_code"] == 3
    assert report["not_run_case_ids"] == [
        "case-two",
        "case-three",
    ]
    assert report["counts"]["not_run"] == 2
    assert report["counts"]["inconclusive"] == 1

    # An expected INCONCLUSIVE remains a failed security gate.
    assert report["outcomes"][0]["expectation_match"] is True
    assert report["outcomes"][0]["status"] == "inconclusive"


def test_failure_takes_precedence_over_incomplete():
    result = make_batch(
        make_outcome(
            "case-one",
            actual=Verdict.NOT_DETECTED,
            expected=Verdict.VULNERABLE,
        ),
        make_outcome(
            "case-two",
            actual=Verdict.INCONCLUSIVE,
        ),
        planned_ids=("case-one", "case-two", "case-three"),
    )

    report = regression_batch_report_dict(result)

    assert report["complete"] is False
    assert report["status"] == "fail"
    assert report["exit_code"] == 1
    assert report["counts"] == {
        "pass": 0,
        "fail": 1,
        "inconclusive": 1,
        "not_run": 1,
    }


def test_expected_vulnerable_does_not_pass_security_gate():
    result = make_batch(
        make_outcome(
            "vulnerable-fixture",
            actual=Verdict.VULNERABLE,
            expected=Verdict.VULNERABLE,
        )
    )

    report = regression_batch_report_dict(result)

    assert report["status"] == "fail"
    assert report["exit_code"] == 1
    assert report["outcomes"][0]["expectation_match"] is True
    assert report["outcomes"][0]["actual_verdict"] == "vulnerable"
    assert report["outcomes"][0]["status"] == "fail"


def test_case_identifiers_do_not_replace_observed_verdicts():
    result = make_batch(
        make_outcome(
            "expected-vulnerable",
            actual=Verdict.NOT_DETECTED,
            expected=Verdict.VULNERABLE,
        )
    )

    report = regression_batch_report_dict(result)
    outcome = report["outcomes"][0]

    assert outcome["expected_verdict"] == "vulnerable"
    assert outcome["actual_verdict"] == "not_detected"
    assert outcome["expectation_match"] is False
    assert outcome["status"] == "fail"


@pytest.mark.parametrize(
    ("actual", "expected_code"),
    [
        (RegressionStatus.PASS, CIExitCode.PASS),
        (RegressionStatus.FAIL, CIExitCode.FAIL),
        (RegressionStatus.INCONCLUSIVE, CIExitCode.INCONCLUSIVE),
    ],
)
def test_exit_code_mapping(actual, expected_code):
    if actual is RegressionStatus.PASS:
        result = make_batch(make_outcome("case-one"))
    elif actual is RegressionStatus.FAIL:
        result = make_batch(
            make_outcome(
                "case-one",
                expected=Verdict.VULNERABLE,
            )
        )
    else:
        result = make_batch(
            make_outcome(
                "case-one",
                actual=Verdict.INCONCLUSIVE,
            )
        )

    assert result.status is actual
    assert batch_exit_code(result) is expected_code


def test_error_exit_code_is_reserved():
    assert CIExitCode.ERROR.value == 2
    assert CIExitCode.ERROR not in {
        batch_exit_code(make_batch(make_outcome("case-one"))),
        batch_exit_code(
            make_batch(
                make_outcome(
                    "case-one",
                    actual=Verdict.INCONCLUSIVE,
                )
            )
        ),
    }


def test_json_is_deterministic():
    result = make_batch(make_outcome("case-one"))

    first = regression_batch_report_json(result)
    second = regression_batch_report_json(result)

    assert first == second
    assert json.loads(first) == regression_batch_report_dict(result)
    assert "\n" not in first


def test_pretty_json_round_trip():
    result = make_batch(make_outcome("case-one"))

    compact = regression_batch_report_json(result)
    pretty = regression_batch_report_json(result, pretty=True)

    assert json.loads(compact) == json.loads(pretty)
    assert "\n" in pretty
    assert len(pretty) > len(compact)


def test_sensitive_diagnostics_are_not_exported():
    secret = "SECRET_NEVER_EXPORT_123"

    result = make_batch(
        make_outcome(
            "case-one",
            actual=Verdict.INCONCLUSIVE,
            reason=f"Target secret: {secret}",
        ),
    )

    serialized = regression_batch_report_json(result)

    assert secret not in serialized
    assert "Internal diagnostic message" not in serialized
    assert '"reason":' not in serialized
    assert '"template":' not in serialized
    assert '"payload":' not in serialized
    assert '"url":' not in serialized
    assert '"headers":' not in serialized
    assert '"cookies":' not in serialized


def test_report_uses_explicit_allowlist():
    result = make_batch(make_outcome("case-one"))
    report = regression_batch_report_dict(result)

    assert set(report) == {
        "schema_version",
        "report_type",
        "status",
        "complete",
        "exit_code",
        "planned_case_ids",
        "executed_case_ids",
        "not_run_case_ids",
        "planned_count",
        "executed_count",
        "requests_used",
        "counts",
        "outcomes",
    }

    assert set(report["outcomes"][0]) == {
        "case_id",
        "expected_verdict",
        "actual_verdict",
        "actual_reason_code",
        "request_count",
        "expectation_match",
        "status",
        "verification",
        "confirmation",
    }
    assert set(report["outcomes"][0]["verification"]) == {
        "schema_version",
        "check_type",
        "verdict",
        "reason_code",
        "request_count",
        "observations",
        "failures",
        "evidence",
        "confidence",
    }


def test_report_mutation_does_not_modify_original():
    result = make_batch(make_outcome("case-one"))
    report = regression_batch_report_dict(result)

    report["planned_case_ids"].append("tampered")
    report["outcomes"][0]["status"] = "fail"
    report["outcomes"][0]["verification"]["observations"].clear()

    fresh = regression_batch_report_dict(result)

    assert fresh["planned_case_ids"] == ["case-one"]
    assert fresh["outcomes"][0]["status"] == "pass"
    assert len(fresh["outcomes"][0]["verification"]["observations"]) == 3


@pytest.mark.parametrize(
    "invalid",
    [None, {}, [], "not-a-batch", 123],
)
def test_invalid_batch_is_rejected(invalid):
    with pytest.raises(TypeError):
        regression_batch_report_dict(invalid)

    with pytest.raises(TypeError):
        batch_exit_code(invalid)


@pytest.mark.parametrize(
    "invalid",
    [None, 0, 1, "true"],
)
def test_invalid_pretty_flag_is_rejected(invalid):
    with pytest.raises(TypeError):
        regression_batch_report_json(
            make_batch(make_outcome("case-one")),
            pretty=invalid,
        )


def test_unapproved_diagnostic_reason_code_is_rejected():
    verification = make_verification(
        "case-one",
        Verdict.INCONCLUSIVE,
        reason_code="private_internal_detail",
    )

    outcome = RegressionOutcome(
        case_id="case-one",
        expected_verdict=Verdict.INCONCLUSIVE,
        verification=verification,
        expectation_match=True,
        status=RegressionStatus.INCONCLUSIVE,
    )

    result = make_batch(outcome)

    with pytest.raises(ValueError, match="not supported"):
        regression_batch_report_json(result)


@pytest.mark.parametrize(
    "result",
    [
        make_batch(make_outcome("passing-case")),
        make_batch(
            make_outcome(
                "failing-case",
                actual=Verdict.VULNERABLE,
                expected=Verdict.VULNERABLE,
            )
        ),
        make_batch(
            make_outcome(
                "inconclusive-case",
                actual=Verdict.INCONCLUSIVE,
                expected=Verdict.INCONCLUSIVE,
            ),
            planned_ids=("inconclusive-case", "not-run-case"),
        ),
    ],
    ids=("pass", "fail", "incomplete"),
)
def test_generated_json_validates_against_schema_v1(result, report_validator):
    report_validator.validate(json.loads(regression_batch_report_json(result)))


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("unexpected",), True),
        (("counts", "unexpected"), 1),
        (("outcomes", 0, "unexpected"), "secret"),
        (("outcomes", 0, "verification", "unexpected"), "secret"),
    ],
)
def test_schema_rejects_additional_fields(report_validator, path, value):
    report = regression_batch_report_dict(make_batch(make_outcome("case-one")))
    target = report
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(ValidationError):
        report_validator.validate(report)


@pytest.mark.parametrize(
    ("status", "exit_code", "complete"),
    [
        ("pass", 3, True),
        ("pass", 0, False),
        ("fail", 0, True),
        ("inconclusive", 0, True),
    ],
)
def test_schema_rejects_inconsistent_ci_state(
    report_validator,
    status,
    exit_code,
    complete,
):
    report = regression_batch_report_dict(make_batch(make_outcome("case-one")))
    report["status"] = status
    report["exit_code"] = exit_code
    report["complete"] = complete

    with pytest.raises(ValidationError):
        report_validator.validate(report)


def test_derived_batch_result_is_rejected():
    class DerivedBatchResult(RegressionBatchResult):
        pass

    original = make_batch(make_outcome("case-one"))
    derived = DerivedBatchResult(
        planned_case_ids=original.planned_case_ids,
        outcomes=original.outcomes,
        status=original.status,
        requests_used=original.requests_used,
    )

    with pytest.raises(TypeError):
        batch_exit_code(derived)
    with pytest.raises(TypeError):
        regression_batch_report_dict(derived)


def test_derived_nested_model_is_rejected():
    class DerivedOutcome(RegressionOutcome):
        pass

    original = make_outcome("case-one")
    derived = DerivedOutcome(
        case_id=original.case_id,
        expected_verdict=original.expected_verdict,
        verification=original.verification,
        expectation_match=original.expectation_match,
        status=original.status,
    )
    result = make_batch(derived)

    with pytest.raises(TypeError, match="derived model"):
        regression_batch_report_dict(result)
