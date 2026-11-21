"""Mechanical compatibility guard for the released regression public API."""

from dataclasses import fields

from test_regression_cases import VALID_CASE

import vintar
from vintar import regression
from vintar.checks.sqli.models import Verdict, VerificationResult

RELEASED_REGRESSION_NAMES = frozenset(
    {
        "BATCH_REPORT_SCHEMA_VERSION",
        "BATCH_REPORT_TYPE",
        "CASE_MAX_RESPONSE_SIZE",
        "CASE_VERSION",
        "MAX_BATCH_CASES",
        "MAX_CASE_BYTES",
        "CIExitCode",
        "RegressionBatchResult",
        "RegressionCase",
        "RegressionOutcome",
        "RegressionStatus",
        "TrustedExecutionPolicy",
        "batch_exit_code",
        "load_regression_case",
        "parse_regression_case",
        "regression_batch_report_dict",
        "regression_batch_report_json",
        "run_regression_batch",
        "run_regression_case",
    }
)

RELEASED_CASE_FIELDS = (
    "schema_version",
    "case_id",
    "check_type",
    "template",
    "point",
    "true_payload",
    "false_payload",
    "expected_verdict",
    "scope",
    "max_requests",
    "max_response_size",
    "requests_per_second",
    "timeout_seconds",
    "confirmation",
)

RELEASED_OUTCOME_FIELDS = (
    "case_id",
    "expected_verdict",
    "verification",
    "expectation_match",
    "status",
    "confirmation",
)

NEW_ERROR_EXPORTS = frozenset(
    {
        "ErrorRegressionCase",
        "ErrorRegressionOutcome",
    }
)

ERROR_CASE_FIELDS = (
    "schema_version",
    "case_id",
    "check_type",
    "template",
    "point",
    "error_payload",
    "expected_verdict",
    "scope",
    "max_requests",
    "max_response_size",
    "requests_per_second",
    "timeout_seconds",
)

ERROR_OUTCOME_FIELDS = (
    "case_id",
    "expected_verdict",
    "error_run",
    "expectation_match",
    "status",
)


def test_released_regression_public_names_still_exist():
    assert RELEASED_REGRESSION_NAMES <= frozenset(regression.__all__)
    assert all(hasattr(regression, name) for name in RELEASED_REGRESSION_NAMES)


def test_regression_case_remains_the_released_boolean_constructor():
    parsed = regression.parse_regression_case(VALID_CASE)
    assert isinstance(parsed, regression.RegressionCase)

    constructed = regression.RegressionCase(
        schema_version=parsed.schema_version,
        case_id=parsed.case_id,
        check_type=parsed.check_type,
        template=parsed.template,
        point=parsed.point,
        true_payload=parsed.true_payload,
        false_payload=parsed.false_payload,
        expected_verdict=parsed.expected_verdict,
        scope=parsed.scope,
        max_requests=parsed.max_requests,
        max_response_size=parsed.max_response_size,
        requests_per_second=parsed.requests_per_second,
        timeout_seconds=parsed.timeout_seconds,
        confirmation=parsed.confirmation,
    )

    assert type(constructed) is regression.RegressionCase
    assert isinstance(constructed, regression.BooleanRegressionCase)
    assert (
        tuple(field.name for field in fields(regression.RegressionCase))
        == RELEASED_CASE_FIELDS
    )


def test_regression_outcome_remains_the_released_boolean_result_model():
    verification = VerificationResult(
        check_id="compatibility-case",
        verdict=Verdict.INCONCLUSIVE,
        observations=(),
        request_count=0,
        reason_code="budget_unavailable",
        reason="Compatibility test result.",
    )

    outcome = regression.RegressionOutcome(
        case_id="compatibility-case",
        expected_verdict=Verdict.INCONCLUSIVE,
        verification=verification,
        expectation_match=True,
        status=regression.RegressionStatus.INCONCLUSIVE,
    )

    assert type(outcome) is regression.RegressionOutcome
    assert outcome.verification is verification
    assert (
        tuple(field.name for field in fields(regression.RegressionOutcome))
        == RELEASED_OUTCOME_FIELDS
    )


def test_top_level_vintar_public_surface_is_unchanged():
    assert callable(vintar.main)


def test_error_case_and_outcome_are_additive_public_exports():
    assert NEW_ERROR_EXPORTS <= frozenset(regression.__all__)
    assert all(hasattr(regression, name) for name in NEW_ERROR_EXPORTS)
    assert tuple(field.name for field in fields(regression.ErrorRegressionCase)) == (
        ERROR_CASE_FIELDS
    )
    assert tuple(field.name for field in fields(regression.ErrorRegressionOutcome)) == (
        ERROR_OUTCOME_FIELDS
    )
