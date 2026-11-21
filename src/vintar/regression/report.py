"""Versioned, allowed reports for regression batches."""

import json
from enum import IntEnum

from vintar.checks.sqli.confirmation_runner import ConfirmationStatus
from vintar.checks.sqli.error_contract import error_product_result
from vintar.checks.sqli.models import VerificationResult
from vintar.checks.sqli.report import verification_report_dict
from vintar.checks.sqli.time_contract import time_product_result
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.runner import (
    ErrorRegressionOutcome,
    RegressionOutcome,
    RegressionStatus,
    TimeRegressionOutcome,
)

BATCH_REPORT_SCHEMA_VERSION = 1
BATCH_REPORT_TYPE = "regression_batch"
_CONFIRMATION_REASON_CODES = frozenset(
    {
        "initial_not_eligible",
        "confirmation_pattern_matched",
        "candidate_confirmation_mismatch",
        "confirmation_budget_unavailable",
        "confirmation_preflight_failed",
        "confirmation_budget_exceeded",
        "confirmation_rate_limit_interrupted",
        "confirmation_timeout",
        "confirmation_request_failed",
        "confirmation_rate_limited",
        "confirmation_truncated",
        "confirmation_non_success_status",
        "confirmation_unstable",
        "confirmation_cross_phase_mismatch",
    }
)


class CIExitCode(IntEnum):
    """Stable process exit codes for CI integrations.

    ERROR is reserved for failures that prevent a valid batch result
    from being produced. It is not a RegressionStatus.
    """

    PASS = 0
    FAIL = 1
    ERROR = 2
    INCONCLUSIVE = 3


def batch_exit_code(
    result: RegressionBatchResult,
) -> CIExitCode:
    """Map a validated batch result to its CI process exit code."""
    if type(result) is not RegressionBatchResult:
        raise TypeError("result must be a RegressionBatchResult.")

    if result.status is RegressionStatus.FAIL:
        return CIExitCode.FAIL

    if not result.complete:
        return CIExitCode.INCONCLUSIVE

    if result.status is RegressionStatus.INCONCLUSIVE:
        return CIExitCode.INCONCLUSIVE

    return CIExitCode.PASS


def regression_batch_report_dict(
    result: RegressionBatchResult,
) -> dict[str, object]:
    """Produce a versioned report using only approved fields.

    This function deliberately excludes target URLs, HTTP headers,
    cookies, payloads, and free-text diagnostic reasons.

    NOT_DETECTED means only that this particular check did not
    detect a vulnerability; it is not a security guarantee.
    """
    if type(result) is not RegressionBatchResult:
        raise TypeError("result must be a RegressionBatchResult.")
    for outcome in result.outcomes:
        if type(outcome) is RegressionOutcome:
            if type(outcome.verification) is not VerificationResult:
                raise TypeError("result contains an unsupported derived model.")
        elif type(outcome) not in {TimeRegressionOutcome, ErrorRegressionOutcome}:
            raise TypeError("result contains an unsupported derived model.")

    executed_ids = tuple(outcome.case_id for outcome in result.outcomes)

    not_run_ids = result.planned_case_ids[len(executed_ids) :]

    counts = {
        "pass": sum(item.status is RegressionStatus.PASS for item in result.outcomes),
        "fail": sum(item.status is RegressionStatus.FAIL for item in result.outcomes),
        "inconclusive": sum(
            item.status is RegressionStatus.INCONCLUSIVE for item in result.outcomes
        ),
        "not_run": len(not_run_ids),
    }

    outcomes: list[dict[str, object]] = []

    for outcome in result.outcomes:
        if type(outcome) is ErrorRegressionOutcome:
            product = error_product_result(outcome.error_run.analysis)
            evidence = outcome.error_run.analysis.evidence
            error_report: dict[str, object] = {
                "status": outcome.error_run.analysis.status.value,
                "reason_code": product.reason_code,
                "request_count": product.request_count,
            }
            if evidence is not None:
                error_report.update(
                    dbms=evidence.dbms,
                    signature_id=evidence.signature_id,
                )
            outcomes.append(
                {
                    "case_id": outcome.case_id,
                    "check_type": "sqli.error",
                    "expected_verdict": outcome.expected_verdict.value,
                    "actual_verdict": product.verdict.value,
                    "actual_reason_code": product.reason_code,
                    "request_count": product.request_count,
                    "expectation_match": outcome.expectation_match,
                    "status": outcome.status.value,
                    "error": error_report,
                }
            )
            continue

        if type(outcome) is TimeRegressionOutcome:
            time_product = time_product_result(outcome.time_run.analysis)
            outcomes.append(
                {
                    "case_id": outcome.case_id,
                    "check_type": "sqli.time",
                    "expected_verdict": outcome.expected_verdict.value,
                    "actual_verdict": time_product.verdict.value,
                    "actual_reason_code": time_product.reason_code,
                    "request_count": time_product.request_count,
                    "expectation_match": outcome.expectation_match,
                    "status": outcome.status.value,
                    "timing": {
                        "status": outcome.time_run.analysis.status.value,
                        "reason_code": time_product.reason_code,
                        "request_count": time_product.request_count,
                    },
                }
            )
            continue

        if not isinstance(outcome, RegressionOutcome):
            raise TypeError("result contains an unsupported derived model.")

        verification = outcome.verification
        confirmation = outcome.confirmation
        if confirmation is None:
            confirmation_report: dict[str, object] = {
                "configured": False,
                "status": "not_configured",
                "reason_code": None,
                "request_count": 0,
            }
        else:
            if confirmation.status is ConfirmationStatus.SKIPPED:
                status = "not_eligible"
            elif confirmation.status is ConfirmationStatus.CANDIDATE:
                status = "matched"
            elif confirmation.reason_code == "candidate_confirmation_mismatch":
                status = "mismatch"
            else:
                status = "operational"
            confirmation_report = {
                "configured": True,
                "status": status,
                "reason_code": confirmation.reason_code,
                "request_count": confirmation.confirmation_requests,
            }
        outcomes.append(
            {
                "case_id": outcome.case_id,
                "expected_verdict": outcome.expected_verdict.value,
                "actual_verdict": outcome.final_verdict.value,
                "actual_reason_code": outcome.final_reason_code,
                "request_count": outcome.request_count,
                "expectation_match": outcome.expectation_match,
                "status": outcome.status.value,
                "verification": verification_report_dict(verification),
                "confirmation": confirmation_report,
            }
        )

    return {
        "schema_version": BATCH_REPORT_SCHEMA_VERSION,
        "report_type": BATCH_REPORT_TYPE,
        "status": result.status.value,
        "complete": result.complete,
        "exit_code": int(batch_exit_code(result)),
        "planned_case_ids": list(result.planned_case_ids),
        "executed_case_ids": list(executed_ids),
        "not_run_case_ids": list(not_run_ids),
        "planned_count": len(result.planned_case_ids),
        "executed_count": len(executed_ids),
        "requests_used": result.requests_used,
        "counts": counts,
        "outcomes": outcomes,
    }


def regression_batch_report_json(
    result: RegressionBatchResult,
    *,
    pretty: bool = False,
) -> str:
    """Serialize a batch report to deterministic, strict JSON."""
    if type(pretty) is not bool:
        raise TypeError("pretty must be a boolean.")

    report = regression_batch_report_dict(result)

    return json.dumps(
        report,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )
