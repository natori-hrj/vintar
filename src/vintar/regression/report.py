"""Versioned, allowed reports for regression batches."""

import json
from enum import IntEnum

from vintar.checks.sqli.confirmation_runner import ConfirmationStatus
from vintar.checks.sqli.models import VerificationResult
from vintar.checks.sqli.report import verification_report_dict
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.runner import (
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


class UnsupportedTimeBatchReportError(ValueError):
    """A time outcome reached the not-yet-supported batch report boundary."""


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
    if any(isinstance(outcome, TimeRegressionOutcome) for outcome in result.outcomes):
        raise UnsupportedTimeBatchReportError(
            "Time SQLi cases are not yet supported in batch reports. Use the Python single-case regression API until Phase 13-3 adds report support."
        )
    boolean_outcomes: list[RegressionOutcome] = []
    for outcome in result.outcomes:
        if (
            type(outcome) is not RegressionOutcome
            or type(outcome.verification) is not VerificationResult
        ):
            raise TypeError("result contains an unsupported derived model.")
        boolean_outcomes.append(outcome)

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

    for outcome in boolean_outcomes:
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
