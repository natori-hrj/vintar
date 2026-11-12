"""Versioned, allowed reports for regression batches."""

import json
from enum import IntEnum

from vintar.checks.sqli.models import VerificationResult
from vintar.checks.sqli.report import verification_report_dict
from vintar.regression.batch import RegressionBatchResult
from vintar.regression.runner import RegressionOutcome, RegressionStatus

BATCH_REPORT_SCHEMA_VERSION = 1
BATCH_REPORT_TYPE = "regression_batch"


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
    if any(
        type(outcome) is not RegressionOutcome
        or type(outcome.verification) is not VerificationResult
        for outcome in result.outcomes
    ):
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
        outcomes.append(
            {
                "case_id": outcome.case_id,
                "expected_verdict": outcome.expected_verdict.value,
                "actual_verdict": outcome.verification.verdict.value,
                "expectation_match": outcome.expectation_match,
                "status": outcome.status.value,
                "verification": verification_report_dict(outcome.verification),
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
