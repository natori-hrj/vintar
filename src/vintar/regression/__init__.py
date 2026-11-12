"""Public API for security regression cases and execution."""

from vintar.regression.batch import (
    MAX_BATCH_CASES,
    RegressionBatchResult,
    run_regression_batch,
)
from vintar.regression.cases import (
    CASE_MAX_RESPONSE_SIZE,
    CASE_VERSION,
    MAX_CASE_BYTES,
    RegressionCase,
    load_regression_case,
    parse_regression_case,
)
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
    TrustedExecutionPolicy,
    run_regression_case,
)

__all__ = [
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
]
