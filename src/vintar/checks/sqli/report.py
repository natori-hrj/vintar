"""Versioned, allowlisted JSON reporting for SQLi verification."""

import json

from vintar.checks.sqli.models import VerificationResult

REPORT_SCHEMA_VERSION = 1
_REPORT_REASON_CODES = frozenset(
    {
        "boolean_candidate",
        "boolean_differential",
        "budget_unavailable",
        "connection_error",
        "insufficient_evidence",
        "no_boolean_difference",
        "no_boolean_difference_literal_input",
        "non_success_status",
        "possible_dynamic_response",
        "probe_failed",
        "rate_limited",
        "truncated_response",
        "unexpected_difference",
        "unstable_response",
    }
)


def verification_report_dict(
    result: VerificationResult,
) -> dict[str, object]:
    """Build a report containing only explicitly permitted fields."""
    if not isinstance(result, VerificationResult):
        raise TypeError("result must be a VerificationResult.")
    if result.reason_code not in _REPORT_REASON_CODES:
        raise ValueError("reason_code is not supported by report schema version 1.")

    observations = [
        {
            "kind": item.kind.value,
            "status_code": item.status_code,
            "body_size": item.body_size,
            "elapsed": float(item.elapsed),
            "body_digest": item.body_digest,
            "truncated": item.truncated,
        }
        for item in result.observations
    ]

    failures = [
        {
            "kind": item.kind.value,
            "error": item.error.value,
            "elapsed": None if item.elapsed is None else float(item.elapsed),
        }
        for item in result.failures
    ]

    evidence = None
    if result.evidence is not None:
        evidence = {
            "baseline_true_similarity": float(result.evidence.baseline_true_similarity),
            "baseline_false_similarity": float(
                result.evidence.baseline_false_similarity
            ),
            "true_false_similarity": float(result.evidence.true_false_similarity),
        }

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "check_type": "sqli_boolean",
        "verdict": result.verdict.value,
        "reason_code": result.reason_code,
        "request_count": result.request_count,
        "observations": observations,
        "failures": failures,
        "evidence": evidence,
        "confidence": (None if result.confidence is None else float(result.confidence)),
    }


def verification_report_json(
    result: VerificationResult,
    *,
    pretty: bool = False,
) -> str:
    """Serialize the allowlisted report as deterministic JSON."""
    if type(pretty) is not bool:
        raise TypeError("pretty must be a boolean.")

    report = verification_report_dict(result)

    return json.dumps(
        report,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )
