"""Product result contract for bounded error-based SQLi analysis."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from vintar.checks.sqli.models import Verdict


class ErrorAnalysisStatus(StrEnum):
    """Classification produced by the pure error-signature analyzer."""

    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ErrorResultRule:
    """Machine-readable invariant for one error-analysis reason."""

    analysis_status: ErrorAnalysisStatus
    product_verdict: Verdict
    minimum_requests: int
    maximum_requests: int
    requires_complete_four: bool
    requires_evidence: bool


def _rule(
    analysis_status: ErrorAnalysisStatus,
    product_verdict: Verdict,
    *,
    requires_evidence: bool = False,
) -> ErrorResultRule:
    return ErrorResultRule(
        analysis_status=analysis_status,
        product_verdict=product_verdict,
        minimum_requests=4,
        maximum_requests=4,
        requires_complete_four=True,
        requires_evidence=requires_evidence,
    )


ERROR_RESULT_RULES: Mapping[str, ErrorResultRule] = MappingProxyType(
    {
        "dbms_error_disclosed": _rule(
            ErrorAnalysisStatus.MATCHED,
            Verdict.VULNERABLE,
            requires_evidence=True,
        ),
        "dbms_error_not_observed": _rule(
            ErrorAnalysisStatus.NOT_MATCHED,
            Verdict.NOT_DETECTED,
        ),
        "baseline_dbms_error": _rule(
            ErrorAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
        ),
        "unstable_response": _rule(
            ErrorAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
        ),
        "unstable_error_signal": _rule(
            ErrorAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
        ),
        "ambiguous_dbms_error": _rule(
            ErrorAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
        ),
        "non_success_status": _rule(
            ErrorAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
        ),
        "truncated_response": _rule(
            ErrorAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
        ),
    }
)


@dataclass(frozen=True, slots=True)
class ErrorProductResult:
    """Stable product verdict derived from one validated error analysis."""

    verdict: Verdict
    reason_code: str
    request_count: int


def error_product_result(analysis: object) -> ErrorProductResult:
    """Map one nominal, validated error analysis through the shared table."""
    from vintar.checks.sqli.error_analyzer import ErrorAnalysis

    if not isinstance(analysis, ErrorAnalysis):
        raise TypeError(
            "Error product mapping requires an ErrorAnalysis produced by the analyzer. Use analyze_error_responses instead of passing raw fields."
        )
    try:
        validated = ErrorAnalysis(
            status=analysis.status,
            reason_code=analysis.reason_code,
            observations=analysis.observations,
            evidence=analysis.evidence,
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise ValueError(
            "Error product mapping requires a valid ErrorAnalysis produced by the analyzer. Use analyze_error_responses instead of constructing or modifying fields."
        ) from None
    rule = ERROR_RESULT_RULES[validated.reason_code]
    return ErrorProductResult(
        verdict=rule.product_verdict,
        reason_code=validated.reason_code,
        request_count=len(validated.observations),
    )
