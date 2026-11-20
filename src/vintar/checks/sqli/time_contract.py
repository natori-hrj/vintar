"""Product result contract for bounded time-based SQLi analysis."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from vintar.checks.sqli.models import Verdict


class TimeAnalysisStatus(StrEnum):
    """Classification produced by the pure timing analyzer."""

    CANDIDATE = "candidate"
    NOT_CONFIRMED = "not_confirmed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class TimeResultRule:
    """Machine-readable invariant for one timing analysis reason."""

    analysis_status: TimeAnalysisStatus
    product_verdict: Verdict
    minimum_requests: int
    maximum_requests: int
    requires_complete_nine: bool
    requires_evidence: bool


def _rule(
    analysis_status: TimeAnalysisStatus,
    product_verdict: Verdict,
    minimum_requests: int,
    maximum_requests: int,
    *,
    requires_complete_nine: bool = False,
    requires_evidence: bool = False,
) -> TimeResultRule:
    return TimeResultRule(
        analysis_status=analysis_status,
        product_verdict=product_verdict,
        minimum_requests=minimum_requests,
        maximum_requests=maximum_requests,
        requires_complete_nine=requires_complete_nine,
        requires_evidence=requires_evidence,
    )


TIME_RESULT_RULES: Mapping[str, TimeResultRule] = MappingProxyType(
    {
        "timing_pattern_matched": _rule(
            TimeAnalysisStatus.CANDIDATE,
            Verdict.INCONCLUSIVE,
            9,
            9,
            requires_complete_nine=True,
            requires_evidence=True,
        ),
        "timing_pattern_not_matched": _rule(
            TimeAnalysisStatus.NOT_CONFIRMED,
            Verdict.NOT_DETECTED,
            9,
            9,
            requires_complete_nine=True,
            requires_evidence=True,
        ),
        "incomplete_probes": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            0,
            8,
        ),
        "probe_timeout": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            1,
            9,
        ),
        "probe_failed": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            1,
            9,
        ),
        "probe_interrupted": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            1,
            9,
        ),
        "rate_limited": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            1,
            9,
        ),
        "non_success_status": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            1,
            9,
        ),
        "truncated_response": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            1,
            9,
        ),
        "unstable_timing": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            9,
            9,
            requires_complete_nine=True,
            requires_evidence=True,
        ),
        "ambiguous_timing": _rule(
            TimeAnalysisStatus.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            9,
            9,
            requires_complete_nine=True,
            requires_evidence=True,
        ),
    }
)


@dataclass(frozen=True, slots=True)
class TimeProductResult:
    """Stable product verdict derived from a timing analysis."""

    verdict: Verdict
    reason_code: str
    request_count: int


def time_product_result(analysis: object) -> TimeProductResult:
    """Map one validated timing analysis without changing its final reason."""
    # Import locally so the analyzer can consume this module's rules without a
    # module-initialization cycle.
    from vintar.checks.sqli.time_analyzer import TimeAnalysis

    if not isinstance(analysis, TimeAnalysis):
        raise TypeError(
            "Time product mapping requires a TimeAnalysis produced by the analyzer. Use analyze_time_probes instead of passing raw result fields."
        )

    try:
        validated = TimeAnalysis(
            status=analysis.status,
            reason_code=analysis.reason_code,
            expected_delay_seconds=analysis.expected_delay_seconds,
            observations=analysis.observations,
            evidence=analysis.evidence,
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        raise ValueError(
            "Time product mapping requires a valid TimeAnalysis produced by the analyzer. Use analyze_time_probes instead of constructing or modifying analysis fields."
        ) from None

    rule = TIME_RESULT_RULES[validated.reason_code]
    request_count = len(validated.observations)
    if validated.status is not rule.analysis_status:
        raise ValueError(
            "Timing reason and analysis status disagree. Use the status required by TIME_RESULT_RULES."
        )
    if not rule.minimum_requests <= request_count <= rule.maximum_requests:
        raise ValueError(
            "Timing reason and request count disagree. Use the bounded request range required by TIME_RESULT_RULES."
        )
    return TimeProductResult(
        verdict=rule.product_verdict,
        reason_code=validated.reason_code,
        request_count=request_count,
    )
