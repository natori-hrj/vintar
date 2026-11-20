"""Product-contract tests for deterministic time-based SQLi analysis."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_sqli_time_analyzer import make_observations, make_plan, run_analysis

from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.time_analyzer import (
    REASONS,
    TimeAnalysis,
    TimeAnalysisStatus,
    TimeProbeOutcome,
    analyze_time_probes,
)
from vintar.checks.sqli.time_contract import (
    TIME_RESULT_RULES,
    time_product_result,
)


def _analyses_by_reason():
    observations = make_observations()

    def terminal(*, outcome=TimeProbeOutcome.COMPLETED, **changes):
        fields = {
            "outcome": outcome,
            "elapsed_seconds": (
                observations[0].elapsed_seconds
                if outcome is TimeProbeOutcome.COMPLETED
                else None
            ),
            "status_code": (
                observations[0].status_code
                if outcome is TimeProbeOutcome.COMPLETED
                else None
            ),
        }
        fields.update(changes)
        observation = replace(
            observations[0],
            **fields,
        )
        return analyze_time_probes(
            plan=make_plan(),
            observations=(observation,),
        )

    return {
        "timing_pattern_matched": run_analysis(),
        "timing_pattern_not_matched": run_analysis(delay=(0.12, 0.13, 0.14)),
        "incomplete_probes": analyze_time_probes(plan=make_plan(), observations=()),
        "probe_timeout": terminal(outcome=TimeProbeOutcome.TIMEOUT),
        "probe_failed": terminal(outcome=TimeProbeOutcome.REQUEST_FAILED),
        "probe_interrupted": terminal(outcome=TimeProbeOutcome.INTERRUPTED),
        "rate_limited": terminal(status_code=429),
        "non_success_status": terminal(status_code=403),
        "truncated_response": terminal(truncated=True),
        "unstable_timing": run_analysis(control=(0.10, 0.50, 0.12)),
        "ambiguous_timing": run_analysis(delay=(0.60, 0.61, 0.62)),
    }


def test_every_timing_reason_maps_to_its_product_verdict():
    analyses = _analyses_by_reason()

    assert analyses.keys() == TIME_RESULT_RULES.keys()
    for reason, analysis in analyses.items():
        product = time_product_result(analysis)
        rule = TIME_RESULT_RULES[reason]

        assert product.verdict is rule.product_verdict
        assert product.reason_code == reason
        assert product.request_count == analysis.request_count

    assert time_product_result(analyses["timing_pattern_matched"]).verdict is (
        Verdict.INCONCLUSIVE
    )
    assert time_product_result(analyses["timing_pattern_not_matched"]).verdict is (
        Verdict.NOT_DETECTED
    )


def test_timing_reason_registry_matches_analyzer_reasons():
    analyzer_reasons = frozenset().union(*REASONS.values())

    assert frozenset(TIME_RESULT_RULES) == analyzer_reasons


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            {"status": TimeAnalysisStatus.NOT_CONFIRMED},
            "status does not match.*TIME_RESULT_RULES",
        ),
        (
            {"reason_code": "unsupported_timing_reason"},
            "Unsupported timing analysis reason.*TIME_RESULT_RULES",
        ),
        (
            {"observations": make_observations()[:-1]},
            "observation count does not match.*TIME_RESULT_RULES",
        ),
        (
            {"evidence": None},
            "Incomplete timing classification evidence.*complete evidence-based classifications",
        ),
    ],
)
def test_forbidden_timing_analysis_combinations_are_rejected(change, message):
    analysis = run_analysis()

    with pytest.raises(ValueError, match=message):
        replace(analysis, **change)


@pytest.mark.parametrize(
    ("analysis", "expected"),
    [
        (
            run_analysis(
                baseline=(0.10, 0.10, 0.10),
                control=(0.10, 0.10, 0.10),
                delay=(0.60, 0.85, 0.85),
            ),
            (TimeAnalysisStatus.CANDIDATE, "timing_pattern_matched"),
        ),
        (
            run_analysis(
                baseline=(0.10, 0.10, 0.10),
                control=(0.10, 0.10, 0.10),
                delay=(0.35, 0.35, 0.35),
            ),
            (TimeAnalysisStatus.NOT_CONFIRMED, "timing_pattern_not_matched"),
        ),
        (
            run_analysis(
                baseline=(0.10, 0.16, 0.22),
                control=(0.10, 0.16, 0.22),
                delay=(0.85, 0.91, 0.97),
            ),
            (TimeAnalysisStatus.CANDIDATE, "timing_pattern_matched"),
        ),
    ],
)
def test_timing_threshold_boundaries_are_exact(analysis, expected):
    assert (analysis.status, analysis.reason_code) == expected


@pytest.mark.parametrize(
    "analysis",
    [
        SimpleNamespace(
            status=TimeAnalysisStatus.NOT_CONFIRMED,
            reason_code="timing_pattern_matched",
            request_count=9,
        ),
        SimpleNamespace(
            status=TimeAnalysisStatus.CANDIDATE,
            reason_code="timing_pattern_matched",
            request_count=8,
        ),
    ],
)
def test_product_mapping_rejects_unvalidated_combinations(analysis):
    with pytest.raises(ValueError, match=r"disagree.*TIME_RESULT_RULES"):
        time_product_result(analysis)


def test_time_analysis_type_remains_immutable():
    assert isinstance(run_analysis(), TimeAnalysis)
