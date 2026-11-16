"""Tests for descriptive time-based SQLi research metrics."""

import math
from dataclasses import replace

import pytest

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_quality import (
    GroundTruth,
    QualitySample,
    summarize_quality,
)
from vintar.checks.sqli.time_research import (
    BinomialInterval,
    CaseStability,
    ControlAssessment,
    IndependentControlResult,
    ResearchSummary,
    assess_independent_control,
    summarize_research,
    wilson_interval,
)


def sample(
    case_id: str,
    iteration: int,
    ground_truth: GroundTruth,
    status: TimeAnalysisStatus | None,
    reason: str,
) -> QualitySample:
    completed = status is not None
    return QualitySample(
        case_id=case_id,
        iteration=iteration,
        ground_truth=ground_truth,
        status=status,
        reason_code=reason,
        budget_used=1,
        transport_attempts=1,
        server_received=1,
        observation_count=int(completed),
        elapsed_seconds=0.1,
    )


def research_summary() -> ResearchSummary:
    quality = summarize_quality(
        (
            sample(
                "reason_only",
                0,
                GroundTruth.NON_VULNERABLE,
                TimeAnalysisStatus.INCONCLUSIVE,
                "unstable_timing",
            ),
            sample(
                "reason_only",
                1,
                GroundTruth.NON_VULNERABLE,
                TimeAnalysisStatus.INCONCLUSIVE,
                "ambiguous_timing",
            ),
            sample(
                "status_and_reason",
                0,
                GroundTruth.VULNERABLE,
                TimeAnalysisStatus.CANDIDATE,
                "timing_pattern_matched",
            ),
            sample(
                "status_and_reason",
                1,
                GroundTruth.VULNERABLE,
                None,
                "execution_error",
            ),
        )
    )
    return summarize_research(quality)


@pytest.mark.parametrize(
    ("successes", "trials", "estimate", "lower", "upper"),
    [
        (0, 1, 0.0, 0.0, 0.7934506856227626),
        (1, 1, 1.0, 0.20654931437723745, 1.0),
        (0, 10, 0.0, 0.0, 0.27753279986288915),
        (5, 10, 0.5, 0.236593090512564, 0.7634069094874361),
        (10, 10, 1.0, 0.7224672001371109, 1.0),
    ],
)
def test_wilson_interval_matches_known_95_percent_values(
    successes,
    trials,
    estimate,
    lower,
    upper,
):
    interval = wilson_interval(successes=successes, trials=trials)

    assert interval is not None
    assert interval.confidence_level == 0.95
    assert interval.estimate == pytest.approx(estimate)
    assert interval.lower == pytest.approx(lower)
    assert interval.upper == pytest.approx(upper)


def test_wilson_interval_returns_none_for_zero_denominator():
    assert wilson_interval(successes=0, trials=0) is None


@pytest.mark.parametrize("confidence_level", [0.5, 0.95, 0.999])
def test_wilson_interval_accepts_confidence_boundaries(confidence_level):
    interval = wilson_interval(
        successes=5,
        trials=10,
        confidence_level=confidence_level,
    )

    assert interval is not None
    assert interval.confidence_level == confidence_level


def test_wilson_interval_accepts_maximum_sample_boundary():
    interval = wilson_interval(successes=5_000, trials=10_000)

    assert interval is not None
    assert interval.estimate == 0.5


@pytest.mark.parametrize(
    ("successes", "trials", "exception"),
    [
        (True, 1, TypeError),
        (0, False, TypeError),
        (-1, 1, ValueError),
        (2, 1, ValueError),
        (0, 10_001, ValueError),
        (10**1000, 10**1000, ValueError),
    ],
)
def test_wilson_interval_rejects_invalid_counts(successes, trials, exception):
    with pytest.raises(exception):
        wilson_interval(successes=successes, trials=trials)


@pytest.mark.parametrize(
    "confidence_level",
    [True, 0.49, 1.0, math.nan, math.inf, -math.inf],
)
def test_wilson_interval_rejects_invalid_confidence(confidence_level):
    with pytest.raises((TypeError, ValueError)):
        wilson_interval(
            successes=1,
            trials=2,
            confidence_level=confidence_level,
        )


def test_binomial_interval_rejects_direct_construction_and_replace_tampering():
    interval = wilson_interval(successes=1, trials=2)
    assert interval is not None

    with pytest.raises(ValueError, match="Inconsistent"):
        replace(interval, estimate=0.75)
    with pytest.raises(ValueError, match="Inconsistent"):
        replace(interval, lower=0.0)
    with pytest.raises((TypeError, ValueError)):
        replace(interval, upper=math.nan)
    with pytest.raises(TypeError):
        replace(interval, confidence_level=True)

    with pytest.raises(ValueError, match="requires observations"):
        BinomialInterval(0, 0, 0.95, 0.0, 0.0, 0.0)


def test_research_summary_separates_status_and_reason_variability():
    result = research_summary()
    cases = {case.case_id: case for case in result.case_stability}

    assert cases["reason_only"].status_changed is False
    assert cases["reason_only"].reason_changed is True
    assert cases["status_and_reason"].status_changed is True
    assert cases["status_and_reason"].reason_changed is True
    assert result.status_flaky_case_rate == 0.5
    assert result.reason_flaky_case_rate == 1.0

    assert result.sensitivity_interval is not None
    assert result.sensitivity_interval.successes == 1
    assert result.sensitivity_interval.trials == 2
    assert result.false_candidate_interval is not None
    assert result.false_candidate_interval.successes == 0
    assert result.false_candidate_interval.trials == 2


def test_execution_error_is_a_distinct_status_and_reason_outcome():
    result = research_summary()
    case = next(
        item for item in result.case_stability if item.case_id == "status_and_reason"
    )

    assert case.status_changed
    assert case.reason_changed


@pytest.mark.parametrize(
    ("field", "value", "exception"),
    [
        ("case_id", "secret=value", ValueError),
        ("repetitions", True, ValueError),
        ("repetitions", 0, ValueError),
        ("repetitions", 101, ValueError),
        ("status_changed", 1, TypeError),
        ("reason_changed", 0, TypeError),
    ],
)
def test_case_stability_rejects_invalid_direct_state(field, value, exception):
    case = CaseStability("case", 2, False, False)

    with pytest.raises(exception):
        replace(case, **{field: value})


def test_research_summary_rejects_inconsistent_direct_state():
    result = research_summary()

    with pytest.raises(ValueError, match="Inconsistent research rate"):
        replace(result, status_flaky_case_rate=0.0)
    with pytest.raises(ValueError, match="Inconsistent research rate"):
        replace(result, reason_flaky_case_rate=0.0)
    with pytest.raises((TypeError, ValueError)):
        replace(result, status_flaky_case_rate=math.nan)
    with pytest.raises(TypeError, match="Invalid research interval"):
        replace(result, sensitivity_interval=True)
    with pytest.raises(ValueError, match="ordering"):
        replace(result, case_stability=tuple(reversed(result.case_stability)))
    with pytest.raises(ValueError, match="repetitions"):
        replace(
            result,
            case_stability=(
                result.case_stability[0],
                replace(result.case_stability[1], repetitions=3),
            ),
        )
    with pytest.raises(ValueError, match="interval trials"):
        replace(result, false_candidate_interval=None)
    assert result.sensitivity_interval is not None
    assert result.false_candidate_interval is not None
    with pytest.raises(ValueError, match="confidence levels"):
        replace(
            result,
            false_candidate_interval=wilson_interval(
                successes=result.false_candidate_interval.successes,
                trials=result.false_candidate_interval.trials,
                confidence_level=0.9,
            ),
        )


def test_research_summary_rejects_invalid_input_type():
    with pytest.raises(TypeError, match="quality summary"):
        summarize_research(object())


@pytest.mark.parametrize(
    ("primary", "control", "expected"),
    [
        (
            TimeAnalysisStatus.CANDIDATE,
            TimeAnalysisStatus.CANDIDATE,
            ControlAssessment.CONTROL_REACTIVE,
        ),
        (
            TimeAnalysisStatus.CANDIDATE,
            TimeAnalysisStatus.NOT_CONFIRMED,
            ControlAssessment.CONTROL_NOT_REACTIVE,
        ),
        (
            TimeAnalysisStatus.CANDIDATE,
            TimeAnalysisStatus.INCONCLUSIVE,
            ControlAssessment.UNDETERMINED,
        ),
        (
            TimeAnalysisStatus.NOT_CONFIRMED,
            TimeAnalysisStatus.CANDIDATE,
            ControlAssessment.UNDETERMINED,
        ),
    ],
)
def test_independent_control_assessment_contract(primary, control, expected):
    result = assess_independent_control(
        primary_case_id="case",
        primary_status=primary,
        control_status=control,
    )

    assert result.assessment is expected
    assert not hasattr(result, "verdict")


def test_independent_control_rejects_tampering_and_secret_identifier():
    result = assess_independent_control(
        primary_case_id="case",
        primary_status=TimeAnalysisStatus.CANDIDATE,
        control_status=TimeAnalysisStatus.NOT_CONFIRMED,
    )

    with pytest.raises(ValueError, match="Inconsistent"):
        replace(result, assessment=ControlAssessment.CONTROL_REACTIVE)

    secret = "Authorization_Bearer_secret.value"
    with pytest.raises(ValueError) as raised:
        assess_independent_control(
            primary_case_id=secret,
            primary_status=TimeAnalysisStatus.CANDIDATE,
            control_status=TimeAnalysisStatus.NOT_CONFIRMED,
        )
    assert secret not in str(raised.value)


def test_research_models_do_not_store_http_or_payload_fields():
    fields = set(ResearchSummary.__dataclass_fields__)
    control_fields = set(IndependentControlResult.__dataclass_fields__)

    assert fields.isdisjoint({"body", "headers", "cookies", "payload", "url"})
    assert control_fields.isdisjoint({"body", "headers", "cookies", "payload", "url"})
