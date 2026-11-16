"""Tests for experimental timing classification quality metrics."""

from dataclasses import replace

import pytest

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_quality import (
    CaseReliability,
    GroundTruth,
    QualitySample,
    summarize_quality,
)


def make_sample(
    case_id="safe",
    iteration=0,
    ground_truth=GroundTruth.NON_VULNERABLE,
    status=TimeAnalysisStatus.NOT_CONFIRMED,
):
    reasons = {
        TimeAnalysisStatus.CANDIDATE: "timing_pattern_matched",
        TimeAnalysisStatus.NOT_CONFIRMED: "timing_pattern_not_matched",
        TimeAnalysisStatus.INCONCLUSIVE: "unstable_timing",
        None: "execution_error",
    }

    return QualitySample(
        case_id=case_id,
        iteration=iteration,
        ground_truth=ground_truth,
        status=status,
        reason_code=reasons[status],
        budget_used=9,
        transport_attempts=9,
        server_received=9,
        observation_count=9,
        elapsed_seconds=1.0,
    )


def make_corpus():
    cases = (
        (
            "vulnerable",
            GroundTruth.VULNERABLE,
            (
                TimeAnalysisStatus.CANDIDATE,
                TimeAnalysisStatus.CANDIDATE,
            ),
        ),
        (
            "safe",
            GroundTruth.NON_VULNERABLE,
            (
                TimeAnalysisStatus.NOT_CONFIRMED,
                TimeAnalysisStatus.NOT_CONFIRMED,
            ),
        ),
        (
            "mimic",
            GroundTruth.NON_VULNERABLE,
            (
                TimeAnalysisStatus.CANDIDATE,
                TimeAnalysisStatus.CANDIDATE,
            ),
        ),
        (
            "jitter",
            GroundTruth.NON_VULNERABLE,
            (
                TimeAnalysisStatus.INCONCLUSIVE,
                TimeAnalysisStatus.NOT_CONFIRMED,
            ),
        ),
    )

    return tuple(
        make_sample(
            case_id=case_id,
            iteration=iteration,
            ground_truth=truth,
            status=status,
        )
        for case_id, truth, statuses in cases
        for iteration, status in enumerate(statuses)
    )


def test_quality_metrics_use_explicit_denominators():
    summary = summarize_quality(make_corpus())

    assert summary.total_cases == 4
    assert summary.repetitions == 2
    assert summary.total_runs == 8
    assert summary.vulnerable_runs == 2
    assert summary.non_vulnerable_runs == 6
    assert summary.true_candidates == 2
    assert summary.false_candidates == 2
    assert summary.candidates == 4
    assert summary.not_confirmed == 3
    assert summary.inconclusive == 1
    assert summary.execution_errors == 0

    assert summary.candidate_sensitivity == pytest.approx(1.0)
    assert summary.false_candidate_rate == pytest.approx(2 / 6)
    assert summary.classification_coverage == pytest.approx(7 / 8)
    assert summary.abstention_rate == pytest.approx(1 / 8)
    assert summary.execution_error_rate == 0
    assert summary.conditional_false_candidate_proportion == (pytest.approx(2 / 5))
    assert summary.flaky_case_rate == pytest.approx(1 / 4)


def test_flaky_classification_is_per_case():
    summary = summarize_quality(make_corpus())

    cases = {case.case_id: case for case in summary.cases}

    assert cases["jitter"].flaky
    assert cases["jitter"].statuses == (
        "inconclusive",
        "not_confirmed",
    )
    assert not cases["vulnerable"].flaky
    assert not cases["safe"].flaky
    assert not cases["mimic"].flaky


def test_execution_error_is_not_inconclusive():
    samples = (
        make_sample(iteration=0),
        make_sample(iteration=1, status=None),
    )

    summary = summarize_quality(samples)

    assert summary.execution_errors == 1
    assert summary.inconclusive == 0
    assert summary.execution_error_rate == 0.5
    assert summary.classification_coverage == 0.5
    assert summary.abstention_rate == 0
    assert summary.false_candidate_rate == 0
    assert summary.conditional_false_candidate_proportion == 0
    assert summary.flaky_case_rate == 1.0


def test_vulnerable_execution_error_remains_in_sensitivity_denominator():
    samples = (
        make_sample(
            iteration=0,
            ground_truth=GroundTruth.VULNERABLE,
            status=TimeAnalysisStatus.CANDIDATE,
        ),
        make_sample(
            iteration=1,
            ground_truth=GroundTruth.VULNERABLE,
            status=None,
        ),
    )

    summary = summarize_quality(samples)

    assert summary.candidate_sensitivity == 0.5
    assert summary.classification_coverage == 0.5
    assert summary.abstention_rate == 0
    assert summary.execution_error_rate == 0.5


def test_undefined_rates_are_none():
    non_vulnerable = summarize_quality((make_sample(),))
    assert non_vulnerable.candidate_sensitivity is None
    assert non_vulnerable.false_candidate_rate == 0.0

    vulnerable = summarize_quality(
        (
            make_sample(
                ground_truth=GroundTruth.VULNERABLE,
                status=TimeAnalysisStatus.CANDIDATE,
            ),
        )
    )
    assert vulnerable.false_candidate_rate is None
    assert vulnerable.conditional_false_candidate_proportion is None


def test_all_inconclusive_runs_have_no_conditional_denominator():
    summary = summarize_quality(
        (
            make_sample(
                iteration=0,
                status=TimeAnalysisStatus.INCONCLUSIVE,
            ),
            make_sample(
                iteration=1,
                status=TimeAnalysisStatus.INCONCLUSIVE,
            ),
        )
    )

    assert summary.classification_coverage == 0
    assert summary.abstention_rate == 1
    assert summary.conditional_false_candidate_proportion is None
    assert summary.flaky_case_rate == 0


def test_case_and_iteration_order_do_not_change_metrics():
    samples = make_corpus()

    assert summarize_quality(samples) == summarize_quality(tuple(reversed(samples)))


def test_duplicate_iterations_are_rejected():
    samples = (
        make_sample(iteration=0),
        make_sample(iteration=0),
    )

    with pytest.raises(ValueError, match="repetitions"):
        summarize_quality(samples)


def test_unbalanced_repetitions_are_rejected():
    samples = (
        make_sample(case_id="first", iteration=0),
        make_sample(case_id="first", iteration=1),
        make_sample(case_id="second", iteration=0),
    )

    with pytest.raises(ValueError, match="repetitions"):
        summarize_quality(samples)


def test_mismatched_ground_truth_is_rejected():
    samples = (
        make_sample(iteration=0),
        make_sample(
            iteration=1,
            ground_truth=GroundTruth.VULNERABLE,
        ),
    )

    with pytest.raises(ValueError, match="ground truth"):
        summarize_quality(samples)


def test_missing_iteration_is_rejected():
    samples = (
        make_sample(iteration=0),
        make_sample(iteration=2),
    )

    with pytest.raises(ValueError, match="repetitions"):
        summarize_quality(samples)


@pytest.mark.parametrize(
    "case_id",
    ("", "a/b", "a b", "日本語", "x" * 101),
)
def test_invalid_case_id_is_rejected(case_id):
    with pytest.raises(ValueError):
        make_sample(case_id=case_id)


@pytest.mark.parametrize(
    "iteration",
    (-1, True, 0.0, 100),
)
def test_invalid_iteration_is_rejected(iteration):
    with pytest.raises(ValueError):
        make_sample(iteration=iteration)


def test_inconsistent_reason_is_rejected():
    with pytest.raises(ValueError, match="reason"):
        replace(
            make_sample(),
            reason_code="timing_pattern_matched",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("budget_used", 10),
        ("budget_used", True),
        ("transport_attempts", -1),
        ("transport_attempts", 10),
        ("server_received", 10),
        ("observation_count", 10),
    ],
)
def test_invalid_accounting_is_rejected(field, value):
    with pytest.raises((TypeError, ValueError)):
        replace(
            make_sample(),
            **{field: value},
        )


def test_execution_error_can_have_partial_accounting():
    sample = replace(
        make_sample(status=None),
        budget_used=2,
        transport_attempts=1,
        server_received=1,
        observation_count=0,
    )

    assert sample.status is None
    assert sample.reason_code == "execution_error"


@pytest.mark.parametrize(
    "value",
    (-1.0, True, float("nan"), float("inf"), 10**1000),
)
def test_invalid_elapsed_is_rejected(value):
    with pytest.raises((TypeError, ValueError)):
        replace(
            make_sample(),
            elapsed_seconds=value,
        )


def test_empty_input_is_rejected():
    with pytest.raises(ValueError):
        summarize_quality(())


def test_non_tuple_input_is_rejected():
    with pytest.raises(ValueError):
        summarize_quality([make_sample()])


def test_invalid_sample_type_is_rejected():
    with pytest.raises(TypeError):
        summarize_quality((object(),))


def test_secrets_are_not_part_of_sample_schema():
    sample = make_sample()

    for name in (
        "payload",
        "headers",
        "cookies",
        "body",
        "authorization",
        "request_template",
    ):
        assert not hasattr(sample, name)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("statuses", ("invalid", "invalid")),
        ("reasons", ("timing_pattern_not_matched",)),
        ("flaky", True),
        ("execution_errors", 1),
    ],
)
def test_case_reliability_rejects_inconsistent_direct_construction(
    field,
    value,
):
    case = next(
        case
        for case in summarize_quality(make_corpus()).cases
        if case.case_id == "safe"
    )

    with pytest.raises((TypeError, ValueError)):
        replace(case, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("total_runs", 9),
        ("candidates", 5),
        ("candidate_sensitivity", 0.5),
        ("classification_coverage", float("nan")),
        ("classification_coverage", True),
        ("budget_used", 73),
        ("server_received", 73),
        ("observations", 73),
        ("observations", 71),
        ("total_elapsed_seconds", float("inf")),
    ],
)
def test_summary_rejects_inconsistent_direct_construction(field, value):
    summary = summarize_quality(make_corpus())

    with pytest.raises((TypeError, ValueError)):
        replace(summary, **{field: value})


def test_case_summary_rejects_duplicate_or_unsorted_cases():
    summary = summarize_quality(make_corpus())

    with pytest.raises(ValueError, match="ordering"):
        replace(summary, cases=tuple(reversed(summary.cases)))

    with pytest.raises(ValueError, match="ordering"):
        replace(summary, cases=(summary.cases[0],) * summary.total_cases)


def test_case_reliability_rejects_secret_bearing_identifier():
    with pytest.raises(ValueError, match="identifier"):
        CaseReliability(
            case_id="secret/value",
            ground_truth=GroundTruth.NON_VULNERABLE,
            statuses=("not_confirmed",),
            reasons=("timing_pattern_not_matched",),
            flaky=False,
            execution_errors=0,
        )


def test_maximum_case_and_repetition_boundaries_are_supported():
    samples = tuple(
        make_sample(
            case_id=f"case_{case}",
            iteration=iteration,
        )
        for case in range(100)
        for iteration in range(100)
    )

    summary = summarize_quality(samples)

    assert summary.total_cases == 100
    assert summary.repetitions == 100
    assert summary.total_runs == 10_000


def test_more_than_one_hundred_cases_are_rejected():
    samples = tuple(make_sample(case_id=f"case_{case}") for case in range(101))

    with pytest.raises(ValueError, match="cases"):
        summarize_quality(samples)
