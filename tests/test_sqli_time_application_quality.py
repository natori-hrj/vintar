"""Tests for application-level timing quality evaluation."""

from dataclasses import replace

import pytest

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_application_quality import (
    ApplicationBenchmark,
    ApplicationOutcome,
    ApplicationUnit,
    summarize_applications,
)
from vintar.checks.sqli.time_quality import GroundTruth, QualitySample

REASONS = {
    TimeAnalysisStatus.CANDIDATE: "timing_pattern_matched",
    TimeAnalysisStatus.NOT_CONFIRMED: "timing_pattern_not_matched",
    TimeAnalysisStatus.INCONCLUSIVE: "unstable_timing",
    None: "execution_error",
}


def sample(
    application_id: str,
    iteration: int,
    truth: GroundTruth,
    status: TimeAnalysisStatus | None,
) -> QualitySample:
    return QualitySample(
        case_id=application_id,
        iteration=iteration,
        ground_truth=truth,
        status=status,
        reason_code=REASONS[status],
        budget_used=9,
        transport_attempts=9,
        server_received=9,
        observation_count=9 if status is not None else 0,
        elapsed_seconds=1.0,
    )


def application(
    application_id: str,
    truth: GroundTruth,
    statuses: tuple[TimeAnalysisStatus | None, ...],
    *,
    framework: str = "fastapi",
    dbms: str = "sqlite",
    sql_context: str = "where",
) -> ApplicationUnit:
    return ApplicationUnit(
        application_id=application_id,
        ground_truth=truth,
        framework=framework,
        dbms=dbms,
        sql_context=sql_context,
        samples=tuple(
            sample(application_id, index, truth, status)
            for index, status in enumerate(statuses)
        ),
    )


def benchmark() -> ApplicationBenchmark:
    return summarize_applications(
        (
            application(
                "vulnerable_a",
                GroundTruth.VULNERABLE,
                (TimeAnalysisStatus.CANDIDATE,) * 3,
            ),
            application(
                "safe_b",
                GroundTruth.NON_VULNERABLE,
                (TimeAnalysisStatus.NOT_CONFIRMED,) * 3,
            ),
            application(
                "mimic_c",
                GroundTruth.NON_VULNERABLE,
                (TimeAnalysisStatus.CANDIDATE,) * 3,
                dbms="none",
                sql_context="none",
            ),
            application(
                "unstable_d",
                GroundTruth.NON_VULNERABLE,
                (
                    TimeAnalysisStatus.CANDIDATE,
                    TimeAnalysisStatus.INCONCLUSIVE,
                    TimeAnalysisStatus.NOT_CONFIRMED,
                ),
                framework="starlette",
            ),
        )
    )


def test_application_rates_use_applications_not_runs():
    result = benchmark()

    assert result.application_count == 4
    assert result.run_count == 12
    assert result.vulnerable_count == 1
    assert result.non_vulnerable_count == 3
    assert result.true_candidates == 1
    assert result.false_candidates == 1

    assert result.candidate_sensitivity == 1
    assert result.false_candidate_rate == pytest.approx(1 / 3)
    assert result.classification_coverage == 0.75
    assert result.abstention_rate == 0.25
    assert result.execution_error_rate == 0
    assert result.mixed_case_rate == 0.25

    assert result.request_count == 108
    assert result.dispatch_count == 108
    assert result.server_received == 108


def test_mixed_application_is_not_promoted_to_candidate():
    result = benchmark()
    unstable = next(
        app for app in result.applications if app.application_id == "unstable_d"
    )

    assert unstable.outcome is ApplicationOutcome.MIXED
    assert unstable.status_flaky
    assert unstable.ground_truth is GroundTruth.NON_VULNERABLE


def test_candidate_requires_all_repetitions():
    unstable = application(
        "vulnerable",
        GroundTruth.VULNERABLE,
        (
            TimeAnalysisStatus.CANDIDATE,
            TimeAnalysisStatus.NOT_CONFIRMED,
        ),
    )

    result = summarize_applications((unstable,))

    assert result.true_candidates == 0
    assert result.candidate_sensitivity == 0
    assert result.abstention_rate == 1


def test_execution_errors_remain_separate():
    failed = application(
        "failed",
        GroundTruth.NON_VULNERABLE,
        (None, None),
    )

    result = summarize_applications((failed,))

    assert failed.outcome is ApplicationOutcome.EXECUTION_ERROR
    assert result.execution_error_rate == 1
    assert result.classification_coverage == 0
    assert result.abstention_rate == 0


def test_mixed_error_is_not_hidden():
    mixed = application(
        "mixed",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.CANDIDATE, None),
    )

    result = summarize_applications((mixed,))

    assert mixed.outcome is ApplicationOutcome.MIXED
    assert mixed.execution_error_count == 1
    assert result.false_candidates == 0
    assert result.abstention_rate == 1
    assert result.execution_error_rate == 0
    assert result.execution_error_run_count == 1


def test_reason_changes_without_status_change():
    app = application(
        "unstable",
        GroundTruth.NON_VULNERABLE,
        (
            TimeAnalysisStatus.INCONCLUSIVE,
            TimeAnalysisStatus.INCONCLUSIVE,
        ),
    )

    changed = replace(
        app,
        samples=(
            app.samples[0],
            replace(
                app.samples[1],
                reason_code="ambiguous_timing",
            ),
        ),
    )

    assert changed.outcome is ApplicationOutcome.INCONCLUSIVE
    assert not changed.status_flaky
    assert changed.reason_flaky


def test_strata_preserve_application_denominators():
    result = benchmark()

    dbms = dict(result.strata("dbms"))

    assert set(dbms) == {"sqlite", "none"}
    assert dbms["sqlite"].application_count == 3
    assert dbms["none"].application_count == 1

    assert dbms["none"].false_candidate_rate == 1
    assert dbms["sqlite"].false_candidate_rate == 0

    frameworks = dict(result.strata("framework"))

    assert frameworks["fastapi"].application_count == 3
    assert frameworks["starlette"].application_count == 1

    for dimension in ("framework", "dbms", "sql_context"):
        groups = result.strata(dimension)
        grouped_ids = tuple(
            app.application_id for _, group in groups for app in group.applications
        )
        assert len(grouped_ids) == result.application_count
        assert set(grouped_ids) == {app.application_id for app in result.applications}


def test_strata_reject_unknown_dimension():
    with pytest.raises(ValueError):
        benchmark().strata("application_id")


def test_wilson_interval_uses_application_count():
    result = benchmark()

    sensitivity = result.sensitivity_interval()
    false_candidates = result.false_candidate_interval()

    assert sensitivity is not None
    assert sensitivity.trials == 1
    assert sensitivity.successes == 1

    assert false_candidates is not None
    assert false_candidates.trials == 3
    assert false_candidates.successes == 1


def test_absent_ground_truth_has_undefined_rate():
    result = summarize_applications(
        (
            application(
                "safe",
                GroundTruth.NON_VULNERABLE,
                (TimeAnalysisStatus.NOT_CONFIRMED,),
            ),
        )
    )

    assert result.candidate_sensitivity is None
    assert result.sensitivity_interval() is None
    assert result.false_candidate_rate == 0

    vulnerable_only = summarize_applications(
        (
            application(
                "vulnerable",
                GroundTruth.VULNERABLE,
                (TimeAnalysisStatus.CANDIDATE,),
            ),
        )
    )
    assert vulnerable_only.false_candidate_rate is None
    assert vulnerable_only.false_candidate_interval() is None


def test_input_order_is_canonicalized():
    original = benchmark()

    reordered = summarize_applications(tuple(reversed(original.applications)))

    assert reordered == original


def test_duplicate_application_ids_are_rejected():
    app = application(
        "duplicate",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="ordering"):
        summarize_applications((app, app))


def test_direct_benchmark_rejects_unsorted_entries():
    existing = benchmark()

    with pytest.raises(ValueError, match="ordering"):
        replace(
            existing,
            applications=tuple(reversed(existing.applications)),
        )


def test_application_rejects_case_id_mismatch():
    app = application(
        "correct",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="provenance"):
        replace(
            app,
            samples=(replace(app.samples[0], case_id="wrong"),),
        )


def test_application_rejects_truth_mismatch():
    app = application(
        "correct",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="provenance"):
        replace(
            app,
            ground_truth=GroundTruth.VULNERABLE,
        )

    with pytest.raises(TypeError, match="ground truth"):
        replace(app, ground_truth="non_vulnerable")


def test_application_rejects_duplicate_iterations():
    app = application(
        "case",
        GroundTruth.NON_VULNERABLE,
        (
            TimeAnalysisStatus.NOT_CONFIRMED,
            TimeAnalysisStatus.NOT_CONFIRMED,
        ),
    )

    with pytest.raises(ValueError, match="iteration"):
        replace(
            app,
            samples=(app.samples[0], app.samples[0]),
        )

    with pytest.raises(ValueError, match="iteration"):
        replace(app, samples=tuple(reversed(app.samples)))

    with pytest.raises(ValueError, match="iteration"):
        replace(app, samples=(app.samples[1],))


def test_application_rejects_invalid_sample_collection():
    app = application(
        "case",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="repetitions"):
        replace(app, samples=[])
    with pytest.raises(TypeError, match="sample"):
        replace(app, samples=(object(),))


@pytest.mark.parametrize(
    "identifier",
    ("", "with space", "path/value", "日本語", "x" * 101),
)
def test_invalid_identifiers_are_rejected(identifier):
    app = application(
        "valid",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="identifier"):
        replace(app, framework=identifier)


@pytest.mark.parametrize(
    "field",
    ("application_id", "framework", "dbms", "sql_context"),
)
def test_invalid_identifier_type_is_rejected(field):
    app = application(
        "valid",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="identifier"):
        replace(app, **{field: True})


def test_empty_benchmark_is_rejected():
    with pytest.raises(ValueError):
        summarize_applications(())


def test_benchmark_case_limit():
    apps = tuple(
        application(
            f"app_{index}",
            GroundTruth.NON_VULNERABLE,
            (TimeAnalysisStatus.NOT_CONFIRMED,),
        )
        for index in range(101)
    )

    with pytest.raises(ValueError, match="size"):
        summarize_applications(apps)


def test_application_repetition_limit():
    valid = application(
        "excessive",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="repetitions"):
        replace(valid, samples=valid.samples * 101)


def test_application_and_repetition_maximum_boundaries():
    applications = tuple(
        application(
            f"app_{index:03d}",
            GroundTruth.NON_VULNERABLE,
            (TimeAnalysisStatus.NOT_CONFIRMED,) * 100,
        )
        for index in range(100)
    )

    result = summarize_applications(applications)

    assert result.application_count == 100
    assert result.run_count == 10_000
    assert result.classification_coverage == 1


def test_no_raw_secrets_are_stored():
    app = application(
        "safe",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    for field in (
        "url",
        "payload",
        "authorization",
        "cookie",
        "response_body",
        "request_template",
    ):
        assert not hasattr(app, field)
