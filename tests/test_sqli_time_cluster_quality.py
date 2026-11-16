"""Tests for clustered experimental timing quality evaluation."""

from dataclasses import replace

import pytest

from vintar.checks.sqli.time_analyzer import TimeAnalysisStatus
from vintar.checks.sqli.time_application_quality import (
    ApplicationOutcome,
    ApplicationUnit,
)
from vintar.checks.sqli.time_cluster_quality import (
    ClusterUnit,
    summarize_clusters,
)
from vintar.checks.sqli.time_quality import GroundTruth, QualitySample


def make_application(
    application_id: str,
    truth: GroundTruth,
    statuses: tuple[TimeAnalysisStatus | None, ...],
) -> ApplicationUnit:
    reasons = {
        TimeAnalysisStatus.CANDIDATE: "timing_pattern_matched",
        TimeAnalysisStatus.NOT_CONFIRMED: "timing_pattern_not_matched",
        TimeAnalysisStatus.INCONCLUSIVE: "unstable_timing",
        None: "execution_error",
    }

    samples = tuple(
        QualitySample(
            case_id=application_id,
            iteration=index,
            ground_truth=truth,
            status=status,
            reason_code=reasons[status],
            budget_used=9,
            transport_attempts=9,
            server_received=9,
            observation_count=9 if status is not None else 0,
            elapsed_seconds=1.0,
        )
        for index, status in enumerate(statuses)
    )

    return ApplicationUnit(
        application_id=application_id,
        ground_truth=truth,
        framework="fastapi",
        dbms="sqlite",
        sql_context="where",
        samples=samples,
    )


def make_cluster(
    cluster_id: str,
    *applications: ApplicationUnit,
) -> ClusterUnit:
    return ClusterUnit(
        cluster_id=cluster_id,
        applications=tuple(
            sorted(
                applications,
                key=lambda app: app.application_id,
            )
        ),
    )


def benchmark():
    candidate = (TimeAnalysisStatus.CANDIDATE,) * 2
    negative = (TimeAnalysisStatus.NOT_CONFIRMED,) * 2

    return summarize_clusters(
        (
            make_cluster(
                "family_a",
                make_application(
                    "vulnerable_a",
                    GroundTruth.VULNERABLE,
                    candidate,
                ),
                make_application(
                    "safe_a",
                    GroundTruth.NON_VULNERABLE,
                    negative,
                ),
            ),
            make_cluster(
                "family_b",
                make_application(
                    "vulnerable_b",
                    GroundTruth.VULNERABLE,
                    negative,
                ),
                make_application(
                    "mimic_b",
                    GroundTruth.NON_VULNERABLE,
                    candidate,
                ),
            ),
            make_cluster(
                "family_c",
                make_application(
                    "safe_c",
                    GroundTruth.NON_VULNERABLE,
                    negative,
                ),
            ),
        )
    )


def test_hierarchy_preserves_run_application_cluster_counts():
    result = benchmark()

    assert result.cluster_count == 3
    assert result.application_count == 5
    assert result.run_count == 10

    apps = result.application_benchmark

    assert apps.application_count == 5
    assert apps.run_count == 10
    assert apps.vulnerable_count == 2
    assert apps.non_vulnerable_count == 3

    assert result.meets_repetition_policy
    assert result.under_replicated_applications == ()


def test_cluster_balanced_sensitivity():
    result = benchmark()
    rate = result.cluster_rate("candidate_sensitivity")

    assert rate is not None
    assert rate.contributing_clusters == 2
    assert rate.values == (
        ("family_a", 1.0),
        ("family_b", 0.0),
    )
    assert rate.estimate == 0.5
    assert rate.leave_one_out_range == (0.0, 1.0)

    assert result.application_benchmark.candidate_sensitivity == 0.5


def test_cluster_balanced_false_candidate_rate():
    result = benchmark()
    rate = result.cluster_rate("false_candidate_rate")

    assert rate is not None
    assert rate.contributing_clusters == 3
    assert rate.estimate == pytest.approx(1 / 3)
    assert rate.leave_one_out_range == pytest.approx((0.0, 0.5))

    assert result.application_benchmark.false_candidate_rate == (pytest.approx(1 / 3))


def test_cluster_equal_weight_differs_from_application_weight():
    candidate = (TimeAnalysisStatus.CANDIDATE,) * 2
    negative = (TimeAnalysisStatus.NOT_CONFIRMED,) * 2

    clustered = summarize_clusters(
        (
            make_cluster(
                "large_family",
                *(
                    make_application(
                        f"mimic_{index}",
                        GroundTruth.NON_VULNERABLE,
                        candidate,
                    )
                    for index in range(9)
                ),
            ),
            make_cluster(
                "small_family",
                make_application(
                    "safe",
                    GroundTruth.NON_VULNERABLE,
                    negative,
                ),
            ),
        )
    )

    assert clustered.application_benchmark.false_candidate_rate == 0.9

    rate = clustered.cluster_rate("false_candidate_rate")

    assert rate is not None
    assert rate.estimate == 0.5
    assert rate.contributing_clusters == 2
    assert rate.leave_one_out_range == (0.0, 1.0)


def test_zero_ground_truth_denominator_is_not_imputed():
    negative = (TimeAnalysisStatus.NOT_CONFIRMED,) * 2

    result = summarize_clusters(
        (
            make_cluster(
                "safe_only",
                make_application(
                    "safe",
                    GroundTruth.NON_VULNERABLE,
                    negative,
                ),
            ),
        )
    )

    assert result.cluster_rate("candidate_sensitivity") is None

    rate = result.cluster_rate("false_candidate_rate")

    assert rate is not None
    assert rate.contributing_clusters == 1
    assert rate.estimate == 0
    assert rate.leave_one_out_range is None


def test_minimum_repetition_policy_is_reported_not_hidden():
    candidate = (TimeAnalysisStatus.CANDIDATE,) * 2
    negative = (TimeAnalysisStatus.NOT_CONFIRMED,)

    result = summarize_clusters(
        (
            make_cluster(
                "family",
                make_application(
                    "enough",
                    GroundTruth.VULNERABLE,
                    candidate,
                ),
                make_application(
                    "too_few",
                    GroundTruth.NON_VULNERABLE,
                    negative,
                ),
            ),
        ),
        minimum_repetitions=2,
    )

    assert not result.meets_repetition_policy
    assert result.under_replicated_applications == ("too_few",)
    assert result.application_count == 2
    assert result.run_count == 3

    rate = result.cluster_rate("candidate_sensitivity")
    assert rate is not None
    assert rate.estimate == 1


def test_minimum_repetitions_can_be_one():
    result = summarize_clusters(
        (
            make_cluster(
                "family",
                make_application(
                    "one",
                    GroundTruth.NON_VULNERABLE,
                    (TimeAnalysisStatus.NOT_CONFIRMED,),
                ),
            ),
        ),
        minimum_repetitions=1,
    )

    assert result.meets_repetition_policy


def test_maximum_repetition_policy_boundary():
    full = make_application(
        "full",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,) * 100,
    )
    short = make_application(
        "short",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,) * 99,
    )

    result = summarize_clusters(
        (make_cluster("family", full, short),),
        minimum_repetitions=100,
    )

    assert result.run_count == 199
    assert result.under_replicated_applications == ("short",)
    assert not result.meets_repetition_policy
    assert result.application_benchmark.application_count == 2


def test_mixed_and_partial_execution_errors_are_preserved():
    app = make_application(
        "mixed",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.CANDIDATE, None),
    )
    result = summarize_clusters((make_cluster("family", app),))

    assert app.outcome is ApplicationOutcome.MIXED
    assert result.execution_error_run_count == 1
    assert result.application_benchmark.execution_error_run_count == 1
    assert result.application_benchmark.mixed_case_rate == 1


def test_strata_preserve_every_application():
    result = benchmark()

    for dimension in ("framework", "dbms", "sql_context"):
        grouped = result.strata(dimension)
        identifiers = [
            app.application_id for _, group in grouped for app in group.applications
        ]

        assert len(identifiers) == result.application_count
        assert len(set(identifiers)) == result.application_count


def test_duplicate_application_across_clusters_is_rejected():
    app = make_application(
        "shared",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="Duplicate"):
        summarize_clusters(
            (
                make_cluster("first", app),
                make_cluster("second", app),
            )
        )


def test_duplicate_cluster_id_is_rejected():
    app_a = make_application(
        "a",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )
    app_b = make_application(
        "b",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="ordering"):
        summarize_clusters(
            (
                make_cluster("same", app_a),
                make_cluster("same", app_b),
            )
        )


def test_direct_construction_rejects_unsorted_clusters():
    current = benchmark()

    with pytest.raises(ValueError, match="ordering"):
        replace(
            current,
            clusters=tuple(reversed(current.clusters)),
        )


def test_unsorted_applications_inside_cluster_are_rejected():
    current = benchmark()
    first = current.clusters[0]

    with pytest.raises(ValueError, match="ordering"):
        replace(
            first,
            applications=tuple(reversed(first.applications)),
        )


@pytest.mark.parametrize(
    "identifier",
    ("", "has space", "path/value", "日本語", "x" * 101, True),
)
def test_invalid_cluster_identifier(identifier):
    app = make_application(
        "valid",
        GroundTruth.NON_VULNERABLE,
        (TimeAnalysisStatus.NOT_CONFIRMED,),
    )

    with pytest.raises(ValueError, match="identifier"):
        ClusterUnit(
            cluster_id=identifier,
            applications=(app,),
        )


@pytest.mark.parametrize(
    "minimum",
    (0, 101, True, 1.5, -1),
)
def test_invalid_minimum_repetitions(minimum):
    current = benchmark()

    with pytest.raises(ValueError, match="repetition"):
        replace(current, minimum_repetitions=minimum)


def test_invalid_metric_is_rejected():
    with pytest.raises(ValueError, match="metric"):
        benchmark().cluster_rate("verdict")


def test_cluster_rate_rejects_inconsistent_values():
    rate = benchmark().cluster_rate("false_candidate_rate")
    assert rate is not None

    with pytest.raises(ValueError, match="value"):
        replace(rate, values=(("family_a", float("nan")),))

    with pytest.raises(TypeError, match="value"):
        replace(rate, values=(("family_a", True),))

    with pytest.raises(ValueError, match="Inconsistent"):
        replace(rate, values=(("family_a", 0.0),))

    with pytest.raises(ValueError, match="Inconsistent"):
        replace(rate, metric="candidate_sensitivity")


def test_cluster_rate_rejects_duplicate_ids():
    rate = benchmark().cluster_rate("classification_coverage")
    assert rate is not None

    with pytest.raises(ValueError, match="ordering"):
        replace(
            rate,
            values=(
                ("family", 0.5),
                ("family", 0.5),
            ),
        )


def test_cluster_rate_requires_validated_cluster_provenance():
    rate = benchmark().cluster_rate("false_candidate_rate")
    assert rate is not None

    with pytest.raises(ValueError, match="provenance"):
        replace(rate, clusters=())
    with pytest.raises(TypeError, match="provenance"):
        replace(rate, clusters=(object(),))
    with pytest.raises(ValueError, match="provenance ordering"):
        replace(rate, clusters=tuple(reversed(rate.clusters)))


def test_empty_cluster_is_rejected():
    with pytest.raises(ValueError, match="collection"):
        ClusterUnit(
            cluster_id="empty",
            applications=(),
        )


def test_cluster_rejects_invalid_application_collection():
    current = benchmark().clusters[0]

    with pytest.raises(ValueError, match="collection"):
        replace(current, applications=[])
    with pytest.raises(TypeError, match="application type"):
        replace(current, applications=(object(),))


def test_benchmark_rejects_invalid_cluster_collection():
    current = benchmark()

    with pytest.raises(ValueError, match="collection"):
        replace(current, clusters=[])
    with pytest.raises(TypeError, match="cluster type"):
        replace(current, clusters=(object(),))


def test_empty_benchmark_is_rejected():
    with pytest.raises(ValueError, match="collection"):
        summarize_clusters(())


def test_maximum_application_boundary():
    apps = tuple(
        make_application(
            f"app_{index:03d}",
            GroundTruth.NON_VULNERABLE,
            (TimeAnalysisStatus.NOT_CONFIRMED,),
        )
        for index in range(100)
    )

    result = summarize_clusters(
        (
            make_cluster("family_a", *apps[:50]),
            make_cluster("family_b", *apps[50:]),
        ),
        minimum_repetitions=1,
    )

    assert result.application_count == 100
    assert result.cluster_count == 2


def test_more_than_one_hundred_applications_rejected():
    apps = tuple(
        make_application(
            f"app_{index:03d}",
            GroundTruth.NON_VULNERABLE,
            (TimeAnalysisStatus.NOT_CONFIRMED,),
        )
        for index in range(101)
    )

    with pytest.raises(ValueError, match="excessive"):
        summarize_clusters(
            (
                make_cluster("family_a", *apps[:50]),
                make_cluster("family_b", *apps[50:]),
            ),
            minimum_repetitions=1,
        )


def test_no_raw_requests_are_retained():
    result = benchmark()

    for name in (
        "url",
        "payload",
        "authorization",
        "cookie",
        "response_body",
        "request_template",
    ):
        assert not hasattr(result, name)

    rate = result.cluster_rate("false_candidate_rate")
    assert rate is not None
    representation = repr(rate)
    assert "application" not in representation
    assert "sample" not in representation
