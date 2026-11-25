"""Regression tests for experimental SQLi timing analysis."""

from dataclasses import FrozenInstanceError, replace

import pytest

from vintar.checks.sqli.decision_facts import (
    TimingDynamicsDecisionFacts,
    TimingInstabilityCause,
)
from vintar.checks.sqli.time_analyzer import (
    TimeAnalysisStatus,
    TimeDecisionInputs,
    TimeObservation,
    TimeProbeOutcome,
    TimeResponseSignature,
    analyze_time_probes,
    classify_time_decision_inputs,
    time_operational_decision_facts,
    time_response_signature,
)
from vintar.checks.sqli.time_plan import (
    TIME_PROBE_ORDER,
    TimePayloads,
    prepare_time_plan,
)
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy


def make_plan(expected_delay: float = 1.0):
    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset(
                {
                    AllowedOrigin(
                        "http",
                        "127.0.0.1",
                        18083,
                    )
                }
            )
        ),
        budget=RequestBudget(9),
        timeout=5.0,
        rate_limiter=RateLimiter(requests_per_second=5.0),
    )

    return prepare_time_plan(
        template=RequestTemplate(
            method="GET",
            url="http://127.0.0.1:18083/products",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=TimePayloads(
            delay="_delayed",
            control="_control",
        ),
        expected_delay_seconds=expected_delay,
        context=context,
    )


def make_observations(
    *,
    baseline=(0.10, 0.11, 0.12),
    control=(0.11, 0.12, 0.13),
    delay=(1.11, 1.12, 1.13),
    rate_wait=0.0,
):
    groups = {
        "baseline": iter(baseline),
        "control": iter(control),
        "delay": iter(delay),
    }

    result = []

    for sequence, kind in enumerate(
        TIME_PROBE_ORDER,
        start=1,
    ):
        elapsed = next(groups[kind.value])

        result.append(
            TimeObservation(
                kind=kind,
                sequence=sequence,
                outcome=TimeProbeOutcome.COMPLETED,
                elapsed_seconds=elapsed,
                status_code=200,
                rate_wait_seconds=rate_wait,
            )
        )

    return tuple(result)


@pytest.mark.parametrize(
    ("inputs", "status", "reason"),
    [
        (
            TimeDecisionInputs(False, False, False, False, False, True, True, False),
            TimeAnalysisStatus.CANDIDATE,
            "timing_pattern_matched",
        ),
        (
            TimeDecisionInputs(False, False, False, False, False, False, False, True),
            TimeAnalysisStatus.NOT_CONFIRMED,
            "timing_pattern_not_matched",
        ),
        (
            TimeDecisionInputs(True, False, False, False, False, True, True, False),
            TimeAnalysisStatus.INCONCLUSIVE,
            "unstable_timing",
        ),
        (
            TimeDecisionInputs(False, False, False, False, False, True, False, False),
            TimeAnalysisStatus.INCONCLUSIVE,
            "ambiguous_timing",
        ),
    ],
)
def test_pure_time_classifier_covers_fixed_decision_precedence(inputs, status, reason):
    actual_status, actual_reason, _ = classify_time_decision_inputs(inputs)

    assert (actual_status, actual_reason) == (status, reason)


def test_time_analyzer_delegates_to_boolean_predicates():
    observations = make_observations()
    analysis = analyze_time_probes(plan=make_plan(), observations=observations)
    direct = classify_time_decision_inputs(
        TimeDecisionInputs(False, False, False, False, False, True, True, False)
    )

    assert (analysis.status, analysis.reason_code, analysis.decision_facts) == direct


def run_analysis(**kwargs):
    return analyze_time_probes(
        plan=make_plan(),
        observations=make_observations(**kwargs),
    )


def test_clear_delay_is_candidate():
    result = run_analysis()

    assert result.status is TimeAnalysisStatus.CANDIDATE
    assert result.reason_code == "timing_pattern_matched"
    assert result.request_count == 9
    assert result.evidence is not None

    assert result.evidence.baseline_median == pytest.approx(0.11)
    assert result.evidence.control_median == pytest.approx(0.12)
    assert result.evidence.delay_median == pytest.approx(1.12)
    assert result.evidence.median_excess == pytest.approx(1.0)


def test_no_delay_is_not_confirmed():
    result = run_analysis(delay=(0.12, 0.13, 0.14))

    assert result.status is TimeAnalysisStatus.NOT_CONFIRMED
    assert result.reason_code == "timing_pattern_not_matched"


def test_stable_high_latency_is_not_a_candidate():
    result = run_analysis(
        baseline=(2.0, 2.01, 2.02),
        control=(2.01, 2.02, 2.03),
        delay=(2.02, 2.03, 2.04),
    )

    assert result.status is TimeAnalysisStatus.NOT_CONFIRMED


def test_high_latency_with_conditional_delay_is_candidate():
    result = run_analysis(
        baseline=(2.0, 2.01, 2.02),
        control=(2.01, 2.02, 2.03),
        delay=(3.01, 3.02, 3.03),
    )

    assert result.status is TimeAnalysisStatus.CANDIDATE


def test_non_sql_delay_mimic_can_still_be_candidate():
    # The analyzer observes timing only, not SQL execution.
    result = run_analysis()

    assert result.status is TimeAnalysisStatus.CANDIDATE
    assert result.evidence is not None


def test_control_instability_is_inconclusive():
    result = run_analysis(
        control=(0.10, 0.50, 0.12),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "unstable_timing"


@pytest.mark.parametrize(
    ("observations", "expected_cause"),
    [
        (
            {"baseline": (0.10, 0.40, 0.10)},
            TimingInstabilityCause.BASELINE_SPAN,
        ),
        (
            {"control": (0.10, 0.40, 0.10)},
            TimingInstabilityCause.CONTROL_SPAN,
        ),
        (
            {
                "baseline": (0.10, 0.10, 0.10),
                "control": (0.40, 0.40, 0.40),
            },
            TimingInstabilityCause.BASELINE_CONTROL_DIFFERENCE,
        ),
        (
            {"baseline": (0.10, 0.20, 0.40)},
            TimingInstabilityCause.DRIFT,
        ),
        (
            {
                "baseline": (0.10, 0.10, 0.10),
                "control": (0.10, 0.10, 0.10),
                "delay": (0.10, 0.10, 2.00),
            },
            TimingInstabilityCause.DELAY_SPAN,
        ),
    ],
)
def test_each_timing_instability_cause_is_reported_alone(observations, expected_cause):
    result = run_analysis(**observations)

    assert isinstance(result.decision_facts, TimingDynamicsDecisionFacts)
    assert result.decision_facts.instability_causes == (expected_cause,)


def test_multiple_timing_instability_causes_use_deterministic_order():
    result = run_analysis(
        baseline=(0.10, 0.50, 0.10),
        control=(0.40, 0.80, 0.40),
        delay=(0.10, 0.10, 2.00),
    )

    assert isinstance(result.decision_facts, TimingDynamicsDecisionFacts)
    assert result.decision_facts.instability_causes == (
        TimingInstabilityCause.BASELINE_SPAN,
        TimingInstabilityCause.CONTROL_SPAN,
        TimingInstabilityCause.BASELINE_CONTROL_DIFFERENCE,
        TimingInstabilityCause.DELAY_SPAN,
    )


@pytest.mark.parametrize(
    "delay",
    [
        (1.20, 2.00, 3.10),
        (3.10, 1.20, 2.00),
        (2.00, 3.10, 1.20),
    ],
)
def test_separated_delay_variance_stays_candidate(delay):
    result = run_analysis(
        delay=delay,
    )

    assert result.status is TimeAnalysisStatus.CANDIDATE
    assert result.reason_code == "timing_pattern_matched"
    assert result.evidence is not None
    assert result.evidence.delay_span == pytest.approx(1.90)


def test_loaded_cpu_bound_delay_shape_is_candidate():
    result = run_analysis(
        baseline=(0.010, 0.014, 0.019),
        control=(0.012, 0.016, 0.021),
        delay=(1.180, 1.795, 2.075),
    )

    assert result.status is TimeAnalysisStatus.CANDIDATE
    assert result.reason_code == "timing_pattern_matched"
    assert result.evidence is not None
    assert result.evidence.delay_span == pytest.approx(0.895)


@pytest.mark.parametrize(
    "delay",
    [
        (0.10, 0.10, 2.00),
        (0.10, 0.60, 1.00),
        (0.10, 0.85, 0.85),
    ],
)
def test_non_candidate_delay_variance_never_concludes_absence(delay):
    result = run_analysis(
        baseline=(0.10, 0.10, 0.10),
        control=(0.10, 0.10, 0.10),
        delay=delay,
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "unstable_timing"


@pytest.mark.parametrize(
    ("maximum_delay", "expected_status", "expected_reason"),
    [
        (
            0.35,
            TimeAnalysisStatus.NOT_CONFIRMED,
            "timing_pattern_not_matched",
        ),
        (
            0.351,
            TimeAnalysisStatus.INCONCLUSIVE,
            "unstable_timing",
        ),
    ],
)
def test_delay_stability_boundary_before_negative_verdict(
    maximum_delay,
    expected_status,
    expected_reason,
):
    result = run_analysis(
        baseline=(0.10, 0.10, 0.10),
        control=(0.10, 0.10, 0.10),
        delay=(0.10, 0.10, maximum_delay),
    )

    assert result.status is expected_status
    assert result.reason_code == expected_reason


def test_baseline_control_difference_is_inconclusive():
    result = run_analysis(
        baseline=(0.1, 0.11, 0.12),
        control=(0.5, 0.51, 0.52),
        delay=(1.5, 1.51, 1.52),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "unstable_timing"


def test_gradual_drift_is_inconclusive():
    result = run_analysis(
        baseline=(0.10, 0.23, 0.40),
        control=(0.11, 0.24, 0.41),
        delay=(1.11, 1.24, 1.41),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "unstable_timing"


def test_intermediate_delay_is_ambiguous():
    result = run_analysis(
        delay=(0.60, 0.61, 0.62),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "ambiguous_timing"
    assert result.evidence is not None
    assert isinstance(result.decision_facts, TimingDynamicsDecisionFacts)
    assert (
        result.decision_facts.candidate_median_met,
        result.decision_facts.candidate_margin_met,
        result.decision_facts.no_delay_condition_met,
    ) == (False, False, False)


def test_stable_delay_span_with_insufficient_margin_is_ambiguous():
    result = run_analysis(
        baseline=(0.10, 0.10, 0.10),
        control=(0.10, 0.10, 0.20),
        delay=(0.69, 0.85, 0.85),
    )

    assert result.evidence is not None
    assert result.evidence.median_excess == pytest.approx(0.75)
    assert result.evidence.minimum_delay_margin == pytest.approx(0.49)
    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "ambiguous_timing"
    assert isinstance(result.decision_facts, TimingDynamicsDecisionFacts)
    assert (
        result.decision_facts.candidate_median_met,
        result.decision_facts.candidate_margin_met,
        result.decision_facts.no_delay_condition_met,
    ) == (True, False, False)


@pytest.mark.parametrize(
    ("delay", "expected_status", "expected_reason"),
    [
        (
            (0.60, 0.85, 0.85),
            TimeAnalysisStatus.CANDIDATE,
            "timing_pattern_matched",
        ),
        (
            (0.599, 0.85, 0.85),
            TimeAnalysisStatus.INCONCLUSIVE,
            "unstable_timing",
        ),
        (
            (0.60, 0.849, 0.849),
            TimeAnalysisStatus.INCONCLUSIVE,
            "ambiguous_timing",
        ),
    ],
)
def test_candidate_threshold_and_margin_boundaries(
    delay,
    expected_status,
    expected_reason,
):
    result = run_analysis(
        baseline=(0.10, 0.10, 0.10),
        control=(0.10, 0.10, 0.10),
        delay=delay,
    )

    assert result.status is expected_status
    assert result.reason_code == expected_reason
    if expected_reason == "ambiguous_timing":
        assert isinstance(result.decision_facts, TimingDynamicsDecisionFacts)
        assert (
            result.decision_facts.candidate_median_met,
            result.decision_facts.candidate_margin_met,
            result.decision_facts.no_delay_condition_met,
        ) == (False, True, False)


def test_exact_no_delay_threshold_is_not_confirmed():
    result = run_analysis(
        baseline=(0.10, 0.10, 0.10),
        control=(0.10, 0.10, 0.10),
        delay=(0.35, 0.35, 0.35),
    )

    assert result.status is TimeAnalysisStatus.NOT_CONFIRMED


def test_exact_stability_threshold_is_not_unstable():
    result = run_analysis(
        baseline=(0.10, 0.16, 0.22),
        control=(0.10, 0.16, 0.22),
        delay=(0.85, 0.91, 0.97),
    )

    assert result.status is TimeAnalysisStatus.CANDIDATE


@pytest.mark.parametrize(
    ("baseline", "control"),
    [
        ((0.10, 0.40, 0.12), (0.10, 0.11, 0.12)),
        ((0.10, 0.11, 0.12), (0.10, 0.40, 0.12)),
        ((0.10, 0.11, 0.50), (0.10, 0.11, 0.12)),
        ((0.10, 0.11, 0.12), (0.10, 0.11, 0.50)),
    ],
)
def test_baseline_or_control_instability_precedes_huge_delay(
    baseline,
    control,
):
    result = run_analysis(
        baseline=baseline,
        control=control,
        delay=(2.00, 3.00, 4.00),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "unstable_timing"


def test_rate_limiter_wait_is_not_treated_as_response_delay():
    result = run_analysis(
        delay=(0.12, 0.13, 0.14),
        rate_wait=3.0,
    )

    assert result.status is TimeAnalysisStatus.NOT_CONFIRMED


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (TimeProbeOutcome.TIMEOUT, "probe_timeout"),
        (TimeProbeOutcome.REQUEST_FAILED, "probe_failed"),
        (TimeProbeOutcome.INTERRUPTED, "probe_interrupted"),
    ],
)
def test_failed_probe_is_inconclusive(outcome, reason):
    observations = list(make_observations()[:4])
    observations[-1] = replace(
        observations[-1],
        outcome=outcome,
        elapsed_seconds=None,
        status_code=None,
    )

    result = analyze_time_probes(
        plan=make_plan(),
        observations=tuple(observations),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == reason
    assert result.evidence is None
    assert result.request_count == 4


def test_timeout_is_not_timing_evidence():
    observations = list(make_observations())
    observations[-1] = replace(
        observations[-1],
        outcome=TimeProbeOutcome.TIMEOUT,
        elapsed_seconds=None,
        status_code=None,
    )

    result = analyze_time_probes(
        plan=make_plan(),
        observations=tuple(observations),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "probe_timeout"
    assert result.evidence is None


@pytest.mark.parametrize(
    ("status_code", "reason"),
    [
        (429, "rate_limited"),
        (403, "non_success_status"),
        (302, "non_success_status"),
        (500, "non_success_status"),
    ],
)
def test_unsafe_http_status_is_inconclusive(
    status_code,
    reason,
):
    observations = list(make_observations()[:3])
    observations[-1] = replace(
        observations[-1],
        status_code=status_code,
    )

    result = analyze_time_probes(
        plan=make_plan(),
        observations=tuple(observations),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == reason
    assert result.evidence is None


def test_truncated_response_is_inconclusive():
    observations = list(make_observations()[:3])
    observations[-1] = replace(
        observations[-1],
        truncated=True,
    )

    result = analyze_time_probes(
        plan=make_plan(),
        observations=tuple(observations),
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "truncated_response"


@pytest.mark.parametrize(
    ("status_code", "truncated"),
    [
        (429, False),
        (403, False),
        (302, False),
        (500, False),
        (200, True),
    ],
)
def test_observations_cannot_continue_after_http_stop(status_code, truncated):
    observations = list(make_observations())
    observations[2] = replace(
        observations[2],
        status_code=status_code,
        truncated=truncated,
    )

    with pytest.raises(ValueError, match="continued"):
        analyze_time_probes(
            plan=make_plan(),
            observations=tuple(observations),
        )


def test_rate_limit_reason_takes_priority_over_truncation():
    observations = list(make_observations()[:3])
    observations[-1] = replace(
        observations[-1],
        status_code=429,
        truncated=True,
    )

    result = analyze_time_probes(
        plan=make_plan(),
        observations=tuple(observations),
    )

    assert result.reason_code == "rate_limited"


def test_incomplete_successful_probes_are_inconclusive():
    result = analyze_time_probes(
        plan=make_plan(),
        observations=make_observations()[:5],
    )

    assert result.status is TimeAnalysisStatus.INCONCLUSIVE
    assert result.reason_code == "incomplete_probes"
    assert result.evidence is None
    assert result.request_count == 5


def test_out_of_order_probes_are_rejected():
    observations = list(make_observations())
    observations[0], observations[1] = (
        observations[1],
        observations[0],
    )

    with pytest.raises(ValueError, match="order"):
        analyze_time_probes(
            plan=make_plan(),
            observations=tuple(observations),
        )


def test_duplicate_probe_sequence_is_rejected():
    observations = list(make_observations())
    observations[1] = replace(
        observations[1],
        sequence=1,
    )

    with pytest.raises(ValueError, match="order"):
        analyze_time_probes(
            plan=make_plan(),
            observations=tuple(observations),
        )


def test_observations_cannot_continue_after_failure():
    observations = list(make_observations())
    observations[2] = replace(
        observations[2],
        outcome=TimeProbeOutcome.TIMEOUT,
        elapsed_seconds=None,
        status_code=None,
    )

    with pytest.raises(ValueError, match="continued"):
        analyze_time_probes(
            plan=make_plan(),
            observations=tuple(observations),
        )


@pytest.mark.parametrize(
    "elapsed",
    [
        -1,
        float("nan"),
        float("inf"),
        True,
        10**1000,
    ],
)
def test_invalid_elapsed_is_rejected(elapsed):
    observation = make_observations()[0]

    with pytest.raises((TypeError, ValueError)):
        replace(
            observation,
            elapsed_seconds=elapsed,
        )


@pytest.mark.parametrize(
    "rate_wait",
    [
        -1.0,
        float("nan"),
        float("inf"),
        True,
        10**1000,
    ],
)
def test_invalid_rate_wait_is_rejected(rate_wait):
    observation = make_observations()[0]

    with pytest.raises((TypeError, ValueError)):
        replace(
            observation,
            rate_wait_seconds=rate_wait,
        )


class IntSubclass(int):
    pass


class FloatSubclass(float):
    pass


@pytest.mark.parametrize("field", ["elapsed_seconds", "rate_wait_seconds"])
@pytest.mark.parametrize(
    "value",
    [True, IntSubclass(1), FloatSubclass(0.25)],
    ids=["bool", "int-subclass", "float-subclass"],
)
def test_timing_measurements_require_exact_builtin_numbers(field, value):
    with pytest.raises(TypeError, match="Invalid timing measurement"):
        replace(make_observations()[0], **{field: value})


def test_non_numeric_status_is_rejected():
    observation = make_observations()[0]

    with pytest.raises(TypeError):
        replace(
            observation,
            status_code="200",
        )


def test_failure_cannot_contain_completed_response_metadata():
    observation = make_observations()[0]

    with pytest.raises(ValueError):
        replace(
            observation,
            outcome=TimeProbeOutcome.TIMEOUT,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "baseline"),
        ("sequence", True),
        ("sequence", 0),
        ("sequence", 10),
        ("outcome", "completed"),
        ("truncated", 1),
        ("status_code", True),
        ("status_code", 99),
        ("status_code", 600),
        ("elapsed_seconds", None),
    ],
)
def test_observation_rejects_invalid_direct_fields(field, value):
    observation = make_observations()[0]

    with pytest.raises((TypeError, ValueError)):
        replace(observation, **{field: value})


def test_observation_is_immutable():
    observation = make_observations()[0]

    with pytest.raises(FrozenInstanceError):
        observation.elapsed_seconds = 2.0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("baseline_median", True),
        ("baseline_median", -1.0),
        ("baseline_median", float("nan")),
        ("baseline_median", float("inf")),
        ("baseline_median", 10**1000),
        ("median_excess", -(10**1000)),
    ],
)
def test_evidence_rejects_invalid_numeric_values(field, value):
    evidence = run_analysis().evidence
    assert evidence is not None

    with pytest.raises((TypeError, ValueError)):
        replace(evidence, **{field: value})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("median_excess", 0.5),
        ("baseline_control_difference", 0.5),
    ],
)
def test_evidence_rejects_inconsistent_derived_values(field, value):
    evidence = run_analysis().evidence
    assert evidence is not None

    with pytest.raises(ValueError, match="Inconsistent"):
        replace(evidence, **{field: value})


def test_evidence_is_immutable():
    evidence = run_analysis().evidence
    assert evidence is not None

    with pytest.raises(FrozenInstanceError):
        evidence.delay_median = 2.0


def test_analysis_rejects_inconsistent_status_reason():
    analysis = run_analysis()

    with pytest.raises(ValueError):
        replace(
            analysis,
            status=TimeAnalysisStatus.NOT_CONFIRMED,
        )


def test_analysis_rejects_classification_not_supported_by_evidence():
    analysis = run_analysis()

    with pytest.raises(ValueError, match="Classification"):
        replace(
            analysis,
            status=TimeAnalysisStatus.INCONCLUSIVE,
            reason_code="unstable_timing",
        )


@pytest.mark.parametrize(
    "expected_delay",
    [
        0.24,
        2.01,
        float("nan"),
        float("inf"),
        True,
        10**1000,
    ],
)
def test_analysis_rejects_invalid_expected_delay(expected_delay):
    analysis = run_analysis()

    with pytest.raises((TypeError, ValueError)):
        replace(analysis, expected_delay_seconds=expected_delay)


def test_analysis_rechecks_classification_when_expected_delay_changes():
    analysis = run_analysis()

    with pytest.raises(ValueError, match="Classification"):
        replace(analysis, expected_delay_seconds=2.0)


def test_completed_classification_requires_evidence():
    analysis = run_analysis()

    with pytest.raises(ValueError, match="Incomplete"):
        replace(
            analysis,
            evidence=None,
        )


def test_analysis_rejects_evidence_not_derived_from_observations():
    analysis = run_analysis()
    assert analysis.evidence is not None
    inconsistent = replace(
        analysis.evidence,
        delay_span=analysis.evidence.delay_span + 0.01,
    )

    with pytest.raises(ValueError, match="does not match"):
        replace(analysis, evidence=inconsistent)


def test_analysis_rejects_terminal_observation_as_candidate():
    analysis = run_analysis()
    observations = list(analysis.observations)
    observations[-1] = replace(
        observations[-1],
        outcome=TimeProbeOutcome.TIMEOUT,
        elapsed_seconds=None,
        status_code=None,
    )

    with pytest.raises(ValueError, match="terminal"):
        replace(analysis, observations=tuple(observations))


def test_analysis_rejects_invalid_observation_order_directly():
    analysis = run_analysis()
    observations = list(analysis.observations)
    observations[0], observations[1] = observations[1], observations[0]

    with pytest.raises(ValueError, match="order"):
        replace(analysis, observations=tuple(observations))


def test_analysis_is_immutable():
    analysis = run_analysis()

    with pytest.raises(FrozenInstanceError):
        analysis.status = TimeAnalysisStatus.INCONCLUSIVE


def test_no_response_bodies_or_payloads_are_retained():
    result = run_analysis()
    rendered = repr(result)

    assert "Pets" not in rendered
    assert "_delayed" not in rendered
    assert "_control" not in rendered

    for observation in result.observations:
        assert not hasattr(observation, "body")
        assert not hasattr(observation, "headers")
        assert not hasattr(observation, "cookies")


def test_analyzer_never_performs_http(monkeypatch):
    def reject_execution(*args, **kwargs):
        raise AssertionError("Analyzer must not execute HTTP.")

    monkeypatch.setattr(
        ExecutionContext,
        "execute",
        reject_execution,
    )

    result = run_analysis()

    assert result.status is TimeAnalysisStatus.CANDIDATE


def test_result_is_deterministic():
    results = [run_analysis() for _ in range(2)]

    assert results[0] == results[1]


@pytest.mark.parametrize(
    ("changes", "error", "field"),
    [
        ({"status_code": True}, ValueError, "Time response status"),
        ({"status_code": 99}, ValueError, "Time response status"),
        ({"truncated": 1}, TypeError, "Time truncation flag"),
        ({"body_size": True}, ValueError, "Time response size"),
        ({"body_size": -1}, ValueError, "Time response size"),
        ({"body_digest": None}, ValueError, "Time response digest"),
        ({"body_digest": "abc"}, ValueError, "Time response digest"),
        ({"body_digest": "z" * 64}, ValueError, "Time response digest"),
    ],
)
def test_time_response_signature_rejects_invalid_metadata(changes, error, field):
    signature = TimeResponseSignature(200, False, 0, "a" * 64)

    with pytest.raises(error) as caught:
        replace(signature, **changes)

    assert str(caught.value) == f"Invalid {field}. Use a completed runner response."


def test_timeout_cannot_supply_a_completed_response_signature():
    observation = TimeObservation(
        kind=TIME_PROBE_ORDER[0], sequence=1, outcome=TimeProbeOutcome.TIMEOUT
    )

    with pytest.raises(ValueError) as caught:
        time_response_signature(observation, body_size=0, body_digest="a" * 64)

    assert str(caught.value) == (
        "Time response signatures require a completed analyzer observation."
    )


@pytest.mark.parametrize(
    ("make_series", "error", "diagnostic"),
    [
        (list, TypeError, "Invalid time analysis observations."),
        (
            lambda series: (*series, series[-1]),
            ValueError,
            "Too many timing observations.",
        ),
        (lambda series: (None, *series[1:]), TypeError, "Invalid timing observation."),
    ],
)
def test_analyzer_rejects_invalid_synthetic_observation_series(
    make_series, error, diagnostic
):
    with pytest.raises(error) as caught:
        analyze_time_probes(
            plan=make_plan(), observations=make_series(make_observations())
        )

    assert str(caught.value) == diagnostic


@pytest.mark.parametrize(
    ("changes", "error", "diagnostic"),
    [
        ({"status": "inconclusive"}, TypeError, "Invalid timing analysis status."),
        ({"reason_code": None}, TypeError, "Invalid timing analysis reason."),
        (
            {"reason_code": "unknown"},
            ValueError,
            "Unsupported timing analysis reason. Use a reason declared in TIME_RESULT_RULES.",
        ),
        ({"observations": []}, TypeError, "Invalid timing observations."),
        ({"observations": (None,)}, TypeError, "Invalid timing observation."),
        ({"evidence": {}}, TypeError, "Invalid timing evidence."),
        ({"decision_facts": {}}, TypeError, "Invalid timing decision facts."),
    ],
)
def test_time_analysis_rejects_invalid_result_fields(changes, error, diagnostic):
    analysis = analyze_time_probes(plan=make_plan(), observations=())

    with pytest.raises(error) as caught:
        replace(analysis, **changes)

    assert str(caught.value) == diagnostic


@pytest.mark.parametrize(
    ("changes", "error", "diagnostic"),
    [
        ({"deadline": 1}, TypeError, "Time deadline fact selector must be a boolean."),
        (
            {"reason_code": "unknown"},
            ValueError,
            "Time operational facts require a terminal Time reason. Use the reason selected by the timing analyzer.",
        ),
    ],
)
def test_time_operational_facts_reject_invalid_inputs(changes, error, diagnostic):
    fields = {
        "reason_code": "probe_timeout",
        "sequence": 1,
        "probe_kind": TIME_PROBE_ORDER[0],
    }

    with pytest.raises(error) as caught:
        time_operational_decision_facts(**(fields | changes))

    assert str(caught.value) == diagnostic


@pytest.mark.parametrize(
    ("changes", "diagnostic"),
    [
        (
            {"sequence": 2},
            "Time operational facts do not identify the stopping plan position. Use the sequence and probe kind selected by the bounded runner.",
        ),
        (
            {"status_code": 503},
            "Time operational status facts contradict the stopping observation. Use the completed response status or omit it when no response exists.",
        ),
    ],
)
def test_time_analysis_rejects_inconsistent_stopping_facts(changes, diagnostic):
    observation = replace(make_observations()[0], status_code=502)
    analysis = analyze_time_probes(plan=make_plan(), observations=(observation,))
    assert analysis.reason_code == "non_success_status"
    assert analysis.decision_facts is not None

    with pytest.raises(ValueError) as caught:
        replace(analysis, decision_facts=replace(analysis.decision_facts, **changes))

    assert str(caught.value) == diagnostic
