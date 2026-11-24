"""Contract tests for bounded Boolean SQLi decision facts."""

import pytest

from vintar.checks.sqli.confirmation import ConfirmationKind
from vintar.checks.sqli.decision_facts import (
    ConfirmationRelation,
    ConfirmationRelationDecisionFacts,
    DecisionStage,
    OperationalCondition,
    OperationalDecisionFacts,
    PairLocalization,
    PredicatePair,
    ResponseDynamicsDecisionFacts,
    TimeOperationalCondition,
    TimingDynamicsDecisionFacts,
    TimingInstabilityCause,
    UnstablePairFacts,
)
from vintar.checks.sqli.models import ProbeError, ProbeKind
from vintar.checks.sqli.time_plan import TimeProbeKind


def test_operational_facts_reject_reason_stage_condition_and_status_mismatches():
    with pytest.raises(ValueError, match="supported operational reason"):
        OperationalDecisionFacts(
            "unknown_reason",
            DecisionStage.INITIAL,
            1,
            ProbeKind.BASELINE,
            OperationalCondition.BUDGET_UNAVAILABLE,
        )
    with pytest.raises(ValueError, match="contradict"):
        OperationalDecisionFacts(
            "budget_unavailable",
            DecisionStage.CONFIRMATION,
            1,
            ConfirmationKind.BASELINE,
            OperationalCondition.BUDGET_UNAVAILABLE,
        )
    with pytest.raises(ValueError, match="1 through 18"):
        OperationalDecisionFacts(
            "probe_failed",
            DecisionStage.INITIAL,
            0,
            ProbeKind.BASELINE,
            ProbeError.TIMEOUT,
        )
    with pytest.raises(ValueError, match="status code"):
        OperationalDecisionFacts(
            "rate_limited",
            DecisionStage.INITIAL,
            1,
            ProbeKind.BASELINE,
            OperationalCondition.RATE_LIMITED,
        )
    with pytest.raises(ValueError, match="429"):
        OperationalDecisionFacts(
            "rate_limited",
            DecisionStage.INITIAL,
            1,
            ProbeKind.BASELINE,
            OperationalCondition.RATE_LIMITED,
            503,
        )
    with pytest.raises(ValueError, match="must omit"):
        OperationalDecisionFacts(
            "probe_failed",
            DecisionStage.INITIAL,
            1,
            ProbeKind.BASELINE,
            ProbeError.TIMEOUT,
            500,
        )


def test_unstable_pair_localization_is_all_or_nothing():
    with pytest.raises(ValueError, match="require nonnegative"):
        UnstablePairFacts(
            ProbeKind.BASELINE,
            PairLocalization.LOCALIZED,
            prefix_size=8,
        )
    with pytest.raises(ValueError, match="must omit"):
        UnstablePairFacts(
            ProbeKind.BASELINE,
            PairLocalization.UNLOCALIZED,
            prefix_size=8,
        )


def test_response_dynamics_facts_reject_inconsistent_reason_and_normalization():
    pair = UnstablePairFacts(ProbeKind.BASELINE, PairLocalization.UNLOCALIZED)
    with pytest.raises(ValueError, match="response-dynamics reason"):
        ResponseDynamicsDecisionFacts("unexpected_difference", False, 0, (pair,))
    with pytest.raises(ValueError, match="flag and echo count"):
        ResponseDynamicsDecisionFacts("unstable_response", True, 0, (pair,))
    with pytest.raises(ValueError, match="localized region"):
        ResponseDynamicsDecisionFacts("possible_dynamic_response", False, 0, (pair,))


@pytest.mark.parametrize(
    "facts",
    [
        ConfirmationRelationDecisionFacts(
            "confirmation_unstable",
            unstable_repeat_kinds=(ConfirmationKind.TRUE_1,),
        ),
        ConfirmationRelationDecisionFacts(
            "confirmation_unstable",
            unreproduced_predicate_pairs=(PredicatePair.FALSE,),
        ),
        ConfirmationRelationDecisionFacts(
            "candidate_confirmation_mismatch",
            mismatched_relations=(ConfirmationRelation.BASELINE_CONTROL,),
        ),
        ConfirmationRelationDecisionFacts(
            "confirmation_cross_phase_mismatch",
            cross_phase_mismatched_kinds=(ProbeKind.TRUE,),
        ),
    ],
)
def test_confirmation_relation_fact_shapes_are_valid(facts):
    assert facts.reason_code


def test_confirmation_relation_facts_reject_empty_or_mislabeled_shapes():
    with pytest.raises(ValueError, match="contradict"):
        ConfirmationRelationDecisionFacts("confirmation_unstable")
    with pytest.raises(ValueError, match="contradict"):
        ConfirmationRelationDecisionFacts(
            "candidate_confirmation_mismatch",
            unreproduced_predicate_pairs=(PredicatePair.TRUE,),
        )
    with pytest.raises(ValueError, match="deterministic order"):
        ConfirmationRelationDecisionFacts(
            "confirmation_cross_phase_mismatch",
            cross_phase_mismatched_kinds=(ProbeKind.FALSE, ProbeKind.BASELINE),
        )


def test_time_operational_facts_reject_reason_condition_and_kind_mismatches():
    with pytest.raises(ValueError, match="contradict"):
        OperationalDecisionFacts(
            "probe_timeout",
            DecisionStage.TIME,
            1,
            TimeProbeKind.BASELINE,
            TimeOperationalCondition.REQUEST_FAILED,
        )
    with pytest.raises(TypeError, match="probe kind"):
        OperationalDecisionFacts(
            "probe_timeout",
            DecisionStage.TIME,
            1,
            ProbeKind.BASELINE,
            TimeOperationalCondition.TIMEOUT,
        )


def test_timing_dynamics_facts_reject_inconsistent_reason_shapes():
    with pytest.raises(ValueError, match="require causes"):
        TimingDynamicsDecisionFacts("unstable_timing")
    with pytest.raises(ValueError, match="three boolean"):
        TimingDynamicsDecisionFacts("ambiguous_timing")
    with pytest.raises(ValueError, match="contradict"):
        TimingDynamicsDecisionFacts(
            "ambiguous_timing",
            candidate_median_met=True,
            candidate_margin_met=True,
            no_delay_condition_met=False,
        )
    with pytest.raises(ValueError, match="deterministic order"):
        TimingDynamicsDecisionFacts(
            "unstable_timing",
            instability_causes=(
                TimingInstabilityCause.DELAY_SPAN,
                TimingInstabilityCause.BASELINE_SPAN,
            ),
        )
