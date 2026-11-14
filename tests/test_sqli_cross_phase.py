"""Pure cross-phase consistency tests."""

import hashlib
from dataclasses import replace

import pytest

from vintar.checks.sqli.confirmation import (
    CONFIRMATION_ORDER,
    ConfirmationKind,
)
from vintar.checks.sqli.confirmation_runner import (
    ConfirmationEvidence,
    ConfirmationObservation,
)
from vintar.checks.sqli.cross_phase import (
    CrossPhaseAssessment,
    CrossPhaseStatus,
    assess_cross_phase_consistency,
)
from vintar.checks.sqli.models import (
    BooleanEvidence,
    Observation,
    ProbeKind,
    Verdict,
    VerificationResult,
)


class DerivedVerificationResult(VerificationResult):
    pass


class DerivedConfirmationEvidence(ConfirmationEvidence):
    pass


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def initial_observation(
    kind: ProbeKind,
    body: bytes,
) -> Observation:
    return Observation(
        kind=kind,
        status_code=200,
        body_size=len(body),
        elapsed=0.01,
        body_digest=digest(body),
        truncated=False,
    )


def confirmation_observation(
    kind: ConfirmationKind,
    body: bytes,
    *,
    status_code: int = 200,
    body_size: int | None = None,
) -> ConfirmationObservation:
    return ConfirmationObservation(
        kind=kind,
        status_code=status_code,
        body_size=len(body) if body_size is None else body_size,
        body_digest=digest(body),
        truncated=False,
    )


def make_initial(
    *,
    baseline: bytes = b"A",
    true: bytes = b"A",
    false: bytes = b"B",
) -> VerificationResult:
    observations = tuple(
        initial_observation(kind, body)
        for kind, body in (
            (ProbeKind.BASELINE, baseline),
            (ProbeKind.BASELINE, baseline),
            (ProbeKind.TRUE, true),
            (ProbeKind.TRUE, true),
            (ProbeKind.FALSE, false),
            (ProbeKind.FALSE, false),
        )
    )

    return VerificationResult(
        check_id="cross-phase-test",
        verdict=Verdict.INCONCLUSIVE,
        observations=observations,
        request_count=6,
        reason_code="boolean_candidate",
        reason="Reproducible Boolean differential.",
        evidence=BooleanEvidence(
            baseline_true_similarity=1.0,
            baseline_false_similarity=0.0,
            true_false_similarity=0.0,
        ),
    )


def make_confirmation(
    *,
    baseline: bytes = b"A",
    true_1: bytes = b"A",
    false_1: bytes = b"B",
    true_2: bytes = b"A",
    false_2: bytes = b"B",
    control: bytes = b"B",
    overrides: dict[
        ConfirmationKind,
        tuple[int, int],
    ]
    | None = None,
) -> ConfirmationEvidence:
    overrides = overrides or {}
    bodies = {
        ConfirmationKind.BASELINE: baseline,
        ConfirmationKind.TRUE_1: true_1,
        ConfirmationKind.FALSE_1: false_1,
        ConfirmationKind.TRUE_2: true_2,
        ConfirmationKind.FALSE_2: false_2,
        ConfirmationKind.CONTROL: control,
    }

    observations = tuple(
        confirmation_observation(
            kind,
            bodies[kind],
            status_code=overrides.get(kind, (200, len(bodies[kind])))[0],
            body_size=overrides.get(kind, (200, len(bodies[kind])))[1],
        )
        for kind in CONFIRMATION_ORDER
    )

    pairs = {
        kind: tuple(item for item in observations if item.kind is kind)
        for kind in ConfirmationKind
    }

    def signature(item: ConfirmationObservation) -> tuple[int, int, str]:
        return item.status_code, item.body_size, item.body_digest

    baseline_signature = signature(pairs[ConfirmationKind.BASELINE][0])
    true_1_signature = signature(pairs[ConfirmationKind.TRUE_1][0])
    false_1_signature = signature(pairs[ConfirmationKind.FALSE_1][0])
    true_2_signature = signature(pairs[ConfirmationKind.TRUE_2][0])
    false_2_signature = signature(pairs[ConfirmationKind.FALSE_2][0])
    control_signature = signature(pairs[ConfirmationKind.CONTROL][0])

    return ConfirmationEvidence(
        observations=observations,
        baseline_matches_true=(
            baseline_signature == true_1_signature == true_2_signature
        ),
        false_matches_control=(
            false_1_signature == false_2_signature == control_signature
        ),
        baseline_differs_from_false=(baseline_signature != false_1_signature),
    )


def test_matching_phases():
    result = assess_cross_phase_consistency(
        initial=make_initial(),
        confirmation=make_confirmation(),
    )

    assert result.status is CrossPhaseStatus.MATCH
    assert result.consistent
    assert result.mismatched_kinds == ()


def test_cache_generation_rollover():
    result = assess_cross_phase_consistency(
        initial=make_initial(
            baseline=b"A",
            true=b"A",
            false=b"B",
        ),
        confirmation=make_confirmation(
            baseline=b"A-generation2",
            true_1=b"A-generation2",
            false_1=b"B-generation2",
            true_2=b"A-generation2",
            false_2=b"B-generation2",
            control=b"B-generation2",
        ),
    )

    assert result.status is CrossPhaseStatus.MISMATCH
    assert result.mismatched_kinds == (
        ProbeKind.BASELINE,
        ProbeKind.TRUE,
        ProbeKind.FALSE,
    )


@pytest.mark.parametrize(
    ("kind", "override", "expected"),
    [
        (
            ConfirmationKind.BASELINE,
            (201, 1),
            ProbeKind.BASELINE,
        ),
        (
            ConfirmationKind.FALSE_1,
            (200, 2),
            ProbeKind.FALSE,
        ),
    ],
    ids=("status", "body-size"),
)
def test_signature_component_mismatch(kind, override, expected):
    result = assess_cross_phase_consistency(
        initial=make_initial(),
        confirmation=make_confirmation(
            overrides={kind: override},
        ),
    )

    assert result.status is CrossPhaseStatus.MISMATCH
    assert result.mismatched_kinds == (expected,)


@pytest.mark.parametrize(
    ("changed", "expected"),
    [
        ("baseline", ProbeKind.BASELINE),
        ("true_1", ProbeKind.TRUE),
        ("false_1", ProbeKind.FALSE),
    ],
)
def test_individual_mismatch(changed, expected):
    values = {
        "baseline": b"A",
        "true_1": b"A",
        "false_1": b"B",
    }

    values[changed] = b"changed"

    confirmation = make_confirmation(
        baseline=values["baseline"],
        true_1=values["true_1"],
        false_1=values["false_1"],
        true_2=b"A",
        false_2=b"B",
        control=b"B",
    )

    result = assess_cross_phase_consistency(
        initial=make_initial(),
        confirmation=confirmation,
    )

    assert result.status is CrossPhaseStatus.MISMATCH
    assert result.mismatched_kinds == (expected,)


def test_matching_false_candidate_remains_matching():
    # A non-SQL WAF can reproduce a fully consistent pattern.
    result = assess_cross_phase_consistency(
        initial=make_initial(),
        confirmation=make_confirmation(),
    )

    assert result.status is CrossPhaseStatus.MATCH

    # MATCH alone must never be interpreted as SQLi proof.


def test_rejects_non_candidate_initial_result():
    initial = make_initial()
    invalid = replace(
        initial,
        reason_code="unexpected_difference",
    )

    with pytest.raises(
        ValueError,
        match="Initial result is not eligible",
    ):
        assess_cross_phase_consistency(
            initial=invalid,
            confirmation=make_confirmation(),
        )


def test_rejects_unstable_initial_pair():
    initial = make_initial()
    observations = list(initial.observations)
    observations[1] = initial_observation(
        ProbeKind.BASELINE,
        b"different-baseline",
    )
    unstable = replace(
        initial,
        observations=tuple(observations),
    )

    with pytest.raises(
        ValueError,
        match="Initial result is not eligible",
    ):
        assess_cross_phase_consistency(
            initial=unstable,
            confirmation=make_confirmation(),
        )


def test_rejects_missing_confirmation_evidence():
    with pytest.raises(
        TypeError,
        match="Invalid confirmation evidence",
    ):
        assess_cross_phase_consistency(
            initial=make_initial(),
            confirmation=None,
        )


def test_confirmation_evidence_rejects_invalid_order_and_instability():
    evidence = make_confirmation()

    with pytest.raises(
        ValueError,
        match="Invalid confirmation observation order",
    ):
        ConfirmationEvidence(
            observations=evidence.observations[::-1],
            baseline_matches_true=evidence.baseline_matches_true,
            false_matches_control=evidence.false_matches_control,
            baseline_differs_from_false=evidence.baseline_differs_from_false,
        )

    observations = list(evidence.observations)
    observations[-1] = confirmation_observation(
        ConfirmationKind.TRUE_1,
        b"unstable",
    )
    with pytest.raises(
        ValueError,
        match="Unstable confirmation evidence",
    ):
        ConfirmationEvidence(
            observations=tuple(observations),
            baseline_matches_true=evidence.baseline_matches_true,
            false_matches_control=evidence.false_matches_control,
            baseline_differs_from_false=evidence.baseline_differs_from_false,
        )


@pytest.mark.parametrize(
    ("initial", "confirmation", "message"),
    [
        (object(), make_confirmation(), "Invalid initial result"),
        (make_initial(), object(), "Invalid confirmation evidence"),
    ],
)
def test_rejects_invalid_input_types(initial, confirmation, message):
    with pytest.raises(TypeError, match=message):
        assess_cross_phase_consistency(
            initial=initial,
            confirmation=confirmation,
        )


def test_rejects_model_subclasses():
    initial = make_initial()
    confirmation = make_confirmation()
    derived_initial = DerivedVerificationResult(
        check_id=initial.check_id,
        verdict=initial.verdict,
        observations=initial.observations,
        request_count=initial.request_count,
        reason_code=initial.reason_code,
        reason=initial.reason,
        failures=initial.failures,
        evidence=initial.evidence,
        confidence=initial.confidence,
    )
    derived_confirmation = DerivedConfirmationEvidence(
        observations=confirmation.observations,
        baseline_matches_true=confirmation.baseline_matches_true,
        false_matches_control=confirmation.false_matches_control,
        baseline_differs_from_false=(confirmation.baseline_differs_from_false),
    )

    with pytest.raises(TypeError, match="Invalid initial result"):
        assess_cross_phase_consistency(
            initial=derived_initial,
            confirmation=confirmation,
        )

    with pytest.raises(
        TypeError,
        match="Invalid confirmation evidence",
    ):
        assess_cross_phase_consistency(
            initial=initial,
            confirmation=derived_confirmation,
        )


def test_assessment_invariants():
    with pytest.raises(ValueError):
        CrossPhaseAssessment(
            status=CrossPhaseStatus.MATCH,
            mismatched_kinds=(ProbeKind.BASELINE,),
        )

    with pytest.raises(ValueError):
        CrossPhaseAssessment(
            status=CrossPhaseStatus.MISMATCH,
            mismatched_kinds=(),
        )

    with pytest.raises(ValueError):
        CrossPhaseAssessment(
            status=CrossPhaseStatus.MISMATCH,
            mismatched_kinds=(
                ProbeKind.FALSE,
                ProbeKind.BASELINE,
            ),
        )

    with pytest.raises(ValueError):
        CrossPhaseAssessment(
            status=CrossPhaseStatus.MISMATCH,
            mismatched_kinds=(
                ProbeKind.BASELINE,
                ProbeKind.BASELINE,
            ),
        )

    with pytest.raises(TypeError):
        CrossPhaseAssessment(
            status="mismatch",
            mismatched_kinds=(ProbeKind.BASELINE,),
        )

    with pytest.raises(TypeError):
        CrossPhaseAssessment(
            status=CrossPhaseStatus.MISMATCH,
            mismatched_kinds=("baseline",),
        )


def test_assessment_does_not_expose_response_hashes():
    result = assess_cross_phase_consistency(
        initial=make_initial(),
        confirmation=make_confirmation(
            baseline=b"A-new",
            true_1=b"A-new",
            true_2=b"A-new",
        ),
    )

    rendered = repr(result)

    assert "body_digest" not in rendered
    assert digest(b"A") not in rendered
    assert digest(b"A-new") not in rendered
    assert "A-new" not in rendered
