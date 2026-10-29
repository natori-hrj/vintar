import json
from dataclasses import FrozenInstanceError, asdict

import pytest

from vintar.checks.sqli.models import (
    JSON_SAFE_INTEGER_MAX,
    BooleanEvidence,
    Observation,
    ProbeError,
    ProbeFailure,
    ProbeKind,
    Verdict,
    VerificationResult,
)

EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def make_observation(**overrides) -> Observation:
    values = {
        "kind": ProbeKind.BASELINE,
        "status_code": 200,
        "body_size": 1024,
        "elapsed": 0.15,
        "body_digest": EMPTY_DIGEST,
        "truncated": False,
    }
    values.update(overrides)
    return Observation(**values)


def make_complete_observations(
    overrides: dict[ProbeKind, Observation] | None = None,
) -> tuple[Observation, ...]:
    observations = {
        ProbeKind.BASELINE: make_observation(),
        ProbeKind.TRUE: make_observation(
            kind=ProbeKind.TRUE,
        ),
        ProbeKind.FALSE: make_observation(
            kind=ProbeKind.FALSE,
        ),
    }
    if overrides is not None:
        observations.update(overrides)
    return tuple(observations.values())


def make_result(**overrides) -> VerificationResult:
    values = {
        "check_id": "sqli-test",
        "verdict": Verdict.INCONCLUSIVE,
        "observations": (make_observation(),),
        "request_count": 1,
        "reason_code": "insufficient_evidence",
        "reason": "Insufficient evidence.",
        "failures": (),
        "confidence": None,
    }
    values.update(overrides)
    return VerificationResult(**values)


def make_conclusive_result(verdict: Verdict) -> VerificationResult:
    observations = make_complete_observations()
    return make_result(
        verdict=verdict,
        observations=observations,
        request_count=len(observations),
        reason_code="boolean_differential",
        reason="Boolean response differential confirmed.",
        evidence=BooleanEvidence(
            baseline_true_similarity=0.99,
            baseline_false_similarity=0.2,
            true_false_similarity=0.2,
        ),
        confidence=0.95,
    )


def test_observation():
    observation = make_observation()

    assert observation.kind is ProbeKind.BASELINE
    assert observation.status_code == 200
    assert observation.body_size == 1024
    assert observation.elapsed == 0.15
    assert observation.body_digest == EMPTY_DIGEST
    assert observation.truncated is False


def test_verification_result():
    result = make_result()

    assert result.verdict is Verdict.INCONCLUSIVE
    assert len(result.observations) == 1
    assert result.request_count == 1
    assert result.confidence is None


@pytest.mark.parametrize("verdict", [Verdict.VULNERABLE, Verdict.NOT_DETECTED])
def test_conclusive_verdicts_require_complete_evidence(verdict):
    result = make_conclusive_result(verdict)

    assert result.verdict is verdict
    assert {item.kind for item in result.observations} == set(ProbeKind)


@pytest.mark.parametrize("kind", list(ProbeKind))
def test_all_probe_kinds(kind):
    observation = make_observation(
        kind=kind,
        body_size=0,
        elapsed=0.0,
    )
    assert observation.kind is kind


@pytest.mark.parametrize("invalid", [True, "1024", None])
def test_invalid_body_size_type(invalid):
    with pytest.raises(TypeError):
        make_observation(body_size=invalid)


@pytest.mark.parametrize("invalid", [-1, JSON_SAFE_INTEGER_MAX + 1, 10**1000])
def test_invalid_body_size_value(invalid):
    with pytest.raises(ValueError):
        make_observation(body_size=invalid)


@pytest.mark.parametrize("invalid", [True, "0.1", []])
def test_invalid_elapsed_type(invalid):
    with pytest.raises(TypeError):
        make_observation(elapsed=invalid)


@pytest.mark.parametrize(
    "invalid",
    [-0.1, float("nan"), float("inf"), float("-inf")],
)
def test_invalid_elapsed_value(invalid):
    with pytest.raises(ValueError):
        make_observation(elapsed=invalid)


@pytest.mark.parametrize("invalid", [True, 200.0, "200"])
def test_invalid_status_code_type(invalid):
    with pytest.raises(TypeError):
        make_observation(status_code=invalid)


@pytest.mark.parametrize("invalid", [99, 600])
def test_invalid_status_code_value(invalid):
    with pytest.raises(ValueError):
        make_observation(status_code=invalid)


@pytest.mark.parametrize("invalid", [None, "baseline", True])
def test_invalid_probe_kind(invalid):
    with pytest.raises(TypeError):
        make_observation(kind=invalid)


@pytest.mark.parametrize("invalid", [None, 123, True])
def test_invalid_body_digest_type(invalid):
    with pytest.raises(TypeError):
        make_observation(body_digest=invalid)


@pytest.mark.parametrize("invalid", ["", "0" * 63, "G" * 64, "A" * 64])
def test_invalid_body_digest_value(invalid):
    with pytest.raises(ValueError):
        make_observation(body_digest=invalid)


@pytest.mark.parametrize("invalid", [True, "0.1", []])
def test_invalid_similarity_type(invalid):
    with pytest.raises(TypeError):
        BooleanEvidence(
            baseline_true_similarity=invalid,
            baseline_false_similarity=0.2,
            true_false_similarity=0.2,
        )


@pytest.mark.parametrize(
    "invalid",
    [-0.1, 1.1, float("nan"), float("inf"), float("-inf")],
)
def test_invalid_similarity_value(invalid):
    with pytest.raises(ValueError):
        BooleanEvidence(
            baseline_true_similarity=invalid,
            baseline_false_similarity=0.2,
            true_false_similarity=0.2,
        )


@pytest.mark.parametrize("invalid", ["true", 1, None])
def test_invalid_truncated(invalid):
    with pytest.raises(TypeError):
        make_observation(truncated=invalid)


@pytest.mark.parametrize("invalid", [True, "0.5", []])
def test_invalid_confidence_type(invalid):
    with pytest.raises(TypeError):
        make_result(confidence=invalid)


@pytest.mark.parametrize(
    "invalid",
    [-0.1, 1.1, float("nan"), float("inf"), float("-inf")],
)
def test_invalid_confidence_value(invalid):
    with pytest.raises(ValueError):
        make_result(confidence=invalid)


@pytest.mark.parametrize("confidence", [0.0, 0.5, 1.0])
def test_valid_confidence(confidence):
    assert make_result(confidence=confidence).confidence == confidence


@pytest.mark.parametrize("invalid", [True, 1.0, "1", None])
def test_invalid_request_count_type(invalid):
    with pytest.raises(TypeError):
        make_result(request_count=invalid)


@pytest.mark.parametrize("invalid", [-1, JSON_SAFE_INTEGER_MAX + 1, 10**1000])
def test_invalid_request_count_value(invalid):
    with pytest.raises(ValueError):
        make_result(request_count=invalid)


@pytest.mark.parametrize("request_count", [0, 2])
def test_request_count_must_equal_recorded_attempts(request_count):
    with pytest.raises(ValueError, match="recorded probe attempts"):
        make_result(request_count=request_count)


def test_probe_failure_accounts_for_request():
    failure = ProbeFailure(
        kind=ProbeKind.TRUE,
        error=ProbeError.CONNECTION,
        elapsed=0.2,
    )
    result = make_result(
        failures=(failure,),
        request_count=2,
        reason_code="connection_error",
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.failures == (failure,)


@pytest.mark.parametrize("invalid", [None, "invalid", []])
def test_invalid_observations(invalid):
    with pytest.raises(TypeError):
        make_result(observations=invalid)


def test_invalid_observation_item():
    with pytest.raises(TypeError):
        make_result(observations=("invalid",))


@pytest.mark.parametrize("invalid", [None, "invalid", []])
def test_invalid_failures(invalid):
    with pytest.raises(TypeError):
        make_result(failures=invalid)


def test_invalid_failure_item():
    with pytest.raises(TypeError):
        make_result(failures=("invalid",), request_count=2)


@pytest.mark.parametrize("invalid", [None, "timeout", 1])
def test_invalid_failure_error(invalid):
    with pytest.raises(TypeError):
        ProbeFailure(kind=ProbeKind.TRUE, error=invalid)


@pytest.mark.parametrize("verdict", [Verdict.VULNERABLE, Verdict.NOT_DETECTED])
def test_conclusive_verdict_rejects_missing_probe_kinds(verdict):
    with pytest.raises(ValueError, match="baseline, true, and false"):
        make_result(verdict=verdict, confidence=0.9)


@pytest.mark.parametrize("verdict", [Verdict.VULNERABLE, Verdict.NOT_DETECTED])
def test_conclusive_verdict_rejects_probe_failures(verdict):
    observations = make_complete_observations()
    failure = ProbeFailure(ProbeKind.TRUE, ProbeError.TIMEOUT)

    with pytest.raises(ValueError, match="probe failures"):
        make_result(
            verdict=verdict,
            observations=observations,
            failures=(failure,),
            request_count=4,
            confidence=0.9,
        )


@pytest.mark.parametrize("verdict", [Verdict.VULNERABLE, Verdict.NOT_DETECTED])
def test_conclusive_verdict_rejects_truncated_observations(verdict):
    observations = make_complete_observations(
        {
            ProbeKind.FALSE: make_observation(
                kind=ProbeKind.FALSE,
                truncated=True,
            )
        }
    )

    with pytest.raises(ValueError, match="truncated"):
        make_result(
            verdict=verdict,
            observations=observations,
            request_count=3,
            evidence=BooleanEvidence(0.99, 0.2, 0.2),
            confidence=0.9,
        )


@pytest.mark.parametrize("verdict", [Verdict.VULNERABLE, Verdict.NOT_DETECTED])
def test_conclusive_verdict_requires_similarity_evidence(verdict):
    observations = make_complete_observations()

    with pytest.raises(ValueError, match="comparison evidence"):
        make_result(
            verdict=verdict,
            observations=observations,
            request_count=3,
            confidence=0.9,
        )


def test_inconclusive_allows_no_attempts():
    result = make_result(
        observations=(),
        request_count=0,
        reason_code="budget_unavailable",
    )

    assert result.verdict is Verdict.INCONCLUSIVE


def test_inconclusive_allows_truncated_observation():
    observation = make_observation(truncated=True)
    result = make_result(observations=(observation,))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.observations[0].truncated is True


def test_comparison_evidence_requires_complete_observations():
    with pytest.raises(ValueError, match="comparison evidence requires"):
        make_result(evidence=BooleanEvidence(0.9, 0.2, 0.2))


@pytest.mark.parametrize("invalid", ["invalid", 1, []])
def test_invalid_evidence_type(invalid):
    with pytest.raises(TypeError):
        make_result(evidence=invalid)


def test_empty_reason():
    with pytest.raises(ValueError, match="reason"):
        make_result(reason="   ")


def test_empty_check_id():
    with pytest.raises(ValueError, match="check_id"):
        make_result(check_id="")


@pytest.mark.parametrize("invalid", ["", "Has-Caps", "1invalid", "has space"])
def test_invalid_reason_code(invalid):
    with pytest.raises(ValueError, match="reason_code"):
        make_result(reason_code=invalid)


def test_models_are_immutable():
    observation = make_observation()
    failure = ProbeFailure(ProbeKind.TRUE, ProbeError.TIMEOUT)
    result = make_result()

    with pytest.raises(FrozenInstanceError):
        observation.body_size = 100

    with pytest.raises(FrozenInstanceError):
        failure.error = ProbeError.UNKNOWN

    with pytest.raises(FrozenInstanceError):
        result.verdict = Verdict.VULNERABLE


def test_result_is_json_serializable():
    failure = ProbeFailure(
        kind=ProbeKind.TRUE,
        error=ProbeError.TIMEOUT,
        elapsed=0.2,
    )
    result = make_result(failures=(failure,), request_count=2)

    serialized = json.loads(json.dumps(asdict(result)))

    assert serialized["verdict"] == "inconclusive"
    assert serialized["failures"][0]["error"] == "timeout"
