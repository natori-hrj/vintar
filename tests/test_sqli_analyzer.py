import hashlib
from dataclasses import replace

import pytest

from vintar.checks.sqli.analyzer import analyze_boolean_responses
from vintar.checks.sqli.models import ProbeKind, Verdict
from vintar.core.models import HttpResult


def response(
    body: bytes = b"baseline",
    *,
    status_code: int = 200,
    truncated: bool = False,
) -> HttpResult:
    return HttpResult(
        status_code=status_code,
        elapsed=0.1,
        body=body,
        headers={},
        truncated=truncated,
    )


def pair(body: bytes) -> tuple[HttpResult, HttpResult]:
    return response(body), response(body)


def analyze(
    baseline=None,
    true_responses=None,
    false_responses=None,
):
    return analyze_boolean_responses(
        check_id="test-sqli",
        baseline=baseline if baseline is not None else pair(b"A"),
        true_responses=(true_responses if true_responses is not None else pair(b"A")),
        false_responses=(
            false_responses if false_responses is not None else pair(b"B")
        ),
    )


def test_boolean_candidate_is_inconclusive():
    result = analyze()

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "boolean_candidate"
    assert result.evidence is not None
    assert result.evidence.baseline_true_similarity == 1.0
    assert result.evidence.baseline_false_similarity == 0.0
    assert result.evidence.true_false_similarity == 0.0


def test_identical_responses_are_not_detected():
    result = analyze(false_responses=pair(b"A"))

    assert result.verdict is Verdict.NOT_DETECTED
    assert result.reason_code == "no_boolean_difference"
    assert "does not prove" in result.reason


def test_unstable_baseline_is_inconclusive():
    result = analyze(baseline=(response(b"A"), response(b"dynamic")))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "unstable_response"
    assert result.evidence is None


def test_unstable_true_response_is_inconclusive():
    result = analyze(true_responses=(response(b"A"), response(b"changed")))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "unstable_response"


def test_unstable_false_response_is_inconclusive():
    result = analyze(false_responses=(response(b"B"), response(b"changed")))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "unstable_response"


def test_truncated_response_is_inconclusive():
    result = analyze(
        false_responses=(
            response(b"B"),
            response(b"B", truncated=True),
        )
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "truncated_response"


def test_truncation_takes_priority_over_instability():
    result = analyze(
        false_responses=(
            response(b"B"),
            response(b"changed", truncated=True),
        )
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "truncated_response"
    assert result.evidence is None


def test_unexpected_difference_is_inconclusive():
    result = analyze(true_responses=pair(b"C"))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "unexpected_difference"


def test_non_success_status_is_inconclusive():
    result = analyze(
        false_responses=(
            response(b"A", status_code=403),
            response(b"A", status_code=403),
        )
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "non_success_status"
    assert result.evidence is None
    assert result.request_count == 6


def test_result_contains_six_observations():
    result = analyze()

    assert result.request_count == 6
    assert len(result.observations) == 6
    assert result.failures == ()
    assert tuple(observation.kind for observation in result.observations) == (
        ProbeKind.BASELINE,
        ProbeKind.BASELINE,
        ProbeKind.TRUE,
        ProbeKind.TRUE,
        ProbeKind.FALSE,
        ProbeKind.FALSE,
    )


def test_observations_contain_sha256_not_raw_body():
    result = analyze()

    assert result.observations[0].body_digest == hashlib.sha256(b"A").hexdigest()
    assert result.observations[-1].body_digest == hashlib.sha256(b"B").hexdigest()
    for observation in result.observations:
        assert len(observation.body_digest) == 64
        assert observation.body_size == 1
        assert not hasattr(observation, "body")


@pytest.mark.parametrize("body", [b"", b"hello", b"\x00\xff"])
def test_binary_response_body_is_supported(body):
    result = analyze(
        baseline=pair(body),
        true_responses=pair(body),
        false_responses=pair(body),
    )

    assert result.verdict is Verdict.NOT_DETECTED


def test_large_response_body_is_supported():
    body = b"A" * (1024 * 1024)

    result = analyze(
        baseline=pair(body),
        true_responses=pair(body),
        false_responses=pair(body),
    )

    assert result.verdict is Verdict.NOT_DETECTED
    assert all(
        observation.body_size == len(body) for observation in result.observations
    )
    assert all(
        observation.body_digest == hashlib.sha256(body).hexdigest()
        for observation in result.observations
    )


@pytest.mark.parametrize("invalid", [[], None, "responses"])
def test_response_pair_must_be_a_tuple(invalid):
    with pytest.raises(TypeError, match="baseline must be a tuple"):
        analyze_boolean_responses(
            check_id="test-sqli",
            baseline=invalid,
            true_responses=pair(b"A"),
            false_responses=pair(b"B"),
        )


@pytest.mark.parametrize("invalid", [(), (response(),), (*pair(b"A"), response())])
def test_response_pair_must_contain_exactly_two_responses(invalid):
    with pytest.raises(ValueError, match="exactly two responses"):
        analyze_boolean_responses(
            check_id="test-sqli",
            baseline=invalid,
            true_responses=pair(b"A"),
            false_responses=pair(b"B"),
        )


@pytest.mark.parametrize("invalid", [(object(), response()), (response(), object())])
def test_response_pair_must_contain_http_results(invalid):
    with pytest.raises(TypeError, match="HttpResult objects"):
        analyze_boolean_responses(
            check_id="test-sqli",
            baseline=pair(b"A"),
            true_responses=invalid,
            false_responses=pair(b"B"),
        )


@pytest.mark.parametrize(
    "invalid_body", ["text", bytearray(b"mutable"), memoryview(b"view")]
)
def test_response_body_must_be_immutable_bytes(invalid_body):
    invalid_response = replace(response(), body=invalid_body)

    with pytest.raises(TypeError, match="response bodies must be bytes"):
        analyze(
            false_responses=(invalid_response, invalid_response),
        )


@pytest.mark.parametrize(
    ("field", "invalid", "error"),
    [
        ("status_code", True, TypeError),
        ("status_code", 99, ValueError),
        ("elapsed", True, TypeError),
        ("elapsed", float("nan"), ValueError),
        ("elapsed", float("inf"), ValueError),
        ("elapsed", -0.1, ValueError),
        ("elapsed", 10**1000, ValueError),
        ("truncated", 1, TypeError),
    ],
)
def test_invalid_http_result_metadata_is_rejected(field, invalid, error):
    invalid_response = replace(response(), **{field: invalid})

    with pytest.raises(error):
        analyze(
            false_responses=(invalid_response, invalid_response),
        )


@pytest.mark.parametrize(
    "status_code",
    [100, 199, 300, 301, 302, 401, 403, 404, 429, 500, 503, 599],
)
def test_non_success_responses_are_inconclusive(status_code):
    result = analyze(
        false_responses=(
            response(b"blocked", status_code=status_code),
            response(b"blocked", status_code=status_code),
        )
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "non_success_status"
    assert result.evidence is None


def test_all_blocked_responses_are_not_marked_not_detected():
    blocked = (
        response(b"Access denied", status_code=403),
        response(b"Access denied", status_code=403),
    )

    result = analyze(
        baseline=blocked,
        true_responses=blocked,
        false_responses=blocked,
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "non_success_status"


def test_non_success_takes_priority_over_instability():
    result = analyze(
        false_responses=(
            response(b"blocked", status_code=403),
            response(b"changed", status_code=403),
        )
    )

    assert result.reason_code == "non_success_status"
    assert result.verdict is Verdict.INCONCLUSIVE


def test_truncation_takes_priority_over_non_success():
    result = analyze(
        false_responses=(
            response(b"blocked", status_code=403),
            response(b"blocked", status_code=403, truncated=True),
        )
    )

    assert result.reason_code == "truncated_response"


def test_successful_statuses_remain_comparable():
    result = analyze(
        baseline=(
            response(b"A", status_code=200),
            response(b"A", status_code=200),
        ),
        true_responses=(
            response(b"A", status_code=200),
            response(b"A", status_code=200),
        ),
        false_responses=(
            response(b"B", status_code=201),
            response(b"B", status_code=201),
        ),
    )

    assert result.reason_code == "boolean_candidate"
    assert result.verdict is Verdict.INCONCLUSIVE


@pytest.mark.parametrize("status_code", [200, 201, 204, 299])
def test_all_2xx_status_boundaries_remain_comparable(status_code):
    responses = (
        response(b"same", status_code=status_code),
        response(b"same", status_code=status_code),
    )

    result = analyze(
        baseline=responses,
        true_responses=responses,
        false_responses=responses,
    )

    assert result.verdict is Verdict.NOT_DETECTED
    assert result.reason_code == "no_boolean_difference"
