import hashlib

from vintar.checks.sqli.dynamic import detect_dynamic_region
from vintar.checks.sqli.models import (
    BooleanEvidence,
    Observation,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.core.models import HttpResult

type ResponsePair = tuple[HttpResult, HttpResult]


def _validate_response_pair(name: str, responses: object) -> ResponsePair:
    """Validate the two completed responses required for one probe kind."""
    if not isinstance(responses, tuple):
        raise TypeError(f"{name} must be a tuple.")
    if len(responses) != 2:
        raise ValueError(f"{name} must contain exactly two responses.")
    if not all(isinstance(response, HttpResult) for response in responses):
        raise TypeError(f"{name} must contain HttpResult objects.")
    if not all(type(response.body) is bytes for response in responses):
        raise TypeError(f"{name} response bodies must be bytes.")

    return responses


def _matches(left: HttpResult, right: HttpResult) -> bool:
    """Compare status and full captured response body."""
    return left.status_code == right.status_code and left.body == right.body


def _stable(responses: ResponsePair) -> bool:
    """Require both attempts to produce identical content."""
    return _matches(responses[0], responses[1])


def _observation(
    kind: ProbeKind,
    response: HttpResult,
) -> Observation:
    return Observation(
        kind=kind,
        status_code=response.status_code,
        body_size=response.size,
        elapsed=response.elapsed,
        body_digest=hashlib.sha256(response.body).hexdigest(),
        truncated=response.truncated,
    )


def analyze_boolean_responses(
    check_id: str,
    baseline: ResponsePair,
    true_responses: ResponsePair,
    false_responses: ResponsePair,
) -> VerificationResult:
    """Analyze six completed, authorized Boolean SQLi probes.

    This function performs no HTTP requests.
    All six requests must have completed successfully.
    """
    baseline = _validate_response_pair("baseline", baseline)
    true_responses = _validate_response_pair("true_responses", true_responses)
    false_responses = _validate_response_pair("false_responses", false_responses)

    groups = (
        (ProbeKind.BASELINE, baseline),
        (ProbeKind.TRUE, true_responses),
        (ProbeKind.FALSE, false_responses),
    )

    observations = tuple(
        _observation(kind, response)
        for kind, responses in groups
        for response in responses
    )

    def result(
        verdict: Verdict,
        reason_code: str,
        reason: str,
        evidence: BooleanEvidence | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            check_id=check_id,
            verdict=verdict,
            observations=observations,
            request_count=len(observations),
            reason_code=reason_code,
            reason=reason,
            evidence=evidence,
        )

    if any(item.truncated for item in observations):
        return result(
            Verdict.INCONCLUSIVE,
            "truncated_response",
            "At least one response was truncated.",
        )

    if any(not 200 <= item.status_code < 300 for item in observations):
        return result(
            Verdict.INCONCLUSIVE,
            "non_success_status",
            "At least one probe returned a non-2xx HTTP status.",
        )

    unstable_pairs = [responses for _, responses in groups if not _stable(responses)]

    if unstable_pairs:
        possible_dynamic = all(
            detect_dynamic_region(responses[0], responses[1]) is not None
            for responses in unstable_pairs
        )

        if possible_dynamic:
            return result(
                Verdict.INCONCLUSIVE,
                "possible_dynamic_response",
                "Repeated probes contain small localized "
                "differences; no Boolean conclusion was made.",
            )

        return result(
            Verdict.INCONCLUSIVE,
            "unstable_response",
            "Repeated probes produced different responses.",
        )

    baseline_response = baseline[0]
    true_response = true_responses[0]
    false_response = false_responses[0]

    baseline_true = _matches(baseline_response, true_response)
    baseline_false = _matches(baseline_response, false_response)
    true_false = _matches(true_response, false_response)

    evidence = BooleanEvidence(
        baseline_true_similarity=float(baseline_true),
        baseline_false_similarity=float(baseline_false),
        true_false_similarity=float(true_false),
    )

    if baseline_true and baseline_false:
        return result(
            Verdict.NOT_DETECTED,
            "no_boolean_difference",
            "No Boolean response difference was detected in these six probes; "
            "this does not prove the target is not vulnerable.",
            evidence,
        )

    if baseline_true and not baseline_false:
        return result(
            Verdict.INCONCLUSIVE,
            "boolean_candidate",
            "Reproducible Boolean differential detected; "
            "additional verification is required.",
            evidence,
        )

    if true_false:
        return result(
            Verdict.NOT_DETECTED,
            "no_boolean_difference_literal_input",
            "The stable TRUE and FALSE probes produced identical responses while "
            "both differed from the baseline. No Boolean differential was detected; "
            "check whether the target treats injected payloads as literal input.",
            evidence,
        )

    return result(
        Verdict.INCONCLUSIVE,
        "unexpected_difference",
        "Responses differ without the expected Boolean pattern.",
        evidence,
    )
