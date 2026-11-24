import hashlib
from dataclasses import replace

from vintar.checks.sqli.decision_facts import (
    BooleanDecisionFacts,
    DecisionStage,
    OperationalCondition,
    OperationalDecisionFacts,
    PairLocalization,
    ResponseDynamicsDecisionFacts,
    UnstablePairFacts,
    select_initial_response_stop,
)
from vintar.checks.sqli.dynamic import detect_dynamic_region
from vintar.checks.sqli.echo_normalization import (
    EchoInput,
    NormalizedEcho,
    normalize_context_bound_echoes,
)
from vintar.checks.sqli.models import (
    BOOLEAN_PROBE_ORDER,
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
    normalization: NormalizedEcho,
) -> Observation:
    return Observation(
        kind=kind,
        status_code=response.status_code,
        body_size=response.size,
        elapsed=response.elapsed,
        body_digest=hashlib.sha256(response.body).hexdigest(),
        truncated=response.truncated,
        normalization_applied=normalization.applied,
        normalized_echo_count=normalization.echo_count,
    )


def _normalize_response_groups(
    groups: tuple[tuple[ProbeKind, ResponsePair], ...],
    echo_values: tuple[str, str, str] | None,
) -> tuple[
    tuple[tuple[ProbeKind, ResponsePair], ...],
    tuple[NormalizedEcho, ...],
]:
    flattened = tuple(response for _, responses in groups for response in responses)
    if echo_values is None:
        normalized = tuple(NormalizedEcho(item.body, False, 0) for item in flattened)
    else:
        if (
            type(echo_values) is not tuple
            or len(echo_values) != 3
            or any(type(value) is not str for value in echo_values)
        ):
            raise TypeError(
                "echo_values must contain the complete baseline, TRUE, and FALSE "
                "parameter values; pass the values used to build the requests."
            )
        values = tuple(value for value in echo_values for _ in range(2))
        normalized = normalize_context_bound_echoes(
            tuple(
                EchoInput(response.body, value)
                for response, value in zip(flattened, values, strict=True)
            )
        )
    normalized_responses = tuple(
        replace(response, body=item.body)
        for response, item in zip(flattened, normalized, strict=True)
    )
    rebuilt: list[tuple[ProbeKind, ResponsePair]] = []
    for index, (kind, _) in enumerate(groups):
        offset = index * 2
        rebuilt.append(
            (kind, (normalized_responses[offset], normalized_responses[offset + 1]))
        )
    return tuple(rebuilt), normalized


def analyze_boolean_responses(
    check_id: str,
    baseline: ResponsePair,
    true_responses: ResponsePair,
    false_responses: ResponsePair,
    *,
    echo_values: tuple[str, str, str] | None = None,
) -> VerificationResult:
    """Analyze six completed, authorized Boolean SQLi probes.

    This function performs no HTTP requests.
    All six requests must have completed successfully.
    """
    baseline = _validate_response_pair("baseline", baseline)
    true_responses = _validate_response_pair("true_responses", true_responses)
    false_responses = _validate_response_pair("false_responses", false_responses)

    groups: tuple[tuple[ProbeKind, ResponsePair], ...] = (
        (ProbeKind.BASELINE, baseline),
        (ProbeKind.TRUE, true_responses),
        (ProbeKind.FALSE, false_responses),
    )
    groups, normalizations = _normalize_response_groups(groups, echo_values)
    baseline = groups[0][1]
    true_responses = groups[1][1]
    false_responses = groups[2][1]

    observations = tuple(
        _observation(kind, response, normalization)
        for (kind, responses), group_normalizations in zip(
            groups,
            (normalizations[0:2], normalizations[2:4], normalizations[4:6]),
            strict=True,
        )
        for response, normalization in zip(responses, group_normalizations, strict=True)
    )

    def result(
        verdict: Verdict,
        reason_code: str,
        reason: str,
        evidence: BooleanEvidence | None = None,
        decision_facts: BooleanDecisionFacts | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            check_id=check_id,
            verdict=verdict,
            observations=observations,
            request_count=len(observations),
            reason_code=reason_code,
            reason=reason,
            evidence=evidence,
            decision_facts=decision_facts,
        )

    observations_by_kind = {
        kind: tuple(item for item in observations if item.kind is kind)
        for kind in ProbeKind
    }
    offsets = {kind: 0 for kind in ProbeKind}
    ordered: list[Observation] = []
    for kind in BOOLEAN_PROBE_ORDER:
        ordered.append(observations_by_kind[kind][offsets[kind]])
        offsets[kind] += 1
    stop = select_initial_response_stop(
        (item.status_code, item.truncated) for item in ordered
    )
    if stop is not None:
        sequence, condition, reason = stop
        item = ordered[sequence - 1]
        explanation = {
            OperationalCondition.RATE_LIMITED: "A probe returned HTTP 429.",
            OperationalCondition.TRUNCATED: "At least one response was truncated.",
            OperationalCondition.NON_SUCCESS_STATUS: "At least one probe returned a non-2xx HTTP status.",
        }[condition]
        return result(
            Verdict.INCONCLUSIVE,
            reason,
            explanation,
            decision_facts=OperationalDecisionFacts(
                reason_code=reason,
                stage=DecisionStage.INITIAL,
                sequence=sequence,
                probe_kind=item.kind,
                condition=condition,
                status_code=item.status_code,
            ),
        )

    unstable_pairs = [
        (kind, responses, detect_dynamic_region(responses[0], responses[1]))
        for kind, responses in groups
        if not _stable(responses)
    ]

    if unstable_pairs:
        possible_dynamic = all(region is not None for _, _, region in unstable_pairs)
        pair_facts = tuple(
            UnstablePairFacts(
                probe_kind=kind,
                localization=(
                    PairLocalization.LOCALIZED
                    if region is not None
                    else PairLocalization.UNLOCALIZED
                ),
                prefix_size=None if region is None else region.prefix_size,
                suffix_size=None if region is None else region.suffix_size,
                first_changed_size=None
                if region is None
                else region.first_changed_size,
                second_changed_size=None
                if region is None
                else region.second_changed_size,
            )
            for kind, _, region in unstable_pairs
        )
        normalization_applied = any(item.applied for item in normalizations)
        normalized_echo_count = sum(item.echo_count for item in normalizations)
        dynamics_reason = (
            "possible_dynamic_response" if possible_dynamic else "unstable_response"
        )
        dynamics_facts = ResponseDynamicsDecisionFacts(
            reason_code=dynamics_reason,
            normalization_applied=normalization_applied,
            normalized_echo_count=normalized_echo_count,
            unstable_pairs=pair_facts,
        )

        if possible_dynamic:
            return result(
                Verdict.INCONCLUSIVE,
                "possible_dynamic_response",
                "Repeated probes contain small localized "
                "differences; no Boolean conclusion was made.",
                decision_facts=dynamics_facts,
            )

        return result(
            Verdict.INCONCLUSIVE,
            "unstable_response",
            "Repeated probes produced different responses.",
            decision_facts=dynamics_facts,
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
