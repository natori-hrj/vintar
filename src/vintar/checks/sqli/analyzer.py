import hashlib
from dataclasses import dataclass, replace

from vintar.checks.sqli.decision_facts import (
    BooleanDecisionFacts,
    DecisionStage,
    OperationalDecisionFacts,
    PairLocalization,
    ResponseDynamicsDecisionFacts,
    UnstablePairFacts,
    select_initial_response_stop,
)
from vintar.checks.sqli.dynamic import DynamicRegion, detect_dynamic_region
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

BOOLEAN_ANALYSIS_REASON_CODES = frozenset(
    {
        "rate_limited",
        "truncated_response",
        "non_success_status",
        "possible_dynamic_response",
        "unstable_response",
        "no_boolean_difference",
        "boolean_candidate",
        "no_boolean_difference_literal_input",
        "unexpected_difference",
    }
)


@dataclass(frozen=True, slots=True)
class BooleanResponseSignature:
    """Sanitized comparison input for one normalized response."""

    kind: ProbeKind
    status_code: int
    body_size: int
    body_digest: str
    truncated: bool
    normalization_applied: bool = False
    normalized_echo_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ProbeKind):
            raise TypeError(
                "Invalid Boolean signature kind. Use an analyzer probe kind."
            )
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ValueError(
                "Invalid Boolean signature status. Use a completed response status."
            )
        if type(self.body_size) is not int or self.body_size < 0:
            raise ValueError(
                "Invalid Boolean signature size. Use the captured nonnegative byte size."
            )
        if (
            type(self.body_digest) is not str
            or len(self.body_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.body_digest)
        ):
            raise ValueError(
                "Invalid Boolean signature digest. Use the analyzer SHA-256 digest."
            )
        if type(self.truncated) is not bool:
            raise TypeError(
                "Invalid Boolean truncation flag. Use the completed response flag."
            )
        if type(self.normalization_applied) is not bool or (
            type(self.normalized_echo_count) is not int
            or self.normalized_echo_count < 0
        ):
            raise TypeError(
                "Invalid Boolean signature normalization facts. Use analyzer-produced "
                "boolean and nonnegative count values."
            )
        if self.normalization_applied != (self.normalized_echo_count > 0):
            raise ValueError(
                "Boolean signature normalization facts disagree. Record a positive "
                "count exactly when normalization was applied."
            )


@dataclass(frozen=True, slots=True)
class BooleanRepeatComparison:
    """Sanitized equality and optional localized region for one repeat pair."""

    probe_kind: ProbeKind
    equal: bool
    dynamic_region: DynamicRegion | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.probe_kind, ProbeKind):
            raise TypeError("Invalid Boolean repeat kind. Use an analyzer probe kind.")
        if type(self.equal) is not bool:
            raise TypeError(
                "Invalid Boolean repeat equality. Use the comparison boolean."
            )
        if self.dynamic_region is not None and not isinstance(
            self.dynamic_region, DynamicRegion
        ):
            raise TypeError(
                "Invalid Boolean dynamic region. Use the shared response comparison."
            )
        if self.equal and self.dynamic_region is not None:
            raise ValueError(
                "Equal Boolean repeats cannot have a dynamic region. Use the shared "
                "comparison result."
            )


@dataclass(frozen=True, slots=True)
class BooleanClassification:
    verdict: Verdict
    reason_code: str
    evidence: BooleanEvidence | None = None
    decision_facts: BooleanDecisionFacts | None = None


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


def boolean_response_signature(
    kind: ProbeKind, observation: Observation
) -> BooleanResponseSignature:
    """Project an analyzer observation to its non-sensitive comparison signature."""
    return BooleanResponseSignature(
        kind=kind,
        status_code=observation.status_code,
        body_size=observation.body_size,
        body_digest=observation.body_digest,
        truncated=observation.truncated,
        normalization_applied=observation.normalization_applied,
        normalized_echo_count=observation.normalized_echo_count,
    )


def _repeat_comparison(
    kind: ProbeKind, responses: ResponsePair
) -> BooleanRepeatComparison:
    equal = _stable(responses)
    return BooleanRepeatComparison(
        probe_kind=kind,
        equal=equal,
        dynamic_region=None
        if equal
        else detect_dynamic_region(responses[0], responses[1]),
    )


def classify_boolean_signatures(
    *,
    signatures: tuple[BooleanResponseSignature, ...],
    repeat_comparisons: tuple[BooleanRepeatComparison, ...],
    normalization_applied: bool,
    normalized_echo_count: int,
) -> BooleanClassification:
    """Classify sanitized normalized signatures without response content."""
    if (
        len(signatures) != len(BOOLEAN_PROBE_ORDER)
        or tuple(item.kind for item in signatures) != BOOLEAN_PROBE_ORDER
    ):
        raise ValueError(
            "Boolean signatures must follow the fixed six-request order. Use "
            "analyzer-produced normalized signatures."
        )
    if tuple(item.probe_kind for item in repeat_comparisons) != tuple(ProbeKind):
        raise ValueError(
            "Boolean repeat comparisons must cover baseline, true, and false in "
            "deterministic order."
        )
    grouped = {
        kind: tuple(item for item in signatures if item.kind is kind)
        for kind in ProbeKind
    }
    for comparison in repeat_comparisons:
        first, second = grouped[comparison.probe_kind]
        equal = (
            first.status_code,
            first.body_size,
            first.body_digest,
        ) == (
            second.status_code,
            second.body_size,
            second.body_digest,
        )
        if comparison.equal is not equal:
            raise ValueError(
                "Boolean repeat comparison contradicts the response signatures. "
                "Use results from the same shared comparison call."
            )
    if type(normalization_applied) is not bool or (
        type(normalized_echo_count) is not int or normalized_echo_count < 0
    ):
        raise TypeError(
            "Invalid Boolean normalization facts. Use analyzer-produced boolean and "
            "nonnegative count values."
        )
    if normalization_applied != (normalized_echo_count > 0):
        raise ValueError(
            "Boolean normalization facts disagree. Record a positive count exactly "
            "when normalization was applied."
        )
    stop = select_initial_response_stop(
        (item.status_code, item.truncated) for item in signatures
    )
    if stop is not None:
        sequence, condition, reason = stop
        item = signatures[sequence - 1]
        return BooleanClassification(
            Verdict.INCONCLUSIVE,
            reason,
            decision_facts=OperationalDecisionFacts(
                reason_code=reason,
                stage=DecisionStage.INITIAL,
                sequence=sequence,
                probe_kind=item.kind,
                condition=condition,
                status_code=item.status_code,
            ),
        )
    unstable = tuple(item for item in repeat_comparisons if not item.equal)
    if unstable:
        pair_facts = tuple(
            UnstablePairFacts(
                probe_kind=item.probe_kind,
                localization=(
                    PairLocalization.LOCALIZED
                    if item.dynamic_region is not None
                    else PairLocalization.UNLOCALIZED
                ),
                prefix_size=None
                if item.dynamic_region is None
                else item.dynamic_region.prefix_size,
                suffix_size=None
                if item.dynamic_region is None
                else item.dynamic_region.suffix_size,
                first_changed_size=None
                if item.dynamic_region is None
                else item.dynamic_region.first_changed_size,
                second_changed_size=None
                if item.dynamic_region is None
                else item.dynamic_region.second_changed_size,
            )
            for item in unstable
        )
        reason = (
            "possible_dynamic_response"
            if all(item.dynamic_region is not None for item in unstable)
            else "unstable_response"
        )
        return BooleanClassification(
            Verdict.INCONCLUSIVE,
            reason,
            decision_facts=ResponseDynamicsDecisionFacts(
                reason_code=reason,
                normalization_applied=normalization_applied,
                normalized_echo_count=normalized_echo_count,
                unstable_pairs=pair_facts,
            ),
        )
    by_kind = {
        kind: next(item for item in signatures if item.kind is kind)
        for kind in ProbeKind
    }

    def matches(left: ProbeKind, right: ProbeKind) -> bool:
        first, second = by_kind[left], by_kind[right]
        return (first.status_code, first.body_size, first.body_digest) == (
            second.status_code,
            second.body_size,
            second.body_digest,
        )

    baseline_true = matches(ProbeKind.BASELINE, ProbeKind.TRUE)
    baseline_false = matches(ProbeKind.BASELINE, ProbeKind.FALSE)
    true_false = matches(ProbeKind.TRUE, ProbeKind.FALSE)
    evidence = BooleanEvidence(
        baseline_true_similarity=float(baseline_true),
        baseline_false_similarity=float(baseline_false),
        true_false_similarity=float(true_false),
    )
    if baseline_true and baseline_false:
        return BooleanClassification(
            Verdict.NOT_DETECTED, "no_boolean_difference", evidence
        )
    if baseline_true and not baseline_false:
        return BooleanClassification(
            Verdict.INCONCLUSIVE, "boolean_candidate", evidence
        )
    if true_false:
        return BooleanClassification(
            Verdict.NOT_DETECTED,
            "no_boolean_difference_literal_input",
            evidence,
        )
    return BooleanClassification(
        Verdict.INCONCLUSIVE, "unexpected_difference", evidence
    )


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
    classification = classify_boolean_signatures(
        signatures=tuple(
            boolean_response_signature(item.kind, item) for item in ordered
        ),
        repeat_comparisons=tuple(
            _repeat_comparison(kind, responses) for kind, responses in groups
        ),
        normalization_applied=any(item.applied for item in normalizations),
        normalized_echo_count=sum(item.echo_count for item in normalizations),
    )
    explanation = {
        "rate_limited": "A probe returned HTTP 429.",
        "truncated_response": "At least one response was truncated.",
        "non_success_status": "At least one probe returned a non-2xx HTTP status.",
        "possible_dynamic_response": (
            "Repeated probes contain small localized differences; no Boolean "
            "conclusion was made."
        ),
        "unstable_response": "Repeated probes produced different responses.",
        "no_boolean_difference": (
            "No Boolean response difference was detected in these six probes; this "
            "does not prove the target is not vulnerable."
        ),
        "boolean_candidate": (
            "Reproducible Boolean differential detected; additional verification "
            "is required."
        ),
        "no_boolean_difference_literal_input": (
            "The stable TRUE and FALSE probes produced identical responses while "
            "both differed from the baseline. No Boolean differential was detected; "
            "check whether the target treats injected payloads as literal input."
        ),
        "unexpected_difference": (
            "Responses differ without the expected Boolean pattern."
        ),
    }[classification.reason_code]
    return result(
        classification.verdict,
        classification.reason_code,
        explanation,
        classification.evidence,
        classification.decision_facts,
    )
