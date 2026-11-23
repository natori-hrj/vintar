"""Pure, bounded error-based SQLi response analysis.

Response bodies do not need to be byte-identical. Real applications commonly add
timestamps, CSRF tokens, request IDs, and other dynamic content. Stability is
therefore defined by repeated status codes and reviewed signature-match sets:
both baselines must have the same status and no signature, while both probes must
have the same status and the same ``(dbms, signature_id)`` set.
"""

import hashlib
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import overload

from vintar.checks.sqli.error_contract import (
    ERROR_RESULT_RULES,
    ErrorAnalysisStatus,
)
from vintar.checks.sqli.error_signatures import ERROR_SCAN_LIMIT, ERROR_SIGNATURES
from vintar.core.models import HttpResult


class ErrorProbeKind(StrEnum):
    """Logical request kind in the fixed four-request plan."""

    BASELINE = "baseline"
    PROBE = "probe"


ERROR_PROBE_ORDER = (
    ErrorProbeKind.BASELINE,
    ErrorProbeKind.PROBE,
    ErrorProbeKind.BASELINE,
    ErrorProbeKind.PROBE,
)


@dataclass(frozen=True, slots=True, order=True)
class ErrorMatch:
    """One reviewed signature observed in a bounded response prefix."""

    dbms: str
    signature_id: str

    def __post_init__(self) -> None:
        signature = ERROR_SIGNATURES.get(self.signature_id)
        if signature is None or signature.dbms != self.dbms:
            raise ValueError(
                "Invalid error-signature match. Use a signature ID and DBMS from ERROR_SIGNATURES."
            )


@dataclass(frozen=True, slots=True)
class ErrorObservation:
    """Sanitized metadata and reviewed matches for one completed response."""

    kind: ErrorProbeKind
    sequence: int
    status_code: int
    body_size: int
    body_digest: str
    truncated: bool
    matches: tuple[ErrorMatch, ...] = field(default=())

    def __post_init__(self) -> None:
        if type(self.kind) is not ErrorProbeKind:
            raise TypeError(
                "Invalid error probe kind. Use ErrorProbeKind.BASELINE or ErrorProbeKind.PROBE."
            )
        if type(self.sequence) is not int or not 1 <= self.sequence <= 4:
            raise ValueError("Invalid error probe sequence. Use positions 1 through 4.")
        if type(self.status_code) is not int or not 100 <= self.status_code <= 599:
            raise ValueError("Invalid HTTP status. Supply a completed HTTP response.")
        if type(self.body_size) is not int or self.body_size < 0:
            raise ValueError("Invalid response size. Supply a nonnegative byte count.")
        if (
            type(self.body_digest) is not str
            or len(self.body_digest) != 64
            or any(char not in "0123456789abcdef" for char in self.body_digest)
        ):
            raise ValueError(
                "Invalid response digest. Supply a lowercase SHA-256 digest."
            )
        if type(self.truncated) is not bool:
            raise TypeError("Invalid truncation flag. Supply a boolean.")
        if type(self.matches) is not tuple or any(
            type(item) is not ErrorMatch for item in self.matches
        ):
            raise TypeError("Invalid error matches. Supply an immutable match tuple.")
        if self.matches != tuple(sorted(set(self.matches))):
            raise ValueError("Invalid error matches. Supply unique sorted matches.")


@dataclass(frozen=True, slots=True)
class ErrorEvidence:
    """Non-sensitive review evidence, not confirmation of changed SQL execution."""

    dbms: str
    signature_id: str

    def __post_init__(self) -> None:
        ErrorMatch(self.dbms, self.signature_id)


@dataclass(frozen=True, slots=True)
class ErrorProbeFailure:
    """One terminal operational failure in the fixed request plan."""

    kind: ErrorProbeKind
    sequence: int
    reason_code: str

    def __post_init__(self) -> None:
        if type(self.kind) is not ErrorProbeKind:
            raise TypeError(
                "Invalid failed error probe kind. Use the ErrorProbeKind from the current request-plan position."
            )
        if type(self.sequence) is not int or not 1 <= self.sequence <= 4:
            raise ValueError(
                "Invalid failed error probe sequence. Use positions 1 through 4."
            )
        if type(self.reason_code) is not str or self.reason_code not in {
            "probe_timeout",
            "probe_failed",
            "probe_interrupted",
        }:
            raise ValueError(
                "Invalid operational error reason. Use probe_timeout, probe_failed, or probe_interrupted from the bounded runner."
            )


@overload
def operational_stop_reason(attempt: ErrorProbeFailure) -> str: ...


@overload
def operational_stop_reason(attempt: ErrorObservation) -> str | None: ...


@overload
def operational_stop_reason(attempt: object) -> str | None: ...


def operational_stop_reason(attempt: object) -> str | None:
    """Derive the single terminal reason, with batch-stop precedence."""
    if type(attempt) is ErrorProbeFailure:
        return attempt.reason_code
    if type(attempt) is not ErrorObservation:
        raise TypeError(
            "Invalid Error SQLi attempt. Supply a recorded observation or probe failure."
        )
    if attempt.status_code == 429:
        return "rate_limited"
    if attempt.truncated:
        return "truncated_response"
    return None


def _operational_sequence_stop(
    attempts: tuple[ErrorObservation | ErrorProbeFailure, ...],
) -> str | None:
    """Return the first stop reason and reject observations after it."""
    for index, attempt in enumerate(attempts):
        reason = operational_stop_reason(attempt)
        if reason is None:
            continue
        if index != len(attempts) - 1:
            raise ValueError(
                "Error SQLi observations continue after an operational stop. The runner stops at the first operational condition, so later observations cannot exist. Pass observations only up to the stop."
            )
        return reason
    return None


def classify_error_observations(
    observations: tuple[ErrorObservation, ...],
) -> tuple[ErrorAnalysisStatus, str, ErrorEvidence | None]:
    """Classify sanitized observations from the fixed Error request plan."""
    if type(observations) is not tuple or any(
        type(item) is not ErrorObservation for item in observations
    ):
        raise TypeError(
            "Invalid Error SQLi observations. Supply an immutable tuple of ErrorObservation values."
        )
    if tuple(item.kind for item in observations) != ERROR_PROBE_ORDER[
        : len(observations)
    ] or tuple(item.sequence for item in observations) != tuple(
        range(1, len(observations) + 1)
    ):
        raise ValueError(
            "Invalid Error SQLi observation order. Use baseline, probe, baseline, probe in sequence."
        )
    terminal_reason = _operational_sequence_stop(observations)
    if terminal_reason is not None:
        return ErrorAnalysisStatus.INCONCLUSIVE, terminal_reason, None

    if len(observations) != len(ERROR_PROBE_ORDER):
        raise ValueError(
            "Incomplete analytical Error SQLi observations. Supply all four responses, or end the sequence at its operational stop."
        )

    baselines = (observations[0], observations[2])
    probes = (observations[1], observations[3])
    if baselines[0].status_code != baselines[1].status_code or (
        probes[0].status_code != probes[1].status_code
    ):
        return ErrorAnalysisStatus.INCONCLUSIVE, "unstable_response", None

    baseline_matches = (baselines[0].matches, baselines[1].matches)
    if baseline_matches[0] != baseline_matches[1]:
        return ErrorAnalysisStatus.INCONCLUSIVE, "unstable_error_signal", None
    if baseline_matches[0]:
        return ErrorAnalysisStatus.INCONCLUSIVE, "baseline_dbms_error", None

    probe_matches = (probes[0].matches, probes[1].matches)
    if probe_matches[0] != probe_matches[1]:
        return ErrorAnalysisStatus.INCONCLUSIVE, "unstable_error_signal", None

    if not 200 <= baselines[0].status_code < 300 or probes[0].status_code == 429:
        return ErrorAnalysisStatus.INCONCLUSIVE, "non_success_status", None

    matches = probe_matches[0]
    if not matches:
        if not 200 <= probes[0].status_code < 300:
            return ErrorAnalysisStatus.INCONCLUSIVE, "non_success_status", None
        return ErrorAnalysisStatus.NOT_MATCHED, "dbms_error_not_observed", None

    if len(matches) != 1:
        return ErrorAnalysisStatus.INCONCLUSIVE, "ambiguous_dbms_error", None

    match = matches[0]
    return (
        ErrorAnalysisStatus.MATCHED,
        "dbms_error_disclosed",
        ErrorEvidence(match.dbms, match.signature_id),
    )


@dataclass(frozen=True, slots=True, repr=False)
class ErrorAnalysis:
    """Validated four-response error-signature classification."""

    status: ErrorAnalysisStatus
    reason_code: str
    observations: tuple[ErrorObservation, ...] = field(repr=False)
    failures: tuple[ErrorProbeFailure, ...] = field(default=(), repr=False)
    evidence: ErrorEvidence | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not ErrorAnalysisStatus:
            raise TypeError(
                "Invalid error analysis status. Use the ErrorAnalysisStatus required by ERROR_RESULT_RULES."
            )
        if type(self.reason_code) is not str:
            raise TypeError(
                "Invalid error analysis reason. Use a string reason declared in ERROR_RESULT_RULES."
            )
        rule = ERROR_RESULT_RULES.get(self.reason_code)
        if rule is None:
            raise ValueError(
                "Unsupported error analysis reason. Use a reason declared in ERROR_RESULT_RULES."
            )
        if type(self.observations) is not tuple or any(
            type(item) is not ErrorObservation for item in self.observations
        ):
            raise TypeError(
                "Invalid error observations. Use analyzer-produced observations."
            )
        if type(self.failures) is not tuple or any(
            type(item) is not ErrorProbeFailure for item in self.failures
        ):
            raise TypeError(
                "Invalid error probe failures. Use runner-produced failure records."
            )
        attempts: tuple[ErrorObservation | ErrorProbeFailure, ...] = tuple(
            sorted(
                (*self.observations, *self.failures),
                key=lambda item: item.sequence,
            )
        )
        if tuple(item.kind for item in attempts) != ERROR_PROBE_ORDER[
            : len(attempts)
        ] or tuple(item.sequence for item in attempts) != tuple(
            range(1, len(attempts) + 1)
        ):
            raise ValueError(
                "Invalid error observation order. Use baseline, probe, baseline, probe."
            )
        implied_reason = _operational_sequence_stop(attempts)
        request_count = len(attempts)
        if (
            self.status is not rule.analysis_status
            or not rule.minimum_requests <= request_count <= rule.maximum_requests
            or (rule.requires_complete_four and request_count != 4)
        ):
            raise ValueError(
                "Error analysis reason, status, or request count disagree. Use ERROR_RESULT_RULES and the complete four-request plan."
            )
        if rule.requires_evidence != (self.evidence is not None):
            raise ValueError(
                "Error analysis evidence disagrees with its reason. Supply evidence only for a reproducible disclosed signature."
            )
        expected: tuple[ErrorAnalysisStatus, str, ErrorEvidence | None]
        if implied_reason is not None:
            if rule.requires_complete_four:
                raise ValueError(
                    "Analytical Error SQLi reason cannot contain an operational stop. Use the derived operational reason and pass observations only up to the stop."
                )
            if self.reason_code != implied_reason:
                terminal = attempts[-1]
                precedence = (
                    " HTTP 429 takes precedence over truncation because the batch stops on rate limits."
                    if implied_reason == "rate_limited"
                    and type(terminal) is ErrorObservation
                    and terminal.truncated
                    else " Use the reason implied by the terminal attempt."
                )
                raise ValueError(
                    "Declared operational reason disagrees with the terminal observation: "
                    f"it implies {implied_reason}.{precedence}"
                )
            expected = (
                ErrorAnalysisStatus.INCONCLUSIVE,
                implied_reason,
                None,
            )
        elif not rule.requires_complete_four:
            raise ValueError(
                "Operational error analysis lacks its declared terminal condition. Stop after HTTP 429 or truncation, or record the runner failure instead."
            )
        else:
            expected = classify_error_observations(self.observations)
        if (self.status, self.reason_code, self.evidence) != expected:
            raise ValueError(
                "Error analysis fields disagree with the recorded responses. Construct results through analyze_error_responses."
            )

    @property
    def request_count(self) -> int:
        return len(self.observations) + len(self.failures)


def match_error_signatures(body: bytes) -> tuple[ErrorMatch, ...]:
    """Return reviewed matches from the bounded response prefix."""
    if type(body) is not bytes:
        raise TypeError(
            "Invalid Error SQLi response body. Supply immutable response bytes."
        )
    bounded = body[:ERROR_SCAN_LIMIT]
    return tuple(
        sorted(
            ErrorMatch(signature.dbms, signature.signature_id)
            for signature in ERROR_SIGNATURES.values()
            if signature.pattern.search(bounded) is not None
        )
    )


def validate_error_probe_payload(payload: object) -> str:
    """Reject payloads that could manufacture a reflected signature match."""
    if type(payload) is not str or not 0 < len(payload) <= 512:
        raise ValueError(
            "Invalid error probe payload. Supply a nonempty reviewed string of at most 512 characters."
        )
    if any(unicodedata.category(char).startswith("C") for char in payload):
        raise ValueError(
            "Invalid error probe payload. Remove control characters and supply reviewed SQL syntax."
        )
    if match_error_signatures(payload.encode("utf-8")):
        raise ValueError(
            "Error probe payload contains a registered DBMS diagnostic and could create a reflected false positive. Supply SQL syntax that does not contain error-signature text."
        )
    return payload


def error_observation(
    kind: ErrorProbeKind,
    sequence: int,
    response: HttpResult,
) -> ErrorObservation:
    if type(response) is not HttpResult or type(response.body) is not bytes:
        raise TypeError(
            "Invalid error-analysis response. Supply completed HttpResult objects."
        )
    return ErrorObservation(
        kind=kind,
        sequence=sequence,
        status_code=response.status_code,
        body_size=len(response.body),
        body_digest=hashlib.sha256(response.body).hexdigest(),
        truncated=response.truncated,
        matches=match_error_signatures(response.body),
    )


def analyze_error_responses(
    baseline_responses: tuple[HttpResult, HttpResult],
    probe_responses: tuple[HttpResult, HttpResult],
    *,
    probe_payload: str,
) -> ErrorAnalysis:
    """Classify four completed responses without network access or body equality."""
    validate_error_probe_payload(probe_payload)
    for name, responses in (
        ("baseline_responses", baseline_responses),
        ("probe_responses", probe_responses),
    ):
        if type(responses) is not tuple or len(responses) != 2:
            raise ValueError(
                f"Invalid {name}. Supply exactly two completed responses from the four-request plan."
            )
    ordered = (
        baseline_responses[0],
        probe_responses[0],
        baseline_responses[1],
        probe_responses[1],
    )
    observations = tuple(
        error_observation(kind, sequence, response)
        for sequence, (kind, response) in enumerate(
            zip(ERROR_PROBE_ORDER, ordered, strict=True), start=1
        )
    )
    status, reason_code, evidence = classify_error_observations(observations)
    return ErrorAnalysis(
        status=status,
        reason_code=reason_code,
        observations=observations,
        evidence=evidence,
    )
