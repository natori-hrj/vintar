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
            raise TypeError("Invalid error probe kind.")
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
    """Non-sensitive identity of one reproducible DBMS diagnostic."""

    dbms: str
    signature_id: str

    def __post_init__(self) -> None:
        ErrorMatch(self.dbms, self.signature_id)


def _expected_result(
    observations: tuple[ErrorObservation, ...],
) -> tuple[ErrorAnalysisStatus, str, ErrorEvidence | None]:
    if any(item.truncated for item in observations):
        return ErrorAnalysisStatus.INCONCLUSIVE, "truncated_response", None

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
    evidence: ErrorEvidence | None = None

    def __post_init__(self) -> None:
        if type(self.status) is not ErrorAnalysisStatus:
            raise TypeError("Invalid error analysis status.")
        if type(self.reason_code) is not str:
            raise TypeError("Invalid error analysis reason.")
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
        if tuple(item.kind for item in self.observations) != ERROR_PROBE_ORDER or tuple(
            item.sequence for item in self.observations
        ) != (1, 2, 3, 4):
            raise ValueError(
                "Invalid error observation order. Use baseline, probe, baseline, probe."
            )
        request_count = len(self.observations)
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
        expected = _expected_result(self.observations)
        if (self.status, self.reason_code, self.evidence) != expected:
            raise ValueError(
                "Error analysis fields disagree with the recorded responses. Construct results through analyze_error_responses."
            )


def _matches(body: bytes) -> tuple[ErrorMatch, ...]:
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
    if _matches(payload.encode("utf-8")):
        raise ValueError(
            "Error probe payload contains a registered DBMS diagnostic and could create a reflected false positive. Supply SQL syntax that does not contain error-signature text."
        )
    return payload


def _observation(
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
        matches=_matches(response.body),
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
        _observation(kind, sequence, response)
        for sequence, (kind, response) in enumerate(
            zip(ERROR_PROBE_ORDER, ordered, strict=True), start=1
        )
    )
    status, reason_code, evidence = _expected_result(observations)
    return ErrorAnalysis(
        status=status,
        reason_code=reason_code,
        observations=observations,
        evidence=evidence,
    )
