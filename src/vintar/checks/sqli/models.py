import math
import re
import sys
from dataclasses import dataclass
from enum import Enum

JSON_SAFE_INTEGER_MAX = (1 << 53) - 1
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_REASON_CODE_PATTERN = re.compile(r"[a-z][a-z0-9_]*")


class Verdict(str, Enum):
    """Final result of a security verification."""

    VULNERABLE = "vulnerable"
    NOT_DETECTED = "not_detected"
    INCONCLUSIVE = "inconclusive"


class ProbeKind(str, Enum):
    """Type of request used for Boolean-based verification."""

    BASELINE = "baseline"
    TRUE = "true"
    FALSE = "false"


class ProbeError(str, Enum):
    """Machine-readable reason why a probe produced no HTTP response."""

    TIMEOUT = "timeout"
    CONNECTION = "connection"
    RESPONSE_READ = "response_read"
    BUDGET_EXCEEDED = "budget_exceeded"
    RATE_LIMIT = "rate_limit"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Observation:
    """Non-sensitive response metadata for one completed HTTP probe."""

    kind: ProbeKind
    status_code: int
    body_size: int
    elapsed: float
    body_digest: str
    truncated: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ProbeKind):
            raise TypeError("kind must be a ProbeKind.")

        if type(self.status_code) is not int:
            raise TypeError("status_code must be an integer.")
        if not 100 <= self.status_code <= 599:
            raise ValueError("Invalid HTTP status code.")

        if type(self.body_size) is not int:
            raise TypeError("body_size must be an integer.")
        if not 0 <= self.body_size <= JSON_SAFE_INTEGER_MAX:
            raise ValueError("body_size must be a JSON-safe non-negative integer.")

        if isinstance(self.elapsed, bool) or not isinstance(self.elapsed, (int, float)):
            raise TypeError("elapsed must be numeric.")
        if (
            self.elapsed < 0
            or self.elapsed > sys.float_info.max
            or not math.isfinite(self.elapsed)
        ):
            raise ValueError("elapsed must be finite and non-negative.")

        if type(self.body_digest) is not str:
            raise TypeError("body_digest must be a string.")
        if _SHA256_PATTERN.fullmatch(self.body_digest) is None:
            raise ValueError("body_digest must be a lowercase SHA-256 digest.")

        if type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean.")


@dataclass(frozen=True, slots=True)
class ProbeFailure:
    """Structured metadata for a probe that produced no HTTP response."""

    kind: ProbeKind
    error: ProbeError
    elapsed: float | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ProbeKind):
            raise TypeError("kind must be a ProbeKind.")
        if not isinstance(self.error, ProbeError):
            raise TypeError("error must be a ProbeError.")

        if self.elapsed is not None:
            if isinstance(self.elapsed, bool) or not isinstance(
                self.elapsed, (int, float)
            ):
                raise TypeError("elapsed must be numeric or None.")
            if (
                self.elapsed < 0
                or self.elapsed > sys.float_info.max
                or not math.isfinite(self.elapsed)
            ):
                raise ValueError("elapsed must be finite and non-negative.")


@dataclass(frozen=True, slots=True)
class BooleanEvidence:
    """Derived similarity evidence across Boolean-based probes."""

    baseline_true_similarity: float
    baseline_false_similarity: float
    true_false_similarity: float

    def __post_init__(self) -> None:
        for name in (
            "baseline_true_similarity",
            "baseline_false_similarity",
            "true_false_similarity",
        ):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"{name} must be numeric.")
            if not 0 <= value <= 1 or not math.isfinite(value):
                raise ValueError(f"{name} must be between 0 and 1.")


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Structured outcome of a SQLi verification attempt.

    request_count counts recorded probe attempts, including ProbeFailure objects.
    It is not a copy of RequestBudget.used_requests.
    """

    check_id: str
    verdict: Verdict
    observations: tuple[Observation, ...]
    request_count: int
    reason_code: str
    reason: str
    failures: tuple[ProbeFailure, ...] = ()
    evidence: BooleanEvidence | None = None
    confidence: float | None = None

    def __post_init__(self) -> None:
        if type(self.check_id) is not str:
            raise TypeError("check_id must be a string.")
        if not self.check_id.strip():
            raise ValueError("check_id cannot be empty.")

        if not isinstance(self.verdict, Verdict):
            raise TypeError("verdict must be a Verdict.")

        if not isinstance(self.observations, tuple):
            raise TypeError("observations must be a tuple.")
        if not all(isinstance(item, Observation) for item in self.observations):
            raise TypeError("observations must contain Observation objects.")

        if not isinstance(self.failures, tuple):
            raise TypeError("failures must be a tuple.")
        if not all(isinstance(item, ProbeFailure) for item in self.failures):
            raise TypeError("failures must contain ProbeFailure objects.")

        if type(self.request_count) is not int:
            raise TypeError("request_count must be an integer.")
        if not 0 <= self.request_count <= JSON_SAFE_INTEGER_MAX:
            raise ValueError("request_count must be a JSON-safe non-negative integer.")

        recorded_attempts = len(self.observations) + len(self.failures)
        if self.request_count != recorded_attempts:
            raise ValueError("request_count must equal recorded probe attempts.")

        if type(self.reason_code) is not str:
            raise TypeError("reason_code must be a string.")
        if _REASON_CODE_PATTERN.fullmatch(self.reason_code) is None:
            raise ValueError("reason_code must be a lowercase identifier.")

        if type(self.reason) is not str:
            raise TypeError("reason must be a string.")
        if not self.reason.strip():
            raise ValueError("reason cannot be empty.")

        if self.confidence is not None:
            if isinstance(self.confidence, bool) or not isinstance(
                self.confidence, (int, float)
            ):
                raise TypeError("confidence must be numeric or None.")
            if not 0 <= self.confidence <= 1 or not math.isfinite(self.confidence):
                raise ValueError("confidence must be between 0 and 1.")

        if self.evidence is not None and not isinstance(self.evidence, BooleanEvidence):
            raise TypeError("evidence must be BooleanEvidence or None.")

        observations_by_kind = {
            observation.kind: observation for observation in self.observations
        }
        required_kinds = {ProbeKind.BASELINE, ProbeKind.TRUE, ProbeKind.FALSE}
        if self.evidence is not None and not required_kinds.issubset(
            observations_by_kind
        ):
            raise ValueError(
                "Boolean comparison evidence requires baseline, true, and false probes."
            )

        if self.verdict is Verdict.INCONCLUSIVE:
            return

        if self.failures:
            raise ValueError("A conclusive result cannot contain probe failures.")
        if any(observation.truncated for observation in self.observations):
            raise ValueError("A conclusive result cannot use truncated observations.")

        if not required_kinds.issubset(observations_by_kind):
            raise ValueError(
                "A conclusive result requires baseline, true, and false probes."
            )

        if self.evidence is None:
            raise ValueError(
                "A conclusive result requires Boolean comparison evidence."
            )
