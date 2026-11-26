"""Secret-free, transport-free authorization check contracts."""

from dataclasses import dataclass
from enum import StrEnum


class AuthenticationMode(StrEnum):
    REQUIRED = "required"
    NONE = "none"


class AuthorizationExpectation(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class ControlKind(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"


class AuthorizationVerdict(StrEnum):
    CONFORMS = "conforms"
    VIOLATION = "violation"
    INCONCLUSIVE = "inconclusive"


class AuthorizationReason(StrEnum):
    DECLARED_DENY_OBSERVED_SUCCESS = "declared_deny_observed_success"
    PROTECTED_MARKER_PRESENT = "protected_marker_present"
    DECLARED_ALLOW_OBSERVED_DENY = "declared_allow_observed_deny"
    ALLOW_ASSERTION_MISMATCH = "allow_assertion_mismatch"
    POSITIVE_CONTROL_FAILED = "positive_control_failed"
    AUTHENTICATION_REJECTED = "authentication_rejected"
    REDIRECT_OBSERVED = "redirect_observed"
    SERVER_ERROR = "server_error"
    RATE_LIMITED = "rate_limited"
    TRANSPORT_TIMEOUT = "transport_timeout"
    TRANSPORT_FAILED = "transport_failed"
    RESPONSE_TRUNCATED = "response_truncated"
    RESPONSE_TOO_LARGE = "response_too_large"
    MEDIA_TYPE_MISMATCH = "media_type_mismatch"
    RESPONSE_PARSE_FAILED = "response_parse_failed"
    ASSERTION_NOT_EVALUABLE = "assertion_not_evaluable"
    UNEXPECTED_STATUS = "unexpected_status"


@dataclass(frozen=True, slots=True, repr=False)
class ResponseAssertions:
    """Bounded response facts declared by an operator-reviewed case."""

    status_codes: tuple[int, ...]
    media_type: str | None
    required_json_pointers: tuple[str, ...]
    forbidden_json_pointers: tuple[str, ...]
    allow_empty_body: bool

    def __post_init__(self) -> None:
        if (
            not self.status_codes
            or len(self.status_codes) > 16
            or any(
                type(code) is not int or not 100 <= code <= 599
                for code in self.status_codes
            )
            or len(set(self.status_codes)) != len(self.status_codes)
        ):
            raise ValueError("Invalid authorization status assertion.")
        if self.media_type not in {None, "application/json"}:
            raise ValueError("Invalid authorization response media type.")
        pointers = self.required_json_pointers + self.forbidden_json_pointers
        if (
            len(self.required_json_pointers) > 32
            or len(self.forbidden_json_pointers) > 32
            or any(
                type(pointer) is not str or len(pointer) > 512 for pointer in pointers
            )
            or len(set(pointers)) != len(pointers)
        ):
            raise ValueError("Invalid authorization response pointer assertion.")
        if pointers and self.media_type != "application/json":
            raise ValueError("JSON pointer assertions require application/json.")
        if type(self.allow_empty_body) is not bool:
            raise TypeError("allow_empty_body must be a boolean.")
