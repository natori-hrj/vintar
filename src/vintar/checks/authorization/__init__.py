"""Pure contracts for explicit authorization regression expectations."""

from vintar.checks.authorization.models import (
    AUTHORIZATION_REASON_VERDICTS,
    AuthenticationMode,
    AuthorizationExpectation,
    AuthorizationOperationResult,
    AuthorizationReason,
    AuthorizationRunResult,
    AuthorizationVerdict,
    ControlKind,
    ResponseAssertions,
)

__all__ = [
    "AUTHORIZATION_REASON_VERDICTS",
    "AuthenticationMode",
    "AuthorizationExpectation",
    "AuthorizationOperationResult",
    "AuthorizationReason",
    "AuthorizationRunResult",
    "AuthorizationVerdict",
    "ControlKind",
    "ResponseAssertions",
]
