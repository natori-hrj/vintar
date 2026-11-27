"""Internal sequential GET runner for approved authorization cases."""

from __future__ import annotations

from collections.abc import Callable, Mapping

import httpx

from vintar.checks.authorization.models import (
    AUTHORIZATION_REASON_VERDICTS,
    AuthorizationExpectation,
    AuthorizationOperationResult,
    AuthorizationReason,
    AuthorizationRunResult,
    ControlKind,
    ResponseAssertions,
)
from vintar.core.budget import RequestBudgetExceededError
from vintar.core.strict_json import parse_strict_json
from vintar.core.transport import ExecutionDeadlineExceededError
from vintar.regression.authorization_cases import (
    AuthorizationCase,
    AuthorizationOperation,
)
from vintar.regression.authorization_execution import (
    AuthorizationExecution,
    build_authorization_execution,
)
from vintar.regression.authorization_policy import AuthorizationRuntimePolicy

ExecutionFactory = Callable[
    [AuthorizationCase, AuthorizationRuntimePolicy, Mapping[str, str]],
    AuthorizationExecution,
]


def _result(
    operation: AuthorizationOperation, reason: AuthorizationReason
) -> AuthorizationOperationResult:
    return AuthorizationOperationResult(
        operation.operation_id,
        operation.identity_id,
        operation.resource_id,
        operation.control,
        operation.expected,
        AUTHORIZATION_REASON_VERDICTS[reason],
        reason,
    )


def _ordered_operations(
    case: AuthorizationCase,
) -> tuple[AuthorizationOperation, ...]:
    return tuple(
        sorted(
            case.operations,
            key=lambda operation: (
                operation.identity_id,
                operation.control is not ControlKind.POSITIVE,
                operation.request.origin.scheme,
                operation.request.origin.host,
                operation.request.origin.port,
                operation.operation_id,
            ),
        )
    )


def _pointer_exists(value: object, pointer: str) -> bool:
    if pointer == "":
        return True
    current = value
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if type(current) is dict:
            mapping = current
            if token not in mapping:
                return False
            current = mapping[token]
        elif type(current) is list:
            if (
                not token.isascii()
                or not token.isdecimal()
                or (len(token) > 1 and token.startswith("0"))
            ):
                return False
            index = int(token)
            if index >= len(current):
                return False
            current = current[index]
        else:
            return False
    return True


def _read_body(response: httpx.Response, maximum: int) -> bytes:
    body = bytearray()
    try:
        for chunk in response.iter_bytes():
            remaining = maximum + 1 - len(body)
            body.extend(chunk[:remaining])
            if len(body) > maximum:
                raise OverflowError
    except OverflowError:
        raise
    except httpx.HTTPError as exc:
        raise EOFError from exc
    return bytes(body)


def _status_reason(status: int) -> AuthorizationReason:
    if status == 401:
        return AuthorizationReason.AUTHENTICATION_REJECTED
    if 300 <= status <= 399:
        return AuthorizationReason.REDIRECT_OBSERVED
    if status == 429:
        return AuthorizationReason.RATE_LIMITED
    if 500 <= status <= 599:
        return AuthorizationReason.SERVER_ERROR
    return AuthorizationReason.UNEXPECTED_STATUS


def _assert_body(
    body: bytes, content_type: str | None, assertions: ResponseAssertions
) -> tuple[bool, AuthorizationReason | None]:
    pointers = assertions.required_json_pointers + assertions.forbidden_json_pointers
    if not body:
        if not assertions.allow_empty_body:
            return False, AuthorizationReason.ASSERTION_NOT_EVALUABLE
        if assertions.required_json_pointers:
            return False, AuthorizationReason.ASSERTION_NOT_EVALUABLE
        return True, None
    if assertions.media_type is not None:
        actual = (
            content_type.partition(";")[0].strip().casefold() if content_type else ""
        )
        if actual != assertions.media_type:
            return False, AuthorizationReason.MEDIA_TYPE_MISMATCH
    if not pointers:
        return True, None
    try:
        value = parse_strict_json(body)
    except (TypeError, ValueError):
        return False, AuthorizationReason.RESPONSE_PARSE_FAILED
    required = all(
        _pointer_exists(value, pointer) for pointer in assertions.required_json_pointers
    )
    forbidden = any(
        _pointer_exists(value, pointer)
        for pointer in assertions.forbidden_json_pointers
    )
    if not required or forbidden:
        return False, None
    return True, None


def _evaluate(
    operation: AuthorizationOperation,
    status: int,
    content_type: str | None,
    body: bytes,
) -> AuthorizationReason:
    assertions = operation.assertions
    if status not in assertions.status_codes:
        if operation.expected is AuthorizationExpectation.DENY and 200 <= status <= 299:
            return AuthorizationReason.DECLARED_DENY_OBSERVED_SUCCESS
        if operation.expected is AuthorizationExpectation.ALLOW and status in {
            401,
            403,
            404,
        }:
            return AuthorizationReason.DECLARED_ALLOW_OBSERVED_DENY
        return _status_reason(status)
    matched, reason = _assert_body(body, content_type, assertions)
    if reason is not None:
        return reason
    if not matched:
        if operation.expected is AuthorizationExpectation.ALLOW:
            return AuthorizationReason.ALLOW_ASSERTION_MISMATCH
        return AuthorizationReason.PROTECTED_MARKER_PRESENT
    if operation.expected is AuthorizationExpectation.ALLOW:
        return AuthorizationReason.DECLARED_ALLOW_OBSERVED_SUCCESS
    return AuthorizationReason.DECLARED_DENY_OBSERVED_DENIAL


def _execute(
    execution: AuthorizationExecution,
    operation: AuthorizationOperation,
    maximum: int,
) -> AuthorizationReason:
    try:
        with execution.client_for(operation.identity_id).stream(
            operation.request.method, operation.request.url
        ) as response:
            content_type = response.headers.get("content-type")
            try:
                body = _read_body(response, maximum)
            except OverflowError:
                return AuthorizationReason.RESPONSE_TOO_LARGE
            except EOFError:
                return AuthorizationReason.RESPONSE_TRUNCATED
            return _evaluate(operation, response.status_code, content_type, body)
    except RequestBudgetExceededError:
        raise
    except ExecutionDeadlineExceededError:
        raise
    except httpx.TimeoutException:
        return AuthorizationReason.TRANSPORT_TIMEOUT
    except httpx.HTTPError:
        return AuthorizationReason.TRANSPORT_FAILED


def _run_authorization_case(
    case: AuthorizationCase,
    policy: AuthorizationRuntimePolicy,
    environ: Mapping[str, str],
    *,
    _execution_factory: ExecutionFactory,
) -> AuthorizationRunResult:
    operations = _ordered_operations(case)
    results: list[AuthorizationOperationResult] = []
    failed_controls: set[str] = set()
    stop_reason: AuthorizationReason | None = None
    execution = _execution_factory(case, policy, environ)
    with execution:
        for operation in operations:
            if stop_reason is not None:
                results.append(_result(operation, stop_reason))
                continue
            if (
                operation.expected is AuthorizationExpectation.DENY
                and operation.identity_id in failed_controls
            ):
                results.append(
                    _result(operation, AuthorizationReason.POSITIVE_CONTROL_FAILED)
                )
                continue
            try:
                reason = _execute(execution, operation, policy.limits.max_response_size)
            except RequestBudgetExceededError:
                stop_reason = AuthorizationReason.REQUEST_BUDGET_EXHAUSTED
                results.append(_result(operation, stop_reason))
                continue
            except ExecutionDeadlineExceededError:
                stop_reason = AuthorizationReason.EXECUTION_DEADLINE_EXCEEDED
                results.append(_result(operation, stop_reason))
                continue
            if operation.control is ControlKind.POSITIVE and reason is not (
                AuthorizationReason.DECLARED_ALLOW_OBSERVED_SUCCESS
            ):
                failed_controls.add(operation.identity_id)
                reason = AuthorizationReason.POSITIVE_CONTROL_FAILED
            elif (
                operation.expected is AuthorizationExpectation.ALLOW
                and operation.identity_id in failed_controls
                and reason is not AuthorizationReason.DECLARED_ALLOW_OBSERVED_SUCCESS
            ):
                reason = AuthorizationReason.POSITIVE_CONTROL_FAILED
            results.append(_result(operation, reason))
    return AuthorizationRunResult(
        case.case_id, tuple(results), execution.budget.used_requests
    )


def run_authorization_case(
    case: AuthorizationCase,
    policy: AuthorizationRuntimePolicy,
    environ: Mapping[str, str],
) -> AuthorizationRunResult:
    """Run one fully approved authorization case; not exposed by current CLIs."""
    return _run_authorization_case(
        case,
        policy,
        environ,
        _execution_factory=build_authorization_execution,
    )
