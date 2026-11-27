"""Internal, isolated execution composition for Authorization Case v1."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Self

import httpx

from vintar.auth.apply import (
    AuthenticatedTransport,
    AuthenticationError,
    CredentialBinding,
    PlannedAuthenticatedRequest,
    preflight_authentication,
    resolve_credentials,
)
from vintar.auth.contracts import reserved_header_names
from vintar.checks.authorization.models import AuthenticationMode
from vintar.core.budget import RequestBudget
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import RequestTemplate
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.core.transport import ScopedTransport
from vintar.regression.authorization_cases import AuthorizationCase
from vintar.regression.authorization_policy import AuthorizationRuntimePolicy


class AuthorizationExecutionError(ValueError):
    """A stable authorization composition rejection without operator data."""


def _fail(code: str, why: str, instead: str) -> AuthorizationExecutionError:
    return AuthorizationExecutionError(f"{code}: Why: {why} Instead: {instead}")


def _auth_error(exc: AuthenticationError) -> AuthorizationExecutionError:
    code = str(exc).partition(":")[0]
    return _fail(
        code,
        "authorization credential preflight or resolution failed.",
        "verify the protected credential configuration, expiry, and identity binding before retrying.",
    )


@dataclass(frozen=True, slots=True)
class AuthorizationExecutionSchedule:
    requests_per_second: float
    planned_max_run_seconds: float


@dataclass(frozen=True, slots=True)
class _ApprovedDispatch:
    method: str
    origin: AllowedOrigin
    raw_path: bytes


_ALLOWED_REQUEST_EXTENSION_NAMES = frozenset({"timeout"})
_HOST_HEADER_NAME = "host"


def _request_origin(url: httpx.URL) -> AllowedOrigin | None:
    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.username
        or url.password
    ):
        return None
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    try:
        return AllowedOrigin(url.scheme, url.host, port)
    except ValueError:
        return None


def _approved_dispatch(
    request: httpx.Request, approved: frozenset[_ApprovedDispatch]
) -> _ApprovedDispatch | None:
    origin = _request_origin(request.url)
    if origin is None:
        return None
    dispatch = _ApprovedDispatch(request.method, origin, request.url.raw_path)
    return dispatch if dispatch in approved else None


def _canonical_host(origin: AllowedOrigin) -> bytes:
    host = f"[{origin.host}]" if ":" in origin.host else origin.host
    default_port = 443 if origin.scheme == "https" else 80
    authority = host if origin.port == default_port else f"{host}:{origin.port}"
    return authority.encode("ascii").lower()


def _validate_host_header(request: httpx.Request, approved: _ApprovedDispatch) -> None:
    values = tuple(
        value for name, value in request.headers.raw if name.lower() == b"host"
    )
    if (
        len(values) != 1
        or any(not 0x21 <= byte <= 0x7E for byte in values[0])
        or values[0].lower() != _canonical_host(approved.origin)
    ):
        raise _fail(
            "authorization_host_header_invalid",
            "the final request does not contain exactly one canonical Host header for its approved origin.",
            "remove explicit Host headers and let the isolated authorization client generate the canonical value.",
        )


def _validate_request_extensions(request: httpx.Request) -> None:
    if not frozenset(request.extensions) <= _ALLOWED_REQUEST_EXTENSION_NAMES:
        raise _fail(
            "authorization_request_extensions_unapproved",
            "the final request contains transport metadata not created by this execution path.",
            "remove custom request extensions and dispatch only through the isolated authorization client.",
        )


class _FinalAuthorizationDispatchGuard(httpx.BaseTransport):
    """Recheck invariants immediately before the underlying pool sees a request."""

    def __init__(
        self,
        transport: httpx.BaseTransport,
        approved: frozenset[_ApprovedDispatch],
    ) -> None:
        self._transport = transport
        self._approved = approved

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        _validate_request_extensions(request)
        approved = _approved_dispatch(request, self._approved)
        if approved is None:
            raise _fail(
                "authorization_operation_unapproved",
                "the final request is not an exact operation approved for this identity.",
                "dispatch only the approved method, origin, and byte-preserved request target through its bound identity.",
            )
        _validate_host_header(request, approved)
        return self._transport.handle_request(request)

    def close(self) -> None:
        self._transport.close()


class _AuthorizationDispatchGuard(httpx.BaseTransport):
    def __init__(
        self,
        transport: httpx.BaseTransport,
        reserved: frozenset[str],
        approved: frozenset[_ApprovedDispatch],
    ) -> None:
        self._transport = transport
        self._reserved = reserved
        self._approved = approved

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        _validate_request_extensions(request)
        approved = _approved_dispatch(request, self._approved)
        if approved is None:
            raise _fail(
                "authorization_operation_unapproved",
                "the final request is not an exact operation approved for this identity.",
                "dispatch only the approved method, origin, and byte-preserved request target through its bound identity.",
            )
        _validate_host_header(request, approved)
        credential_headers = self._reserved - {_HOST_HEADER_NAME}
        if credential_headers.intersection(name.casefold() for name in request.headers):
            raise _fail(
                "auth_collision",
                "the final request contains a provider-owned header.",
                "remove credential headers from request and client defaults and configure them only through authorization policy.",
            )
        return self._transport.handle_request(request)

    def close(self) -> None:
        self._transport.close()


@dataclass(slots=True, repr=False)
class AuthorizationIdentityExecution:
    identity_id: str
    client: httpx.Client
    transport: httpx.BaseTransport


@dataclass(slots=True, repr=False)
class AuthorizationExecution:
    identities: tuple[AuthorizationIdentityExecution, ...]
    budget: RequestBudget
    rate_limiter: RateLimiter
    schedule: AuthorizationExecutionSchedule
    reserved_headers: frozenset[str]
    _closed: bool = False

    def client_for(self, identity_id: str) -> httpx.Client:
        matches = tuple(
            identity.client
            for identity in self.identities
            if identity.identity_id == identity_id
        )
        if len(matches) != 1:
            raise _fail(
                "authorization_identity_unavailable",
                "the selected identity has no unique execution context.",
                "select one identity declared by the preflighted authorization case.",
            )
        return matches[0]

    def close(self) -> None:
        if self._closed:
            return
        for identity in reversed(self.identities):
            identity.client.close()
        self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


TransportFactory = Callable[[str], httpx.BaseTransport]


def _schedule(
    operation_count: int, policy: AuthorizationRuntimePolicy
) -> AuthorizationExecutionSchedule:
    rate = policy.limits.max_requests_per_second
    duration = operation_count * policy.limits.max_timeout_seconds
    duration += (operation_count - 1) / rate
    return AuthorizationExecutionSchedule(rate, duration)


def _preflight(
    case: AuthorizationCase, policy: AuthorizationRuntimePolicy
) -> tuple[
    dict[str, frozenset[AllowedOrigin]],
    dict[str, frozenset[_ApprovedDispatch]],
    tuple[CredentialBinding, ...],
    tuple[PlannedAuthenticatedRequest, ...],
    frozenset[str],
    AuthorizationExecutionSchedule,
]:
    approvals = tuple(
        approval for approval in policy.approvals if approval.case_id == case.case_id
    )
    if not approvals or any(
        approval.case_sha256 != case.case_sha256
        or approval.environment_class != case.environment_class
        for approval in approvals
    ):
        raise _fail(
            "authorization_approval_mismatch",
            "the case is not bound to matching trusted approvals.",
            "approve the exact case digest and environment class before execution.",
        )
    case_identities = {item.identity_id: item for item in case.identities}
    policy_identities = {item.identity_id: item for item in policy.identities}
    if case_identities.keys() != policy_identities.keys() or any(
        case_identities[name].authentication != policy_identities[name].authentication
        for name in case_identities
    ):
        raise _fail(
            "authorization_identity_mismatch",
            "case and policy identities do not match exactly.",
            "approve every case identity with the same authentication mode.",
        )
    approved = {
        (
            operation.operation_id,
            operation.identity_id,
            operation.method,
            operation.path,
            operation.expected,
            approval.origin,
        )
        for approval in approvals
        for operation in approval.operations
    }
    planned = {
        (
            operation.operation_id,
            operation.identity_id,
            operation.request.method,
            operation.request.path,
            operation.expected,
            operation.request.origin,
        )
        for operation in case.operations
    }
    if approved != planned:
        raise _fail(
            "authorization_operation_mismatch",
            "case operations do not match the trusted approvals exactly.",
            "approve every exact identity, method, path, origin, and expectation.",
        )
    if len(case.operations) > policy.limits.max_requests:
        raise _fail(
            "authorization_request_budget_insufficient",
            "the shared request budget cannot cover the complete case.",
            "increase the trusted limit or reduce the reviewed case before execution.",
        )
    origins: dict[str, set[AllowedOrigin]] = {name: set() for name in case_identities}
    dispatches: dict[str, set[_ApprovedDispatch]] = {
        name: set() for name in case_identities
    }
    requests: list[PlannedAuthenticatedRequest] = []
    for operation in case.operations:
        origins[operation.identity_id].add(operation.request.origin)
        dispatches[operation.identity_id].add(
            _ApprovedDispatch(
                operation.request.method,
                operation.request.origin,
                operation.request.path.encode("ascii"),
            )
        )
        if (
            case_identities[operation.identity_id].authentication
            is AuthenticationMode.REQUIRED
        ):
            requests.append(
                PlannedAuthenticatedRequest(
                    operation.identity_id,
                    RequestTemplate(operation.request.method, operation.request.url),
                )
            )
    bindings = tuple(
        CredentialBinding(identity.credential_source, frozenset(origins[name]))
        for name, identity in policy_identities.items()
        if identity.credential_source is not None
    )
    reserved = frozenset({_HOST_HEADER_NAME}).union(
        *(reserved_header_names(binding.source) for binding in bindings)
    )
    schedule = _schedule(len(case.operations), policy)
    return (
        {name: frozenset(values) for name, values in origins.items()},
        {name: frozenset(values) for name, values in dispatches.items()},
        bindings,
        tuple(requests),
        reserved,
        schedule,
    )


def _default_transport_factory(_identity_id: str) -> httpx.BaseTransport:
    return httpx.HTTPTransport(trust_env=False, proxy=None)


def _build_authorization_execution(
    case: AuthorizationCase,
    policy: AuthorizationRuntimePolicy,
    environ: Mapping[str, str],
    *,
    transport_factory: TransportFactory,
    clock: Callable[[], float],
) -> AuthorizationExecution:
    if (
        type(case) is not AuthorizationCase
        or type(policy) is not AuthorizationRuntimePolicy
    ):
        raise TypeError("Invalid authorization execution input.")
    origins, dispatches, bindings, requests, reserved, schedule = _preflight(
        case, policy
    )
    run = None
    if bindings:
        try:
            plan = preflight_authentication(
                bindings,
                requests,
                planned_max_run_seconds=schedule.planned_max_run_seconds,
            )
            run = resolve_credentials(plan, environ)
        except AuthenticationError as exc:
            raise _auth_error(exc) from None
    budget = RequestBudget(policy.limits.max_requests)
    rate_limiter = RateLimiter(requests_per_second=schedule.requests_per_second)
    deadline = clock() + schedule.planned_max_run_seconds
    contexts: list[AuthorizationIdentityExecution] = []
    try:
        for identity in case.identities:
            underlying = transport_factory(identity.identity_id)
            final_guard = _FinalAuthorizationDispatchGuard(
                underlying, dispatches[identity.identity_id]
            )
            scoped = ScopedTransport(
                final_guard,
                ScopePolicy(frozenset(origins[identity.identity_id])),
                budget,
                rate_limiter,
                close_underlying=True,
                deadline=deadline,
                clock=clock,
            )
            active: httpx.BaseTransport = scoped
            if identity.authentication is AuthenticationMode.REQUIRED:
                if run is None:
                    raise RuntimeError("Missing resolved authorization credentials.")
                active = AuthenticatedTransport(
                    scoped,
                    run,
                    identity_id=identity.identity_id,
                    close_underlying=True,
                    reject_auth_failure_statuses=False,
                )
            guarded = _AuthorizationDispatchGuard(
                active, reserved, dispatches[identity.identity_id]
            )
            client = httpx.Client(
                transport=guarded,
                cookies=httpx.Cookies(),
                trust_env=False,
                follow_redirects=False,
                timeout=policy.limits.max_timeout_seconds,
            )
            contexts.append(
                AuthorizationIdentityExecution(identity.identity_id, client, underlying)
            )
    except Exception:
        for context in reversed(contexts):
            context.client.close()
        raise
    return AuthorizationExecution(
        tuple(contexts), budget, rate_limiter, schedule, reserved
    )


def build_authorization_execution(
    case: AuthorizationCase,
    policy: AuthorizationRuntimePolicy,
    environ: Mapping[str, str],
) -> AuthorizationExecution:
    """Build isolated identity contexts; no production caller exists in PR 2."""
    return _build_authorization_execution(
        case,
        policy,
        environ,
        transport_factory=_default_transport_factory,
        clock=time.monotonic,
    )
