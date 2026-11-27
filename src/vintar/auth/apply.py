"""Resolve and apply externally supplied credentials at the dispatch boundary."""

from __future__ import annotations

import base64
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Never

import httpx

from vintar.auth.contracts import (
    CredentialKind,
    IdentityCredentialSource,
    reserved_header_names,
)
from vintar.core.request import RequestTemplate
from vintar.core.scope import AllowedOrigin
from vintar.core.template import validate_template

EXPIRY_SAFETY_MARGIN_SECONDS = 60


class AuthenticationError(ValueError):
    """A stable authentication-boundary rejection without credential material."""


def _fail(code: str, why: str, instead: str) -> AuthenticationError:
    return AuthenticationError(f"{code}: Why: {why} Instead: {instead}")


@dataclass(frozen=True, slots=True, repr=False)
class CredentialBinding:
    source: IdentityCredentialSource
    allowed_origins: frozenset[AllowedOrigin]

    def __post_init__(self) -> None:
        if type(self.source) is not IdentityCredentialSource:
            raise TypeError("Invalid credential source.")
        origins = frozenset(self.allowed_origins)
        if not origins or not all(type(item) is AllowedOrigin for item in origins):
            raise ValueError("Invalid credential origins.")
        object.__setattr__(self, "allowed_origins", origins)


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticationPlan:
    bindings: tuple[CredentialBinding, ...]
    planned_max_run_seconds: float


@dataclass(frozen=True, slots=True, repr=False)
class PlannedAuthenticatedRequest:
    identity_id: str
    template: RequestTemplate

    def __post_init__(self) -> None:
        if type(self.identity_id) is not str or not self.identity_id:
            raise ValueError("Invalid planned authentication identity.")
        if type(self.template) is not RequestTemplate:
            raise TypeError("Invalid planned request template.")


class _Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def __repr__(self) -> str:
        return "<credential redacted>"

    def __str__(self) -> Never:
        raise TypeError("Credential material cannot be converted to text.")

    def __format__(self, _spec: str) -> Never:
        raise TypeError("Credential material cannot be formatted.")

    def __eq__(self, _other: object) -> Never:
        raise TypeError("Credential material cannot be compared.")

    def __hash__(self) -> Never:
        raise TypeError("Credential material cannot be hashed.")

    def __reduce__(self) -> Never:
        raise TypeError("Credential material cannot be pickled.")

    def __copy__(self) -> Never:
        raise TypeError("Credential material cannot be copied.")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("Credential material cannot be copied.")


@dataclass(frozen=True, slots=True, repr=False)
class _ResolvedCredential:
    binding: CredentialBinding
    value: _Secret


@dataclass(frozen=True, slots=True, repr=False)
class AuthenticationRun:
    _credentials: tuple[_ResolvedCredential, ...]


AUTH_FAILURE_STATUS_CODES = frozenset({401, 403, 407})


class AuthenticatedTransport(httpx.BaseTransport):
    """Apply one resolved identity immediately before bounded dispatch."""

    def __init__(
        self,
        transport: httpx.BaseTransport,
        run: AuthenticationRun,
        *,
        identity_id: str,
        close_underlying: bool = False,
        reject_auth_failure_statuses: bool = True,
    ) -> None:
        if not isinstance(transport, httpx.BaseTransport):
            raise TypeError("Invalid authentication transport.")
        if type(run) is not AuthenticationRun or type(identity_id) is not str:
            raise TypeError("Invalid authenticated dispatch input.")
        self._transport = transport
        self._run = run
        self._identity_id = identity_id
        self._close_underlying = close_underlying
        if type(reject_auth_failure_statuses) is not bool:
            raise TypeError("Invalid authentication rejection policy.")
        self._reject_auth_failure_statuses = reject_auth_failure_statuses
        self.auth_failure_status: int | None = None
        self.auth_failure_attempt: int | None = None
        self._attempts = 0

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        apply_authentication(request, self._run, identity_id=self._identity_id)
        self._attempts += 1
        response = self._transport.handle_request(request)
        if response.status_code in AUTH_FAILURE_STATUS_CODES:
            self.auth_failure_status = response.status_code
            self.auth_failure_attempt = self._attempts
            if self._reject_auth_failure_statuses:
                response.close()
                raise httpx.RequestError(
                    "The authenticated request was rejected.", request=request
                )
        return response

    def close(self) -> None:
        if self._close_underlying:
            self._transport.close()

    @property
    def attempts(self) -> int:
        return self._attempts


def _origin(url: httpx.URL) -> AllowedOrigin:
    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.username
        or url.password
    ):
        raise _fail(
            "auth_origin_mismatch",
            "the request does not have an approved HTTP origin.",
            "dispatch only to the exact origin approved for this identity.",
        )
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    return AllowedOrigin(url.scheme, url.host, port)


def _validate_templates(
    requests: Sequence[PlannedAuthenticatedRequest],
    bindings: tuple[CredentialBinding, ...],
) -> None:
    if not requests:
        raise _fail(
            "auth_configuration_invalid",
            "the planned run has no request templates.",
            "preflight the complete non-empty request plan.",
        )
    reserved = frozenset().union(
        *(reserved_header_names(binding.source) for binding in bindings)
    )
    binding_map = {binding.source.identity_id: binding for binding in bindings}
    for planned in requests:
        if type(planned) is not PlannedAuthenticatedRequest:
            raise _fail(
                "auth_configuration_invalid",
                "the run contains an invalid planned request.",
                "supply identity-bound templates for the complete request plan.",
            )
        binding = binding_map.get(planned.identity_id)
        if (
            binding is None
            or _origin(httpx.URL(planned.template.url)) not in binding.allowed_origins
        ):
            raise _fail(
                "auth_origin_mismatch",
                "a planned request origin is outside its credential binding.",
                "bind every case and probe to the exact origin approved for its identity.",
            )
        template = planned.template
        names = [name.casefold() for name, _value in template.headers]
        if len(names) != len(set(names)) or reserved.intersection(names):
            raise _fail(
                "auth_collision",
                "a planned request contains a duplicate or provider-owned header.",
                "remove the header from every case and probe template and configure it only through authentication policy.",
            )
        validate_template(template)


def preflight_authentication(
    bindings: Sequence[CredentialBinding],
    requests: Sequence[PlannedAuthenticatedRequest],
    *,
    planned_max_run_seconds: float,
    now: datetime | None = None,
) -> AuthenticationPlan:
    """Validate the complete secret-free authentication plan."""
    normalized = tuple(bindings)
    if not normalized or not all(
        type(item) is CredentialBinding for item in normalized
    ):
        raise _fail(
            "auth_configuration_invalid",
            "the run has no valid credential bindings.",
            "supply one approved binding for each identity.",
        )
    identities = [item.source.identity_id for item in normalized]
    env_vars = [item.source.env_var for item in normalized]
    if len(identities) != len(set(identities)):
        raise _fail(
            "auth_configuration_invalid",
            "an identity has more than one credential binding.",
            "supply exactly one binding per identity.",
        )
    if len(env_vars) != len(set(env_vars)):
        raise _fail(
            "auth_configuration_invalid",
            "one secret source is assigned to multiple identities.",
            "give each identity its own environment variable.",
        )
    if (
        isinstance(planned_max_run_seconds, bool)
        or not isinstance(planned_max_run_seconds, (int, float))
        or not math.isfinite(planned_max_run_seconds)
        or planned_max_run_seconds <= 0
    ):
        raise _fail(
            "auth_configuration_invalid",
            "the planned maximum run duration is invalid.",
            "supply a finite positive upper bound for the whole run.",
        )
    instant = datetime.now(UTC) if now is None else now
    _validate_expiry(normalized, float(planned_max_run_seconds), instant)
    _validate_templates(requests, normalized)
    return AuthenticationPlan(normalized, float(planned_max_run_seconds))


def _validate_expiry(
    bindings: tuple[CredentialBinding, ...],
    planned_max_run_seconds: float,
    instant: datetime,
) -> None:
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise _fail(
            "auth_configuration_invalid",
            "the authentication clock is not timezone-aware.",
            "use an aware UTC clock.",
        )
    required_until = instant.astimezone(UTC) + timedelta(
        seconds=planned_max_run_seconds + EXPIRY_SAFETY_MARGIN_SECONDS
    )
    for binding in bindings:
        expiry = binding.source.expires_at
        if expiry is not None and (
            type(expiry) is not datetime
            or expiry.tzinfo is None
            or expiry.utcoffset() is None
        ):
            raise _fail(
                "auth_configuration_invalid",
                "the approved credential expiry is not a timezone-aware timestamp.",
                "supply an explicit UTC policy expiry.",
            )
        if expiry is not None and expiry <= required_until:
            raise _fail(
                "auth_material_expired",
                "the approved credential expiry does not cover the whole planned run and safety margin.",
                "provide a credential with a later policy expiry or shorten the plan.",
            )


def _credential_value(source: IdentityCredentialSource, value: str) -> str:
    if not value:
        raise _fail(
            "auth_material_unavailable",
            f"the approved environment variable {source.env_var} is empty.",
            f"set {source.env_var} to a non-empty {source.credential_kind.value} credential.",
        )
    if value != value.strip():
        raise _fail(
            "auth_configuration_invalid",
            "the credential has leading or trailing whitespace.",
            "supply the credential without surrounding whitespace.",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise _fail(
            "auth_configuration_invalid",
            "the credential contains a forbidden control character.",
            "supply one single-line credential value.",
        )
    if source.credential_kind is CredentialKind.BASIC:
        username, separator, password = value.partition(":")
        if not separator or not username or not password or ":" in username:
            raise _fail(
                "auth_configuration_invalid",
                "the Basic credential is not a non-empty username and password.",
                "supply username:password with a non-empty username and password.",
            )
        encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"
    try:
        value.encode("ascii")
    except UnicodeEncodeError:
        raise _fail(
            "auth_configuration_invalid",
            "the credential cannot be represented as a safe HTTP header value.",
            "supply a single-line ASCII Bearer token or API key.",
        ) from None
    if source.credential_kind is CredentialKind.BEARER:
        return f"Bearer {value}"
    return value


def resolve_credentials(
    plan: AuthenticationPlan,
    environ: Mapping[str, str],
    *,
    now: datetime | None = None,
) -> AuthenticationRun:
    """Read every approved environment-variable name exactly once for this run."""
    if type(plan) is not AuthenticationPlan:
        raise TypeError("Invalid authentication plan.")
    instant = datetime.now(UTC) if now is None else now
    _validate_expiry(
        plan.bindings,
        plan.planned_max_run_seconds,
        instant,
    )
    resolved: list[_ResolvedCredential] = []
    for binding in plan.bindings:
        name = binding.source.env_var
        try:
            raw = environ[name]
        except KeyError:
            raise _fail(
                "auth_material_unavailable",
                f"the approved environment variable {name} is missing.",
                f"set {name} to the credential for its approved identity.",
            ) from None
        if type(raw) is not str:
            raise _fail(
                "auth_configuration_invalid",
                "the credential source did not return text.",
                "supply credentials through a text environment value.",
            )
        resolved.append(
            _ResolvedCredential(
                binding, _Secret(_credential_value(binding.source, raw))
            )
        )
    return AuthenticationRun(tuple(resolved))


def apply_authentication(
    request: httpx.Request, run: AuthenticationRun, *, identity_id: str
) -> None:
    """Set only the approved credential header immediately before dispatch."""
    if type(request) is not httpx.Request or type(run) is not AuthenticationRun:
        raise TypeError("Invalid authenticated dispatch input.")
    matches = tuple(
        item
        for item in run._credentials
        if item.binding.source.identity_id == identity_id
    )
    if len(matches) != 1:
        raise _fail(
            "auth_configuration_invalid",
            "the requested identity has no unique resolved credential.",
            "resolve exactly one approved credential for the identity.",
        )
    credential = matches[0]
    if _origin(request.url) not in credential.binding.allowed_origins:
        raise _fail(
            "auth_origin_mismatch",
            "the final request origin is outside the credential binding.",
            "dispatch only to the exact origin approved for this identity.",
        )
    reserved = frozenset().union(
        *(reserved_header_names(item.binding.source) for item in run._credentials)
    )
    existing = [name.casefold() for name in request.headers]
    if reserved.intersection(existing):
        raise _fail(
            "auth_collision",
            "the final request contains a provider-owned header before authentication application.",
            "remove credential headers from case and client defaults and let the authentication boundary set only the selected identity's header.",
        )
    applied_header = credential.binding.source.header_name.casefold()
    before = (
        request.method,
        request.url,
        request.url.raw_path,
        tuple(request.headers.multi_items()),
    )
    before_stream = request.stream
    request.headers[credential.binding.source.header_name] = credential.value._value
    after = (
        request.method,
        request.url,
        request.url.raw_path,
        tuple(
            (name, value)
            for name, value in request.headers.multi_items()
            if name.casefold() != applied_header
        ),
    )
    if after != before or request.stream is not before_stream:
        raise RuntimeError("Authentication application changed a non-header field.")
    if _origin(request.url) not in credential.binding.allowed_origins:
        raise _fail(
            "auth_origin_mismatch",
            "the authenticated request origin changed before dispatch.",
            "dispatch only to the exact origin approved for this identity.",
        )
