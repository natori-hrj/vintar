"""Pure runtime target binding for validated regression cases."""

from dataclasses import replace

import httpx

from vintar.core.scope import AllowedOrigin, ScopePolicy, validate_scope
from vintar.regression.cases import AnyRegressionCase
from vintar.regression.cases_v2 import PostJsonRegressionCase


def parse_runtime_origin(value: str) -> AllowedOrigin:
    """Parse one unambiguous HTTP(S) origin."""
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or "?" in value
        or "#" in value
        or "@" in value
        or "\\" in value
        or "%" in value
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)
    ):
        raise ValueError("Invalid origin.")

    authority = value.partition("://")[2].removesuffix("/")
    if not authority or authority.endswith(":"):
        raise ValueError("Invalid origin.")

    url = httpx.URL(value)

    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.username
        or url.password
        or url.path not in {"", "/"}
        or url.query
        or url.fragment
    ):
        raise ValueError("Invalid origin.")

    port = url.port
    if port is None:
        port = 443 if url.scheme == "https" else 80

    return AllowedOrigin(
        scheme=url.scheme,
        host=url.host,
        port=port,
    )


def bind_runtime_target(
    case: AnyRegressionCase,
    *,
    target: AllowedOrigin,
    trusted_scope: ScopePolicy,
) -> AnyRegressionCase:
    """Copy a validated case onto an independently authorized origin.

    Schema v1's original absolute origin is a placeholder in this workflow.
    The raw request path and all injection inputs remain unchanged.
    """
    if isinstance(case, PostJsonRegressionCase):
        raise TypeError(
            "Schema v2 POST JSON cases cannot be rebound before trusted POST execution is implemented."
        )
    if not isinstance(case, AnyRegressionCase):
        raise TypeError("Invalid regression case.")
    if type(target) is not AllowedOrigin:
        raise TypeError("Invalid runtime target.")
    if type(trusted_scope) is not ScopePolicy:
        raise TypeError("Invalid trusted scope.")

    if target not in trusted_scope.allowed_origins:
        raise ValueError("Runtime target is not authorized.")

    original = httpx.URL(case.template.url)
    rebound_url = original.copy_with(
        scheme=target.scheme,
        host=target.host,
        port=target.port,
    )

    if rebound_url.raw_path != original.raw_path:
        raise ValueError("Runtime target binding changed the request path.")

    rebound = replace(
        case,
        template=replace(case.template, url=str(rebound_url)),
        scope=ScopePolicy(allowed_origins=frozenset({target})),
    )

    # Case reconstruction revalidates the full injection plan.
    validate_scope(rebound.template.url, trusted_scope)
    return rebound
