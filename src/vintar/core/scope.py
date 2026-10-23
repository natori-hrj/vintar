from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class AllowedOrigin:
    scheme: str
    host: str
    port: int

    def __post_init__(self) -> None:
        scheme = self.scheme.lower()
        host = self.host.lower()

        if scheme not in ("http", "https"):
            raise ValueError("Unsupported origin scheme.")

        if not host:
            raise ValueError("Origin host cannot be empty.")

        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("Invalid origin port.")

        object.__setattr__(self, "scheme", scheme)
        object.__setattr__(self, "host", host)


@dataclass(frozen=True)
class ScopePolicy:
    allowed_origins: frozenset[AllowedOrigin]

    def __post_init__(self) -> None:
        origins = frozenset(self.allowed_origins)

        if not origins:
            raise ValueError("At least one allowed origin is required.")

        if not all(isinstance(origin, AllowedOrigin) for origin in origins):
            raise ValueError("Invalid allowed origin.")

        object.__setattr__(self, "allowed_origins", origins)


def validate_scope(url: str, policy: ScopePolicy) -> None:
    """Reject URLs outside the configured scope."""

    try:
        parsed = httpx.URL(url)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid target URL.") from exc

    if parsed.scheme not in ("http", "https"):
        raise ValueError("Unsupported URL scheme.")

    if not parsed.host:
        raise ValueError("Target URL must have a host.")

    if parsed.username or parsed.password:
        raise ValueError("URL credentials are not allowed.")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    origin = AllowedOrigin(
        scheme=parsed.scheme,
        host=parsed.host,
        port=port,
    )

    if origin not in policy.allowed_origins:
        raise ValueError("Target origin is outside the allowed scope.")
