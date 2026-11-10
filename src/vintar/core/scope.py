from dataclasses import dataclass

import httpx


@dataclass(frozen=True)
class AllowedOrigin:
    scheme: str
    host: str
    port: int

    def __post_init__(self) -> None:
        if type(self.scheme) is not str:
            raise ValueError("Invalid origin scheme.")
        if type(self.host) is not str:
            raise ValueError("Invalid origin host.")

        scheme = self.scheme.lower()
        host = self.host

        if scheme not in ("http", "https"):
            raise ValueError("Unsupported origin scheme.")

        if not host:
            raise ValueError("Origin host cannot be empty.")

        if any(delimiter in host for delimiter in "/?#@"):
            raise ValueError("Invalid origin host.")

        authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
        try:
            parsed_host = httpx.URL(f"http://{authority}")
            if (
                not parsed_host.host
                or parsed_host.username
                or parsed_host.password
                or parsed_host.port is not None
                or parsed_host.path != "/"
            ):
                raise ValueError("Invalid origin host.")
            host = parsed_host.raw_host.decode("ascii").lower()
        except (UnicodeError, ValueError):
            raise ValueError("Invalid origin host.") from None

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

    port = (
        parsed.port
        if parsed.port is not None
        else (443 if parsed.scheme == "https" else 80)
    )

    origin = AllowedOrigin(
        scheme=parsed.scheme,
        host=parsed.host,
        port=port,
    )

    if origin not in policy.allowed_origins:
        raise ValueError("Target origin is outside the allowed scope.")
