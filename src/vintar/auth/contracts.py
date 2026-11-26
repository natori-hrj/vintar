"""Secret-free identity and credential-source contracts."""

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class CredentialKind(StrEnum):
    BEARER = "bearer"
    API_KEY_HEADER = "api_key_header"
    BASIC = "basic"


RESERVED_AUTH_HEADER_NAMES = frozenset({"authorization"})
FORBIDDEN_API_KEY_HEADER_NAMES = frozenset(
    {
        "connection",
        "content-encoding",
        "content-length",
        "content-type",
        "cookie",
        "expect",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
_FIELD_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def validate_credential_header(kind: CredentialKind, header_name: str) -> None:
    """Validate one provider-owned HTTP field name without credential access."""
    if type(header_name) is not str or _FIELD_NAME.fullmatch(header_name) is None:
        raise ValueError("Invalid credential header name.")
    normalized = header_name.casefold()
    if kind in {CredentialKind.BEARER, CredentialKind.BASIC}:
        if normalized != "authorization":
            raise ValueError("Invalid credential header name.")
        return
    if normalized in RESERVED_AUTH_HEADER_NAMES | FORBIDDEN_API_KEY_HEADER_NAMES:
        raise ValueError("Invalid credential header name.")


def reserved_header_names(source: "IdentityCredentialSource") -> frozenset[str]:
    """Return normalized provider-owned names without resolving credentials."""
    if source.credential_kind is CredentialKind.API_KEY_HEADER:
        return RESERVED_AUTH_HEADER_NAMES | {source.header_name.casefold()}
    return RESERVED_AUTH_HEADER_NAMES


@dataclass(frozen=True, slots=True, repr=False)
class IdentityCredentialSource:
    identity_id: str
    credential_kind: CredentialKind
    env_var: str
    header_name: str
    expires_at: datetime | None

    def __post_init__(self) -> None:
        validate_credential_header(self.credential_kind, self.header_name)
