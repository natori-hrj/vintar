"""Secret-free identity and credential-source contracts."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class CredentialKind(StrEnum):
    BEARER = "bearer"
    API_KEY_HEADER = "api_key_header"
    BASIC = "basic"


RESERVED_AUTH_HEADER_NAMES = frozenset({"authorization"})


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
