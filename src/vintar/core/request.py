from dataclasses import dataclass
from enum import StrEnum


class InjectionLocation(StrEnum):
    QUERY = "query"


class InjectionMode(StrEnum):
    REPLACE = "replace"
    APPEND = "append"


@dataclass(frozen=True)
class RequestTemplate:
    method: str
    url: str
    headers: tuple[tuple[str, str], ...] = ()
    cookies: tuple[tuple[str, str], ...] = ()
    params: tuple[tuple[str, str], ...] = ()
    body: bytes | None = None


@dataclass(frozen=True)
class InjectionPoint:
    location: InjectionLocation
    name: str
    occurrence: int = 0
    mode: InjectionMode = InjectionMode.REPLACE

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("Injection point name cannot be empty.")

        if self.occurrence < 0:
            raise ValueError("Occurrence must be non-negative.")
