from dataclasses import dataclass
from enum import StrEnum

from vintar.core.json_body import JsonBody, JsonPointer


class InjectionLocation(StrEnum):
    QUERY = "query"
    JSON_BODY = "json_body"


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
    json_body: JsonBody | None = None


@dataclass(frozen=True)
class InjectionPoint:
    location: InjectionLocation
    name: str = ""
    occurrence: int = 0
    mode: InjectionMode = InjectionMode.REPLACE
    pointer: JsonPointer | None = None

    def __post_init__(self) -> None:
        if self.occurrence < 0:
            raise ValueError("Occurrence must be non-negative.")
        if self.location is not InjectionLocation.JSON_BODY:
            if not self.name:
                raise ValueError("Query injection point name cannot be empty.")
            if self.pointer is not None:
                raise ValueError(
                    "Query injection cannot use a JSON Pointer. Remove the pointer and use a query parameter name."
                )
            return
        if self.name:
            raise ValueError(
                "JSON body injection cannot use a query name. Remove the name and use a JSON Pointer."
            )
        if type(self.pointer) is not JsonPointer:
            raise ValueError(
                "JSON body injection requires a JSON Pointer. Use JsonPointer.parse()."
            )
        if self.occurrence != 0:
            raise ValueError(
                "JSON body injection cannot select an occurrence. Use one explicit JSON Pointer."
            )
        if self.mode is not InjectionMode.REPLACE:
            raise ValueError(
                "JSON body injection does not support append. Use replace mode."
            )
