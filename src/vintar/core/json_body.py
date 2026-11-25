"""Immutable, lossless JSON request-body primitives."""

import json
import math
from dataclasses import dataclass
from typing import Never, cast

from vintar.core.strict_json import (
    DuplicateJsonKeyError,
    parse_strict_json,
    serialize_json_integer,
)

type JsonLeaf = bool | int | float | str | None
type _JsonValue = JsonLeaf | _JsonArray | _JsonObject

MAX_JSON_POINTER_CHARACTERS = 1_048_576
JSON_POINTER_TOO_LONG_MESSAGE = (
    "JSON Pointer is too long. Use a pointer of at most 1048576 characters."
)


@dataclass(frozen=True, slots=True, repr=False)
class _JsonArray:
    values: tuple[_JsonValue, ...]


@dataclass(frozen=True, slots=True, repr=False)
class _JsonObject:
    members: tuple[tuple[str, _JsonValue], ...]


def _freeze(value: object) -> _JsonValue:
    if value is None or type(value) in (bool, int, float, str):
        return cast(JsonLeaf, value)
    if isinstance(value, list):
        return _JsonArray(tuple(_freeze(child) for child in value))
    if isinstance(value, dict):
        return _JsonObject(
            tuple(sorted((key, _freeze(child)) for key, child in value.items()))
        )
    raise TypeError("Strict JSON parser returned an unsupported value type.")


def _serialize(value: _JsonValue) -> str:
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        return serialize_json_integer(value)
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError(
                "JSON body contains a non-finite float. Use a finite JSON number."
            )
        return repr(value)
    if type(value) is str:
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, _JsonArray):
        return "[" + ",".join(_serialize(child) for child in value.values) + "]"
    if not isinstance(value, _JsonObject):
        raise TypeError("JSON body contains an unsupported value type.")
    return (
        "{"
        + ",".join(
            f"{json.dumps(key, ensure_ascii=True)}:{_serialize(child)}"
            for key, child in value.members
        )
        + "}"
    )


@dataclass(frozen=True, slots=True, repr=False, init=False, eq=False)
class JsonBody:
    """An immutable strict-JSON document with deterministic serialization."""

    _value: _JsonValue
    _canonical: bytes

    def __init__(self) -> None:
        raise TypeError("JsonBody must be created with JsonBody.from_bytes().")

    @classmethod
    def _from_value(cls, value: _JsonValue) -> "JsonBody":
        body = object.__new__(cls)
        object.__setattr__(body, "_value", value)
        object.__setattr__(body, "_canonical", _serialize(value).encode("ascii"))
        return body

    @classmethod
    def from_bytes(cls, data: bytes) -> "JsonBody":
        try:
            return cls._from_value(_freeze(parse_strict_json(data)))
        except DuplicateJsonKeyError as exc:
            raise ValueError(
                "JSON body contains duplicate object member names. Use each member name once."
            ) from exc

    def to_bytes(self) -> bytes:
        """Serialize with sorted object keys and Python repr for finite floats."""
        return self._canonical

    def __eq__(self, other: object) -> bool:
        if type(other) is not JsonBody:
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self) -> int:
        return hash(self._canonical)


@dataclass(frozen=True, slots=True, init=False)
class JsonPointer:
    """A parsed RFC 6901 pointer with strict escape processing."""

    tokens: tuple[str, ...]

    def __init__(self) -> None:
        raise TypeError("JsonPointer must be created with JsonPointer.parse().")

    @classmethod
    def _from_tokens(cls, tokens: tuple[str, ...]) -> "JsonPointer":
        pointer = object.__new__(cls)
        object.__setattr__(pointer, "tokens", tokens)
        return pointer

    @classmethod
    def parse(cls, value: str) -> "JsonPointer":
        if type(value) is not str:
            raise TypeError("JSON Pointer must be a string. Use an RFC 6901 pointer.")
        if len(value) > MAX_JSON_POINTER_CHARACTERS:
            raise ValueError(JSON_POINTER_TOO_LONG_MESSAGE)
        if value == "":
            return cls._from_tokens(())
        if not value.startswith("/"):
            raise ValueError(
                "JSON Pointer must be empty or start with '/'. Use RFC 6901 pointer syntax."
            )
        tokens: list[str] = []
        for encoded in value[1:].split("/"):
            decoded: list[str] = []
            index = 0
            while index < len(encoded):
                character = encoded[index]
                if character != "~":
                    decoded.append(character)
                    index += 1
                    continue
                if index + 1 >= len(encoded) or encoded[index + 1] not in "01":
                    raise ValueError(
                        "JSON Pointer contains an invalid escape. Use ~0 for '~' and ~1 for '/'."
                    )
                decoded.append("~" if encoded[index + 1] == "0" else "/")
                index += 2
            tokens.append("".join(decoded))
        return cls._from_tokens(tuple(tokens))


def _array_index(token: str, length: int) -> int:
    if token == "-":
        raise ValueError(
            "JSON Pointer append syntax is not supported. Use an existing explicit array index."
        )
    if token == "*":
        raise ValueError(
            "JSON Pointer wildcards are not supported. Use an existing explicit array index."
        )
    if not token.isascii() or not token.isdecimal():
        raise ValueError(
            "JSON Pointer array token is not a non-negative decimal index. Use an existing explicit array index."
        )
    if len(token) > 1 and token.startswith("0"):
        raise ValueError(
            "JSON Pointer array index has a leading zero. Use its canonical decimal index."
        )
    if length == 0:
        raise ValueError(
            "JSON Pointer array index does not exist. Use an index of an existing leaf."
        )
    maximum = str(length - 1)
    if len(token) > len(maximum):
        raise ValueError(
            "JSON Pointer array index does not exist. Use an index of an existing leaf."
        )
    index = int(token)
    if index >= length:
        raise ValueError(
            "JSON Pointer array index does not exist. Use an index of an existing leaf."
        )
    return index


def _replace(
    value: _JsonValue, tokens: tuple[str, ...], replacement: JsonLeaf
) -> _JsonValue:
    if not tokens:
        if isinstance(value, (_JsonArray, _JsonObject)):
            raise ValueError(
                "JSON Pointer resolves to a container. Use a pointer to an existing leaf."
            )
        return replacement
    token, remaining = tokens[0], tokens[1:]
    if isinstance(value, _JsonObject):
        for index, (key, child) in enumerate(value.members):
            if key == token:
                members = list(value.members)
                members[index] = (key, _replace(child, remaining, replacement))
                return _JsonObject(tuple(members))
        raise ValueError(
            "JSON Pointer object member does not exist. Use a pointer to an existing leaf."
        )
    if isinstance(value, _JsonArray):
        index = _array_index(token, len(value.values))
        values = list(value.values)
        values[index] = _replace(values[index], remaining, replacement)
        return _JsonArray(tuple(values))
    raise ValueError(
        "JSON Pointer traverses through a leaf. Use a pointer to an existing leaf."
    )


def replace_json_leaf(
    body: JsonBody, pointer: JsonPointer, replacement: JsonLeaf
) -> JsonBody:
    """Return a copied body with exactly one existing leaf replaced."""
    if type(body) is not JsonBody:
        raise TypeError("JSON body must be a JsonBody. Parse strict JSON first.")
    if type(pointer) is not JsonPointer:
        raise TypeError(
            "JSON pointer must be a JsonPointer. Parse RFC 6901 syntax first."
        )
    if replacement is not None and type(replacement) not in (bool, int, float, str):
        raise TypeError(
            "JSON replacement must be a JSON leaf value. Use a scalar value."
        )
    if type(replacement) is float and not math.isfinite(replacement):
        raise ValueError("JSON replacement must be finite. Use a finite JSON number.")
    if type(replacement) is int:
        serialize_json_integer(replacement)
    return JsonBody._from_value(_replace(body._value, pointer.tokens, replacement))


def _value_at(body: JsonBody, pointer: JsonPointer) -> _JsonValue:
    if type(body) is not JsonBody:
        raise TypeError("JSON body must be a JsonBody. Parse strict JSON first.")
    if type(pointer) is not JsonPointer:
        raise TypeError(
            "JSON pointer must be a JsonPointer. Parse RFC 6901 syntax first."
        )
    value = body._value
    for token in pointer.tokens:
        if isinstance(value, _JsonObject):
            for key, child in value.members:
                if key == token:
                    value = child
                    break
            else:
                raise ValueError(
                    "JSON Pointer object member does not exist. Use a pointer to an existing leaf."
                )
        elif isinstance(value, _JsonArray):
            value = value.values[_array_index(token, len(value.values))]
        else:
            _raise_pointer_value_error(
                "JSON Pointer traverses through a leaf. Use a pointer to an existing leaf."
            )
    return value


def json_leaf_at(body: JsonBody, pointer: JsonPointer) -> JsonLeaf:
    """Return one existing leaf selected by a concrete RFC 6901 pointer."""
    value = _value_at(body, pointer)
    if isinstance(value, (_JsonArray, _JsonObject)):
        _raise_pointer_value_error(
            "JSON Pointer resolves to a container. Use a pointer to an existing leaf."
        )
    return value


def json_array_at(body: JsonBody, pointer: JsonPointer) -> None:
    """Require a concrete pointer to resolve to an existing JSON array."""
    if not isinstance(_value_at(body, pointer), _JsonArray):
        _raise_pointer_value_error(
            "JSON Pointer does not resolve to an array. Use a pointer to an existing array."
        )


def _raise_pointer_value_error(message: str) -> Never:
    raise ValueError(message)
