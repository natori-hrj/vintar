"""Strict JSON parsing shared by bounded JSON consumers."""

import json
import math

MAX_STRICT_JSON_BYTES = 1_048_576
MAX_STRICT_JSON_NESTING = 48
MAX_JSON_INTEGER_DIGITS = 4_300
JSON_INTEGER_TOO_LONG_MESSAGE = (
    "JSON integer is too long. Use a string field for large identifiers."
)


class DuplicateJsonKeyError(ValueError):
    """An object contains repeated JSON member names."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON member names at every object depth."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKeyError("Duplicate JSON member name.")
        result[key] = value
    return result


class StrictJsonError(ValueError):
    """A JSON document is invalid, ambiguous, or outside supported bounds."""


def _parse_integer(source: str) -> int:
    digits = source.removeprefix("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise StrictJsonError(JSON_INTEGER_TOO_LONG_MESSAGE)
    return int(source)


def serialize_json_integer(value: int) -> str:
    """Serialize one bounded JSON integer with CPython's linear conversion."""
    try:
        text = str(value)
    except ValueError as exc:
        raise StrictJsonError(JSON_INTEGER_TOO_LONG_MESSAGE) from exc
    digits = text.removeprefix("-")
    if len(digits) > MAX_JSON_INTEGER_DIGITS:
        raise StrictJsonError(JSON_INTEGER_TOO_LONG_MESSAGE)
    return text


def _parse_float(source: str) -> float:
    try:
        value = float(source)
    except (ValueError, OverflowError) as exc:
        raise StrictJsonError(
            "JSON number is invalid. Use a valid finite JSON number."
        ) from exc
    if not math.isfinite(value):
        raise StrictJsonError(
            "JSON number is outside the finite float range. Use an integer or a finite float within Python's supported range."
        )
    return value


def _reject_constant(_source: str) -> object:
    raise StrictJsonError(
        "JSON number must be finite. Use an integer or a finite JSON number."
    )


def _check_nesting(value: object, depth: int = 0) -> None:
    if depth > MAX_STRICT_JSON_NESTING:
        raise StrictJsonError(
            f"JSON nesting exceeds {MAX_STRICT_JSON_NESTING}. Use a flatter JSON document."
        )
    if isinstance(value, dict):
        for child in value.values():
            _check_nesting(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            _check_nesting(child, depth + 1)


def parse_strict_json(data: bytes) -> object:
    """Parse bounded UTF-8 JSON, retaining integers and normalizing finite floats."""
    if type(data) is not bytes:
        raise TypeError("JSON input must be bytes. Encode the document as UTF-8 bytes.")
    if len(data) > MAX_STRICT_JSON_BYTES:
        raise StrictJsonError(
            f"JSON input exceeds {MAX_STRICT_JSON_BYTES} bytes. Use a smaller JSON document."
        )
    try:
        source = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJsonError(
            "JSON input is not valid UTF-8. Encode the document as UTF-8."
        ) from exc
    try:
        value = json.loads(
            source,
            object_pairs_hook=unique_object,
            parse_int=_parse_integer,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except DuplicateJsonKeyError:
        raise
    except StrictJsonError:
        raise
    except (ValueError, RecursionError) as exc:
        raise StrictJsonError(
            "JSON input is invalid or excessively nested. Use one bounded JSON document with no trailing data."
        ) from exc
    _check_nesting(value)
    return value
