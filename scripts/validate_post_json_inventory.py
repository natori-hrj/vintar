#!/usr/bin/env python3
"""Validate a POST JSON inventory without disclosing report contents."""

import json
import os
import re
import stat
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from vintar.core.strict_json import DuplicateJsonKeyError, unique_object
from vintar.regression.post_json_inventory import MAX_REPORT_BYTES

_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS = {
    version: _ROOT / "schemas" / f"openapi-post-json-inventory-v{version}.schema.json"
    for version in (1, 2)
}
_SCHEMA = _SCHEMAS[1]
_ERROR_MESSAGE = (
    "Vintar: POST JSON inventory validation failed. "
    "Regenerate the report with the current Vintar version and try again."
)
_DUPLICATE_KEY_MESSAGE = (
    "Vintar: POST JSON inventory validation failed. "
    "Duplicate JSON keys make the report ambiguous across parsers. "
    "Regenerate the report with vintar inventory-post-json."
)
_INJECTABLE_MESSAGE = (
    "Vintar: POST JSON inventory validation failed. "
    "Version 1 never marks POST fields injectable. "
    "Regenerate the report with vintar inventory-post-json."
)
_POINTER = re.compile(r"(?:/(?:[^~/]|~[01])*)*")
_BLOCKING_REASONS = (
    "post_method_unsupported",
    "request_body_case_generation_unsupported",
)


class InjectableFieldError(ValueError):
    """A v1 report claims a POST field is injectable."""


def _read_bounded(path: Path) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Report is not a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Report is not a regular file.")
        data = bytearray()
        while len(data) <= MAX_REPORT_BYTES:
            chunk = os.read(descriptor, min(65_536, MAX_REPORT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Report exceeds the size limit.")
    return bytes(data)


def _is_pointer(value: object) -> bool:
    return isinstance(value, str) and _POINTER.fullmatch(value) is not None


def _semantic_validate(report: dict[str, object]) -> None:
    operations = report["operations"]
    counts = report["counts"]
    if not isinstance(operations, list) or not isinstance(counts, dict):
        raise TypeError("Invalid report shape.")
    operation_keys = [
        (operation["path"], operation["operation_pointer"]) for operation in operations
    ]
    if operation_keys != sorted(operation_keys) or len(operation_keys) != len(
        set(operation_keys)
    ):
        raise ValueError("Operations are unordered or duplicated.")

    field_count = diagnostic_count = 0
    for operation in operations:
        if (
            operation["case_generation"] != "unsupported"
            or tuple(operation["blocking_reasons"]) != _BLOCKING_REASONS
        ):
            raise ValueError("Case generation contradicts blocking reasons.")
        for pointer_name in (
            "operation_pointer",
            "request_body_pointer",
        ):
            if not _is_pointer(operation[pointer_name]):
                raise ValueError("Invalid operation pointer.")

        auth = operation["auth"]
        alternatives = auth["alternatives"]
        public = not alternatives or any(not item["schemes"] for item in alternatives)
        if auth["public"] is not public:
            raise ValueError("Public authentication status is contradictory.")
        if auth["source"] == "none" and (not auth["public"] or alternatives):
            raise ValueError("Unspecified authentication is contradictory.")
        alternative_keys: list[tuple[str, ...]] = []
        for alternative in alternatives:
            schemes = alternative["schemes"]
            names = [scheme["name"] for scheme in schemes]
            if names != sorted(names) or len(names) != len(set(names)):
                raise ValueError("Authentication schemes are unordered or duplicated.")
            alternative_keys.append(tuple(names))
        if alternative_keys != sorted(alternative_keys) or len(alternative_keys) != len(
            set(alternative_keys)
        ):
            raise ValueError("Authentication alternatives are unordered or duplicated.")

        fields = operation["fields"]
        field_keys = [
            (field["json_pointer"], field["schema_pointer"]) for field in fields
        ]
        if field_keys != sorted(field_keys) or len(field_keys) != len(set(field_keys)):
            raise ValueError("Fields are unordered or duplicated.")
        for field in fields:
            if not all(
                _is_pointer(field[name])
                for name in (
                    "json_pointer",
                    "schema_pointer",
                    "schema_definition_pointer",
                )
            ):
                raise ValueError("Invalid field pointer.")
            types = field["types"]
            if types != sorted(types) or len(types) != len(set(types)):
                raise ValueError("Field types are unordered or duplicated.")
            reasons = field["reasons"]
            if reasons != sorted(reasons) or len(reasons) != len(set(reasons)):
                raise ValueError("Field reasons are unordered or duplicated.")
            if field["injectable"] is not False:
                raise InjectableFieldError(_INJECTABLE_MESSAGE)
            if not reasons:
                raise ValueError("Injectability contradicts reasons.")
            field_count += 1

        diagnostics = operation["diagnostics"]
        diagnostic_keys = [
            (
                item["schema_pointer"],
                item["schema_definition_pointer"] or "",
                item["reason"],
            )
            for item in diagnostics
        ]
        if diagnostic_keys != sorted(diagnostic_keys) or len(diagnostic_keys) != len(
            set(diagnostic_keys)
        ):
            raise ValueError("Diagnostics are unordered or duplicated.")
        for diagnostic in diagnostics:
            if not _is_pointer(diagnostic["schema_pointer"]) or (
                diagnostic["schema_definition_pointer"] is not None
                and not _is_pointer(diagnostic["schema_definition_pointer"])
            ):
                raise ValueError("Invalid diagnostic pointer.")
        diagnostic_count += len(diagnostics)

        candidates = operation.get("review_candidates", [])
        candidate_ids = [candidate["candidate_id"] for candidate in candidates]
        if candidate_ids != sorted(candidate_ids) or len(candidate_ids) != len(
            set(candidate_ids)
        ):
            raise ValueError("Review candidates are unordered or duplicated.")
        if report["schema_version"] == 2:
            expected_candidates = (
                0
                if diagnostics
                else sum(tuple(field["types"]) == ("string",) for field in fields)
            )
            if len(candidates) != expected_candidates:
                raise ValueError("Review candidate coverage is inconsistent.")
        for candidate in candidates:
            if candidate["approval"] != "unapproved" or diagnostics:
                raise ValueError("Review candidate contradicts its operation field.")

    expected = {
        "operations": len(operations),
        "case_generatable": 0,
        "fields": field_count,
        "injectable_fields": 0,
        "unsupported_inputs": field_count,
        "diagnostics": diagnostic_count,
    }
    if any(counts[name] != value for name, value in expected.items()):
        raise ValueError("Report counts are inconsistent.")


def _validate(path: Path) -> None:
    raw = _read_bounded(path)
    report = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    if not isinstance(report, dict) or type(report.get("schema_version")) is not int:
        raise TypeError("Invalid report shape.")
    schema_path = _SCHEMAS.get(report["schema_version"])
    if schema_path is None:
        raise ValueError("Unsupported report version.")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.check_schema(schema)
    try:
        validator.validate(report)
    except ValidationError as exc:
        if tuple(exc.absolute_schema_path)[-2:] == ("injectable", "const"):
            raise InjectableFieldError(_INJECTABLE_MESSAGE) from exc
        raise
    _semantic_validate(report)


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError("Invalid arguments.")
        _validate(Path(sys.argv[1]))
        return 0
    except InjectableFieldError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except DuplicateJsonKeyError:
        print(_DUPLICATE_KEY_MESSAGE, file=sys.stderr)
        return 2
    except (OSError, UnicodeError, TypeError, ValueError, ValidationError, SchemaError):
        print(_ERROR_MESSAGE, file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        code = main()
    except Exception as exc:
        print(_ERROR_MESSAGE, file=sys.stderr)
        raise SystemExit(2) from exc
    raise SystemExit(code)
