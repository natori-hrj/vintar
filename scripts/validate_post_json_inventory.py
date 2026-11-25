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

_ROOT = Path(__file__).resolve().parents[1]
_SCHEMA = _ROOT / "schemas" / "openapi-post-json-inventory-v1.schema.json"
_MAX_REPORT_BYTES = 2_097_152
_ERROR_MESSAGE = (
    "Vintar: POST JSON inventory validation failed. "
    "Regenerate the report with the current Vintar version and try again."
)
_POINTER = re.compile(r"(?:/(?:[^~/]|~[01])*)*")
_BLOCKING_REASONS = (
    "post_method_unsupported",
    "request_body_case_generation_unsupported",
)


def _read_bounded(path: Path) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("Report is not a regular file.")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("Report is not a regular file.")
        data = bytearray()
        while len(data) <= _MAX_REPORT_BYTES:
            chunk = os.read(descriptor, min(65_536, _MAX_REPORT_BYTES + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(descriptor)
    if len(data) > _MAX_REPORT_BYTES:
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

    field_count = injectable_count = diagnostic_count = 0
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
            if (field["injectable"] and reasons) or (
                not field["injectable"] and not reasons
            ):
                raise ValueError("Injectability contradicts reasons.")
            field_count += 1
            injectable_count += int(field["injectable"])

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

    expected = {
        "operations": len(operations),
        "case_generatable": 0,
        "fields": field_count,
        "injectable_fields": injectable_count,
        "unsupported_inputs": field_count - injectable_count,
        "diagnostics": diagnostic_count,
    }
    if any(counts[name] != value for name, value in expected.items()):
        raise ValueError("Report counts are inconsistent.")


def _validate(path: Path) -> None:
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.check_schema(schema)
    report = json.loads(_read_bounded(path).decode("utf-8"))
    validator.validate(report)
    if not isinstance(report, dict):
        raise TypeError("Invalid report shape.")
    _semantic_validate(report)


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError("Invalid arguments.")
        _validate(Path(sys.argv[1]))
        return 0
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
