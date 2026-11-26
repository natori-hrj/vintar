#!/usr/bin/env python3
"""Validate a redacted POST JSON discovery review artifact."""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from vintar.core.strict_json import DuplicateJsonKeyError, unique_object
from vintar.regression.post_json_review import MAX_REVIEW_BYTES, concrete_review_pointer

_ROOT = Path(__file__).resolve().parents[1]
_SCHEMAS = {
    1: _ROOT / "schemas" / "post-json-discovery-review-v1.schema.json",
    2: _ROOT / "schemas" / "post-json-discovery-review-v2.schema.json",
}
_ERROR = (
    "Vintar: POST JSON review validation failed. Regenerate the review from the "
    "current inventory and explicit answers."
)


def _validate(path: Path) -> None:
    data = path.read_bytes()
    if len(data) > MAX_REVIEW_BYTES:
        raise ValueError("Review exceeds its size limit.")
    report = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    if not isinstance(report, dict):
        raise TypeError("Invalid review shape.")
    schema_path = _SCHEMAS.get(report.get("schema_version"))
    if schema_path is None:
        raise ValueError("Unsupported review schema version.")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    validator.check_schema(schema)
    validator.validate(report)
    operation = report["operation"]
    field = report["field"]
    if operation["approved"] is not True:
        raise ValueError("Operation is not explicitly approved.")
    if report["side_effect"]["confirmed"] is not True:
        raise ValueError("Side effect is not explicitly confirmed.")
    if report["environment"]["confirmed"] is not True:
        raise ValueError("Environment is not explicitly confirmed.")
    concrete_review_pointer(
        field["json_pointer_pattern"],
        field["concrete_json_pointer"],
        tuple(field.get("literal_star_positions", [])),
    )


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError("Invalid arguments.")
        _validate(Path(sys.argv[1]))
        return 0
    except (
        DuplicateJsonKeyError,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        ValidationError,
        SchemaError,
    ):
        print(_ERROR, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
