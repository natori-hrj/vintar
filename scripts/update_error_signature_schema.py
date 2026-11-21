"""Generate the Error SQLi DBMS/signature pairs in the CI report schema."""

import argparse
import json
from collections import defaultdict
from pathlib import Path

from vintar.checks.sqli.error_signatures import ERROR_SIGNATURES

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "regression-batch-report-v1.schema.json"
_DEFINITION_PREFIX = '    "error_signature_pairs": '


def error_signature_pair_schema() -> dict[str, object]:
    """Return the deterministic schema fragment derived from the registry."""
    ids_by_dbms: dict[str, list[str]] = defaultdict(list)
    for signature_id, signature in ERROR_SIGNATURES.items():
        ids_by_dbms[signature.dbms].append(signature_id)
    return {
        "oneOf": [
            {
                "properties": {
                    "dbms": {"const": dbms},
                    "signature_id": {"enum": sorted(ids_by_dbms[dbms])},
                },
                "required": ["dbms", "signature_id"],
            }
            for dbms in sorted(ids_by_dbms)
        ]
    }


def _render_fragment(fragment: dict[str, object]) -> str:
    rendered = json.dumps(fragment, ensure_ascii=False, indent=2, sort_keys=False)
    lines = rendered.splitlines()
    return lines[0] + "\n" + "\n".join(f"    {line}" for line in lines[1:])


def update_schema(path: Path = SCHEMA_PATH) -> None:
    """Replace only the generated pair definition while preserving the schema."""
    source = path.read_text(encoding="utf-8")
    prefix_start = source.find(_DEFINITION_PREFIX)
    if prefix_start < 0:
        raise ValueError(
            "Error signature schema anchor is missing. Add the error_signature_pairs definition before regenerating the schema."
        )
    value_start = prefix_start + len(_DEFINITION_PREFIX)
    _, relative_end = json.JSONDecoder().raw_decode(source[value_start:])
    updated = (
        source[:value_start]
        + _render_fragment(error_signature_pair_schema())
        + source[value_start + relative_end :]
    )
    path.write_text(updated, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="Update the generated schema fragment."
    )
    args = parser.parse_args()
    if not args.write:
        parser.error("the schema is unchanged; pass --write to regenerate it")
    update_schema()


if __name__ == "__main__":
    main()
