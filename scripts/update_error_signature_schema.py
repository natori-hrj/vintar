"""Generate the Error SQLi DBMS/signature pairs in the CI report schema."""

import argparse
import json
from collections import defaultdict
from collections.abc import Mapping
from pathlib import Path

from vintar.checks.sqli.error_signatures import ERROR_SIGNATURES, ErrorSignature

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "regression-batch-report-v1.schema.json"
_DEFINITION_PREFIX = '    "error_signature_pairs": '


def error_signature_pair_schema(
    registry: Mapping[str, ErrorSignature] = ERROR_SIGNATURES,
) -> dict[str, object]:
    """Return the deterministic schema fragment derived from the registry."""
    ids_by_dbms: dict[str, list[str]] = defaultdict(list)
    for signature_id, signature in registry.items():
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


def generated_schema(
    source: str,
    registry: Mapping[str, ErrorSignature] = ERROR_SIGNATURES,
) -> str:
    """Return schema text with the registry-derived pair definition replaced."""
    prefix_start = source.find(_DEFINITION_PREFIX)
    if prefix_start < 0:
        raise ValueError(
            "Error signature schema anchor is missing. Add the error_signature_pairs definition before regenerating the schema."
        )
    value_start = prefix_start + len(_DEFINITION_PREFIX)
    _, relative_end = json.JSONDecoder().raw_decode(source[value_start:])
    updated = (
        source[:value_start]
        + _render_fragment(error_signature_pair_schema(registry))
        + source[value_start + relative_end :]
    )
    return updated


def update_schema(
    path: Path = SCHEMA_PATH,
    registry: Mapping[str, ErrorSignature] = ERROR_SIGNATURES,
) -> None:
    """Replace only the generated pair definition while preserving the schema."""
    source = path.read_text(encoding="utf-8")
    path.write_text(generated_schema(source, registry), encoding="utf-8")


def check_schema(
    path: Path = SCHEMA_PATH,
    registry: Mapping[str, ErrorSignature] = ERROR_SIGNATURES,
) -> None:
    """Reject a committed schema whose generated fragment is stale."""
    source = path.read_text(encoding="utf-8")
    if source != generated_schema(source, registry):
        raise ValueError(
            "Error signature schema is stale. Run scripts/update_error_signature_schema.py --write and commit the regenerated schema."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument(
        "--write", action="store_true", help="Update the generated schema fragment."
    )
    action.add_argument(
        "--check", action="store_true", help="Fail if the generated fragment is stale."
    )
    args = parser.parse_args()
    if args.write:
        update_schema()
    else:
        check_schema()


if __name__ == "__main__":
    main()
