"""Explicit probe examples for exercising low-level check APIs in tests."""

from dataclasses import dataclass

from vintar.checks.sqli.probe_families import BooleanConfirmationPreset


@dataclass(frozen=True, slots=True)
class BooleanProbeExample:
    true_payload: str
    false_payload: str


def get_boolean_probe_preset(name: str) -> BooleanProbeExample:
    examples = {
        "numeric": BooleanProbeExample(" AND 1=1-- ", " AND 1=2-- "),
        "string-quoted": BooleanProbeExample("' AND 1=1-- ", "' AND 1=2-- "),
    }
    return examples[name]


def get_boolean_confirmation_preset(name: str) -> BooleanConfirmationPreset:
    examples = {
        "numeric": BooleanConfirmationPreset(
            " AND 2<3-- ", " AND 2>3-- ", " AND 7=7-- "
        ),
        "string-quoted": BooleanConfirmationPreset(
            "' AND 2<3-- ", "' AND 2>3-- ", "' AND 7=7-- "
        ),
    }
    return examples[name]
