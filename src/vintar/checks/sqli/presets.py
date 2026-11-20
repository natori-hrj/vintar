"""Reviewed, offline Boolean SQLi probe presets."""

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class BooleanProbePreset:
    """One reviewed TRUE/FALSE payload pair for an explicit SQL context."""

    true_payload: str
    false_payload: str

    def __post_init__(self) -> None:
        if (
            type(self.true_payload) is not str
            or type(self.false_payload) is not str
            or not self.true_payload
            or not self.false_payload
            or self.true_payload == self.false_payload
        ):
            raise ValueError("Probe preset payloads must be distinct nonempty strings.")


@dataclass(frozen=True, slots=True)
class BooleanConfirmationPreset:
    """Reviewed predicates used after an eligible Boolean candidate."""

    true_payload: str
    false_payload: str
    baseline_preserving_control: str

    def __post_init__(self) -> None:
        values = (
            self.true_payload,
            self.false_payload,
            self.baseline_preserving_control,
        )
        if any(type(value) is not str or not value for value in values):
            raise ValueError("Confirmation preset payloads must be nonempty strings.")
        if len(set(values)) != len(values):
            raise ValueError("Confirmation preset payloads must be distinct.")


BOOLEAN_PROBE_PRESETS: Mapping[str, BooleanProbePreset] = MappingProxyType(
    {
        "numeric": BooleanProbePreset(
            true_payload=" AND 1=1-- ",
            false_payload=" AND 1=2-- ",
        ),
        "string-quoted": BooleanProbePreset(
            true_payload="' AND 1=1-- ",
            false_payload="' AND 1=2-- ",
        ),
    }
)
BOOLEAN_PROBE_PRESET_NAMES = tuple(sorted(BOOLEAN_PROBE_PRESETS))

BOOLEAN_CONFIRMATION_PRESETS: Mapping[str, BooleanConfirmationPreset] = (
    MappingProxyType(
        {
            "numeric": BooleanConfirmationPreset(
                true_payload=" AND 2<3-- ",
                false_payload=" AND 2>3-- ",
                baseline_preserving_control=" AND 7=7-- ",
            ),
            "string-quoted": BooleanConfirmationPreset(
                true_payload="' AND 2<3-- ",
                false_payload="' AND 2>3-- ",
                baseline_preserving_control="' AND 7=7-- ",
            ),
        }
    )
)

if BOOLEAN_CONFIRMATION_PRESETS.keys() != BOOLEAN_PROBE_PRESETS.keys():
    raise ValueError("Confirmation presets must match the Boolean probe preset names.")

for _name, _confirmation in BOOLEAN_CONFIRMATION_PRESETS.items():
    _initial = BOOLEAN_PROBE_PRESETS[_name]
    if (
        len(
            {
                _initial.true_payload,
                _initial.false_payload,
                _confirmation.true_payload,
                _confirmation.false_payload,
                _confirmation.baseline_preserving_control,
            }
        )
        != 5
    ):
        raise ValueError(
            "Initial and confirmation preset payloads must all be distinct."
        )


def get_boolean_probe_preset(name: object) -> BooleanProbePreset:
    """Return one exact named preset without inferring a SQL context."""
    if type(name) is not str or name not in BOOLEAN_PROBE_PRESETS:
        valid = ", ".join(BOOLEAN_PROBE_PRESET_NAMES)
        raise ValueError(f"Unknown Boolean probe preset. Use one of: {valid}.")
    return BOOLEAN_PROBE_PRESETS[name]


def get_boolean_confirmation_preset(name: object) -> BooleanConfirmationPreset:
    """Return one exact confirmation preset without inferring a SQL context."""
    if type(name) is not str or name not in BOOLEAN_CONFIRMATION_PRESETS:
        valid = ", ".join(BOOLEAN_PROBE_PRESET_NAMES)
        raise ValueError(f"Unknown Boolean confirmation preset. Use one of: {valid}.")
    return BOOLEAN_CONFIRMATION_PRESETS[name]
