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


def get_boolean_probe_preset(name: object) -> BooleanProbePreset:
    """Return one exact named preset without inferring a SQL context."""
    if type(name) is not str or name not in BOOLEAN_PROBE_PRESETS:
        valid = ", ".join(BOOLEAN_PROBE_PRESET_NAMES)
        raise ValueError(f"Unknown Boolean probe preset. Use one of: {valid}.")
    return BOOLEAN_PROBE_PRESETS[name]
