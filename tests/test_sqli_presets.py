"""Contracts for the reviewed offline Boolean SQLi probe presets."""

from dataclasses import FrozenInstanceError

import pytest

from vintar.checks.sqli.presets import (
    BOOLEAN_PROBE_PRESET_NAMES,
    BOOLEAN_PROBE_PRESETS,
    BooleanProbePreset,
    get_boolean_probe_preset,
)


def test_boolean_probe_presets_are_exact_and_sorted():
    assert BOOLEAN_PROBE_PRESET_NAMES == ("numeric", "string-quoted")
    assert BOOLEAN_PROBE_PRESETS == {
        "numeric": BooleanProbePreset(" AND 1=1-- ", " AND 1=2-- "),
        "string-quoted": BooleanProbePreset("' AND 1=1-- ", "' AND 1=2-- "),
    }
    assert all(
        get_boolean_probe_preset(name) is BOOLEAN_PROBE_PRESETS[name]
        for name in BOOLEAN_PROBE_PRESET_NAMES
    )


def test_boolean_probe_presets_are_immutable():
    preset = get_boolean_probe_preset("numeric")
    with pytest.raises(FrozenInstanceError):
        preset.true_payload = "changed"
    with pytest.raises(TypeError):
        BOOLEAN_PROBE_PRESETS["new"] = preset


@pytest.mark.parametrize("name", ["unknown", "Numeric", "", 1, [], None])
def test_unknown_boolean_probe_preset_lists_valid_options(name):
    with pytest.raises(ValueError, match=r"Use one of: numeric, string-quoted\."):
        get_boolean_probe_preset(name)


@pytest.mark.parametrize(
    ("true_payload", "false_payload"),
    [("", "false"), ("true", ""), ("same", "same"), (1, "false")],
)
def test_boolean_probe_preset_rejects_invalid_payloads(true_payload, false_payload):
    with pytest.raises(ValueError, match="distinct nonempty strings"):
        BooleanProbePreset(true_payload, false_payload)
