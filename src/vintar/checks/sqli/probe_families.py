"""Public, payload-free references to versioned built-in probe families."""

import re
from dataclasses import dataclass

_FAMILY_ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")


@dataclass(frozen=True, slots=True)
class ProbeFamilyRef:
    """An exact reference to one reviewed catalog family."""

    name: str
    version: int

    def __post_init__(self) -> None:
        if type(self.name) is not str or _FAMILY_ID.fullmatch(self.name) is None:
            raise ValueError(
                "Invalid probe family name. Why: family names use 1-64 lowercase "
                "letters, digits, dots, or hyphens. Instead: supply a documented "
                "family name."
            )
        if type(self.version) is not int or self.version < 1:
            raise ValueError(
                "Invalid probe family version. Why: a positive integer version is "
                "required. Instead: supply the documented catalog version explicitly."
            )


@dataclass(frozen=True, slots=True)
class BooleanConfirmationPreset:
    """Explicit Boolean confirmation inputs supplied by an operator or loader."""

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
