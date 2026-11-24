"""Trusted, in-process delivery of the exact observations used by SQLi analyzers.

This module is deliberately disconnected from case schemas and CLI configuration.
Callers may pass a sink only through the Python execution API.
"""

from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class RecordedSqliObservation:
    """One analyzer observation with its production request identity."""

    family: str
    sequence: int
    kind: str
    observation: object = field(repr=False)

    def __post_init__(self) -> None:
        if self.family not in {"boolean", "confirmation", "time", "error"}:
            raise ValueError("Invalid SQLi observation family.")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("Invalid SQLi observation sequence.")
        if type(self.kind) is not str or not self.kind:
            raise ValueError("Invalid SQLi observation kind.")


SqliObservationSink = Callable[[RecordedSqliObservation], None]


def emit_observation(
    sink: SqliObservationSink | None,
    *,
    family: str,
    sequence: int,
    kind: str,
    observation: object,
) -> None:
    """Deliver an immutable observation to a trusted caller when configured."""
    if sink is not None:
        sink(RecordedSqliObservation(family, sequence, kind, observation))
