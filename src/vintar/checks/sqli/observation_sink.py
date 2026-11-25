"""Trusted, in-process delivery of the exact observations used by SQLi analyzers.

This module is deliberately disconnected from case schemas and CLI configuration.
Callers may pass a sink only through the Python execution API.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum


class AttemptOutcome(StrEnum):
    """Whether one fixed-plan position returned an analyzer response."""

    RESPONSE = "response"
    NO_RESPONSE = "no_response"
    NOT_DISPATCHED = "not_dispatched"


@dataclass(frozen=True, slots=True)
class RecordedSqliObservation:
    """One trusted fixed-plan attempt with its production request identity."""

    family: str
    sequence: int
    kind: str
    observation: object | None = field(default=None, repr=False)
    outcome: AttemptOutcome = AttemptOutcome.RESPONSE
    failure: StrEnum | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.family not in {"boolean", "confirmation", "time", "error"}:
            raise ValueError("Invalid SQLi observation family.")
        if type(self.sequence) is not int or self.sequence < 1:
            raise ValueError("Invalid SQLi observation sequence.")
        if type(self.kind) is not str or not self.kind:
            raise ValueError("Invalid SQLi observation kind.")
        if not isinstance(self.outcome, AttemptOutcome):
            raise TypeError("Invalid SQLi attempt outcome.")
        if self.outcome is AttemptOutcome.RESPONSE:
            if self.observation is None or self.failure is not None:
                raise ValueError(
                    "A response attempt requires one analyzer observation and no "
                    "failure. Emit the exact runner observation instead."
                )
        elif self.observation is not None or not isinstance(self.failure, StrEnum):
            raise ValueError(
                "A response-less attempt requires one existing failure enum and no "
                "observation. Emit the bounded runner stop instead."
            )


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


def emit_attempt_stop(
    sink: SqliObservationSink | None,
    *,
    family: str,
    sequence: int,
    kind: str,
    outcome: AttemptOutcome,
    failure: StrEnum,
) -> None:
    """Deliver one no-response or pre-dispatch stop to a trusted caller."""
    if outcome is AttemptOutcome.RESPONSE:
        raise ValueError(
            "Attempt stops cannot use the response outcome. Emit a response "
            "observation instead."
        )
    if sink is not None:
        sink(
            RecordedSqliObservation(
                family=family,
                sequence=sequence,
                kind=kind,
                outcome=outcome,
                failure=failure,
            )
        )
