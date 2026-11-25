"""Pure cross-phase consistency assessment for Boolean SQLi.

Evaluates existing evidence without HTTP I/O.
This module does not modify ConfirmationOutcome or Verdict.

MATCH means response signatures agree across phases.
It does not prove SQL execution or a SQL injection vulnerability.
"""

from dataclasses import dataclass
from enum import StrEnum

from vintar.checks.sqli.confirmation import (
    ConfirmationKind,
    confirmation_eligible,
)
from vintar.checks.sqli.confirmation_runner import (
    ConfirmationEvidence,
    ConfirmationObservation,
)
from vintar.checks.sqli.models import (
    Observation,
    ProbeKind,
    VerificationResult,
)


class CrossPhaseStatus(StrEnum):
    MATCH = "match"
    MISMATCH = "mismatch"


@dataclass(frozen=True, slots=True)
class CrossPhaseAssessment:
    """Non-sensitive cross-phase comparison result.

    MATCH only means the supplied response signatures agree. It does
    not establish input provenance, SQL execution, or vulnerability.
    """

    status: CrossPhaseStatus
    mismatched_kinds: tuple[ProbeKind, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.status, CrossPhaseStatus):
            raise TypeError("Invalid cross-phase status.")

        if type(self.mismatched_kinds) is not tuple:
            raise TypeError("Invalid mismatched kinds.")

        allowed = (
            ProbeKind.BASELINE,
            ProbeKind.TRUE,
            ProbeKind.FALSE,
        )

        if any(not isinstance(kind, ProbeKind) for kind in self.mismatched_kinds):
            raise TypeError("Invalid mismatched probe kind.")

        if self.mismatched_kinds != tuple(
            kind for kind in allowed if kind in self.mismatched_kinds
        ):
            raise ValueError("Invalid mismatched probe ordering.")

        if self.status is CrossPhaseStatus.MATCH:
            if self.mismatched_kinds:
                raise ValueError("MATCH cannot have mismatches.")

        elif not self.mismatched_kinds:
            raise ValueError("MISMATCH requires mismatched kinds.")

    @property
    def consistent(self) -> bool:
        return self.status is CrossPhaseStatus.MATCH


def _signature(
    observation: Observation | ConfirmationObservation,
) -> tuple[int, int, str]:
    return (
        observation.status_code,
        observation.body_size,
        observation.body_digest,
    )


def assess_cross_phase_consistency(
    *,
    initial: VerificationResult,
    confirmation: ConfirmationEvidence,
) -> CrossPhaseAssessment:
    """Compare baseline, true_1 and false_1 across both stages.

    Preconditions:
    - initial is a complete, eligible six-probe candidate
    - confirmation is validated, complete twelve-probe evidence

    The function does not establish provenance or authorization.
    Both inputs must originate from the same trusted Runner execution.

    Raw responses, request templates, headers, cookies, and payloads
    are not read, retained, or returned.
    """
    if type(initial) is not VerificationResult:
        raise TypeError("Invalid initial result.")

    if type(confirmation) is not ConfirmationEvidence:
        raise TypeError("Invalid confirmation evidence.")

    if not confirmation_eligible(initial):
        raise ValueError("Initial result is not eligible.")

    return assess_cross_phase_observations(
        initial=initial.observations,
        confirmation=confirmation.observations,
    )


def assess_cross_phase_observations(
    *,
    initial: tuple[Observation, ...],
    confirmation: tuple[ConfirmationObservation, ...],
) -> CrossPhaseAssessment:
    """Compare complete sanitized initial and confirmation observations."""
    if type(initial) is not tuple or any(
        type(item) is not Observation for item in initial
    ):
        raise TypeError("Invalid initial observations.")
    if type(confirmation) is not tuple or any(
        type(item) is not ConfirmationObservation for item in confirmation
    ):
        raise TypeError("Invalid confirmation observations.")
    mapping = (
        (ProbeKind.BASELINE, ConfirmationKind.BASELINE),
        (ProbeKind.TRUE, ConfirmationKind.TRUE_1),
        (ProbeKind.FALSE, ConfirmationKind.FALSE_1),
    )

    mismatches: list[ProbeKind] = []

    for initial_kind, confirmation_kind in mapping:
        initial_items = tuple(item for item in initial if item.kind is initial_kind)

        confirmation_items = tuple(
            item for item in confirmation if item.kind is confirmation_kind
        )

        if len(initial_items) != 2 or len(confirmation_items) != 2:
            raise ValueError(
                "Cross-phase comparison requires two observations for each mapped "
                "kind. Use complete analyzer-produced observations."
            )

        # Both pairs were already checked for internal stability
        # by confirmation_eligible and ConfirmationEvidence.
        initial_signature = _signature(initial_items[0])
        confirmation_signature = _signature(confirmation_items[0])

        if initial_signature != confirmation_signature:
            mismatches.append(initial_kind)

    return CrossPhaseAssessment(
        status=(CrossPhaseStatus.MISMATCH if mismatches else CrossPhaseStatus.MATCH),
        mismatched_kinds=tuple(mismatches),
    )
