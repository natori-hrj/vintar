"""Prepare an authorized, immutable SQLi confirmation plan.

This module only prepares and validates requests. It performs no HTTP I/O.

The confirmation stage is twelve *additional* probes after the existing
six-probe Boolean check. Both stages must share one ExecutionContext
with an eighteen-request budget.

A confirmed response pattern must not be interpreted as proof of SQLi.
"""

import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

from vintar.checks.sqli.models import (
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.request import InjectionPoint, RequestTemplate
from vintar.core.scope import validate_scope
from vintar.core.template import validate_template

INITIAL_REQUESTS = 6
CONFIRMATION_REQUESTS = 12
TOTAL_REQUESTS = INITIAL_REQUESTS + CONFIRMATION_REQUESTS

MAX_PAYLOAD_LENGTH = 512
MAX_CONTROL_LENGTH = 128
CONTROL_PREFIX = "__vintar_control_"
MIN_CONTROL_SUFFIX_LENGTH = 8


class ConfirmationKind(StrEnum):
    BASELINE = "baseline"
    TRUE_1 = "true_1"
    FALSE_1 = "false_1"
    CONTROL = "control"
    TRUE_2 = "true_2"
    FALSE_2 = "false_2"


CONFIRMATION_ORDER = (
    ConfirmationKind.BASELINE,
    ConfirmationKind.TRUE_1,
    ConfirmationKind.FALSE_1,
    ConfirmationKind.CONTROL,
    ConfirmationKind.TRUE_2,
    ConfirmationKind.FALSE_2,
    ConfirmationKind.BASELINE,
    ConfirmationKind.FALSE_2,
    ConfirmationKind.TRUE_2,
    ConfirmationKind.CONTROL,
    ConfirmationKind.FALSE_1,
    ConfirmationKind.TRUE_1,
)


@dataclass(frozen=True, slots=True, repr=False)
class ConfirmationPayloads:
    """Trusted probe suffixes.

    Values are raw strings. Encoding belongs to the HTTP transport.

    The control is supplied by the caller. A future execution layer
    should generate a fresh control once per run, then reuse it for
    both control probes.
    """

    true_1: str = field(repr=False)
    false_1: str = field(repr=False)
    true_2: str = field(repr=False)
    false_2: str = field(repr=False)
    control: str = field(repr=False)

    def __post_init__(self) -> None:
        boolean_values = (
            self.true_1,
            self.false_1,
            self.true_2,
            self.false_2,
        )

        for value in boolean_values:
            if type(value) is not str:
                raise TypeError("Invalid confirmation payload.")
            if not 0 < len(value) <= MAX_PAYLOAD_LENGTH:
                raise ValueError("Invalid confirmation payload.")
            if any(unicodedata.category(ch).startswith("C") for ch in value):
                raise ValueError("Invalid confirmation payload.")

        if len(set(boolean_values)) != 4:
            raise ValueError("Confirmation payloads must be distinct.")

        if type(self.control) is not str:
            raise TypeError("Invalid confirmation control.")

        if not 0 < len(self.control) <= MAX_CONTROL_LENGTH:
            raise ValueError("Invalid confirmation control.")

        if not self.control.startswith(CONTROL_PREFIX):
            raise ValueError("Invalid confirmation control.")

        if not all(ch.isascii() and (ch.isalnum() or ch == "_") for ch in self.control):
            raise ValueError("Invalid confirmation control.")

        suffix = self.control[len(CONTROL_PREFIX) :]
        if len(suffix) < MIN_CONTROL_SUFFIX_LENGTH:
            raise ValueError("Invalid confirmation control.")

        if self.control in boolean_values:
            raise ValueError("Confirmation control must be distinct.")


@dataclass(frozen=True, slots=True, repr=False)
class ConfirmationStep:
    kind: ConfirmationKind
    template: RequestTemplate = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ConfirmationKind):
            raise TypeError("Invalid confirmation probe kind.")

        if not isinstance(self.template, RequestTemplate):
            raise TypeError("Invalid confirmation template.")

        try:
            validate_template(self.template)
        except (TypeError, ValueError):
            raise ValueError("Invalid confirmation template.") from None


@dataclass(frozen=True, slots=True, repr=False)
class ConfirmationPlan:
    """Structurally validated plan, with no execution side effects.

    Do not serialize request templates into reports: they may contain
    authorization headers, cookies, or injected payloads.

    Scope authorization is only established by prepare_confirmation_plan.
    An execution layer must still use ExecutionContext for every request.
    """

    steps: tuple[ConfirmationStep, ...] = field(repr=False)
    point: InjectionPoint = field(repr=False)
    payloads: ConfirmationPayloads = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.steps) is not tuple:
            raise TypeError("Confirmation steps must be a tuple.")

        if len(self.steps) != CONFIRMATION_REQUESTS:
            raise ValueError("Invalid confirmation plan length.")

        if not all(isinstance(step, ConfirmationStep) for step in self.steps):
            raise TypeError("Invalid confirmation step.")

        if tuple(step.kind for step in self.steps) != CONFIRMATION_ORDER:
            raise ValueError("Invalid confirmation probe order.")

        if not isinstance(self.point, InjectionPoint):
            raise TypeError("Invalid confirmation injection point.")
        if not isinstance(self.payloads, ConfirmationPayloads):
            raise TypeError("Invalid confirmation payloads.")

        baseline = self.steps[0].template

        try:
            expected = {
                ConfirmationKind.BASELINE: baseline,
                ConfirmationKind.TRUE_1: inject(
                    baseline, self.point, self.payloads.true_1
                ),
                ConfirmationKind.FALSE_1: inject(
                    baseline, self.point, self.payloads.false_1
                ),
                ConfirmationKind.TRUE_2: inject(
                    baseline, self.point, self.payloads.true_2
                ),
                ConfirmationKind.FALSE_2: inject(
                    baseline, self.point, self.payloads.false_2
                ),
                ConfirmationKind.CONTROL: inject(
                    baseline, self.point, self.payloads.control
                ),
            }

            if len(set(expected.values())) != len(expected):
                raise ValueError
            if any(step.template != expected[step.kind] for step in self.steps):
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("Invalid confirmation plan templates.") from None

    @property
    def request_count(self) -> int:
        return len(self.steps)


def confirmation_eligible(
    initial: VerificationResult,
) -> bool:
    """Only a complete six-probe Boolean candidate may continue."""
    if not isinstance(initial, VerificationResult):
        raise TypeError("Invalid initial verification result.")

    if not (
        initial.verdict is Verdict.INCONCLUSIVE
        and initial.reason_code == "boolean_candidate"
        and initial.request_count == INITIAL_REQUESTS
        and len(initial.observations) == INITIAL_REQUESTS
        and not initial.failures
        and initial.evidence is not None
    ):
        return False

    counts = Counter(observation.kind for observation in initial.observations)
    if counts != Counter(
        {
            ProbeKind.BASELINE: 2,
            ProbeKind.TRUE: 2,
            ProbeKind.FALSE: 2,
        }
    ):
        return False

    if any(
        observation.truncated or not 200 <= observation.status_code < 300
        for observation in initial.observations
    ):
        return False

    for kind in ProbeKind:
        pair = tuple(
            observation
            for observation in initial.observations
            if observation.kind is kind
        )
        left, right = pair
        if (
            left.status_code,
            left.body_size,
            left.body_digest,
        ) != (
            right.status_code,
            right.body_size,
            right.body_digest,
        ):
            return False

    return (
        initial.evidence.baseline_true_similarity == 1.0
        and initial.evidence.baseline_false_similarity == 0.0
        and initial.evidence.true_false_similarity == 0.0
    )


def prepare_confirmation_plan(
    *,
    initial: VerificationResult,
    template: RequestTemplate,
    point: InjectionPoint,
    payloads: ConfirmationPayloads,
    context: ExecutionContext,
) -> ConfirmationPlan | None:
    """Validate all twelve requests before returning an execution plan.

    Return None if the initial result is not eligible.

    Invalid inputs or insufficient budget are rejected without sending
    any requests or consuming any request budget.

    This is not a DNS/IP egress security boundary. Network-level
    isolation remains necessary in untrusted CI environments.

    VerificationResult does not carry target or InjectionPoint provenance.
    Budget counters therefore cannot prove that ``initial`` came from this
    context, template, or point. The execution layer must add a bound,
    unforgeable run handle before this plan is used for HTTP I/O.

    RequestBudget is single-threaded mutable state. A later execution layer
    must recheck that all twelve requests remain available immediately before
    starting, then rely on ExecutionContext to consume each request.
    """
    if not isinstance(initial, VerificationResult):
        raise TypeError("Invalid initial verification result.")
    if not isinstance(template, RequestTemplate):
        raise TypeError("Invalid request template.")
    if not isinstance(point, InjectionPoint):
        raise TypeError("Invalid injection point.")
    if not isinstance(payloads, ConfirmationPayloads):
        raise TypeError("Invalid confirmation payloads.")
    if not isinstance(context, ExecutionContext):
        raise TypeError("Invalid execution context.")

    if not confirmation_eligible(initial):
        return None

    # Require the exact shared-budget state. This verifies accounting only;
    # it does not establish result or target provenance (see docstring).
    if (
        context.budget.max_requests != TOTAL_REQUESTS
        or context.budget.used_requests != INITIAL_REQUESTS
        or context.budget.remaining != CONFIRMATION_REQUESTS
    ):
        raise ValueError("Invalid confirmation request budget.")

    try:
        validate_template(template)
        validate_scope(template.url, context.scope)

        templates = {
            ConfirmationKind.BASELINE: template,
            ConfirmationKind.TRUE_1: inject(template, point, payloads.true_1),
            ConfirmationKind.FALSE_1: inject(template, point, payloads.false_1),
            ConfirmationKind.TRUE_2: inject(template, point, payloads.true_2),
            ConfirmationKind.FALSE_2: inject(template, point, payloads.false_2),
            ConfirmationKind.CONTROL: inject(template, point, payloads.control),
        }

        # All distinct logical probes must result in distinct requests.
        if len(set(templates.values())) != len(templates):
            raise ValueError("Duplicate confirmation templates.")

        # Full-plan preflight, before any confirmation HTTP request.
        for request_template in templates.values():
            validate_template(request_template)
            validate_scope(request_template.url, context.scope)

    except (TypeError, ValueError):
        # No raw URLs, payloads, or credentials in error messages.
        raise ValueError("Invalid or unauthorized confirmation plan.") from None

    return ConfirmationPlan(
        steps=tuple(
            ConfirmationStep(
                kind=kind,
                template=templates[kind],
            )
            for kind in CONFIRMATION_ORDER
        ),
        point=point,
        payloads=payloads,
    )
