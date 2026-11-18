"""Prepare bounded time-based SQL injection verification plans.

This module validates an immutable request plan without sending HTTP
requests, measuring latency, or classifying vulnerabilities.

Payloads are trusted inputs supplied by the caller. They must never
be accepted directly from untrusted configuration.
"""

import math
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum

from vintar.core.executor import ExecutionContext
from vintar.core.injector import inject
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import validate_scope
from vintar.core.template import validate_template

TIME_REQUESTS = 9
MIN_DELAY_SECONDS = 0.25
MAX_DELAY_SECONDS = 2.0
MIN_TIMEOUT_MARGIN_SECONDS = 0.5
MAX_REQUEST_TIMEOUT_SECONDS = 8.0
MAX_PAYLOAD_LENGTH = 512


class TimeProbeKind(StrEnum):
    BASELINE = "baseline"
    CONTROL = "control"
    DELAY = "delay"


TIME_PROBE_ORDER = (
    TimeProbeKind.BASELINE,
    TimeProbeKind.CONTROL,
    TimeProbeKind.DELAY,
    TimeProbeKind.CONTROL,
    TimeProbeKind.DELAY,
    TimeProbeKind.BASELINE,
    TimeProbeKind.DELAY,
    TimeProbeKind.BASELINE,
    TimeProbeKind.CONTROL,
)


def _validate_injection_point(point: object) -> None:
    if type(point) is not InjectionPoint:
        raise TypeError("Invalid time injection point.")
    if type(point.location) is not InjectionLocation:
        raise TypeError("Invalid time injection location.")
    if type(point.name) is not str or not point.name:
        raise TypeError("Invalid time injection point name.")
    if type(point.occurrence) is not int or point.occurrence < 0:
        raise TypeError("Invalid time injection occurrence.")
    if type(point.mode) is not InjectionMode:
        raise TypeError("Invalid time injection mode.")


@dataclass(frozen=True, slots=True, repr=False)
class TimePayloads:
    """Trusted, distinct conditional delay and control expressions."""

    delay: str = field(repr=False)
    control: str = field(repr=False)

    def __post_init__(self) -> None:
        for value in (self.delay, self.control):
            if type(value) is not str:
                raise TypeError("Invalid time-based payload.")
            if not 0 < len(value) <= MAX_PAYLOAD_LENGTH:
                raise ValueError("Invalid time-based payload.")
            if any(unicodedata.category(char).startswith("C") for char in value):
                raise ValueError("Invalid time-based payload.")

        if self.delay == self.control:
            raise ValueError("Time-based payloads must be distinct.")


@dataclass(frozen=True, slots=True, repr=False)
class TimeProbe:
    """A single prevalidated logical request."""

    kind: TimeProbeKind
    template: RequestTemplate = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.kind) is not TimeProbeKind:
            raise TypeError("Invalid time probe kind.")

        if type(self.template) is not RequestTemplate:
            raise TypeError("Invalid time probe template.")

        try:
            validate_template(self.template)
        except (TypeError, ValueError):
            raise ValueError("Invalid time probe template.") from None


@dataclass(frozen=True, slots=True, repr=False)
class TimePlan:
    """A structural plan, not an execution authorization token.

    Context, source template, and injected payload provenance cannot
    be established from this data object alone.
    """

    steps: tuple[TimeProbe, ...] = field(repr=False)
    point: InjectionPoint = field(repr=False)
    payloads: TimePayloads = field(repr=False)
    expected_delay_seconds: float
    request_timeout_seconds: float

    def __post_init__(self) -> None:
        if type(self.steps) is not tuple:
            raise TypeError("Time plan steps must be a tuple.")
        if len(self.steps) != TIME_REQUESTS:
            raise ValueError("Invalid time plan length.")

        if not all(type(step) is TimeProbe for step in self.steps):
            raise TypeError("Invalid time plan step.")

        if tuple(step.kind for step in self.steps) != TIME_PROBE_ORDER:
            raise ValueError("Invalid time probe order.")

        _validate_injection_point(self.point)

        if type(self.payloads) is not TimePayloads:
            raise TypeError("Invalid time payloads.")

        delay = self.expected_delay_seconds
        timeout = self.request_timeout_seconds

        if type(delay) is not int and type(delay) is not float:
            raise TypeError("Invalid time plan duration.")
        if type(timeout) is not int and type(timeout) is not float:
            raise TypeError("Invalid time plan duration.")

        if not (MIN_DELAY_SECONDS <= delay <= MAX_DELAY_SECONDS) or not math.isfinite(
            delay
        ):
            raise ValueError("Expected delay is outside the supported range.")

        if not (
            delay + MIN_TIMEOUT_MARGIN_SECONDS <= timeout <= MAX_REQUEST_TIMEOUT_SECONDS
        ) or not math.isfinite(timeout):
            raise ValueError("Invalid time plan request timeout.")

        baseline = self.steps[0].template

        try:
            requests = {
                TimeProbeKind.BASELINE: baseline,
                TimeProbeKind.CONTROL: inject(
                    baseline,
                    self.point,
                    self.payloads.control,
                ),
                TimeProbeKind.DELAY: inject(
                    baseline,
                    self.point,
                    self.payloads.delay,
                ),
            }

            if len(set(requests.values())) != len(requests):
                raise ValueError

            if any(step.template != requests[step.kind] for step in self.steps):
                raise ValueError

        except (TypeError, ValueError):
            raise ValueError("Invalid time plan templates.") from None

    @property
    def request_count(self) -> int:
        return len(self.steps)


def prepare_time_plan(
    *,
    template: RequestTemplate,
    point: InjectionPoint,
    payloads: TimePayloads,
    expected_delay_seconds: float,
    context: ExecutionContext,
) -> TimePlan:
    """Validate a complete, bounded time-based request plan.

    The context must use a fresh nine-request budget.

    This function does not consume budget or perform HTTP I/O.

    The request timeout is not a total wall-clock deadline.
    A future runner must impose a separate monotonic execution
    deadline that includes rate-limit waits and transport work.

    This function does not validate the semantics of SQL payloads.
    """
    if type(template) is not RequestTemplate:
        raise TypeError("Invalid time plan template.")

    _validate_injection_point(point)

    if type(payloads) is not TimePayloads:
        raise TypeError("Invalid time plan payloads.")

    if type(context) is not ExecutionContext:
        raise TypeError("Invalid time plan context.")

    if (
        context.budget.max_requests != TIME_REQUESTS
        or context.budget.used_requests != 0
        or context.budget.remaining != TIME_REQUESTS
    ):
        raise ValueError("Invalid initial time request budget.")

    delay = expected_delay_seconds

    if type(delay) is not int and type(delay) is not float:
        raise TypeError("Invalid expected time delay.")

    if not MIN_DELAY_SECONDS <= delay <= MAX_DELAY_SECONDS or not math.isfinite(delay):
        raise ValueError("Invalid expected time delay.")

    if not (
        delay + MIN_TIMEOUT_MARGIN_SECONDS
        <= context.timeout
        <= MAX_REQUEST_TIMEOUT_SECONDS
    ) or not math.isfinite(context.timeout):
        raise ValueError("Invalid time verification timeout.")

    try:
        requests = {
            TimeProbeKind.BASELINE: template,
            TimeProbeKind.CONTROL: inject(template, point, payloads.control),
            TimeProbeKind.DELAY: inject(template, point, payloads.delay),
        }

        if len(set(requests.values())) != len(requests):
            raise ValueError

        for request in requests.values():
            validate_template(request)
            validate_scope(request.url, context.scope)

        plan = TimePlan(
            steps=tuple(
                TimeProbe(
                    kind=kind,
                    template=requests[kind],
                )
                for kind in TIME_PROBE_ORDER
            ),
            point=point,
            payloads=payloads,
            expected_delay_seconds=float(delay),
            request_timeout_seconds=float(context.timeout),
        )

    except (TypeError, ValueError):
        raise ValueError("Invalid or unauthorized time verification plan.") from None

    return plan
