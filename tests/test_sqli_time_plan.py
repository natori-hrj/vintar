"""Tests for immutable time-based SQLi verification plans."""

from dataclasses import FrozenInstanceError, replace

import pytest

from vintar.checks.sqli.time_plan import (
    TIME_PROBE_ORDER,
    TIME_REQUESTS,
    TimePayloads,
    TimePlan,
    TimeProbe,
    TimeProbeKind,
    prepare_time_plan,
)
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy

ORIGIN = "http://127.0.0.1:18082"


def make_context(
    *,
    requests: int = 9,
    timeout: float = 5.0,
) -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset(
                {
                    AllowedOrigin(
                        "http",
                        "127.0.0.1",
                        18082,
                    )
                }
            )
        ),
        budget=RequestBudget(requests),
        timeout=timeout,
        rate_limiter=RateLimiter(
            requests_per_second=5.0,
        ),
        max_response_size=1_048_576,
    )


def make_template(
    *,
    url: str = ORIGIN + "/products",
) -> RequestTemplate:
    return RequestTemplate(
        method="GET",
        url=url,
        params=(("category", "Pets"),),
    )


def make_point() -> InjectionPoint:
    return InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        mode=InjectionMode.APPEND,
    )


def make_payloads() -> TimePayloads:
    return TimePayloads(
        delay="_delayed",
        control="_control",
    )


def make_plan(
    *,
    context: ExecutionContext | None = None,
    expected_delay_seconds: float = 1.0,
) -> TimePlan:
    return prepare_time_plan(
        template=make_template(),
        point=make_point(),
        payloads=make_payloads(),
        expected_delay_seconds=expected_delay_seconds,
        context=context or make_context(),
    )


def test_plan_has_nine_probes_in_expected_order():
    plan = make_plan()

    assert plan.request_count == TIME_REQUESTS
    assert len(plan.steps) == 9
    assert tuple(step.kind for step in plan.steps) == TIME_PROBE_ORDER

    assert tuple(step.kind for step in plan.steps).count(TimeProbeKind.BASELINE) == 3

    assert tuple(step.kind for step in plan.steps).count(TimeProbeKind.CONTROL) == 3

    assert tuple(step.kind for step in plan.steps).count(TimeProbeKind.DELAY) == 3


def test_each_probe_uses_correct_injection():
    plan = make_plan()

    for step in plan.steps:
        value = step.template.params[0][1]

        if step.kind is TimeProbeKind.BASELINE:
            assert value == "Pets"

        elif step.kind is TimeProbeKind.CONTROL:
            assert value == "Pets_control"

        else:
            assert value == "Pets_delayed"


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (InjectionMode.APPEND, "selected_control"),
        (InjectionMode.REPLACE, "_control"),
    ],
)
def test_plan_preserves_occurrence_and_injection_mode(mode, expected):
    template = RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        params=(
            ("category", "ignored"),
            ("category", "selected"),
        ),
    )
    point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        occurrence=1,
        mode=mode,
    )

    plan = prepare_time_plan(
        template=template,
        point=point,
        payloads=make_payloads(),
        expected_delay_seconds=1.0,
        context=make_context(),
    )
    control = next(step for step in plan.steps if step.kind is TimeProbeKind.CONTROL)

    assert control.template.params == (
        ("category", "ignored"),
        ("category", expected),
    )


def test_plan_does_not_consume_request_budget():
    context = make_context()

    plan = make_plan(context=context)

    assert plan.request_count == 9
    assert context.budget.used_requests == 0
    assert context.budget.remaining == 9


def test_plan_is_immutable():
    plan = make_plan()

    with pytest.raises(
        (AttributeError, TypeError),
    ):
        plan.steps = ()

    with pytest.raises(
        (AttributeError, TypeError),
    ):
        plan.payloads = make_payloads()


def test_nested_plan_models_are_immutable():
    plan = make_plan()

    with pytest.raises(FrozenInstanceError):
        plan.payloads.delay = "changed"

    with pytest.raises(FrozenInstanceError):
        plan.steps[0].kind = TimeProbeKind.DELAY


def test_payload_values_are_not_in_repr():
    plan = make_plan()

    output = repr(plan)

    assert "_delayed" not in output
    assert "_control" not in output
    assert "Pets" not in output
    assert "category" not in output


@pytest.mark.parametrize(
    "value",
    [
        "",
        "\n",
        "\x00",
        "\ud800",
        "a" * 513,
    ],
)
def test_invalid_payload_is_rejected(value):
    with pytest.raises(ValueError):
        TimePayloads(
            delay=value,
            control="_control",
        )


@pytest.mark.parametrize(
    "value",
    [
        None,
        1,
        True,
    ],
)
def test_payload_requires_string(value):
    with pytest.raises(TypeError):
        TimePayloads(
            delay=value,
            control="_control",
        )


def test_duplicate_payload_is_rejected():
    with pytest.raises(
        ValueError,
        match="distinct",
    ):
        TimePayloads(
            delay="_same",
            control="_same",
        )


@pytest.mark.parametrize(
    "delay",
    [
        0,
        -1,
        0.1,
        2.5,
        float("nan"),
        float("inf"),
        -(10**1000),
        10**1000,
        True,
        None,
    ],
)
def test_invalid_expected_delay_is_rejected(delay):
    with pytest.raises(
        (TypeError, ValueError),
    ):
        make_plan(
            expected_delay_seconds=delay,
        )


@pytest.mark.parametrize(
    "timeout",
    [
        0.5,
        1.49,
        8.01,
    ],
)
def test_invalid_timeout_margin_is_rejected(timeout):
    with pytest.raises(ValueError):
        make_plan(
            context=make_context(timeout=timeout),
        )


def test_timeout_equal_to_margin_boundary_is_allowed():
    plan = make_plan(
        context=make_context(timeout=1.5),
    )

    assert plan.request_timeout_seconds == 1.5


@pytest.mark.parametrize("delay", [0.25, 2.0])
def test_expected_delay_boundaries_are_allowed(delay):
    plan = make_plan(
        context=make_context(timeout=delay + 0.5),
        expected_delay_seconds=delay,
    )

    assert plan.expected_delay_seconds == delay


def test_maximum_timeout_boundary_is_allowed():
    plan = make_plan(context=make_context(timeout=8.0))

    assert plan.request_timeout_seconds == 8.0


def test_budget_must_have_exactly_nine_requests():
    with pytest.raises(
        ValueError,
        match="budget",
    ):
        make_plan(
            context=make_context(requests=8),
        )

    with pytest.raises(
        ValueError,
        match="budget",
    ):
        make_plan(
            context=make_context(requests=10),
        )


def test_budget_must_be_unused():
    context = make_context()
    context.budget.consume()

    with pytest.raises(
        ValueError,
        match="budget",
    ):
        make_plan(context=context)

    assert context.budget.used_requests == 1


def test_out_of_scope_target_is_rejected():
    context = make_context()

    with pytest.raises(
        ValueError,
        match="Invalid or unauthorized",
    ):
        prepare_time_plan(
            template=make_template(url="http://example.invalid/products"),
            point=make_point(),
            payloads=make_payloads(),
            expected_delay_seconds=1.0,
            context=context,
        )

    assert context.budget.used_requests == 0


def test_missing_injection_point_is_rejected():
    context = make_context()

    point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="missing",
        mode=InjectionMode.APPEND,
    )

    with pytest.raises(
        ValueError,
        match="Invalid or unauthorized",
    ):
        prepare_time_plan(
            template=make_template(),
            point=point,
            payloads=make_payloads(),
            expected_delay_seconds=1.0,
            context=context,
        )

    assert context.budget.used_requests == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("location", "query"),
        ("name", 1),
        ("occurrence", 0.0),
        ("occurrence", True),
        ("mode", "append"),
    ],
)
def test_injection_point_fields_require_exact_types(field, value):
    context = make_context()
    point = replace(make_point(), **{field: value})

    with pytest.raises(TypeError, match="injection"):
        prepare_time_plan(
            template=make_template(),
            point=point,
            payloads=make_payloads(),
            expected_delay_seconds=1.0,
            context=context,
        )

    assert context.budget.used_requests == 0


def test_plan_rejects_reordered_probes():
    plan = make_plan()

    steps = list(plan.steps)
    steps[0], steps[1] = steps[1], steps[0]

    with pytest.raises(
        ValueError,
        match="order",
    ):
        replace(plan, steps=tuple(steps))


def test_plan_rejects_inconsistent_template():
    plan = make_plan()

    steps = list(plan.steps)
    steps[2] = TimeProbe(
        kind=TimeProbeKind.DELAY,
        template=make_template(),
    )

    with pytest.raises(
        ValueError,
        match="templates",
    ):
        replace(plan, steps=tuple(steps))


def test_plan_rejects_payloads_inconsistent_with_templates():
    plan = make_plan()

    with pytest.raises(ValueError, match="templates"):
        replace(
            plan,
            payloads=TimePayloads(
                delay="_other_delay",
                control="_other_control",
            ),
        )


def test_plan_rejects_invalid_injection_point_on_replace():
    plan = make_plan()
    invalid_point = replace(plan.point, occurrence=0.0)

    with pytest.raises(TypeError, match="occurrence"):
        replace(plan, point=invalid_point)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_delay_seconds", True),
        ("expected_delay_seconds", float("nan")),
        ("expected_delay_seconds", 10**1000),
        ("request_timeout_seconds", True),
        ("request_timeout_seconds", float("inf")),
        ("request_timeout_seconds", 10**1000),
    ],
)
def test_plan_rejects_invalid_direct_durations(field, value):
    plan = make_plan()

    with pytest.raises((TypeError, ValueError)):
        replace(plan, **{field: value})


def test_plan_rejects_incomplete_sequence():
    plan = make_plan()

    with pytest.raises(
        ValueError,
        match="length",
    ):
        replace(plan, steps=plan.steps[:-1])


def test_plan_does_not_perform_http(monkeypatch):
    def reject_execution(*args, **kwargs):
        raise AssertionError("Plan construction must never execute HTTP.")

    monkeypatch.setattr(
        ExecutionContext,
        "execute",
        reject_execution,
    )

    plan = make_plan()

    assert plan.request_count == 9


def test_secret_headers_and_cookies_are_not_exposed():
    secret = "time-plan-secret"

    template = RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        headers=(("Authorization", f"Bearer {secret}"),),
        cookies=(("session", secret),),
        params=(("category", "Pets"),),
    )

    plan = prepare_time_plan(
        template=template,
        point=make_point(),
        payloads=make_payloads(),
        expected_delay_seconds=1.0,
        context=make_context(),
    )

    output = repr(plan)

    assert secret not in output
    assert "Bearer" not in output
    assert "_delayed" not in output
    assert "_control" not in output


def test_validation_error_does_not_expose_secret_template_data():
    secret = "invalid-time-plan-secret"
    context = make_context()
    template = RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        headers=(("Authorization", f"Bearer {secret}"),),
        cookies=(("session", secret),),
        params=(("category", "Pets"),),
    )
    missing_point = replace(make_point(), name=secret)

    with pytest.raises(ValueError) as exc_info:
        prepare_time_plan(
            template=template,
            point=missing_point,
            payloads=make_payloads(),
            expected_delay_seconds=1.0,
            context=context,
        )

    assert secret not in str(exc_info.value)
    assert context.budget.used_requests == 0
