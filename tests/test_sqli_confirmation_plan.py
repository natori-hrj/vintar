"""Step 55.1: confirmation plan invariants and security preflight."""

from dataclasses import replace

import httpx
import pytest

from vintar.checks.sqli.confirmation import (
    CONFIRMATION_ORDER,
    CONFIRMATION_REQUESTS,
    TOTAL_REQUESTS,
    ConfirmationKind,
    ConfirmationPayloads,
    ConfirmationPlan,
    ConfirmationStep,
    confirmation_eligible,
    prepare_confirmation_plan,
)
from vintar.checks.sqli.models import ProbeKind, Verdict
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
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

ORIGIN = "http://localhost:8000"

TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
CONTROL = "__vintar_control_7f4a9c2e"


@pytest.fixture
def payloads() -> ConfirmationPayloads:
    return ConfirmationPayloads(
        true_1=TRUE_1,
        false_1=FALSE_1,
        true_2=TRUE_2,
        false_2=FALSE_2,
        control=CONTROL,
    )


@pytest.fixture
def template() -> RequestTemplate:
    return RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        params=(("category", "Pets"),),
    )


@pytest.fixture
def point() -> InjectionPoint:
    return InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        mode=InjectionMode.APPEND,
    )


@pytest.fixture
def context() -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        budget=RequestBudget(TOTAL_REQUESTS),
        rate_limiter=RateLimiter(
            requests_per_second=10,
        ),
        max_response_size=1_048_576,
    )


def run_initial(
    *,
    context: ExecutionContext,
    template: RequestTemplate,
    point: InjectionPoint,
    candidate: bool = True,
):
    received = []

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params.get_list(point.name)[point.occurrence]
        received.append(value)

        matching_values = [
            item_value for name, item_value in template.params if name == point.name
        ]
        prefix = (
            matching_values[point.occurrence]
            if point.mode is InjectionMode.APPEND
            else ""
        )
        if candidate and value == prefix + FALSE_1:
            body = b"no-results"
        else:
            body = b"products-found"

        return httpx.Response(200, content=body)

    result = verify_boolean_sqli(
        check_id="confirmation-plan-test",
        template=template,
        point=point,
        true_payload=TRUE_1,
        false_payload=FALSE_1,
        context=context,
        transport=httpx.MockTransport(handler),
    )

    assert len(received) == 6
    assert context.budget.used_requests == 6

    return result


def prepared(
    context,
    template,
    point,
    payloads,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )

    assert initial.verdict is Verdict.INCONCLUSIVE
    assert initial.reason_code == "boolean_candidate"

    plan = prepare_confirmation_plan(
        initial=initial,
        template=template,
        point=point,
        payloads=payloads,
        context=context,
    )

    assert plan is not None
    return plan


def test_confirmation_plan_has_exactly_twelve_steps(
    context,
    template,
    point,
    payloads,
):
    plan = prepared(context, template, point, payloads)

    assert isinstance(plan, ConfirmationPlan)
    assert plan.request_count == CONFIRMATION_REQUESTS
    assert len(plan.steps) == 12

    assert tuple(step.kind for step in plan.steps) == CONFIRMATION_ORDER

    assert context.budget.used_requests == 6
    assert context.budget.remaining == 12


def test_each_probe_is_sent_twice_in_the_expected_order(
    context,
    template,
    point,
    payloads,
):
    plan = prepared(context, template, point, payloads)

    expected = (
        "Pets",
        "Pets" + TRUE_1,
        "Pets" + FALSE_1,
        "Pets" + CONTROL,
        "Pets" + TRUE_2,
        "Pets" + FALSE_2,
        "Pets",
        "Pets" + FALSE_2,
        "Pets" + TRUE_2,
        "Pets" + CONTROL,
        "Pets" + FALSE_1,
        "Pets" + TRUE_1,
    )

    assert tuple(step.template.params[0][1] for step in plan.steps) == expected

    assert all(step.template.method == "GET" for step in plan.steps)

    assert all(step.template.url == template.url for step in plan.steps)


def test_initial_candidate_is_eligible(
    context,
    template,
    point,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )
    assert confirmation_eligible(initial)


def test_eligibility_rejects_inconsistent_candidate_metadata(
    context,
    template,
    point,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )
    assert initial.evidence is not None

    without_evidence = replace(initial, evidence=None)
    assert not confirmation_eligible(without_evidence)

    non_success = replace(
        initial,
        observations=tuple(
            replace(observation, status_code=403)
            for observation in initial.observations
        ),
    )
    assert not confirmation_eligible(non_success)

    wrong_kinds = list(initial.observations)
    wrong_kinds[-1] = replace(
        wrong_kinds[-1],
        kind=ProbeKind.TRUE,
    )
    assert not confirmation_eligible(replace(initial, observations=tuple(wrong_kinds)))

    unstable = list(initial.observations)
    unstable[0] = replace(
        unstable[0],
        body_digest="0" * 64,
    )
    assert not confirmation_eligible(replace(initial, observations=tuple(unstable)))

    wrong_evidence = replace(
        initial,
        evidence=replace(
            initial.evidence,
            baseline_true_similarity=0.0,
        ),
    )
    assert not confirmation_eligible(wrong_evidence)


def test_non_candidate_does_not_prepare_confirmation(
    context,
    template,
    point,
    payloads,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
        candidate=False,
    )

    assert initial.verdict is Verdict.NOT_DETECTED
    assert not confirmation_eligible(initial)

    plan = prepare_confirmation_plan(
        initial=initial,
        template=template,
        point=point,
        payloads=payloads,
        context=context,
    )

    assert plan is None
    assert context.budget.used_requests == 6


def test_budget_must_be_shared_with_initial_stage(
    template,
    point,
    payloads,
):
    initial_context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        budget=RequestBudget(18),
    )

    initial = run_initial(
        context=initial_context,
        template=template,
        point=point,
    )

    new_context = ExecutionContext(
        scope=initial_context.scope,
        budget=RequestBudget(18),
    )

    with pytest.raises(
        ValueError,
        match="Invalid confirmation request budget",
    ):
        prepare_confirmation_plan(
            initial=initial,
            template=template,
            point=point,
            payloads=payloads,
            context=new_context,
        )

    assert new_context.budget.used_requests == 0


def test_insufficient_budget_is_rejected(
    context,
    template,
    point,
    payloads,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )

    # Simulate another operation consuming the shared budget.
    context.budget.consume()

    with pytest.raises(
        ValueError,
        match="Invalid confirmation request budget",
    ):
        prepare_confirmation_plan(
            initial=initial,
            template=template,
            point=point,
            payloads=payloads,
            context=context,
        )

    assert context.budget.used_requests == 7


def test_out_of_scope_plan_is_rejected_before_any_new_request(
    context,
    template,
    point,
    payloads,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )

    outside = replace(
        template,
        url="http://untrusted.invalid/products",
    )

    with pytest.raises(
        ValueError,
        match="Invalid or unauthorized confirmation plan",
    ):
        prepare_confirmation_plan(
            initial=initial,
            template=outside,
            point=point,
            payloads=payloads,
            context=context,
        )

    assert context.budget.used_requests == 6


def test_missing_injection_point_is_rejected(
    context,
    template,
    payloads,
):
    point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        mode=InjectionMode.APPEND,
    )

    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )

    wrong_point = replace(point, name="missing")

    with pytest.raises(
        ValueError,
        match="Invalid or unauthorized confirmation plan",
    ):
        prepare_confirmation_plan(
            initial=initial,
            template=template,
            point=wrong_point,
            payloads=payloads,
            context=context,
        )

    assert context.budget.used_requests == 6


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        True,
        1,
        "",
        "\x00",
        "\n",
        "\u0085",
        "\u202e",
        "\ud800",
        "x" * 513,
    ],
)
def test_invalid_boolean_payload_is_rejected(invalid):
    with pytest.raises((TypeError, ValueError)):
        ConfirmationPayloads(
            true_1=invalid,
            false_1=FALSE_1,
            true_2=TRUE_2,
            false_2=FALSE_2,
            control=CONTROL,
        )


@pytest.mark.parametrize(
    "control",
    [
        None,
        True,
        1,
        "",
        "__vintar_control_",
        "__vintar_control_short",
        "control-with-hyphens",
        "' OR 1=1-- ",
        "__vintar_control_\n",
        "__vintar_control_" + "a" * 128,
    ],
)
def test_invalid_control_is_rejected(control):
    with pytest.raises((TypeError, ValueError)):
        ConfirmationPayloads(
            true_1=TRUE_1,
            false_1=FALSE_1,
            true_2=TRUE_2,
            false_2=FALSE_2,
            control=control,
        )


def test_duplicate_boolean_payloads_are_rejected():
    with pytest.raises(ValueError, match="distinct"):
        ConfirmationPayloads(
            true_1=TRUE_1,
            false_1=TRUE_1,
            true_2=TRUE_2,
            false_2=FALSE_2,
            control=CONTROL,
        )


def test_plan_order_is_immutable(
    context,
    template,
    point,
    payloads,
):
    plan = prepared(context, template, point, payloads)

    assert isinstance(plan.steps, tuple)

    with pytest.raises(
        (AttributeError, TypeError),
    ):
        plan.steps = ()

    with pytest.raises(ValueError, match="order"):
        ConfirmationPlan(
            steps=tuple(reversed(plan.steps)),
            point=point,
            payloads=payloads,
        )


def test_all_confirmation_models_are_immutable(
    context,
    template,
    point,
    payloads,
):
    plan = prepared(context, template, point, payloads)

    with pytest.raises((AttributeError, TypeError)):
        payloads.true_1 = "changed"

    with pytest.raises((AttributeError, TypeError)):
        plan.steps[0].kind = ConfirmationKind.TRUE_1

    with pytest.raises((AttributeError, TypeError)):
        plan.point = replace(point, occurrence=1)


def test_sensitive_request_values_are_not_in_repr(
    context,
    template,
    point,
    payloads,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )

    sensitive = replace(
        template,
        headers=(("Authorization", "Bearer test-secret"),),
    )

    plan = prepare_confirmation_plan(
        initial=initial,
        template=sensitive,
        point=point,
        payloads=payloads,
        context=context,
    )

    assert plan is not None

    for value in (payloads, plan, *plan.steps):
        output = repr(value)
        assert "test-secret" not in output
        assert CONTROL not in output
        assert TRUE_1 not in output
        assert FALSE_1 not in output


def test_invalid_plan_length_is_rejected(
    template,
    point,
    payloads,
):
    step = ConfirmationStep(
        kind=ConfirmationKind.BASELINE,
        template=template,
    )

    with pytest.raises(ValueError, match="length"):
        ConfirmationPlan(
            steps=(step,),
            point=point,
            payloads=payloads,
        )


def test_direct_plan_rejects_templates_not_derived_from_payloads(
    context,
    template,
    point,
    payloads,
):
    plan = prepared(context, template, point, payloads)
    steps = list(plan.steps)
    steps[1] = ConfirmationStep(
        kind=ConfirmationKind.TRUE_1,
        template=replace(
            steps[1].template,
            url="http://untrusted.invalid/products",
        ),
    )

    with pytest.raises(ValueError, match="templates"):
        ConfirmationPlan(
            steps=tuple(steps),
            point=point,
            payloads=payloads,
        )


@pytest.mark.parametrize(
    "mode",
    [InjectionMode.APPEND, InjectionMode.REPLACE],
)
def test_duplicate_parameter_occurrence_and_request_fields_are_preserved(
    context,
    payloads,
    mode,
):
    duplicate_template = RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        headers=(("X-Test", "preserved"),),
        cookies=(("session", "preserved"),),
        params=(
            ("category", "First"),
            ("other", "value"),
            ("category", "Second"),
        ),
    )
    duplicate_point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        occurrence=1,
        mode=mode,
    )
    initial = run_initial(
        context=context,
        template=duplicate_template,
        point=duplicate_point,
    )

    plan = prepare_confirmation_plan(
        initial=initial,
        template=duplicate_template,
        point=duplicate_point,
        payloads=payloads,
        context=context,
    )

    assert plan is not None
    for step in plan.steps:
        assert step.template.url == duplicate_template.url
        assert step.template.method == duplicate_template.method
        assert step.template.headers == duplicate_template.headers
        assert step.template.cookies == duplicate_template.cookies
        assert step.template.body == duplicate_template.body
        assert step.template.params[:2] == duplicate_template.params[:2]

    true_value = next(
        step.template.params[2][1]
        for step in plan.steps
        if step.kind is ConfirmationKind.TRUE_1
    )
    expected_prefix = "Second" if mode is InjectionMode.APPEND else ""
    assert true_value == expected_prefix + TRUE_1


def test_preparation_never_sends_confirmation_requests(
    context,
    template,
    point,
    payloads,
):
    initial = run_initial(
        context=context,
        template=template,
        point=point,
    )

    used_before = context.budget.used_requests

    plan = prepare_confirmation_plan(
        initial=initial,
        template=template,
        point=point,
        payloads=payloads,
        context=context,
    )

    assert plan is not None
    assert context.budget.used_requests == used_before
    assert context.budget.remaining == 12
