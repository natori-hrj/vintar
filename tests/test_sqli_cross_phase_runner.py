"""Runner-level cross-phase regression tests."""

from dataclasses import replace

import httpx
import pytest

from vintar.checks.sqli.confirmation_runner import (
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.models import Verdict
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

ORIGIN = "http://127.0.0.1:18081"
TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
BASELINE_PRESERVING_CONTROL = "' AND 7=7-- "


def make_context() -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", 18081)})
        ),
        budget=RequestBudget(18),
        timeout=3.0,
        rate_limiter=RateLimiter(requests_per_second=100),
        max_response_size=1_048_576,
    )


def run_case(
    mode: str,
    *,
    context: ExecutionContext | None = None,
    received: list[str] | None = None,
    template: RequestTemplate | None = None,
):
    context = context or make_context()
    received = received if received is not None else []
    template = template or RequestTemplate(
        method="GET",
        url=f"{ORIGIN}/products",
        params=(("category", "Pets"),),
    )

    def handler(request: httpx.Request) -> httpx.Response:
        category = request.url.params["category"]
        received.append(category)
        sequence = len(received)
        false_probe = category in {
            "Pets" + FALSE_1,
            "Pets" + FALSE_2,
        }

        if mode == "stable":
            body = b"B" if false_probe else b"A"
        elif mode == "rollover":
            prefix = b"g1-" if sequence <= 6 else b"g2-"
            body = prefix + (b"B" if false_probe else b"A")
        elif mode == "not_confirmed":
            body = b"B" if category == "Pets" + FALSE_1 else b"A"
        elif mode == "unstable":
            body = (
                (b"B" if false_probe else b"A")
                if sequence <= 6
                else f"dynamic-{sequence}".encode("ascii")
            )
        elif mode == "no_difference":
            body = b"same"
        elif mode == "confirmation_403":
            if sequence == 7:
                return httpx.Response(403, content=b"blocked")
            body = b"B" if false_probe else b"A"
        else:
            raise AssertionError("Invalid test mode")

        return httpx.Response(200, content=body)

    outcome = verify_boolean_sqli_with_confirmation(
        check_id=f"cross-phase-{mode}",
        template=template,
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        true_1=TRUE_1,
        false_1=FALSE_1,
        true_2=TRUE_2,
        false_2=FALSE_2,
        baseline_preserving_control=BASELINE_PRESERVING_CONTROL,
        context=context,
        transport=httpx.MockTransport(handler),
    )

    return outcome, context, received


@pytest.mark.parametrize(
    ("mode", "expected", "reason", "requests"),
    [
        (
            "stable",
            ConfirmationStatus.CANDIDATE,
            "confirmation_pattern_matched",
            18,
        ),
        (
            "rollover",
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_cross_phase_mismatch",
            18,
        ),
        (
            "not_confirmed",
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_unstable",
            18,
        ),
        (
            "unstable",
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_unstable",
            18,
        ),
        (
            "no_difference",
            ConfirmationStatus.SKIPPED,
            "initial_not_eligible",
            6,
        ),
        (
            "confirmation_403",
            ConfirmationStatus.INCONCLUSIVE,
            "confirmation_non_success_status",
            7,
        ),
    ],
)
def test_runner_cross_phase_contract(
    mode,
    expected,
    reason,
    requests,
):
    outcome, context, received = run_case(mode)

    assert outcome.status is expected
    assert outcome.reason_code == reason
    assert outcome.total_requests == requests
    assert outcome.request_count == requests
    assert context.budget.used_requests == requests
    assert len(received) == requests
    assert outcome.initial.verdict is not Verdict.VULNERABLE

    if mode == "rollover":
        assert outcome.initial.reason_code == "boolean_candidate"
        assert outcome.confirmation_requests == 12
        assert outcome.evidence is None

    if mode == "stable":
        assert outcome.evidence is not None

    if mode == "not_confirmed":
        assert outcome.evidence is None


def test_mismatch_outcome_rejects_invalid_direct_construction():
    mismatch, _, _ = run_case("rollover")
    candidate, _, _ = run_case("stable")
    assert candidate.evidence is not None

    with pytest.raises(
        ValueError,
        match="Incomplete cross-phase mismatch",
    ):
        replace(
            mismatch,
            confirmation_requests=11,
            total_requests=17,
        )

    with pytest.raises(
        ValueError,
        match="Inconsistent inconclusive",
    ):
        replace(mismatch, evidence=candidate.evidence)

    with pytest.raises(
        ValueError,
        match="Inconsistent inconclusive",
    ):
        replace(
            mismatch,
            reason_code="confirmation_pattern_matched",
        )


@pytest.mark.parametrize(
    "mode",
    ("not_confirmed", "unstable", "no_difference", "confirmation_403"),
)
def test_non_candidate_result_does_not_invoke_guard(
    monkeypatch,
    mode,
):
    def reject_guard(**_kwargs):
        raise AssertionError("Guard must not evaluate non-candidates.")

    monkeypatch.setattr(
        "vintar.checks.sqli.cross_phase.assess_cross_phase_consistency",
        reject_guard,
    )

    outcome, context, received = run_case(mode)

    assert outcome.status is not ConfirmationStatus.CANDIDATE
    assert context.budget.used_requests == len(received)


@pytest.mark.parametrize(
    "guard_behavior",
    ("exception", "invalid-result"),
)
def test_guard_failure_is_sanitized_and_never_returns_candidate(
    monkeypatch,
    guard_behavior,
):
    secret = "guard-internal-secret"

    if guard_behavior == "exception":

        def replacement(**_kwargs):
            raise ValueError(secret)

    else:

        def replacement(**_kwargs):
            return object()

    monkeypatch.setattr(
        "vintar.checks.sqli.cross_phase.assess_cross_phase_consistency",
        replacement,
    )
    received: list[str] = []
    context = make_context()

    with pytest.raises(
        RuntimeError,
        match=r"^Cross-phase consistency assessment failed\.$",
    ) as captured:
        run_case(
            "stable",
            context=context,
            received=received,
        )

    assert secret not in str(captured.value)
    assert context.budget.used_requests == 18
    assert len(received) == 18


def test_mismatch_does_not_expose_sensitive_data():
    secret = "cross-phase-secret"
    outcome, context, received = run_case(
        "rollover",
        template=RequestTemplate(
            method="GET",
            url=f"{ORIGIN}/products",
            headers=(("Authorization", f"Bearer {secret}"),),
            cookies=(("session", secret),),
            params=(("category", "Pets"),),
        ),
    )

    rendered = repr(outcome)
    assert outcome.status is ConfirmationStatus.INCONCLUSIVE
    assert outcome.evidence is None
    assert context.budget.used_requests == len(received) == 18

    for value in (
        secret,
        TRUE_1,
        FALSE_1,
        TRUE_2,
        FALSE_2,
        BASELINE_PRESERVING_CONTROL,
        "g1-",
        "g2-",
    ):
        assert value not in rendered


def test_cross_phase_result_is_repeatable():
    snapshots = []

    for _ in range(2):
        outcome, context, received = run_case("rollover")
        snapshots.append(
            (
                outcome.status,
                outcome.reason_code,
                outcome.request_count,
                context.budget.used_requests,
                len(received),
            )
        )

    assert snapshots[0] == snapshots[1]
