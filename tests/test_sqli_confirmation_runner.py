"""end-to-end confirmation orchestration with MockTransport."""

import sqlite3
from dataclasses import replace

import httpx
import pytest

from vintar.checks.sqli import confirmation_runner
from vintar.checks.sqli.confirmation_runner import (
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.observation_sink import RecordedSqliObservation
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
BASELINE_PRESERVING_CONTROL = "' AND 7=7-- "


def make_context(
    *,
    max_requests: int = 18,
    max_response_size: int = 1_048_576,
) -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        budget=RequestBudget(max_requests),
        rate_limiter=RateLimiter(requests_per_second=10),
        max_response_size=max_response_size,
    )


def run_check(
    handler,
    *,
    context=None,
    template=None,
    point=None,
    observation_sink=None,
):
    context = context or make_context()
    template = template or RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        params=(("category", "Pets"),),
    )
    point = point or InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        mode=InjectionMode.APPEND,
    )

    result = verify_boolean_sqli_with_confirmation(
        check_id="confirmation-runner-test",
        template=template,
        point=point,
        true_1=TRUE_1,
        false_1=FALSE_1,
        true_2=TRUE_2,
        false_2=FALSE_2,
        baseline_preserving_control=BASELINE_PRESERVING_CONTROL,
        context=context,
        transport=httpx.MockTransport(handler),
        observation_sink=observation_sink,
    )

    return result, context


def sqlite_body(category: str, *, vulnerable: bool) -> bytes:
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE products (name TEXT NOT NULL, category TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            (
                ("Cat toy", "Pets"),
                ("Dog toy", "Pets"),
                ("Notebook", "Office"),
            ),
        )

        if vulnerable:
            rows = db.execute(
                f"SELECT name FROM products WHERE category = '{category}'"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT name FROM products WHERE category = ?",
                (category,),
            ).fetchall()

    return "\n".join(sorted(row[0] for row in rows)).encode()


def test_vulnerable_sqlite_runs_eighteen_requests():
    received = []

    def handler(request):
        category = request.url.params["category"]
        received.append(category)
        return httpx.Response(
            200,
            content=sqlite_body(category, vulnerable=True),
        )

    result, context = run_check(handler)

    assert result.initial.verdict is Verdict.INCONCLUSIVE
    assert result.initial.reason_code == "boolean_candidate"

    assert result.status is ConfirmationStatus.CANDIDATE
    assert result.reason_code == "confirmation_pattern_matched"

    assert result.total_requests == 18
    assert result.request_count == 18
    assert result.confirmation_requests == 12
    assert context.budget.used_requests == 18
    assert context.budget.remaining == 0
    assert len(received) == 18

    assert received[:6] == [
        "Pets",
        "Pets" + TRUE_1,
        "Pets" + FALSE_1,
        "Pets",
        "Pets" + FALSE_1,
        "Pets" + TRUE_1,
    ]

    assert received[6:12] == [
        "Pets",
        "Pets" + TRUE_1,
        "Pets" + FALSE_1,
        "Pets" + BASELINE_PRESERVING_CONTROL,
        "Pets" + TRUE_2,
        "Pets" + FALSE_2,
    ]
    assert received[15] == "Pets" + BASELINE_PRESERVING_CONTROL


def test_trusted_sink_receives_initial_and_confirmation_observations_in_order():
    recorded: list[RecordedSqliObservation] = []

    def handler(request):
        category = request.url.params["category"]
        return httpx.Response(200, content=sqlite_body(category, vulnerable=True))

    result, _ = run_check(handler, observation_sink=recorded.append)

    assert [item.sequence for item in recorded] == list(range(1, 19))
    assert [item.family for item in recorded] == ["boolean"] * 6 + ["confirmation"] * 12
    assert [item.kind for item in recorded[:6]] == [
        "baseline",
        "true",
        "false",
        "baseline",
        "false",
        "true",
    ]
    assert [item.kind for item in recorded[6:]] == [
        kind.value for kind in confirmation_runner.CONFIRMATION_ORDER
    ]

    assert result.evidence is not None
    assert result.evidence.baseline_matches_true
    assert result.evidence.baseline_matches_control
    assert result.evidence.false_pair_matches
    assert result.evidence.baseline_differs_from_false
    assert len(result.evidence.observations) == 12

    for observation in result.evidence.observations:
        assert len(observation.body_digest) == 64
        assert observation.body_size >= 0
        assert not hasattr(observation, "body")


def test_parameterized_sqlite_skips_confirmation():
    received = []

    def handler(request):
        category = request.url.params["category"]
        received.append(category)
        return httpx.Response(
            200,
            content=sqlite_body(category, vulnerable=False),
        )

    result, context = run_check(handler)

    assert result.initial.verdict is Verdict.NOT_DETECTED
    assert result.initial.reason_code == "no_boolean_difference_literal_input"
    assert result.status is ConfirmationStatus.SKIPPED
    assert result.reason_code == "initial_not_eligible"

    assert result.confirmation_requests == 0
    assert result.total_requests == 6
    assert context.budget.used_requests == 6
    assert len(received) == 6


def test_no_initial_difference_skips_confirmation():
    received = []

    def handler(request):
        received.append(request.url.params["category"])
        return httpx.Response(200, content=b"same")

    result, context = run_check(handler)

    assert result.initial.verdict is Verdict.NOT_DETECTED
    assert result.status is ConfirmationStatus.SKIPPED
    assert result.total_requests == 6
    assert context.budget.remaining == 12
    assert len(received) == 6


def test_non_sql_filter_can_still_mimic_confirmation():
    received = []

    def handler(request):
        category = request.url.params["category"]
        received.append(category)

        blocked = category in {
            "Pets" + FALSE_1,
            "Pets" + FALSE_2,
        }

        return httpx.Response(
            200,
            content=b"B" if blocked else b"A",
        )

    result, context = run_check(handler)

    assert result.status is ConfirmationStatus.CANDIDATE
    assert result.total_requests == 18
    assert context.budget.used_requests == 18
    assert len(received) == 18

    # This is why candidate must never become VULNERABLE here.
    assert result.initial.verdict is Verdict.INCONCLUSIVE


def test_simple_non_sql_branch_is_not_confirmed():
    received = []

    def handler(request):
        category = request.url.params["category"]
        received.append(category)
        return httpx.Response(
            200,
            content=(b"B" if category == "Pets" + FALSE_1 else b"A"),
        )

    result, context = run_check(handler)

    assert result.initial.reason_code == "boolean_candidate"
    assert result.status is ConfirmationStatus.INCONCLUSIVE
    assert result.reason_code == "candidate_confirmation_mismatch"
    assert result.total_requests == 18
    assert result.confirmation_requests == 12
    assert result.evidence is not None
    assert len(received) == 18
    assert context.budget.used_requests == 18


@pytest.mark.parametrize(
    ("failure", "expected_reason"),
    [
        ("429", "confirmation_rate_limited"),
        ("403", "confirmation_non_success_status"),
        ("timeout", "confirmation_timeout"),
        ("disconnect", "confirmation_request_failed"),
        ("truncated", "confirmation_truncated"),
    ],
)
def test_confirmation_stops_on_first_bad_response(
    failure,
    expected_reason,
):
    received = []
    context = make_context(max_response_size=32)

    def handler(request):
        category = request.url.params["category"]
        received.append(category)

        if len(received) == 7:
            if failure == "429":
                return httpx.Response(429, content=b"limited")
            if failure == "403":
                return httpx.Response(403, content=b"blocked")
            if failure == "timeout":
                raise httpx.ReadTimeout("synthetic timeout", request=request)
            if failure == "disconnect":
                raise httpx.ReadError("synthetic disconnect", request=request)
            if failure == "truncated":
                return httpx.Response(200, content=b"X" * 256)

        body = b"B" if category == "Pets" + FALSE_1 else b"A"
        return httpx.Response(200, content=body)

    result, context = run_check(
        handler,
        context=context,
    )

    assert result.initial.reason_code == "boolean_candidate"
    assert result.status is ConfirmationStatus.INCONCLUSIVE
    assert result.reason_code == expected_reason

    assert result.total_requests == 7
    assert result.confirmation_requests == 1
    assert context.budget.used_requests == 7
    assert len(received) == 7
    assert result.evidence is None


def test_unstable_confirmation_does_not_become_candidate():
    received = []

    def handler(request):
        category = request.url.params["category"]
        received.append(category)

        if len(received) <= 6:
            content = b"B" if category == "Pets" + FALSE_1 else b"A"
        else:
            content = f"dynamic-{len(received)}".encode()

        return httpx.Response(200, content=content)

    result, context = run_check(handler)

    assert result.status is ConfirmationStatus.INCONCLUSIVE
    assert result.reason_code == "confirmation_unstable"
    assert result.evidence is None
    assert result.total_requests == 18
    assert context.budget.used_requests == 18


def test_initial_rate_limit_prevents_confirmation():
    received = []

    def handler(request):
        received.append(request)
        return httpx.Response(429, content=b"limited")

    result, context = run_check(handler)

    assert result.initial.reason_code == "rate_limited"
    assert result.status is ConfirmationStatus.SKIPPED
    assert result.total_requests == 1
    assert result.confirmation_requests == 0
    assert len(received) == 1
    assert context.budget.used_requests == 1


def test_initial_timeout_prevents_confirmation():
    received = []

    def handler(request):
        received.append(request)
        raise httpx.ReadTimeout("synthetic timeout", request=request)

    result, context = run_check(handler)

    assert result.initial.reason_code == "probe_failed"
    assert result.status is ConfirmationStatus.SKIPPED
    assert result.total_requests == 1
    assert result.confirmation_requests == 0
    assert len(received) == 1
    assert context.budget.used_requests == 1


def test_invalid_budget_is_rejected_before_http():
    received = []

    def handler(request):
        received.append(request)
        return httpx.Response(200, content=b"ok")

    with pytest.raises(
        ValueError,
        match="Invalid initial confirmation budget",
    ):
        run_check(
            handler,
            context=make_context(max_requests=17),
        )

    assert received == []


def test_out_of_scope_is_rejected_before_http():
    received = []

    def handler(request):
        received.append(request)
        return httpx.Response(200, content=b"ok")

    outside = RequestTemplate(
        method="GET",
        url="http://untrusted.invalid/products",
        params=(("category", "Pets"),),
    )

    with pytest.raises(
        ValueError,
        match="Invalid or unauthorized confirmation inputs",
    ):
        run_check(handler, template=outside)

    assert received == []


def test_invalid_secret_template_error_is_redacted():
    received = []
    secret = "do-not-disclose"
    invalid = RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        headers=(("Authorization", f"Bearer {secret}\n"),),
        params=(("category", "Pets"),),
    )

    def handler(request):
        received.append(request)
        return httpx.Response(200, content=b"unused")

    with pytest.raises(ValueError) as captured:
        run_check(handler, template=invalid)

    assert str(captured.value) == ("Invalid or unauthorized confirmation inputs.")
    assert secret not in str(captured.value)
    assert received == []


def test_result_repr_does_not_expose_payloads():
    sensitive_template = RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        headers=(("Authorization", "Bearer test-secret"),),
        cookies=(("session", "cookie-secret"),),
        params=(("category", "Pets"),),
    )

    def handler(request):
        assert request.headers["Authorization"] == "Bearer test-secret"
        assert "cookie-secret" in request.headers["Cookie"]
        category = request.url.params["category"]

        blocked = category in {
            "Pets" + FALSE_1,
            "Pets" + FALSE_2,
        }

        return httpx.Response(200, content=b"B" if blocked else b"A")

    result, _ = run_check(
        handler,
        template=sensitive_template,
    )

    output = repr(result)

    assert TRUE_1 not in output
    assert FALSE_1 not in output
    assert BASELINE_PRESERVING_CONTROL not in output
    assert "Authorization" not in output
    assert "test-secret" not in output
    assert "cookie-secret" not in output
    assert result.status is ConfirmationStatus.CANDIDATE


def test_result_models_reject_inconsistent_direct_construction():
    def handler(request):
        category = request.url.params["category"]
        blocked = category in {
            "Pets" + FALSE_1,
            "Pets" + FALSE_2,
        }
        return httpx.Response(
            200,
            content=b"B" if blocked else b"A",
        )

    result, _ = run_check(handler)
    assert result.evidence is not None

    observation = result.evidence.observations[0]
    with pytest.raises(ValueError):
        replace(observation, status_code=99)
    with pytest.raises(ValueError):
        replace(observation, body_digest="0" * 63)
    with pytest.raises(TypeError):
        replace(observation, truncated=1)

    with pytest.raises(ValueError, match="Inconsistent"):
        replace(
            result.evidence,
            baseline_matches_true=False,
        )

    with pytest.raises(ValueError, match="request count"):
        replace(result, total_requests=17)
    with pytest.raises(ValueError, match="candidate"):
        replace(
            result,
            reason_code="candidate_confirmation_mismatch",
        )
    with pytest.raises(ValueError, match="Incomplete"):
        replace(result, evidence=None)
    with pytest.raises(ValueError, match="Missing"):
        replace(
            result,
            status=ConfirmationStatus.INCONCLUSIVE,
            reason_code="confirmation_timeout",
            confirmation_requests=0,
            total_requests=6,
            evidence=None,
        )
    with pytest.raises(ValueError, match="pre-execution"):
        replace(
            result,
            status=ConfirmationStatus.INCONCLUSIVE,
            reason_code="confirmation_preflight_failed",
            confirmation_requests=1,
            total_requests=7,
            evidence=None,
        )
    with pytest.raises(ValueError, match="unstable"):
        replace(
            result,
            status=ConfirmationStatus.INCONCLUSIVE,
            reason_code="confirmation_unstable",
            confirmation_requests=11,
            total_requests=17,
            evidence=None,
        )


def test_baseline_preserving_control_is_fixed_and_reused():
    controls = []

    for _ in range(2):
        received = []

        def handler(request, received=received):
            category = request.url.params["category"]
            received.append(category)
            blocked = category in {
                "Pets" + FALSE_1,
                "Pets" + FALSE_2,
            }
            return httpx.Response(
                200,
                content=b"B" if blocked else b"A",
            )

        result, _ = run_check(handler)
        assert result.status is ConfirmationStatus.CANDIDATE
        run_controls = [
            value for value in received if value == "Pets" + BASELINE_PRESERVING_CONTROL
        ]
        assert run_controls == ["Pets" + BASELINE_PRESERVING_CONTROL] * 2
        controls.append(run_controls[0])

    assert controls[0] == controls[1]


@pytest.mark.parametrize(
    "mode",
    [InjectionMode.APPEND, InjectionMode.REPLACE],
)
def test_duplicate_parameter_occurrence_for_both_modes(mode):
    received = []
    template = RequestTemplate(
        method="GET",
        url=ORIGIN + "/products",
        params=(
            ("category", "First"),
            ("category", "Second"),
        ),
    )
    point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        occurrence=1,
        mode=mode,
    )
    prefix = "Second" if mode is InjectionMode.APPEND else ""

    def handler(request):
        values = request.url.params.get_list("category")
        received.append(tuple(values))
        assert values[0] == "First"
        value = values[1]
        blocked = value in {
            prefix + FALSE_1,
            prefix + FALSE_2,
        }
        return httpx.Response(
            200,
            content=b"B" if blocked else b"A",
        )

    result, context = run_check(
        handler,
        template=template,
        point=point,
    )

    assert result.status is ConfirmationStatus.CANDIDATE
    assert result.total_requests == 18
    assert context.budget.used_requests == 18
    assert len(received) == 18


def test_all_confirmation_requests_are_preflighted_before_initial_http(
    monkeypatch,
):
    received = []
    original_inject = confirmation_runner.inject

    def rejecting_inject(template, point, payload):
        if payload == TRUE_2:
            raise ValueError("synthetic invalid confirmation template")
        return original_inject(template, point, payload)

    monkeypatch.setattr(
        confirmation_runner,
        "inject",
        rejecting_inject,
    )

    def handler(request):
        received.append(request)
        return httpx.Response(200, content=b"unused")

    with pytest.raises(
        ValueError,
        match="Invalid or unauthorized confirmation inputs",
    ):
        run_check(handler)

    assert received == []
