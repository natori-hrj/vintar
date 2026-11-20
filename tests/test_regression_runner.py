"""Tests for policy-constrained regression execution."""

from dataclasses import FrozenInstanceError, replace

import httpx
import pytest

from vintar.checks.sqli.models import (
    BooleanEvidence,
    Observation,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import RequestTemplate
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression import runner as runner_module
from vintar.regression.cases import parse_regression_case
from vintar.regression.runner import (
    RegressionOutcome,
    RegressionStatus,
    TrustedExecutionPolicy,
    run_regression_case,
)

CASE_SOURCE = """
version = 1
id = "product-search-sqli"
type = "sqli.boolean"
expected_verdict = "not_detected"

[target]
url = "http://localhost:8000/products"
allowed_origin = "http://localhost:8000"

[[target.params]]
name = "category"
value = "Pets"

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 2.0
timeout_seconds = 10.0
"""
EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def make_case(expected: str = "not_detected"):
    source = CASE_SOURCE.replace(
        'expected_verdict = "not_detected"',
        f'expected_verdict = "{expected}"',
    )
    return parse_regression_case(source)


def make_confirmed_case():
    source = (
        CASE_SOURCE.replace(
            'expected_verdict = "not_detected"',
            'expected_verdict = "inconclusive"',
        )
        .replace(
            'false_payload = "false-probe"',
            'false_payload = "false-probe"\n\n[probes.confirmation]\ntrue_payload = "true-two"\nfalse_payload = "false-two"\nbaseline_preserving_control = "control"',
        )
        .replace("max_requests = 6", "max_requests = 18")
    )
    return parse_regression_case(source)


def make_case_for_origin(url: str, origin: str):
    source = CASE_SOURCE.replace(
        'url = "http://localhost:8000/products"',
        f'url = "{url}"',
    ).replace(
        'allowed_origin = "http://localhost:8000"',
        f'allowed_origin = "{origin}"',
    )
    return parse_regression_case(source)


def make_scope(host: str = "localhost") -> ScopePolicy:
    return ScopePolicy(allowed_origins=frozenset({AllowedOrigin("http", host, 8000)}))


def make_policy(**overrides) -> TrustedExecutionPolicy:
    values = {
        "scope": make_scope(),
        "max_requests": 6,
        "max_requests_per_second": 2.0,
        "max_timeout_seconds": 10.0,
        "max_response_size": 1_048_576,
    }
    values.update(overrides)
    return TrustedExecutionPolicy(**values)


def make_inconclusive_result(
    case_id: str,
) -> VerificationResult:
    return VerificationResult(
        check_id=case_id,
        verdict=Verdict.INCONCLUSIVE,
        observations=(),
        request_count=0,
        reason_code="budget_unavailable",
        reason="Test result.",
    )


def make_vulnerable_result(case_id: str) -> VerificationResult:
    observations = tuple(
        Observation(
            kind=kind,
            status_code=200,
            body_size=0,
            elapsed=0.1,
            body_digest=EMPTY_DIGEST,
        )
        for kind in (ProbeKind.BASELINE, ProbeKind.TRUE, ProbeKind.FALSE)
    )
    return VerificationResult(
        check_id=case_id,
        verdict=Verdict.VULNERABLE,
        observations=observations,
        request_count=3,
        reason_code="boolean_differential",
        reason="Verified test differential.",
        evidence=BooleanEvidence(1.0, 0.0, 0.0),
    )


@pytest.fixture(autouse=True)
def deterministic_rate_limiter(monkeypatch):
    """Keep runner integration tests real without wall-clock sleeps."""
    now = [0.0]

    def sleep(delay: float) -> None:
        now[0] += delay

    def factory(*, requests_per_second: float) -> RateLimiter:
        return RateLimiter(
            requests_per_second=requests_per_second,
            _clock=lambda: now[0],
            _sleep=sleep,
        )

    monkeypatch.setattr(runner_module, "RateLimiter", factory)


def test_disallowed_scope_is_rejected_without_http():
    case = make_case()
    policy = make_policy(scope=make_scope("example.com"))

    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(
        ValueError,
        match="trusted execution scope",
    ):
        run_regression_case(
            case,
            policy=policy,
            transport=httpx.MockTransport(handler),
        )

    assert calls == []


def test_trusted_budget_cannot_be_bypassed():
    case = make_case()
    policy = make_policy(max_requests=5)
    calls = []

    with pytest.raises(ValueError, match="budget"):
        run_regression_case(
            case,
            policy=policy,
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_configured_confirmation_preserves_boolean_candidate_contract():
    case = make_confirmed_case()
    false_values = {"Petsfalse-probe", "Petsfalse-two"}

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params["category"]
        return httpx.Response(200, text="none" if value in false_values else "all")

    outcome = run_regression_case(
        case,
        policy=make_policy(max_requests=18),
        transport=httpx.MockTransport(handler),
    )

    assert outcome.final_verdict is Verdict.INCONCLUSIVE
    assert outcome.final_reason_code == "boolean_candidate"
    assert outcome.request_count == 18
    assert outcome.confirmation is not None
    assert outcome.confirmation.reason_code == "confirmation_pattern_matched"
    assert outcome.status is RegressionStatus.INCONCLUSIVE


def test_confirmation_mismatch_is_final_inconclusive_reason():
    case = make_confirmed_case()

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params["category"]
        return httpx.Response(200, text="none" if value == "Petsfalse-probe" else "all")

    outcome = run_regression_case(
        case,
        policy=make_policy(max_requests=18),
        transport=httpx.MockTransport(handler),
    )

    assert outcome.final_verdict is Verdict.INCONCLUSIVE
    assert outcome.final_reason_code == "candidate_confirmation_mismatch"
    assert outcome.request_count == 18


def test_six_probes_run_through_existing_engine():
    case = make_case()
    policy = make_policy()

    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request.url.params["category"])
        return httpx.Response(
            200,
            content=b"same",
        )

    outcome = run_regression_case(
        case,
        policy=policy,
        transport=httpx.MockTransport(handler),
    )

    assert received == [
        "Pets",
        "Petstrue-probe",
        "Petsfalse-probe",
        "Pets",
        "Petsfalse-probe",
        "Petstrue-probe",
    ]

    assert outcome.verification.request_count == 6
    assert outcome.verification.verdict is Verdict.NOT_DETECTED
    assert outcome.expectation_match is True
    assert outcome.status is RegressionStatus.PASS


def test_boolean_candidate_is_inconclusive():
    case = make_case()
    received: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        value = request.url.params["category"]
        received.append(value)

        body = b"different" if "false-probe" in value else b"baseline"

        return httpx.Response(
            200,
            content=body,
        )

    outcome = run_regression_case(
        case,
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert len(received) == 6
    assert outcome.verification.verdict is Verdict.INCONCLUSIVE
    assert outcome.verification.reason_code == "boolean_candidate"
    assert outcome.expectation_match is False
    assert outcome.status is RegressionStatus.INCONCLUSIVE


def test_http_429_is_inconclusive_and_stops():
    case = make_case(expected="inconclusive")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            429,
            content=b"rate limited",
        )

    outcome = run_regression_case(
        case,
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert len(calls) == 1
    assert outcome.verification.request_count == 1
    assert outcome.verification.reason_code == "rate_limited"
    assert outcome.expectation_match is True
    assert outcome.status is RegressionStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("actual", "expected", "matched", "status"),
    [
        (
            Verdict.NOT_DETECTED,
            Verdict.NOT_DETECTED,
            True,
            RegressionStatus.PASS,
        ),
        (
            Verdict.NOT_DETECTED,
            Verdict.VULNERABLE,
            False,
            RegressionStatus.FAIL,
        ),
        (
            Verdict.VULNERABLE,
            Verdict.VULNERABLE,
            True,
            RegressionStatus.FAIL,
        ),
        (
            Verdict.VULNERABLE,
            Verdict.NOT_DETECTED,
            False,
            RegressionStatus.FAIL,
        ),
        (
            Verdict.INCONCLUSIVE,
            Verdict.INCONCLUSIVE,
            True,
            RegressionStatus.INCONCLUSIVE,
        ),
        (
            Verdict.INCONCLUSIVE,
            Verdict.NOT_DETECTED,
            False,
            RegressionStatus.INCONCLUSIVE,
        ),
    ],
)
def test_outcome_classification(
    actual: Verdict,
    expected: Verdict,
    matched: bool,
    status: RegressionStatus,
):
    from vintar.regression.runner import _classify

    assert matched is (actual is expected)
    assert _classify(actual, matched) is status


def test_outcome_rejects_inconsistent_match():
    result = make_inconclusive_result("test-case")

    with pytest.raises(
        ValueError,
        match="expectation match",
    ):
        RegressionOutcome(
            case_id="test-case",
            expected_verdict=Verdict.INCONCLUSIVE,
            verification=result,
            expectation_match=False,
            status=RegressionStatus.INCONCLUSIVE,
        )


def test_outcome_rejects_inconsistent_status():
    result = make_inconclusive_result("test-case")

    with pytest.raises(
        ValueError,
        match="regression status",
    ):
        RegressionOutcome(
            case_id="test-case",
            expected_verdict=Verdict.INCONCLUSIVE,
            verification=result,
            expectation_match=True,
            status=RegressionStatus.PASS,
        )


def test_outcome_rejects_mismatched_case_id():
    result = make_inconclusive_result("original-case")

    with pytest.raises(
        ValueError,
        match="identifier mismatch",
    ):
        RegressionOutcome(
            case_id="different-case",
            expected_verdict=Verdict.INCONCLUSIVE,
            verification=result,
            expectation_match=True,
            status=RegressionStatus.INCONCLUSIVE,
        )


def test_outcome_rejects_invalid_case_identifier():
    result = make_inconclusive_result("invalid case id")

    with pytest.raises(ValueError, match="Invalid case identifier"):
        RegressionOutcome(
            case_id="invalid case id",
            expected_verdict=Verdict.INCONCLUSIVE,
            verification=result,
            expectation_match=True,
            status=RegressionStatus.INCONCLUSIVE,
        )


def test_expected_vulnerable_match_remains_gate_failure():
    result = make_vulnerable_result("vulnerable-fixture")

    outcome = RegressionOutcome(
        case_id="vulnerable-fixture",
        expected_verdict=Verdict.VULNERABLE,
        verification=result,
        expectation_match=True,
        status=RegressionStatus.FAIL,
    )

    assert outcome.expectation_match is True
    assert outcome.status is RegressionStatus.FAIL


def test_execution_limits_are_capped(monkeypatch):
    from vintar.regression import runner

    case = make_case()
    captured = []

    def fake_verify(**kwargs):
        captured.append(kwargs["context"])
        return make_inconclusive_result(kwargs["check_id"])

    monkeypatch.setattr(
        runner,
        "verify_boolean_sqli",
        fake_verify,
    )

    policy = make_policy(
        max_requests_per_second=0.5,
        max_timeout_seconds=3.0,
        max_response_size=4096,
    )

    outcome = run_regression_case(
        case,
        policy=policy,
    )

    context = captured[0]

    assert context.scope == make_scope()
    assert context.budget.max_requests == 6
    assert context.rate_limiter.requests_per_second == 0.5
    assert context.timeout == 3.0
    assert context.max_response_size == 4096
    assert outcome.status is RegressionStatus.INCONCLUSIVE


def test_case_limits_cannot_be_relaxed_by_broader_policy(monkeypatch):
    captured = []

    def fake_verify(**kwargs):
        captured.append(kwargs["context"])
        return make_inconclusive_result(kwargs["check_id"])

    monkeypatch.setattr(runner_module, "verify_boolean_sqli", fake_verify)

    run_regression_case(
        make_case(),
        policy=make_policy(
            max_requests=12,
            max_requests_per_second=5.0,
            max_timeout_seconds=20.0,
            max_response_size=2_097_152,
        ),
    )

    context = captured[0]
    assert context.budget.max_requests == 6
    assert context.rate_limiter.requests_per_second == 2.0
    assert context.timeout == 10.0
    assert context.max_response_size == 1_048_576


def test_case_cannot_expand_trusted_scope():
    case = make_case()

    broader_scope = ScopePolicy(
        allowed_origins=frozenset(
            {
                AllowedOrigin("http", "localhost", 8000),
                AllowedOrigin("http", "example.com", 80),
            }
        )
    )

    modified_case = replace(
        case,
        scope=broader_scope,
    )

    received: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        received.append(request)
        return httpx.Response(
            200,
            content=b"same",
        )

    outcome = run_regression_case(
        modified_case,
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert outcome.status is RegressionStatus.PASS
    assert len(received) == 6
    assert all(request.url.host == "localhost" for request in received)


def test_nonempty_scope_intersection_cannot_authorize_different_target():
    case = make_case()
    broader_scope = ScopePolicy(
        allowed_origins=frozenset(
            {
                AllowedOrigin("http", "localhost", 8000),
                AllowedOrigin("http", "example.com", 80),
            }
        )
    )
    modified_case = replace(
        case,
        template=RequestTemplate(
            method="GET",
            url="http://example.com/products",
            params=case.template.params,
        ),
        scope=broader_scope,
    )
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    with pytest.raises(ValueError, match="outside the allowed scope"):
        run_regression_case(
            modified_case,
            policy=make_policy(),
            transport=httpx.MockTransport(handler),
        )

    assert calls == []


@pytest.mark.parametrize(
    ("url", "case_origin", "trusted_origin"),
    [
        (
            "http://[::1]:80/products",
            "http://[::1]",
            AllowedOrigin("http", "::1", 80),
        ),
        (
            "https://例え.テスト:443/products",
            "https://例え.テスト",
            AllowedOrigin("https", "xn--r8jz45g.xn--zckzah", 443),
        ),
        (
            "http://localhost:80/products",
            "http://localhost",
            AllowedOrigin("http", "LOCALHOST", 80),
        ),
    ],
    ids=["ipv6", "idn", "default-port"],
)
def test_normalized_origin_intersection_is_enforced(
    url,
    case_origin,
    trusted_origin,
):
    case = make_case_for_origin(url, case_origin)
    policy = make_policy(scope=ScopePolicy(allowed_origins=frozenset({trusted_origin})))
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, content=b"same")

    outcome = run_regression_case(
        case,
        policy=policy,
        transport=httpx.MockTransport(handler),
    )

    assert len(calls) == 6
    assert outcome.status is RegressionStatus.PASS


def test_different_trusted_port_is_rejected_without_http():
    case = make_case()
    policy = make_policy(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8001)})
        )
    )
    calls = []

    with pytest.raises(ValueError, match="trusted execution scope"):
        run_regression_case(
            case,
            policy=policy,
            transport=httpx.MockTransport(
                lambda request: calls.append(request) or httpx.Response(200)
            ),
        )

    assert calls == []


def test_httpx_failure_becomes_inconclusive_outcome():
    case = make_case()
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        raise httpx.ConnectError("sensitive target detail", request=request)

    outcome = run_regression_case(
        case,
        policy=make_policy(),
        transport=httpx.MockTransport(handler),
    )

    assert len(calls) == 1
    assert outcome.verification.verdict is Verdict.INCONCLUSIVE
    assert outcome.verification.reason_code == "probe_failed"
    assert outcome.status is RegressionStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    "invalid",
    [None, {}, "case", 123],
)
def test_invalid_case_is_rejected(invalid):
    with pytest.raises(TypeError):
        run_regression_case(
            invalid,
            policy=make_policy(),
        )


@pytest.mark.parametrize(
    "invalid",
    [None, {}, "policy", 123],
)
def test_invalid_policy_is_rejected(invalid):
    with pytest.raises(TypeError):
        run_regression_case(
            make_case(),
            policy=invalid,
        )


@pytest.mark.parametrize(
    "invalid",
    [0, -1, True, 1.5],
)
def test_invalid_trusted_budget_is_rejected(invalid):
    with pytest.raises(ValueError):
        make_policy(max_requests=invalid)


@pytest.mark.parametrize(
    "invalid",
    [0, 0.01, -1, True, "fast", float("nan"), float("inf")],
)
def test_invalid_trusted_rate_is_rejected(invalid):
    with pytest.raises(ValueError):
        make_policy(max_requests_per_second=invalid)


def test_huge_trusted_rate_is_rejected_without_overflow():
    with pytest.raises(ValueError, match="execution limit"):
        make_policy(max_requests_per_second=10**10_000)


@pytest.mark.parametrize("rate", [0.1, 10.0])
def test_valid_trusted_rate_boundaries(rate):
    policy = make_policy(max_requests_per_second=rate)

    assert policy.max_requests_per_second == rate


@pytest.mark.parametrize(
    "invalid",
    [0, -1, True, "slow", float("nan"), float("inf")],
)
def test_invalid_trusted_timeout_is_rejected(invalid):
    with pytest.raises(ValueError):
        make_policy(max_timeout_seconds=invalid)


@pytest.mark.parametrize("invalid", [0, -1, True, 1.5])
def test_invalid_trusted_response_size_is_rejected(invalid):
    with pytest.raises(ValueError):
        make_policy(max_response_size=invalid)


def test_policy_and_outcome_are_immutable():
    policy = make_policy()
    outcome = run_regression_case(
        make_case(expected="inconclusive"),
        policy=policy,
        transport=httpx.MockTransport(lambda request: httpx.Response(429)),
    )

    with pytest.raises(FrozenInstanceError):
        policy.max_requests = 100
    with pytest.raises(FrozenInstanceError):
        outcome.status = RegressionStatus.PASS


def test_sensitive_fields_are_absent_from_outcome_repr():
    case = make_case()

    outcome = run_regression_case(
        case,
        policy=make_policy(),
        transport=httpx.MockTransport(lambda request: httpx.Response(429)),
    )

    text = repr(outcome)

    assert "true-probe" not in text
    assert "false-probe" not in text
    assert "localhost" not in text
    assert "localhost" not in repr(make_policy())
