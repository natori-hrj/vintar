"""Real HTTP middleware interference corpus.

All scenarios are non-SQL implementations.
A CANDIDATE result is therefore a false candidate.

Only loopback HTTP is used.
"""

import socket
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from vintar.checks.sqli.confirmation_runner import (
    ConfirmationStatus,
    verify_boolean_sqli_with_confirmation,
)
from vintar.checks.sqli.cross_phase import (
    CrossPhaseStatus,
    assess_cross_phase_consistency,
)
from vintar.checks.sqli.models import ProbeKind, Verdict
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

TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
BASELINE_PRESERVING_CONTROL = "' AND 7=7-- "

SCENARIOS = (
    "waf200_mimic",
    "waf403",
    "waf429",
    "waf200_blanket",
    "auth401",
    "auth302",
    "auth200_login",
    "cache_ignore_query",
    "cache_dynamic",
    "cache_rollover",
)

EXPECTED = {
    "waf200_mimic": (ConfirmationStatus.CANDIDATE, 18),
    "waf403": (ConfirmationStatus.SKIPPED, 6),
    "waf429": (ConfirmationStatus.SKIPPED, 3),
    "waf200_blanket": (ConfirmationStatus.SKIPPED, 6),
    "auth401": (ConfirmationStatus.INCONCLUSIVE, 7),
    "auth302": (ConfirmationStatus.INCONCLUSIVE, 7),
    "auth200_login": (ConfirmationStatus.INCONCLUSIVE, 18),
    "cache_ignore_query": (ConfirmationStatus.SKIPPED, 6),
    "cache_dynamic": (ConfirmationStatus.INCONCLUSIVE, 18),
    "cache_rollover": (ConfirmationStatus.INCONCLUSIVE, 18),
}


@dataclass(frozen=True, repr=False)
class ReceivedRequest:
    scenario: str
    category: str
    raw_query: str
    sequence: int


@dataclass(repr=False)
class FixtureState:
    received: list[ReceivedRequest] = field(default_factory=list)
    route_calls: Counter[str] = field(default_factory=Counter)
    middleware_responses: Counter[str] = field(default_factory=Counter)
    middleware_calls: int = 0
    _lock: threading.Lock = field(
        default_factory=threading.Lock,
        init=False,
        repr=False,
    )

    def record(
        self,
        scenario: str,
        category: str,
        raw_query: str,
    ) -> int:
        with self._lock:
            sequence = len(self.received) + 1
            self.received.append(
                ReceivedRequest(
                    scenario=scenario,
                    category=category,
                    raw_query=raw_query,
                    sequence=sequence,
                )
            )
            return sequence

    def record_route(self, scenario: str) -> None:
        with self._lock:
            self.route_calls[scenario] += 1

    def record_intercept(self, scenario: str) -> None:
        with self._lock:
            self.middleware_responses[scenario] += 1

    def record_middleware_call(self) -> None:
        with self._lock:
            self.middleware_calls += 1

    def middleware_call_count(self) -> int:
        with self._lock:
            return self.middleware_calls

    def snapshot(
        self,
    ) -> tuple[
        tuple[ReceivedRequest, ...],
        dict[str, int],
        dict[str, int],
    ]:
        with self._lock:
            return (
                tuple(self.received),
                dict(self.route_calls),
                dict(self.middleware_responses),
            )

    def reset(self) -> None:
        with self._lock:
            self.received.clear()
            self.route_calls.clear()
            self.middleware_responses.clear()
            self.middleware_calls = 0


def is_false_1(category: str) -> bool:
    return category == "Pets" + FALSE_1


def is_false_2(category: str) -> bool:
    return category == "Pets" + FALSE_2


def text_response(
    content: bytes,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> Response:
    return Response(
        content=content,
        status_code=status_code,
        headers=headers,
        media_type="text/plain",
    )


def middleware_response(
    scenario: str,
    category: str,
    sequence: int,
) -> Response | None:
    """Return an intercepted response or None to reach the route."""
    injected = category != "Pets"
    false_1 = is_false_1(category)
    false_2 = is_false_2(category)
    if scenario == "waf200_mimic":
        if false_2:
            return text_response(b"B")

    elif scenario == "waf403":
        if false_1:
            return text_response(
                b"blocked",
                status_code=403,
            )

    elif scenario == "waf429":
        if false_1:
            return text_response(
                b"rate-limited",
                status_code=429,
            )

    elif scenario == "waf200_blanket":
        if injected:
            return text_response(b"waf-block-page")

    elif scenario == "auth401":
        if sequence >= 7:
            return text_response(
                b"authentication-required",
                status_code=401,
            )

    elif scenario == "auth302":
        if sequence >= 7:
            return text_response(
                b"",
                status_code=302,
                headers={"Location": "/login"},
            )

    elif scenario == "auth200_login":
        if sequence >= 7:
            return text_response(b"login-page")

    elif scenario == "cache_ignore_query":
        return text_response(b"cached-products")

    elif scenario == "cache_dynamic":
        if sequence >= 7:
            return text_response(f"nonce-{sequence}".encode("ascii"))

    elif scenario == "cache_rollover":
        if sequence >= 7:
            blocked = false_1 or false_2
            return text_response(b"B-generation2" if blocked else b"A-generation2")

    else:
        raise ValueError("Unknown middleware scenario.")

    return None


def create_app(state: FixtureState) -> FastAPI:
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def simulated_middleware(request: Request, call_next):
        state.record_middleware_call()
        path = request.url.path

        if not path.startswith("/products/"):
            return text_response(
                b"not-found",
                status_code=404,
            )

        scenario = path.removeprefix("/products/")
        if scenario not in SCENARIOS:
            return text_response(
                b"not-found",
                status_code=404,
            )

        categories = request.query_params.getlist("category")
        if not categories:
            return text_response(
                b"missing-category",
                status_code=422,
            )
        if len(categories) != 1:
            return text_response(
                b"duplicate-category",
                status_code=400,
            )

        category = categories[0]
        raw_query = request.scope["query_string"].decode("ascii")

        sequence = state.record(
            scenario=scenario,
            category=category,
            raw_query=raw_query,
        )

        intercepted = middleware_response(
            scenario=scenario,
            category=category,
            sequence=sequence,
        )

        if intercepted is not None:
            state.record_intercept(scenario)
            return intercepted

        return await call_next(request)

    @app.get("/products/{scenario}")
    async def products(
        scenario: str,
        request: Request,
    ) -> Response:
        state.record_route(scenario)
        category = request.query_params["category"]

        return text_response(b"B" if is_false_1(category) else b"A")

    return app


@pytest.fixture
def middleware_server():
    state = FixtureState()
    app = create_app(state)

    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )
    worker = None
    server = None

    try:
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
        except OSError:
            pytest.skip("Loopback socket unavailable")

        assert listener.getsockname()[0] == "127.0.0.1"
        port = listener.getsockname()[1]

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            lifespan="off",
            access_log=False,
            log_level="critical",
            server_header=False,
        )

        server = uvicorn.Server(config)

        worker = threading.Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            daemon=True,
        )
        worker.start()

        deadline = time.monotonic() + 5

        while not server.started and worker.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)

        assert server.started
        assert worker.is_alive()

        yield state, f"http://127.0.0.1:{port}"

    finally:
        if server is not None:
            server.should_exit = True

        if worker is not None:
            worker.join(timeout=5)
            if worker.is_alive() and server is not None:
                server.force_exit = True
                worker.join(timeout=5)

            assert not worker.is_alive()

        listener.close()


def run_confirmation(
    origin: str,
    scenario: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    cookies: tuple[tuple[str, str], ...] = (),
):
    port = urlsplit(origin).port
    assert port is not None

    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset(
                {
                    AllowedOrigin(
                        "http",
                        "127.0.0.1",
                        port,
                    )
                }
            )
        ),
        budget=RequestBudget(18),
        timeout=5.0,
        rate_limiter=RateLimiter(
            requests_per_second=100,
        ),
        max_response_size=1_048_576,
    )

    outcome = verify_boolean_sqli_with_confirmation(
        check_id=f"middleware-{scenario}",
        template=RequestTemplate(
            method="GET",
            url=f"{origin}/products/{scenario}",
            headers=headers,
            cookies=cookies,
            params=(("category", "Pets"),),
        ),
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
    )

    return outcome, context


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_middleware_corpus(
    middleware_server,
    scenario,
):
    state, origin = middleware_server
    outcome, context = run_confirmation(origin, scenario)
    expected_status, expected_count = EXPECTED[scenario]

    received, route_calls, intercepted = state.snapshot()

    assert outcome.status is expected_status
    assert outcome.request_count == expected_count
    assert outcome.total_requests == expected_count
    assert context.budget.used_requests == expected_count
    assert len(received) == expected_count
    assert state.middleware_call_count() == expected_count
    assert len(received) <= 18

    assert route_calls.get(scenario, 0) + intercepted.get(scenario, 0) == expected_count

    assert outcome.initial.verdict is not Verdict.VULNERABLE

    assert [item.sequence for item in received] == list(range(1, expected_count + 1))

    for item in received:
        assert parse_qs(
            item.raw_query,
            keep_blank_values=True,
        ) == {"category": [item.category]}

        assert " " not in item.raw_query
        assert "'" not in item.raw_query

        if "'" in item.category:
            assert "%27" in item.raw_query

    if expected_status is ConfirmationStatus.CANDIDATE:
        assert outcome.evidence is not None
        assert outcome.reason_code == ("confirmation_pattern_matched")
        assert outcome.confirmation_requests == 12

    elif outcome.reason_code == "candidate_confirmation_mismatch":
        assert outcome.evidence is not None

    else:
        assert outcome.evidence is None

    if scenario in ("auth401", "auth302"):
        assert outcome.reason_code == ("confirmation_non_success_status")

    if scenario == "cache_dynamic":
        assert outcome.reason_code == ("confirmation_unstable")

    if scenario == "cache_rollover":
        assert outcome.reason_code == ("confirmation_cross_phase_mismatch")
        assert outcome.confirmation_requests == 12

    if scenario == "waf403":
        assert outcome.initial.reason_code == ("non_success_status")

    if scenario == "waf429":
        assert outcome.initial.reason_code == "rate_limited"


def test_middleware_corpus_has_no_sql_execution():
    state = FixtureState()
    app = create_app(state)

    assert {route.path for route in app.routes} == {"/products/{scenario}"}

    assert not hasattr(state, "sql_started")
    assert not hasattr(state, "sql_completed")


def test_middleware_rejects_missing_and_duplicate_query_values(
    middleware_server,
):
    state, origin = middleware_server

    with httpx.Client(
        trust_env=False,
        follow_redirects=False,
        timeout=3,
    ) as client:
        missing = client.get(f"{origin}/products/waf200_mimic")
        duplicate = client.get(
            f"{origin}/products/waf200_mimic",
            params=(
                ("category", "Pets"),
                ("category", "Office"),
            ),
        )

    received, route_calls, intercepted = state.snapshot()

    assert missing.status_code == 422
    assert duplicate.status_code == 400
    assert state.middleware_call_count() == 2
    assert received == ()
    assert route_calls == {}
    assert intercepted == {}


def test_login_redirect_is_not_followed(
    middleware_server,
):
    state, origin = middleware_server
    outcome, _ = run_confirmation(origin, "auth302")

    received, _, _ = state.snapshot()

    assert outcome.status is ConfirmationStatus.INCONCLUSIVE
    assert outcome.total_requests == 7
    assert len(received) == 7
    assert state.middleware_call_count() == 7
    assert all(item.scenario == "auth302" for item in received)


def test_cache_rollover_is_rejected_by_cross_phase_guard(
    middleware_server,
):
    state, origin = middleware_server
    outcome, context = run_confirmation(
        origin,
        "cache_rollover",
    )

    received, _, _ = state.snapshot()

    assert len(received) == 18
    assert state.middleware_call_count() == 18
    assert context.budget.used_requests == 18

    assert outcome.initial.verdict is Verdict.INCONCLUSIVE
    assert outcome.initial.reason_code == "boolean_candidate"
    assert outcome.status is ConfirmationStatus.INCONCLUSIVE
    assert outcome.reason_code == ("confirmation_cross_phase_mismatch")
    assert outcome.evidence is None
    assert outcome.confirmation_requests == 12


@pytest.mark.parametrize(
    ("scenario", "expected_status", "mismatched_kinds"),
    [
        (
            "waf200_mimic",
            CrossPhaseStatus.MATCH,
            (),
        ),
        (
            "auth200_login",
            CrossPhaseStatus.MISMATCH,
            (
                ProbeKind.BASELINE,
                ProbeKind.TRUE,
                ProbeKind.FALSE,
            ),
        ),
    ],
)
def test_cross_phase_guard_uses_existing_http_evidence_only(
    middleware_server,
    scenario,
    expected_status,
    mismatched_kinds,
):
    state, origin = middleware_server
    outcome, context = run_confirmation(origin, scenario)

    assert outcome.evidence is not None

    requests_before = state.middleware_call_count()
    budget_before = context.budget.used_requests

    assessment = assess_cross_phase_consistency(
        initial=outcome.initial,
        confirmation=outcome.evidence,
    )

    assert assessment.status is expected_status
    assert assessment.mismatched_kinds == mismatched_kinds
    assert state.middleware_call_count() == requests_before
    assert context.budget.used_requests == budget_before
    assert requests_before == 18


def test_baseline_preserving_control_is_fixed_and_repeated(
    middleware_server,
):
    state, origin = middleware_server
    for _ in range(2):
        state.reset()
        outcome, _ = run_confirmation(
            origin,
            "waf200_mimic",
        )

        assert outcome.status is ConfirmationStatus.CANDIDATE

        received, _, _ = state.snapshot()
        values = [
            item.category
            for item in received
            if item.category == "Pets" + BASELINE_PRESERVING_CONTROL
        ]

        assert len(values) == 2
        assert values[0] == values[1]
        assert values[0] == "Pets" + BASELINE_PRESERVING_CONTROL


def test_middleware_classification_is_repeatable(
    middleware_server,
):
    state, origin = middleware_server
    runs = []

    for _ in range(2):
        result = {}

        for scenario in SCENARIOS:
            state.reset()
            outcome, _ = run_confirmation(
                origin,
                scenario,
            )
            result[scenario] = (
                outcome.status,
                outcome.reason_code,
                outcome.request_count,
            )

        runs.append(result)

    assert runs[0] == runs[1]


def test_middleware_corpus_metrics(
    middleware_server,
):
    state, origin = middleware_server

    results: dict[str, ConfirmationStatus] = {}
    counts: dict[str, int] = {}

    for scenario in SCENARIOS:
        state.reset()

        outcome, context = run_confirmation(
            origin,
            scenario,
        )
        received, _, _ = state.snapshot()

        results[scenario] = outcome.status
        counts[scenario] = outcome.request_count

        assert len(received) == context.budget.used_requests

    assert sum(counts.values()) == 107
    assert sum(min(6, count) for count in counts.values()) == 57
    assert sum(max(0, count - 6) for count in counts.values()) == 50

    distribution = Counter(results.values())

    assert distribution == {
        ConfirmationStatus.CANDIDATE: 1,
        ConfirmationStatus.INCONCLUSIVE: 5,
        ConfirmationStatus.SKIPPED: 4,
    }

    false_candidates = distribution[ConfirmationStatus.CANDIDATE]
    decisive = distribution[ConfirmationStatus.CANDIDATE]
    non_decisions = (
        distribution[ConfirmationStatus.INCONCLUSIVE]
        + distribution[ConfirmationStatus.SKIPPED]
    )

    assert false_candidates / len(SCENARIOS) == 1 / 10
    assert false_candidates / decisive == 1.0
    assert decisive / len(SCENARIOS) == 1 / 10

    assert distribution[ConfirmationStatus.SKIPPED] / len(SCENARIOS) == 4 / 10
    assert distribution[ConfirmationStatus.INCONCLUSIVE] / len(SCENARIOS) == 5 / 10
    assert non_decisions / len(SCENARIOS) == 9 / 10

    groups = {
        "waf": tuple(item for item in SCENARIOS if item.startswith("waf")),
        "auth": tuple(item for item in SCENARIOS if item.startswith("auth")),
        "cache": tuple(item for item in SCENARIOS if item.startswith("cache")),
    }

    expected_group_rates = {
        "waf": (1 / 4, 1.0),
        "auth": (0.0, 0.0),
        "cache": (0.0, 0.0),
    }

    for name, scenarios in groups.items():
        candidates = sum(
            results[item] is ConfirmationStatus.CANDIDATE for item in scenarios
        )

        group_decisive = sum(
            results[item]
            in {
                ConfirmationStatus.CANDIDATE,
            }
            for item in scenarios
        )

        false_candidate_rate = candidates / len(scenarios)
        conditional_rate = candidates / group_decisive if group_decisive else 0.0

        assert (
            false_candidate_rate,
            conditional_rate,
        ) == expected_group_rates[name]


def test_middleware_output_does_not_expose_probe_values(
    middleware_server,
    capsys,
):
    _, origin = middleware_server

    secret = "middleware-secret-value"

    outcome, _ = run_confirmation(
        origin,
        "waf200_mimic",
        headers=(("Authorization", f"Bearer {secret}"),),
        cookies=(("session", secret),),
    )

    output = repr(outcome)
    captured = capsys.readouterr()

    for value in (
        TRUE_1,
        FALSE_1,
        TRUE_2,
        FALSE_2,
        BASELINE_PRESERVING_CONTROL,
        secret,
    ):
        assert value not in output
        assert value not in captured.out
        assert value not in captured.err
