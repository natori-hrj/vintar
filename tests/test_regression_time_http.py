"""Exercise Schema v1 time cases through the single-case loopback runner."""

import socket
import threading
from urllib.parse import urlsplit

import pytest
import uvicorn
from test_sqli_time_reliability_http import (
    CONTROL_PAYLOAD,
    DELAY_PAYLOAD,
    DELAY_SECONDS,
    ReliabilityServer,
    ServerState,
    create_app,
    expected_probe_values,
)

from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.time_analyzer import (
    TimeAnalysisStatus,
    TimeObservation,
    TimeProbeOutcome,
    analyze_time_probes,
)
from vintar.checks.sqli.time_contract import time_product_result
from vintar.checks.sqli.time_plan import (
    TIME_PROBE_ORDER,
    TimePayloads,
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
from vintar.regression.cases import TimeRegressionCase, parse_regression_case
from vintar.regression.runner import (
    RegressionStatus,
    TrustedExecutionPolicy,
    run_regression_case,
)

SAFE_LIVE_OUTCOMES = frozenset(
    {
        (
            Verdict.NOT_DETECTED,
            "timing_pattern_not_matched",
            RegressionStatus.PASS,
        ),
        (
            Verdict.INCONCLUSIVE,
            "unstable_timing",
            RegressionStatus.INCONCLUSIVE,
        ),
    }
)
DELAY_SIGNAL_LIVE_OUTCOMES = frozenset(
    {
        (
            Verdict.INCONCLUSIVE,
            "timing_pattern_matched",
            RegressionStatus.INCONCLUSIVE,
        ),
        (
            Verdict.INCONCLUSIVE,
            "unstable_timing",
            RegressionStatus.INCONCLUSIVE,
        ),
    }
)
RECORDED_ELAPSED_SECONDS = {
    "vulnerable": (
        0.007061,
        0.004588,
        0.352533,
        0.001884,
        0.353464,
        0.001846,
        0.353944,
        0.003003,
        0.001503,
    ),
    "safe": (0.006, 0.003, 0.003, 0.003, 0.002, 0.002, 0.003, 0.002, 0.002),
}


def time_case(origin: str, mode: str, expected: str) -> TimeRegressionCase:
    source = f'''\
version = 1
id = "time-{mode}"
type = "sqli.time"
expected_verdict = "{expected}"

[target]
url = "{origin}/reliability/{mode}"
allowed_origin = "{origin}"

[[target.params]]
name = "category"
value = "Pets"

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
delay_payload = "{DELAY_PAYLOAD}"
control_payload = "{CONTROL_PAYLOAD}"
expected_delay_seconds = 0.25

[limits]
max_requests = 9
requests_per_second = 10.0
timeout_seconds = 3.0
'''
    case = parse_regression_case(source)
    assert isinstance(case, TimeRegressionCase)
    return case


@pytest.fixture(scope="module")
def time_regression_server():
    state = ServerState()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(128)
        except OSError:
            pytest.fail(
                "Cannot bind the time regression fixture to loopback. Check that the runner permits ephemeral IPv4 loopback sockets."
            )

        port = listener.getsockname()[1]
        ready = threading.Event()
        server = ReliabilityServer(
            uvicorn.Config(
                create_app(state),
                host="127.0.0.1",
                port=port,
                lifespan="off",
                access_log=False,
                log_level="critical",
                server_header=False,
            ),
            ready,
        )
        worker = threading.Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            daemon=True,
        )
        worker.start()
        if not ready.wait(timeout=5.0) or not worker.is_alive():
            pytest.fail(
                "The time regression fixture did not start. Check thread scheduling and loopback transport setup."
            )

        try:
            yield state, f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            worker.join(timeout=5.0)
            if worker.is_alive():
                server.force_exit = True
                worker.join(timeout=5.0)
            assert not worker.is_alive(), (
                "The time regression fixture did not stop. Check the server shutdown event and loopback transport state."
            )
    finally:
        listener.close()


@pytest.mark.parametrize(
    ("mode", "expected", "delay_calls"),
    [
        ("vulnerable", "inconclusive", 6),
        ("safe", "not_detected", 0),
    ],
)
def test_time_case_loopback_order_counts_statuses_and_deadline(
    time_regression_server,
    mode,
    expected,
    delay_calls,
):
    state, origin = time_regression_server
    state.reset()
    port = urlsplit(origin).port
    assert port is not None
    policy = TrustedExecutionPolicy(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", port)})
        ),
        max_requests=9,
        max_requests_per_second=10.0,
        max_timeout_seconds=3.0,
        max_time_execution_seconds=30.0,
    )

    outcome = run_regression_case(
        time_case(origin, mode, expected),
        policy=policy,
    )

    received, sql_calls, observed_delay_calls = state.snapshot()
    assert outcome.time_run is not None
    analysis = outcome.time_run.analysis
    elapsed_values = tuple(item.elapsed_seconds for item in analysis.observations)
    diagnostic = (
        f"case_id={'time-' + mode!r}, status={analysis.status.value!r}, "
        f"reason_code={analysis.reason_code!r}, elapsed_seconds={elapsed_values!r}"
    )
    product_outcome = (
        outcome.final_verdict,
        outcome.final_reason_code,
        outcome.status,
    )
    allowed = DELAY_SIGNAL_LIVE_OUTCOMES if mode == "vulnerable" else SAFE_LIVE_OUTCOMES

    assert product_outcome in allowed, diagnostic
    if mode == "vulnerable":
        assert analysis.status is not TimeAnalysisStatus.NOT_CONFIRMED, diagnostic
    assert outcome.request_count == 9, diagnostic
    assert outcome.time_run.budget_used == 9, diagnostic
    assert outcome.time_run.transport_attempts == 9, diagnostic
    assert not outcome.time_run.deadline_exceeded, diagnostic
    assert received == 9, diagnostic
    assert state.received_values() == expected_probe_values(), diagnostic
    assert [item.status_code for item in outcome.time_run.analysis.observations] == [
        200
    ] * 9, diagnostic
    assert sql_calls == 9, diagnostic
    assert observed_delay_calls == delay_calls, diagnostic
    if mode == "vulnerable":
        assert state.delay_value_count(DELAY_SECONDS) == 3
        assert state.delay_value_count(0.0) == 3


def analyze_fixed_elapsed(elapsed_values: tuple[float, ...]):
    origin = "http://127.0.0.1:18085"
    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", 18085)})
        ),
        budget=RequestBudget(9),
        timeout=3.0,
        rate_limiter=RateLimiter(requests_per_second=100.0),
    )
    plan = prepare_time_plan(
        template=RequestTemplate(
            method="GET",
            url=origin + "/reliability/fixed",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=TimePayloads(delay=DELAY_PAYLOAD, control=CONTROL_PAYLOAD),
        expected_delay_seconds=0.25,
        context=context,
    )
    observations = tuple(
        TimeObservation(
            kind=kind,
            sequence=sequence,
            outcome=TimeProbeOutcome.COMPLETED,
            elapsed_seconds=elapsed,
            status_code=200,
        )
        for sequence, (kind, elapsed) in enumerate(
            zip(TIME_PROBE_ORDER, elapsed_values, strict=True), start=1
        )
    )
    return analyze_time_probes(plan=plan, observations=observations)


@pytest.mark.parametrize(
    ("mode", "expected_status", "expected_reason", "expected_verdict"),
    [
        (
            "vulnerable",
            TimeAnalysisStatus.CANDIDATE,
            "timing_pattern_matched",
            Verdict.INCONCLUSIVE,
        ),
        (
            "safe",
            TimeAnalysisStatus.NOT_CONFIRMED,
            "timing_pattern_not_matched",
            Verdict.NOT_DETECTED,
        ),
    ],
)
def test_fixed_observations_classify_regression_time_case_exactly(
    mode, expected_status, expected_reason, expected_verdict
):
    analysis = analyze_fixed_elapsed(RECORDED_ELAPSED_SECONDS[mode])
    product = time_product_result(analysis)
    elapsed_values = tuple(item.elapsed_seconds for item in analysis.observations)
    diagnostic = (
        f"case_id={'time-' + mode!r}, status={analysis.status.value!r}, "
        f"reason_code={analysis.reason_code!r}, elapsed_seconds={elapsed_values!r}"
    )

    assert analysis.status is expected_status, diagnostic
    assert analysis.reason_code == expected_reason, diagnostic
    assert product.verdict is expected_verdict, diagnostic
    assert product.reason_code == expected_reason, diagnostic
