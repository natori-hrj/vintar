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
from vintar.core.scope import AllowedOrigin, ScopePolicy
from vintar.regression.cases import TimeRegressionCase, parse_regression_case
from vintar.regression.runner import (
    RegressionStatus,
    TrustedExecutionPolicy,
    run_regression_case,
)


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
    ("mode", "expected", "verdict", "reason", "delay_calls"),
    [
        (
            "vulnerable",
            "inconclusive",
            Verdict.INCONCLUSIVE,
            "timing_pattern_matched",
            6,
        ),
        (
            "safe",
            "not_detected",
            Verdict.NOT_DETECTED,
            "timing_pattern_not_matched",
            0,
        ),
    ],
)
def test_time_case_loopback_order_counts_statuses_and_deadline(
    time_regression_server,
    mode,
    expected,
    verdict,
    reason,
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
    assert outcome.final_verdict is verdict
    assert outcome.final_reason_code == reason
    assert outcome.expectation_match
    assert outcome.status is (
        RegressionStatus.PASS
        if verdict is Verdict.NOT_DETECTED
        else RegressionStatus.INCONCLUSIVE
    )
    assert outcome.request_count == 9
    assert outcome.time_run is not None
    assert outcome.time_run.budget_used == 9
    assert outcome.time_run.transport_attempts == 9
    assert not outcome.time_run.deadline_exceeded
    assert received == 9
    assert state.received_values() == expected_probe_values()
    assert [item.status_code for item in outcome.time_run.analysis.observations] == [
        200
    ] * 9
    assert sql_calls == 9
    assert observed_delay_calls == delay_calls
    if mode == "vulnerable":
        assert state.delay_value_count(DELAY_SECONDS) == 3
        assert state.delay_value_count(0.0) == 3
