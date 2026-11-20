"""Measure the Boolean candidate signal on labeled synthetic observations."""

import errno
import json
import socket
from collections import Counter
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
import test_sqli_http_e2e
from test_sqli_analyzer import analyze, pair, response
from test_sqli_http_e2e import (
    LIVE_TWIN_ENDPOINTS,
    SAFE_PETS_LIMITATION,
    LiveEndpoint,
    LoopbackShutdownError,
    LoopbackStartupError,
    check_parameterized_benign_response,
    run_live_endpoint,
)

from vintar.checks.sqli.models import Verdict

REAL_REPORT = "sqli-candidate-reliability.json"

REPLAY = (
    ("replay-boolean-differential", "positive", pair(b"different")),
    ("replay-stable-equivalent", "negative", pair(b"A")),
)


def classify(expected, verdict, reason):
    if verdict is Verdict.INCONCLUSIVE and reason == "boolean_candidate":
        return "tp" if expected == "positive" else "fp"
    if verdict is Verdict.NOT_DETECTED:
        return "fn" if expected == "positive" else "tn"
    return "non_decision"


def observation(endpoint, label, result):
    return {
        "endpoint_id": endpoint,
        "expected_label": label,
        "verdict": result.verdict.value,
        "reason_code": result.reason_code,
        "classification": classify(label, result.verdict, result.reason_code),
    }


def replay_report(records):
    counts = Counter(row["classification"] for row in records)
    return {
        "records": sorted(records, key=lambda row: row["endpoint_id"]),
        "counts": {
            key: counts[key] for key in ("tp", "fn", "fp", "tn", "non_decision")
        },
    }


def live_observation(endpoint, result):
    return {
        "endpoint_id": endpoint.endpoint_id,
        "expected_label": endpoint.expected_label,
        "initial_value": endpoint.initial_value,
        "preset": endpoint.preset_name,
        "verdict": result.verdict.value,
        "reason_code": result.reason_code,
        "classification": classify(
            endpoint.expected_label, result.verdict, result.reason_code
        ),
        "request_count": result.request_count,
        "failure_category": None,
        "message": None,
    }


def live_transport_failure(endpoint, category, message):
    return {
        "endpoint_id": endpoint.endpoint_id,
        "expected_label": endpoint.expected_label,
        "initial_value": endpoint.initial_value,
        "preset": endpoint.preset_name,
        "verdict": None,
        "reason_code": None,
        "classification": "non_decision",
        "request_count": 0,
        "failure_category": category,
        "message": message,
    }


def live_report(records):
    counts = Counter(row["classification"] for row in records)
    return {
        "records": sorted(records, key=lambda row: row["endpoint_id"]),
        "counts": {
            key: counts[key] for key in ("tp", "fn", "fp", "tn", "non_decision")
        },
    }


def measure_live_endpoint(endpoint, runner=run_live_endpoint):
    try:
        result, port = runner(endpoint)
    except OSError:
        return live_transport_failure(
            endpoint,
            "socket_bind",
            "Cannot bind the live loopback fixture. Check the loopback transport setup.",
        )
    except LoopbackStartupError as exc:
        return live_transport_failure(endpoint, "startup", str(exc))
    except LoopbackShutdownError as exc:
        return live_transport_failure(endpoint, "shutdown", str(exc))
    except AssertionError:
        return live_transport_failure(
            endpoint,
            "unexpected_response",
            "The live fixture response was inconsistent. Check response stability and transport setup.",
        )

    assert port > 0
    return live_observation(endpoint, result)


def measure_live_loopback(runner=run_live_endpoint):
    records = [
        measure_live_endpoint(endpoint, runner) for endpoint in LIVE_TWIN_ENDPOINTS
    ]
    live = live_report(records)
    limitation = {
        "records": [
            {
                key: record[key]
                for key in (
                    "endpoint_id",
                    "expected_label",
                    "initial_value",
                    "preset",
                    "verdict",
                    "reason_code",
                    "request_count",
                    "failure_category",
                    "message",
                )
            }
            for record in live["records"]
            if record["expected_label"] == "negative"
            and record["classification"] == "non_decision"
        ]
    }
    return live, limitation


def replay_failures(report):
    failures = []
    for row in report["records"]:
        classification = row["classification"]
        signal = f"{row['verdict']}/{row['reason_code']}"
        endpoint = row["endpoint_id"]
        if classification == "non_decision":
            failures.append(
                f"{endpoint} produced non-decision {signal}. Check the replay observations "
                "for instability, truncation, or execution errors."
            )
        if classification == "fn":
            failures.append(
                f"{endpoint} missed the expected Boolean candidate with {signal}. "
                "Check the positive fixture label and analyzer comparison."
            )
        if classification == "fp":
            failures.append(
                f"{endpoint} unexpectedly emitted a Boolean candidate with {signal}. "
                "Check the negative fixture label and analyzer comparison."
            )

    return failures


def live_failures(report):
    failures = []
    for row in report["records"]:
        endpoint = row["endpoint_id"]
        signal = f"{row['verdict']}/{row['reason_code']}"
        classification = row["classification"]
        if row["failure_category"] is not None:
            failures.append(
                f"{endpoint} produced non-decision {signal} "
                f"({row['failure_category']}). {row['message']}"
            )
        elif classification == "non_decision":
            failures.append(
                f"{endpoint} produced non-decision {signal}. The live check requires "
                "a decision; check response stability or transport setup."
            )
        elif classification == "fn":
            failures.append(
                f"{endpoint} missed the expected Boolean candidate with {signal}. "
                "Check the fixture label and response stability."
            )
        elif classification == "fp":
            failures.append(
                f"{endpoint} unexpectedly emitted a Boolean candidate with {signal}. "
                "Check the fixture label and response stability."
            )
    return failures


def known_limitation_failures(report):
    if not report["records"]:
        return []
    [row] = report["records"]
    if row["failure_category"] is not None:
        return [
            (
                f"{row['endpoint_id']} with initial value Pets produced "
                f"{row['verdict']}/{row['reason_code']} "
                f"({row['failure_category']}). {row['message']}"
            )
        ]
    if (
        row["verdict"] == "inconclusive"
        and row["reason_code"] == "unexpected_difference"
    ):
        return []
    return [
        (
            f"{row['endpoint_id']} with initial value Pets produced "
            f"{row['verdict']}/{row['reason_code']} instead of the documented known "
            "non-decision. Check response stability and the parameterized fixture."
        )
    ]


def assert_replay_results(report):
    if failures := replay_failures(report):
        pytest.fail("\n".join(failures))


@pytest.fixture(scope="module")
def measurements():
    return replay_report(
        [
            observation(endpoint, label, analyze(false_responses=control))
            for endpoint, label, control in REPLAY
        ]
    )


@pytest.mark.parametrize(
    "index", [0, 1], ids=["positive-candidate", "negative-not-detected"]
)
def test_replay_matches_independent_label(measurements, index):
    assert_replay_results({"records": [measurements["records"][index]]})


@pytest.mark.parametrize(
    ("label", "result", "category", "message"),
    [
        (
            "positive",
            analyze(baseline=(response(b"A"), response(b"changed"))),
            "non_decision",
            "Check the replay observations",
        ),
        (
            "positive",
            analyze(false_responses=pair(b"A")),
            "fn",
            "Check the positive fixture label",
        ),
        ("negative", analyze(), "fp", "Check the negative fixture label"),
    ],
)
def test_failed_measurements_get_actionable_diagnostics(
    label, result, category, message
):
    report = replay_report([observation("failure-example", label, result)])
    assert report["counts"][category] == 1
    assert report["counts"]["tp"] == report["counts"]["tn"] == 0
    with pytest.raises(pytest.fail.Exception, match=message):
        assert_replay_results(report)


def run_measurement(
    measurements,
    path,
    check_loopback=check_parameterized_benign_response,
    check_live_loopback=measure_live_loopback,
):
    loopback = check_loopback()
    live, limitations = check_live_loopback()
    positive_covered = any(
        row["expected_label"] == "positive"
        and row["request_count"] > 0
        and row["verdict"] is not None
        and row["failure_category"] is None
        and row["reason_code"] not in {"probe_failed", "rate_limited"}
        for row in live["records"]
    )
    report = {
        "schema_version": 2,
        "check": "sqli.boolean",
        "live_positive_measurement": "covered" if positive_covered else "not_covered",
        "replay": measurements,
        "live_loopback": live,
        "known_limitations": limitations,
        "fixed_app_loopback": {"records": [loopback]},
    }
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    failures = [f"replay: {failure}" for failure in replay_failures(measurements)]
    failures.extend(f"live_loopback: {failure}" for failure in live_failures(live))
    failures.extend(
        f"known_limitations: {failure}"
        for failure in known_limitation_failures(limitations)
    )
    if loopback["status"] == "failed":
        failures.append(
            f"fixed_loopback ({loopback['failure_category']}): {loopback['message']}"
        )
    if failures:
        pytest.fail("\n".join([*failures, f"Measurement report: {path}"]))


def test_candidate_report_is_sorted_and_counts_match_records(measurements, tmp_path):
    path = tmp_path / REAL_REPORT
    run_measurement(measurements, path)
    report = json.loads(path.read_text(encoding="utf-8"))
    [record] = report["fixed_app_loopback"]["records"]
    assert record["status"] == "passed", (
        "The fixed route did not pass. Check the report's loopback record."
    )
    records = measurements["records"]
    assert [row["endpoint_id"] for row in records] == sorted(
        row["endpoint_id"] for row in records
    ), "Replay records are out of order. Sort the report by endpoint ID."
    assert sum(measurements["counts"].values()) == len(records), (
        "Replay counts do not match the observations. Count each record once."
    )
    assert replay_report(list(reversed(records))) == measurements, (
        "The report changed when observations were reversed. Sort records and count classifications independently of input order."
    )
    live = report["live_loopback"]
    assert live["counts"] == {
        "fn": 0,
        "fp": 0,
        "non_decision": 0,
        "tn": 2,
        "tp": 2,
    }
    assert sum(live["counts"].values()) == len(live["records"])
    assert report["schema_version"] == 2
    assert report["live_positive_measurement"] == "covered"
    assert report["known_limitations"]["records"] == []
    assert "counts" not in report["known_limitations"]


def test_live_twins_share_declared_values_within_each_sql_context():
    contexts = {}
    for endpoint in LIVE_TWIN_ENDPOINTS:
        contexts.setdefault(endpoint.preset_name, []).append(endpoint)
    assert set(contexts) == {"numeric", "string-quoted"}
    for endpoints in contexts.values():
        assert len({endpoint.initial_value for endpoint in endpoints}) == 1
        assert {endpoint.expected_label for endpoint in endpoints} == {
            "positive",
            "negative",
        }


def test_live_endpoint_rejects_non_benign_initial_value():
    with pytest.raises(
        ValueError,
        match="benign value declared for the fixture parameter",
    ):
        LiveEndpoint(
            endpoint_id="invalid-baseline",
            path="/safe",
            expected_label="negative",
            parameter_name="category",
            initial_value="Pets' OR '1'='1",
            preset_name="string-quoted",
        )


def test_live_loopback_uses_fresh_server_for_each_case():
    servers = []

    def binder():
        server = test_sqli_http_e2e._Server()
        servers.append(server)
        return server

    for endpoint in LIVE_TWIN_ENDPOINTS:
        _, port = run_live_endpoint(endpoint, binder)
        assert port > 0

    assert len(servers) == len(LIVE_TWIN_ENDPOINTS)
    assert servers[0] is not servers[1]


def test_safe_pets_is_not_detected_as_literal_input():
    result, _ = run_live_endpoint(SAFE_PETS_LIMITATION)
    assert result.verdict is Verdict.NOT_DETECTED
    assert result.reason_code == "no_boolean_difference_literal_input"


@pytest.mark.parametrize(
    ("endpoint", "result", "classification", "remediation"),
    [
        (
            LIVE_TWIN_ENDPOINTS[0],
            SimpleNamespace(
                verdict=Verdict.NOT_DETECTED,
                reason_code="no_boolean_difference",
                request_count=6,
            ),
            "fn",
            "fixture label",
        ),
        (
            LIVE_TWIN_ENDPOINTS[1],
            SimpleNamespace(
                verdict=Verdict.INCONCLUSIVE,
                reason_code="boolean_candidate",
                request_count=6,
            ),
            "fp",
            "fixture label",
        ),
        (
            LIVE_TWIN_ENDPOINTS[0],
            SimpleNamespace(
                verdict=Verdict.INCONCLUSIVE,
                reason_code="unstable_response",
                request_count=6,
            ),
            "non_decision",
            "response stability",
        ),
    ],
    ids=("false-negative", "false-positive", "non-decision"),
)
def test_live_failures_write_report_before_failing(
    measurements, simulated_report, endpoint, result, classification, remediation
):
    passing_live, limitations = passing_live_measurement()
    records = [
        row
        for row in passing_live["records"]
        if row["endpoint_id"] != endpoint.endpoint_id
    ]
    records.append(live_observation(endpoint, result))
    live = live_report(records)
    path = simulated_report(classification)

    with pytest.raises(pytest.fail.Exception, match=endpoint.endpoint_id) as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            lambda: (live, limitations),
        )

    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["live_loopback"]["counts"][classification] == 1
    assert f"{result.verdict.value}/{result.reason_code}" in str(caught.value)
    assert remediation in str(caught.value)


@pytest.mark.parametrize(
    "category",
    ["socket_bind", "startup", "transport", "shutdown", "probe_failed", "rate_limited"],
)
def test_unfinished_live_positive_writes_not_covered_report(
    measurements, simulated_report, category
):
    positive_endpoints = [
        endpoint
        for endpoint in LIVE_TWIN_ENDPOINTS
        if endpoint.expected_label == "positive"
    ]
    failures = []
    for endpoint in positive_endpoints:
        if category in {"probe_failed", "rate_limited"}:
            failure = live_observation(
                endpoint,
                SimpleNamespace(
                    verdict=Verdict.INCONCLUSIVE,
                    reason_code=category,
                    request_count=1,
                ),
            )
        else:
            failure = live_transport_failure(
                endpoint,
                category,
                "The live fixture could not complete the check. Check the loopback transport setup.",
            )
        failures.append(failure)
    passing_live, limitations = passing_live_measurement()
    records = [
        row for row in passing_live["records"] if row["expected_label"] != "positive"
    ]
    live = live_report([*records, *failures])
    path = simulated_report(f"live-{category}")

    with pytest.raises(pytest.fail.Exception, match="live_loopback:") as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            lambda: (live, limitations),
        )

    diagnostic = str(caught.value)
    assert all(endpoint.endpoint_id in diagnostic for endpoint in positive_endpoints)
    assert category in diagnostic
    assert "transport setup" in diagnostic
    assert str(path) in diagnostic
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["live_loopback"]["counts"]["non_decision"] == 2
    assert report["live_positive_measurement"] == "not_covered"


def passing_live_measurement():
    positive = SimpleNamespace(
        verdict=Verdict.INCONCLUSIVE,
        reason_code="boolean_candidate",
        request_count=6,
    )
    negative = SimpleNamespace(
        verdict=Verdict.NOT_DETECTED,
        reason_code="no_boolean_difference_literal_input",
        request_count=6,
    )
    results = {
        "sqlite-vulnerable": positive,
        "sqlite-parameterized": negative,
        "sqlite-numeric-vulnerable": positive,
        "sqlite-numeric-parameterized": negative,
    }

    def runner(endpoint):
        return results[endpoint.endpoint_id], 43210

    return measure_live_loopback(runner)


def assert_failed_report(measurements, path, check_loopback, category, remediation):
    with pytest.raises(pytest.fail.Exception, match="fixed_loopback") as caught:
        run_measurement(
            measurements,
            path,
            check_loopback,
            passing_live_measurement,
        )
    assert str(path) in str(caught.value)
    assert f"fixed_loopback ({category})" in str(caught.value)
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["replay"]["counts"] == measurements["counts"]
    assert report["live_positive_measurement"] == "covered"
    [record] = report["fixed_app_loopback"]["records"]
    assert record["mode"] == "fixed_loopback"
    assert record["status"] == "failed"
    assert record["failure_category"] == category
    assert remediation in record["message"]
    assert remediation in str(caught.value)


@pytest.fixture
def simulated_report(tmp_path, monkeypatch):
    def deny_network(*args, **kwargs):
        pytest.fail(
            "A simulated case attempted networking. Inject the relevant test component."
        )

    monkeypatch.setattr(socket, "socket", deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", deny_network)

    def output(case):
        return tmp_path / f"sqli-candidate-reliability.simulated-{case}.json"

    yield output
    assert not (tmp_path / REAL_REPORT).exists(), (
        "A simulation wrote the real measurement filename. Use a simulated report path."
    )


def test_bind_denial_writes_report_before_failing(measurements, simulated_report):
    def deny_bind():
        raise PermissionError(errno.EPERM, "simulated restricted socket")

    assert_failed_report(
        measurements,
        simulated_report("socket-bind"),
        lambda: check_parameterized_benign_response(deny_bind),
        "socket_bind",
        "Check that the runner permits IPv4 loopback sockets",
    )


@pytest.fixture
def simulated_binder():
    def bind():
        return SimpleNamespace(
            server_address=("127.0.0.1", 0),
            serve_forever=lambda: None,
            server_close=lambda: None,
        )

    return bind


@pytest.fixture
def simulated_server(monkeypatch, simulated_binder):
    @contextmanager
    def start(server):
        yield server, "http://127.0.0.1:1"

    monkeypatch.setattr(test_sqli_http_e2e, "running_server", start)
    return simulated_binder


def test_unexpected_safe_response_writes_report_before_failing(
    measurements, simulated_report, simulated_server, monkeypatch
):
    def unexpected(_client, url, *, params):
        assert url.endswith("/safe") and params == {"category": "Pets"}
        return test_sqli_http_e2e.httpx.Response(
            status_code=200, content=b"unexpected rows"
        )

    monkeypatch.setattr(test_sqli_http_e2e.httpx.Client, "get", unexpected)
    assert_failed_report(
        measurements,
        simulated_report("unexpected-response"),
        lambda: check_parameterized_benign_response(simulated_server),
        "unexpected_response",
        "Check the seeded SQLite rows",
    )


def test_non_decision_writes_report_before_failing(simulated_report):
    result = analyze(baseline=(response(b"A"), response(b"changed")))
    measurements = replay_report([observation("unstable-replay", "positive", result)])
    path = simulated_report("non-decision")
    with pytest.raises(
        pytest.fail.Exception, match="replay: unstable-replay"
    ) as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            passing_live_measurement,
        )
    assert str(path) in str(caught.value)
    assert (
        json.loads(path.read_text(encoding="utf-8"))["replay"]["counts"]["non_decision"]
        == 1
    )


def test_simulated_startup_failure_is_recorded(
    measurements, simulated_report, simulated_binder, monkeypatch
):
    def fail(_thread):
        raise RuntimeError("simulated worker startup failure")

    monkeypatch.setattr(test_sqli_http_e2e.threading.Thread, "start", fail)
    assert_failed_report(
        measurements,
        simulated_report("startup"),
        lambda: check_parameterized_benign_response(simulated_binder),
        "startup",
        "Check thread availability",
    )


def test_simulated_transport_failure_is_recorded(
    measurements, simulated_report, simulated_server, monkeypatch
):
    def fail(_client, url, *, params):
        assert url.endswith("/safe") and params == {"category": "Pets"}
        raise test_sqli_http_e2e.httpx.ConnectError("simulated request failure")

    monkeypatch.setattr(test_sqli_http_e2e.httpx.Client, "get", fail)
    assert_failed_report(
        measurements,
        simulated_report("transport"),
        lambda: check_parameterized_benign_response(simulated_server),
        "transport",
        "Check loopback transport",
    )


def test_simulated_fixed_shutdown_failure_preserves_report(
    measurements, simulated_report, simulated_binder, monkeypatch
):
    @contextmanager
    def fail_on_shutdown(server):
        server.received = [("/safe", "Pets", "category=Pets")]
        server.query_errors = 0
        server.handler_failed = False
        yield server, "http://127.0.0.1:1"
        raise LoopbackShutdownError(
            "The loopback worker did not stop. Check server shutdown and outstanding requests."
        )

    def benign_response(_client, _url, *, params):
        assert params == {"category": "Pets"}
        return test_sqli_http_e2e.httpx.Response(200, content=b"Cat toy\nDog toy")

    monkeypatch.setattr(test_sqli_http_e2e, "running_server", fail_on_shutdown)
    monkeypatch.setattr(test_sqli_http_e2e.httpx.Client, "get", benign_response)
    assert_failed_report(
        measurements,
        simulated_report("fixed-shutdown"),
        lambda: check_parameterized_benign_response(simulated_binder),
        "shutdown",
        "The loopback worker did not stop. Check server shutdown and outstanding requests.",
    )
