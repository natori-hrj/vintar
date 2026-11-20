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
    KNOWN_LIMITATION_ENDPOINTS,
    LIVE_TWIN_ENDPOINTS,
    SAFE_PETS_LIMITATION,
    LiveEndpoint,
    LoopbackFixtureCheckError,
    LoopbackShutdownError,
    LoopbackStartupError,
    check_parameterized_benign_response,
    run_confirmed_live_endpoint,
    run_live_endpoint,
)

from vintar.checks.sqli.confirmation_runner import ConfirmationStatus
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


def known_limitation_observation(limitation, outcome):
    if outcome.status is ConfirmationStatus.CANDIDATE:
        verdict = Verdict.INCONCLUSIVE
        reason_code = "boolean_candidate"
    elif outcome.status is ConfirmationStatus.SKIPPED:
        verdict = outcome.initial.verdict
        reason_code = outcome.initial.reason_code
    else:
        verdict = Verdict.INCONCLUSIVE
        reason_code = outcome.reason_code

    return {
        "limitation_id": limitation.limitation_id,
        "endpoint_id": limitation.endpoint.endpoint_id,
        "expected_label": limitation.endpoint.expected_label,
        "initial_value": limitation.endpoint.initial_value,
        "preset": limitation.endpoint.preset_name,
        "initial_verdict": outcome.initial.verdict.value,
        "initial_reason_code": outcome.initial.reason_code,
        "confirmation_status": outcome.status.value,
        "reason_code": outcome.reason_code,
        "verdict": verdict.value,
        "classification": classify(
            limitation.endpoint.expected_label,
            verdict,
            reason_code,
        ),
        "request_count": outcome.request_count,
        "failure_category": None,
        "message": None,
    }


def measure_known_limitation(limitation, runner=run_confirmed_live_endpoint):
    try:
        outcome, port = runner(limitation.endpoint)
    except OSError:
        return {
            **known_limitation_observation(
                limitation,
                SimpleNamespace(
                    initial=SimpleNamespace(
                        verdict=Verdict.INCONCLUSIVE, reason_code=None
                    ),
                    status=ConfirmationStatus.INCONCLUSIVE,
                    reason_code=None,
                    request_count=0,
                ),
            ),
            "classification": "non_decision",
            "failure_category": "socket_bind",
            "message": "Cannot bind the known-limitation fixture. Check the loopback transport setup.",
        }
    except (LoopbackStartupError, LoopbackShutdownError) as exc:
        return {
            **known_limitation_observation(
                limitation,
                SimpleNamespace(
                    initial=SimpleNamespace(
                        verdict=Verdict.INCONCLUSIVE, reason_code=None
                    ),
                    status=ConfirmationStatus.INCONCLUSIVE,
                    reason_code=None,
                    request_count=0,
                ),
            ),
            "classification": "non_decision",
            "failure_category": "transport",
            "message": str(exc),
        }
    except LoopbackFixtureCheckError as exc:
        return {
            **known_limitation_observation(limitation, exc.outcome),
            "classification": "non_decision",
            "failure_category": "unexpected_response",
            "message": str(exc),
            "fixture_observations": exc.observed_values,
        }
    assert port > 0
    return known_limitation_observation(limitation, outcome)


def measure_live_loopback(
    runner=run_live_endpoint,
    limitation_runner=run_confirmed_live_endpoint,
):
    records = [
        measure_live_endpoint(endpoint, runner) for endpoint in LIVE_TWIN_ENDPOINTS
    ]
    live = live_report(records)
    limitation = {
        "records": sorted(
            [
                measure_known_limitation(item, limitation_runner)
                for item in KNOWN_LIMITATION_ENDPOINTS
            ],
            key=lambda row: row["limitation_id"],
        )
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
    failures = []
    expected = {item.limitation_id: item for item in KNOWN_LIMITATION_ENDPOINTS}
    rows_by_id = {}
    for row in report["records"]:
        limitation_id = row["limitation_id"]
        if limitation_id in rows_by_id:
            failures.append(
                f"Duplicate known limitation {limitation_id}. Check the tests-side "
                "declaration and measurement assembly."
            )
        rows_by_id[limitation_id] = row

    missing = sorted(set(expected) - set(rows_by_id))
    new = sorted(set(rows_by_id) - set(expected))
    if missing:
        failures.append(
            f"Missing known limitations: {', '.join(missing)}. Run every declared "
            "loopback limitation fixture."
        )
    if new:
        failures.append(
            f"Undeclared known limitations: {', '.join(new)}. Add an immutable "
            "tests-side declaration and documentation before accepting them."
        )

    for limitation_id in sorted(set(expected) & set(rows_by_id)):
        declaration = expected[limitation_id]
        row = rows_by_id[limitation_id]
        if row["failure_category"] is not None:
            failures.append(
                f"{limitation_id} with initial value {row['initial_value']} "
                f"did not complete ({row['failure_category']}). {row['message']}"
            )
        elif not (
            row["endpoint_id"] == declaration.endpoint.endpoint_id
            and row["expected_label"] == "negative"
            and row["initial_verdict"] == "inconclusive"
            and row["initial_reason_code"] == "boolean_candidate"
            and row["confirmation_status"]
            == declaration.expected_confirmation_status.value
            and row["reason_code"] == declaration.expected_reason_code
            and row["verdict"] == "inconclusive"
            and row["classification"] == "fp"
            and row["request_count"] == 18
        ):
            failures.append(
                f"{limitation_id} no longer matches its declared structural false "
                "candidate behavior. Check the fixture label, response relation, "
                "confirmation predicates, and transport setup."
            )
    return failures


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
    positive_rows = [
        row for row in live["records"] if row["expected_label"] == "positive"
    ]
    positive_covered = bool(positive_rows) and all(
        row["request_count"] > 0
        and row["verdict"] is not None
        and row["failure_category"] is None
        and row["reason_code"] not in {"probe_failed", "rate_limited"}
        for row in positive_rows
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
    limitation_records = report["known_limitations"]["records"]
    assert [row["limitation_id"] for row in limitation_records] == [
        "structural-full-mimic",
        "structural-waf-200",
    ]
    assert all(row["classification"] == "fp" for row in limitation_records)
    assert all(row["request_count"] == 18 for row in limitation_records)
    assert "counts" not in report["known_limitations"]


def test_known_limitation_ids_match_evaluation_document():
    documentation = (
        test_sqli_http_e2e.ROOT / "docs" / "sqli-boolean-evaluation.md"
    ).read_text(encoding="utf-8")
    for limitation in KNOWN_LIMITATION_ENDPOINTS:
        marker = f"`{limitation.limitation_id}`"
        assert documentation.count(marker) == 1


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    [
        ("missing", "Missing known limitations"),
        ("duplicate", "Duplicate known limitation"),
        ("new", "Undeclared known limitations"),
        ("resolved", "no longer matches"),
    ],
)
def test_known_limitation_registry_drift_fails(mutation, diagnostic):
    _, limitations = passing_live_measurement()
    records = [dict(row) for row in limitations["records"]]
    if mutation == "missing":
        records.pop()
    elif mutation == "duplicate":
        records.append(dict(records[0]))
    elif mutation == "new":
        records.append({**records[0], "limitation_id": "undeclared"})
    else:
        records[0]["confirmation_status"] = "inconclusive"
        records[0]["reason_code"] = "candidate_confirmation_mismatch"
        records[0]["classification"] = "non_decision"

    failures = known_limitation_failures({"records": records})
    assert any(diagnostic in failure for failure in failures)


def test_demoted_known_limitation_saves_actual_classification_before_failing(
    measurements, simulated_report
):
    live, limitations = passing_live_measurement()
    declaration = KNOWN_LIMITATION_ENDPOINTS[0]
    demoted = known_limitation_observation(
        declaration,
        SimpleNamespace(
            initial=SimpleNamespace(
                verdict=Verdict.INCONCLUSIVE,
                reason_code="boolean_candidate",
            ),
            status=ConfirmationStatus.INCONCLUSIVE,
            reason_code="candidate_confirmation_mismatch",
            request_count=18,
        ),
    )
    limitations["records"] = [
        demoted if row["limitation_id"] == declaration.limitation_id else row
        for row in limitations["records"]
    ]
    path = simulated_report("demoted-known-limitation")

    with pytest.raises(pytest.fail.Exception, match="no longer matches") as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            lambda: (live, limitations),
        )

    report = json.loads(path.read_text(encoding="utf-8"))
    saved = next(
        row
        for row in report["known_limitations"]["records"]
        if row["limitation_id"] == declaration.limitation_id
    )
    assert saved["verdict"] == "inconclusive"
    assert saved["reason_code"] == "candidate_confirmation_mismatch"
    assert saved["classification"] == "non_decision"
    assert f"Measurement report: {path}" in str(caught.value)


def test_known_limitation_count_mismatch_writes_diagnostic_report(
    measurements, simulated_report
):
    live, limitations = passing_live_measurement()
    declaration = KNOWN_LIMITATION_ENDPOINTS[0]
    outcome = SimpleNamespace(
        initial=SimpleNamespace(
            verdict=Verdict.INCONCLUSIVE,
            reason_code="boolean_candidate",
        ),
        status=ConfirmationStatus.CANDIDATE,
        reason_code="confirmation_pattern_matched",
        request_count=18,
    )

    def mismatched_count(_endpoint):
        raise LoopbackFixtureCheckError(
            "The loopback request counts disagreed: client sent 18, but the server "
            "observed 17. Check transport setup and confirmation request accounting.",
            outcome=outcome,
            observed_values={
                "client_request_count": 18,
                "budget_used_requests": 18,
                "server_total_requests": 17,
                "server_accepted_requests": 17,
                "handler_failed": False,
                "actual_query_errors": 0,
                "expected_query_errors": 0,
            },
        )

    failure = measure_known_limitation(declaration, mismatched_count)
    limitations["records"] = [
        failure if row["limitation_id"] == declaration.limitation_id else row
        for row in limitations["records"]
    ]
    path = simulated_report("known-limitation-count-mismatch")

    with pytest.raises(pytest.fail.Exception, match="client sent 18") as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            lambda: (live, limitations),
        )

    report = json.loads(path.read_text(encoding="utf-8"))
    saved = next(
        row
        for row in report["known_limitations"]["records"]
        if row["limitation_id"] == declaration.limitation_id
    )
    assert saved["failure_category"] == "unexpected_response"
    assert saved["classification"] == "non_decision"
    assert saved["request_count"] == 18
    assert saved["initial_reason_code"] == "boolean_candidate"
    assert saved["confirmation_status"] == "candidate"
    assert saved["reason_code"] == "confirmation_pattern_matched"
    assert saved["fixture_observations"]["client_request_count"] == 18
    assert saved["fixture_observations"]["server_total_requests"] == 17
    assert "server observed 17" in str(caught.value)
    assert len(report["live_loopback"]["records"]) == len(LIVE_TWIN_ENDPOINTS)
    assert len(report["known_limitations"]["records"]) == len(
        KNOWN_LIMITATION_ENDPOINTS
    )


def test_known_limitation_sql_error_mismatch_preserves_completed_outcome(
    measurements, simulated_report
):
    live, limitations = passing_live_measurement()
    declaration = KNOWN_LIMITATION_ENDPOINTS[1]
    outcome = SimpleNamespace(
        initial=SimpleNamespace(
            verdict=Verdict.INCONCLUSIVE,
            reason_code="boolean_candidate",
        ),
        status=ConfirmationStatus.CANDIDATE,
        reason_code="confirmation_pattern_matched",
        request_count=18,
    )

    def mismatched_sql_errors(_endpoint):
        raise LoopbackFixtureCheckError(
            "The loopback SQL error count disagreed: expected 0, but observed 1. "
            "Check the declared fixture expectation and probe context.",
            outcome=outcome,
            observed_values={
                "client_request_count": 18,
                "budget_used_requests": 18,
                "server_total_requests": 18,
                "server_accepted_requests": 18,
                "handler_failed": False,
                "actual_query_errors": 1,
                "expected_query_errors": 0,
            },
        )

    failure = measure_known_limitation(declaration, mismatched_sql_errors)
    limitations["records"] = [
        failure if row["limitation_id"] == declaration.limitation_id else row
        for row in limitations["records"]
    ]
    path = simulated_report("known-limitation-sql-error-mismatch")

    with pytest.raises(pytest.fail.Exception, match="observed 1"):
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            lambda: (live, limitations),
        )

    report = json.loads(path.read_text(encoding="utf-8"))
    saved = next(
        row
        for row in report["known_limitations"]["records"]
        if row["limitation_id"] == declaration.limitation_id
    )
    assert saved["request_count"] == 18
    assert saved["initial_reason_code"] == "boolean_candidate"
    assert saved["confirmation_status"] == "candidate"
    assert saved["classification"] == "non_decision"
    assert saved["fixture_observations"] == {
        "client_request_count": 18,
        "budget_used_requests": 18,
        "server_total_requests": 18,
        "server_accepted_requests": 18,
        "handler_failed": False,
        "actual_query_errors": 1,
        "expected_query_errors": 0,
    }


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


def test_multiple_known_limitation_failures_preserve_all_diagnostics(
    measurements, simulated_report
):
    live, passing_limitations = passing_live_measurement()
    limitations = {
        "records": [
            {
                **row,
                "request_count": 0,
                "failure_category": "transport",
                "message": "The known limitation could not complete. Check the loopback transport setup.",
            }
            for row in passing_limitations["records"]
        ]
    }
    path = simulated_report("multiple-negative-limitations")

    with pytest.raises(pytest.fail.Exception) as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            lambda: (live, limitations),
        )

    diagnostic = str(caught.value)
    for limitation in KNOWN_LIMITATION_ENDPOINTS:
        assert limitation.limitation_id in diagnostic
        assert f"initial value {limitation.endpoint.initial_value}" in diagnostic
    assert f"Measurement report: {path}" in diagnostic
    report = json.loads(path.read_text(encoding="utf-8"))
    assert len(report["known_limitations"]["records"]) == len(
        KNOWN_LIMITATION_ENDPOINTS
    )


def test_partial_positive_failure_writes_not_covered_report(
    measurements, simulated_report
):
    passing_live, limitations = passing_live_measurement()
    failed_endpoint = next(
        endpoint
        for endpoint in LIVE_TWIN_ENDPOINTS
        if endpoint.endpoint_id == "sqlite-numeric-vulnerable"
    )
    failure = live_transport_failure(
        failed_endpoint,
        "transport",
        "The numeric fixture could not complete. Check the loopback transport setup.",
    )
    records = [
        row
        for row in passing_live["records"]
        if row["endpoint_id"] != failed_endpoint.endpoint_id
    ]
    live = live_report([*records, failure])
    path = simulated_report("partial-positive-failure")

    with pytest.raises(pytest.fail.Exception) as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
            lambda: (live, limitations),
        )

    diagnostic = str(caught.value)
    assert failed_endpoint.endpoint_id in diagnostic
    assert f"Measurement report: {path}" in diagnostic
    report = json.loads(path.read_text(encoding="utf-8"))
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

    def limitation_runner(endpoint):
        initial = SimpleNamespace(
            verdict=Verdict.INCONCLUSIVE,
            reason_code="boolean_candidate",
        )
        return (
            SimpleNamespace(
                initial=initial,
                status=ConfirmationStatus.CANDIDATE,
                reason_code="confirmation_pattern_matched",
                request_count=18,
            ),
            43210,
        )

    return measure_live_loopback(runner, limitation_runner)


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
