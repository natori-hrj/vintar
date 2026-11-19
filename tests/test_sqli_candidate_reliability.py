"""Measure the Boolean candidate signal on labeled synthetic observations."""

import errno
import json
from collections import Counter

import pytest
import test_sqli_http_e2e
from test_sqli_analyzer import analyze, pair, response
from test_sqli_http_e2e import check_parameterized_benign_response

from vintar.checks.sqli.models import Verdict

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
    measurements, path, check_loopback=check_parameterized_benign_response
):
    loopback = check_loopback()
    report = {
        "schema_version": 1,
        "check": "sqli.boolean",
        "live_positive_measurement": "not_covered",
        "replay": measurements,
        "fixed_app_loopback": {"records": [loopback]},
    }
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    failures = [f"replay: {failure}" for failure in replay_failures(measurements)]
    if loopback["status"] == "failed":
        failures.append(
            f"fixed_loopback ({loopback['failure_category']}): {loopback['message']}"
        )
    if failures:
        pytest.fail("\n".join([*failures, f"Measurement report: {path}"]))


def test_candidate_report_is_sorted_and_counts_match_records(measurements, tmp_path):
    path = tmp_path / "sqli-candidate-reliability.json"
    run_measurement(measurements, path)
    [record] = json.loads(path.read_text(encoding="utf-8"))["fixed_app_loopback"][
        "records"
    ]
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


def assert_failed_report(measurements, tmp_path, check_loopback, category, remediation):
    path = tmp_path / "sqli-candidate-reliability.json"
    with pytest.raises(pytest.fail.Exception, match="fixed_loopback") as caught:
        run_measurement(measurements, path, check_loopback)
    assert str(path) in str(caught.value)
    report = json.loads(path.read_text(encoding="utf-8"))
    assert report["replay"]["counts"] == measurements["counts"]
    assert report["live_positive_measurement"] == "not_covered"
    [record] = report["fixed_app_loopback"]["records"]
    assert record["mode"] == "fixed_loopback"
    assert record["status"] == "failed"
    assert record["failure_category"] == category
    assert remediation in record["message"]
    assert remediation in str(caught.value)


def test_bind_denial_writes_report_before_failing(measurements, tmp_path):
    def deny_bind():
        raise PermissionError(errno.EPERM, "simulated restricted socket")

    assert_failed_report(
        measurements,
        tmp_path,
        lambda: check_parameterized_benign_response(deny_bind),
        "socket_bind",
        "Check that the runner permits IPv4 loopback sockets",
    )


def test_unexpected_safe_response_writes_report_before_failing(
    measurements, tmp_path, monkeypatch
):
    def unexpected(category, *, safe):
        assert category == "Pets" and safe
        return b"unexpected rows"

    monkeypatch.setattr(test_sqli_http_e2e, "_sql_result", unexpected)
    assert_failed_report(
        measurements,
        tmp_path,
        check_parameterized_benign_response,
        "unexpected_response",
        "Check the seeded SQLite rows",
    )


def test_non_decision_writes_report_before_failing(tmp_path):
    result = analyze(baseline=(response(b"A"), response(b"changed")))
    measurements = replay_report([observation("unstable-replay", "positive", result)])
    path = tmp_path / "sqli-candidate-reliability.json"
    with pytest.raises(
        pytest.fail.Exception, match="replay: unstable-replay"
    ) as caught:
        run_measurement(
            measurements,
            path,
            lambda: test_sqli_http_e2e.fixed_loopback_record(None, "Fixture passed."),
        )
    assert str(path) in str(caught.value)
    assert (
        json.loads(path.read_text(encoding="utf-8"))["replay"]["counts"]["non_decision"]
        == 1
    )


@pytest.mark.parametrize(
    ("method", "error", "category", "remediation"),
    [
        ("thread", RuntimeError, "startup", "Check thread availability"),
        (
            "request",
            test_sqli_http_e2e.httpx.ConnectError,
            "transport",
            "Check loopback transport",
        ),
    ],
)
def test_other_expected_loopback_failures_are_recorded(
    measurements, tmp_path, monkeypatch, method, error, category, remediation
):
    def fail(*args, **kwargs):
        raise error("simulated loopback failure")

    if method == "thread":
        monkeypatch.setattr(test_sqli_http_e2e.threading.Thread, "start", fail)
    else:
        monkeypatch.setattr(test_sqli_http_e2e.httpx.Client, "get", fail)
    assert_failed_report(
        measurements,
        tmp_path,
        check_parameterized_benign_response,
        category,
        remediation,
    )
