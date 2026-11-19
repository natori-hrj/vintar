"""Measure the Boolean candidate signal on labeled synthetic observations."""

import json
from collections import Counter

import pytest
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


def assert_replay_results(report):
    for row in report["records"]:
        classification = row["classification"]
        signal = f"{row['verdict']}/{row['reason_code']}"
        endpoint = row["endpoint_id"]
        if classification == "non_decision":
            pytest.fail(
                f"{endpoint} produced non-decision {signal}. Check the replay observations "
                "for instability, truncation, or execution errors."
            )
        if classification == "fn":
            pytest.fail(
                f"{endpoint} missed the expected Boolean candidate with {signal}. "
                "Check the positive fixture label and analyzer comparison."
            )
        if classification == "fp":
            pytest.fail(
                f"{endpoint} unexpectedly emitted a Boolean candidate with {signal}. "
                "Check the negative fixture label and analyzer comparison."
            )


@pytest.fixture(scope="module")
def measurements():
    return replay_report(
        [
            observation(endpoint, label, analyze(false_responses=control))
            for endpoint, label, control in REPLAY
        ]
    )


@pytest.fixture(scope="module")
def fixed_loopback():
    check_parameterized_benign_response()
    return {
        "records": [
            {"endpoint_id": "/safe", "check": "benign_response", "status": "pass"}
        ]
    }


@pytest.mark.parametrize(
    "index", [0, 1], ids=["positive-candidate", "negative-not-detected"]
)
def test_replay_matches_independent_label(measurements, index):
    assert_replay_results({"records": [measurements["records"][index]]})


def test_parameterized_fixture_returns_expected_benign_response(fixed_loopback):
    assert fixed_loopback["records"][0]["status"] == "pass", (
        "The fixed route did not pass its benign response assertion. Check the fixture response."
    )


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


def test_candidate_report_is_sorted_and_counts_match_records(
    measurements, fixed_loopback, tmp_path
):
    report = {
        "schema_version": 1,
        "check": "sqli.boolean",
        "live_positive_measurement": "not_covered",
        "replay": measurements,
        "fixed_app_loopback": fixed_loopback,
    }
    path = tmp_path / "sqli-candidate-reliability.json"
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    assert_replay_results(measurements)
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
