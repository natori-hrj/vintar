"""Offline contracts for reviewed error-based SQLi signature analysis."""

import ast
import time
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from vintar.checks.sqli.error_analyzer import (
    ErrorAnalysis,
    ErrorAnalysisStatus,
    ErrorProbeFailure,
    ErrorProbeKind,
    analyze_error_responses,
    error_observation,
    validate_error_probe_payload,
)
from vintar.checks.sqli.error_contract import (
    ERROR_RESULT_RULES,
    error_product_result,
)
from vintar.checks.sqli.error_signatures import (
    ERROR_SCAN_LIMIT,
    ERROR_SIGNATURE_DBMS_NAMES,
    ERROR_SIGNATURE_IDS,
    ERROR_SIGNATURES,
    get_error_signature,
)
from vintar.checks.sqli.models import Verdict
from vintar.core.models import HttpResult

ROOT = Path(__file__).resolve().parents[1]
SIGNATURE_MODULE = ROOT / "src" / "vintar" / "checks" / "sqli" / "error_signatures.py"

SIGNATURE_FIXTURES = {
    "sqlite_operational_syntax": (
        b'sqlite3.OperationalError: unrecognized token: "\'"',
        b"sqlite3.OperationalError: database is locked",
    ),
    "postgresql_syntax_error": (
        b'org.postgresql.util.PSQLException: ERROR: syntax error at or near "\\""',
        b'org.postgresql.util.PSQLException: WARNING: syntax error at or near "\\""',
    ),
    "mysql_syntax_error_1064": (
        b"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
        b"You have an issue in your SQL syntax; check the manual for your database",
    ),
    "mssql_syntax_error": (
        b"Microsoft ODBC SQL Server Driver SQL Server Incorrect syntax near '\"'.",
        b"ODBC driver reported Incorrect syntax near '\"'.",
    ),
    "oracle_syntax_error": (
        b"ORA-00933: SQL command not properly ended",
        b"ORA-00933: database unavailable",
    ),
}


def response(
    body: bytes,
    *,
    status: int = 200,
    truncated: bool = False,
) -> HttpResult:
    return HttpResult(
        status_code=status,
        elapsed=0.01,
        body=body,
        headers={},
        truncated=truncated,
    )


def analyze(
    baseline_one: HttpResult,
    probe_one: HttpResult,
    baseline_two: HttpResult,
    probe_two: HttpResult,
):
    return analyze_error_responses(
        (baseline_one, baseline_two),
        (probe_one, probe_two),
        probe_payload="'",
    )


def operational_analysis(reason: str, request_count: int) -> ErrorAnalysis:
    observations = tuple(
        error_observation(
            ErrorProbeKind(kind),
            sequence,
            response(
                b"terminal" if sequence == request_count else b"completed",
                status=(
                    429
                    if reason == "rate_limited" and sequence == request_count
                    else 200
                ),
                truncated=(
                    reason == "truncated_response" and sequence == request_count
                ),
            ),
        )
        for sequence, kind in enumerate(
            ("baseline", "probe", "baseline", "probe")[:request_count],
            start=1,
        )
        if reason in {"rate_limited", "truncated_response"} or sequence < request_count
    )
    failures = (
        ()
        if reason in {"rate_limited", "truncated_response"}
        else (
            ErrorProbeFailure(
                ErrorProbeKind(
                    ("baseline", "probe", "baseline", "probe")[request_count - 1]
                ),
                request_count,
                reason,
            ),
        )
    )
    return ErrorAnalysis(
        status=ErrorAnalysisStatus.INCONCLUSIVE,
        reason_code=reason,
        observations=observations,
        failures=failures,
    )


def test_signature_registry_is_exact_sorted_and_immutable():
    assert ERROR_SIGNATURE_IDS == tuple(sorted(SIGNATURE_FIXTURES))
    assert ERROR_SIGNATURE_DBMS_NAMES == (
        "mssql",
        "mysql",
        "oracle",
        "postgresql",
        "sqlite",
    )
    assert tuple(ERROR_SIGNATURES) == ERROR_SIGNATURE_IDS
    assert all(
        get_error_signature(signature_id) is ERROR_SIGNATURES[signature_id]
        for signature_id in ERROR_SIGNATURE_IDS
    )
    with pytest.raises(FrozenInstanceError):
        get_error_signature("sqlite_operational_syntax").dbms = "changed"
    with pytest.raises(TypeError):
        ERROR_SIGNATURES["new"] = get_error_signature("sqlite_operational_syntax")


@pytest.mark.parametrize("value", ["unknown", "SQLite", "", 1, [], None])
def test_signature_lookup_rejects_unknown_values_actionably(value):
    with pytest.raises(ValueError, match=r"Unknown error signature.*Use one of:"):
        get_error_signature(value)


def test_signature_registry_stays_offline_and_data_only():
    tree = ast.parse(SIGNATURE_MODULE.read_text(encoding="utf-8"))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    assert imports == {"collections.abc", "dataclasses", "re", "types"}
    assert not any(
        name.startswith(("httpx", "vintar.core", "vintar.regression", "vintar.cli"))
        for name in imports
    )


@pytest.mark.parametrize("signature_id", ERROR_SIGNATURE_IDS)
def test_each_signature_detects_dynamic_reproducible_probe_pages(signature_id):
    diagnostic, _ = SIGNATURE_FIXTURES[signature_id]
    analysis = analyze(
        response(b"baseline timestamp=1 csrf=alpha"),
        response(b"request-id=one " + diagnostic, status=500),
        response(b"baseline timestamp=2 csrf=beta"),
        response(b"request-id=two " + diagnostic, status=500),
    )

    assert analysis.status is ErrorAnalysisStatus.MATCHED
    assert analysis.reason_code == "dbms_error_disclosed"
    assert analysis.evidence is not None
    assert analysis.evidence.signature_id == signature_id
    assert analysis.evidence.dbms == ERROR_SIGNATURES[signature_id].dbms
    product = error_product_result(analysis)
    assert product.verdict is Verdict.INCONCLUSIVE
    assert product.reason_code == "dbms_error_disclosed"
    assert product.request_count == 4
    assert analysis.observations[0].body_digest != analysis.observations[2].body_digest
    assert analysis.observations[1].body_digest != analysis.observations[3].body_digest


@pytest.mark.parametrize("signature_id", ERROR_SIGNATURE_IDS)
def test_each_signature_near_miss_is_not_detected(signature_id):
    _, near_miss = SIGNATURE_FIXTURES[signature_id]
    analysis = analyze(
        response(b"baseline one"),
        response(near_miss + b" token=one"),
        response(b"baseline two"),
        response(near_miss + b" token=two"),
    )
    assert analysis.status is ErrorAnalysisStatus.NOT_MATCHED
    assert analysis.reason_code == "dbms_error_not_observed"
    assert error_product_result(analysis).verdict is Verdict.NOT_DETECTED


@pytest.mark.parametrize("signature_id", ERROR_SIGNATURE_IDS)
def test_each_signature_near_miss_generic_500_is_inconclusive(signature_id):
    _, near_miss = SIGNATURE_FIXTURES[signature_id]
    analysis = analyze(
        response(b"baseline one"),
        response(near_miss, status=500),
        response(b"baseline two"),
        response(near_miss + b" request=two", status=500),
    )
    assert analysis.status is ErrorAnalysisStatus.INCONCLUSIVE
    assert analysis.reason_code == "non_success_status"
    assert error_product_result(analysis).verdict is Verdict.INCONCLUSIVE


@pytest.mark.parametrize("signature_id", ERROR_SIGNATURE_IDS)
def test_each_signature_already_in_baseline_is_inconclusive(signature_id):
    diagnostic, _ = SIGNATURE_FIXTURES[signature_id]
    analysis = analyze(
        response(b"baseline one " + diagnostic),
        response(b"probe one " + diagnostic),
        response(b"baseline two " + diagnostic),
        response(b"probe two " + diagnostic),
    )
    assert analysis.reason_code == "baseline_dbms_error"
    assert error_product_result(analysis).verdict is Verdict.INCONCLUSIVE


@pytest.mark.parametrize("signature_id", ERROR_SIGNATURE_IDS)
def test_each_signature_is_rejected_from_probe_payload(signature_id):
    diagnostic, _ = SIGNATURE_FIXTURES[signature_id]
    with pytest.raises(
        ValueError,
        match=r"contains a registered DBMS diagnostic.*reflected false positive.*Supply SQL syntax",
    ):
        validate_error_probe_payload(diagnostic.decode("ascii"))


def test_dynamic_signature_free_bodies_remain_not_detected():
    analysis = analyze(
        response(b"timestamp=1 csrf=alpha"),
        response(b"echo=' request-id=one"),
        response(b"timestamp=2 csrf=beta"),
        response(b"echo=' request-id=two"),
    )
    assert analysis.reason_code == "dbms_error_not_observed"
    assert error_product_result(analysis).verdict is Verdict.NOT_DETECTED


@pytest.mark.parametrize("pair", ["baseline", "probe"])
def test_status_drift_between_repeats_is_unstable_response(pair):
    statuses = {
        "baseline": (response(b"b1"), response(b"b2", status=201)),
        "probe": (response(b"p1"), response(b"p2", status=500)),
    }
    baselines = (
        statuses["baseline"]
        if pair == "baseline"
        else (response(b"b1"), response(b"b2"))
    )
    probes = (
        statuses["probe"] if pair == "probe" else (response(b"p1"), response(b"p2"))
    )
    analysis = analyze(baselines[0], probes[0], baselines[1], probes[1])
    assert analysis.reason_code == "unstable_response"


def test_signature_in_only_one_probe_is_unstable_error_signal():
    diagnostic, _ = SIGNATURE_FIXTURES["sqlite_operational_syntax"]
    analysis = analyze(
        response(b"baseline one"),
        response(diagnostic, status=500),
        response(b"baseline two"),
        response(b"generic error", status=500),
    )
    assert analysis.reason_code == "unstable_error_signal"


def test_different_probe_signature_sets_are_unstable_error_signal():
    sqlite, _ = SIGNATURE_FIXTURES["sqlite_operational_syntax"]
    mysql, _ = SIGNATURE_FIXTURES["mysql_syntax_error_1064"]
    analysis = analyze(
        response(b"baseline one"),
        response(sqlite, status=500),
        response(b"baseline two"),
        response(mysql, status=500),
    )
    assert analysis.reason_code == "unstable_error_signal"


def test_multiple_reproducible_signatures_are_ambiguous():
    sqlite, _ = SIGNATURE_FIXTURES["sqlite_operational_syntax"]
    mysql, _ = SIGNATURE_FIXTURES["mysql_syntax_error_1064"]
    body = sqlite + b"\n" + mysql
    analysis = analyze(
        response(b"baseline one"),
        response(body),
        response(b"baseline two"),
        response(b"request=two " + body),
    )
    assert analysis.reason_code == "ambiguous_dbms_error"


def test_truncated_response_is_inconclusive():
    analysis = analyze(
        response(b"baseline one"),
        response(b"probe one"),
        response(b"baseline two"),
        response(b"probe two", truncated=True),
    )
    assert analysis.reason_code == "truncated_response"


def test_rate_limit_precedes_truncation_in_pure_analysis():
    analysis = analyze(
        response(b"baseline one"),
        response(b"probe one"),
        response(b"baseline two"),
        response(b"limited", status=429, truncated=True),
    )

    assert analysis.reason_code == "rate_limited"
    assert analysis.request_count == 4


def test_matching_is_bounded_to_the_reviewed_scan_limit():
    diagnostic, _ = SIGNATURE_FIXTURES["sqlite_operational_syntax"]
    body = b"A" * ERROR_SCAN_LIMIT + diagnostic
    analysis = analyze(
        response(b"baseline one"),
        response(body),
        response(b"baseline two"),
        response(body + b" request=two"),
    )
    assert analysis.reason_code == "dbms_error_not_observed"


def test_all_patterns_finish_quickly_on_large_adversarial_input():
    adversarial = b"A" * ERROR_SCAN_LIMIT
    started = time.perf_counter()
    for signature in ERROR_SIGNATURES.values():
        assert signature.pattern.search(adversarial) is None
    elapsed = time.perf_counter() - started
    assert elapsed < 2.0, (
        "Reviewed error-signature matching exceeded two seconds on a 1 MiB adversarial body. Replace the pattern with bounded linear-time structure."
    )


def test_result_rule_table_matches_every_analyzer_reason_and_product_verdict():
    sqlite, _ = SIGNATURE_FIXTURES["sqlite_operational_syntax"]
    mysql, _ = SIGNATURE_FIXTURES["mysql_syntax_error_1064"]
    examples = (
        analyze(response(b"b1"), response(sqlite), response(b"b2"), response(sqlite)),
        analyze(response(b"b1"), response(b"p1"), response(b"b2"), response(b"p2")),
        analyze(response(sqlite), response(b"p1"), response(sqlite), response(b"p2")),
        analyze(
            response(b"b1"),
            response(b"p1"),
            response(b"b2", status=201),
            response(b"p2"),
        ),
        analyze(response(b"b1"), response(sqlite), response(b"b2"), response(b"p2")),
        analyze(
            response(b"b1"),
            response(sqlite + mysql),
            response(b"b2"),
            response(sqlite + mysql),
        ),
        analyze(
            response(b"b1"),
            response(b"error", status=500),
            response(b"b2"),
            response(b"error two", status=500),
        ),
        analyze(
            response(b"b1"),
            response(b"p1"),
            response(b"b2"),
            response(b"p2", truncated=True),
        ),
    )
    operational = tuple(
        operational_analysis(reason, 1)
        for reason in (
            "probe_timeout",
            "probe_failed",
            "probe_interrupted",
        )
    )
    rate_limited = operational_analysis("rate_limited", 1)
    all_examples = (*examples, *operational, rate_limited)
    assert {analysis.reason_code for analysis in all_examples} == set(
        ERROR_RESULT_RULES
    )
    for analysis in all_examples:
        rule = ERROR_RESULT_RULES[analysis.reason_code]
        product = error_product_result(analysis)
        assert analysis.status is rule.analysis_status
        assert product.verdict is rule.product_verdict
        assert rule.minimum_requests <= product.request_count <= rule.maximum_requests
        if rule.requires_complete_four:
            assert product.request_count == 4
        assert rule.requires_evidence == (analysis.evidence is not None)


@pytest.mark.parametrize("reason", ERROR_RESULT_RULES)
def test_every_result_rule_accepts_its_request_count_boundaries(reason):
    rule = ERROR_RESULT_RULES[reason]
    if rule.requires_complete_four:
        sqlite, _ = SIGNATURE_FIXTURES["sqlite_operational_syntax"]
        mysql, _ = SIGNATURE_FIXTURES["mysql_syntax_error_1064"]
        examples = {
            "dbms_error_disclosed": analyze(
                response(b"b1"), response(sqlite), response(b"b2"), response(sqlite)
            ),
            "dbms_error_not_observed": analyze(
                response(b"b1"), response(b"p1"), response(b"b2"), response(b"p2")
            ),
            "baseline_dbms_error": analyze(
                response(sqlite), response(b"p1"), response(sqlite), response(b"p2")
            ),
            "unstable_response": analyze(
                response(b"b1"),
                response(b"p1"),
                response(b"b2", status=201),
                response(b"p2"),
            ),
            "unstable_error_signal": analyze(
                response(b"b1"), response(sqlite), response(b"b2"), response(b"p2")
            ),
            "ambiguous_dbms_error": analyze(
                response(b"b1"),
                response(sqlite + mysql),
                response(b"b2"),
                response(sqlite + mysql),
            ),
            "non_success_status": analyze(
                response(b"b1"),
                response(b"p1", status=500),
                response(b"b2"),
                response(b"p2", status=500),
            ),
        }
        analysis = examples[reason]
        assert analysis.request_count == rule.minimum_requests == rule.maximum_requests
        return

    for boundary in {rule.minimum_requests, rule.maximum_requests}:
        analysis = operational_analysis(reason, boundary)
        assert analysis.reason_code == reason
        assert analysis.request_count == boundary


def test_no_error_signature_reason_can_confirm_a_vulnerability():
    assert all(
        rule.product_verdict is not Verdict.VULNERABLE
        for rule in ERROR_RESULT_RULES.values()
    ), (
        "Displaying a DBMS diagnostic is not proof that input changed SQL execution. "
        "A VULNERABLE verdict requires an independent confirmation step designed separately."
    )
