"""Fixed-response tests for context-bound Boolean echo normalization."""

import pytest

from vintar.checks.sqli.analyzer import analyze_boolean_responses
from vintar.checks.sqli.decision_facts import ResponseDynamicsDecisionFacts
from vintar.checks.sqli.echo_normalization import (
    EchoInput,
    normalize_context_bound_echoes,
)
from vintar.checks.sqli.models import Verdict
from vintar.core.models import HttpResult


def response(body: bytes) -> HttpResult:
    return HttpResult(200, 0.01, body, {})


def pair(first: bytes, second: bytes | None = None) -> tuple[HttpResult, HttpResult]:
    return response(first), response(first if second is None else second)


def analyze(
    baseline: tuple[HttpResult, HttpResult],
    true: tuple[HttpResult, HttpResult],
    false: tuple[HttpResult, HttpResult],
    values: tuple[str, str, str],
):
    return analyze_boolean_responses(
        "echo-test",
        baseline,
        true,
        false,
        echo_values=values,
    )


def test_dsvw_raw_echo_becomes_not_detected() -> None:
    baseline = b"footer (v<b>0.5</b>) end"
    true = b"footer (v<b>0.5 AND 1=1-- </b>) end"
    false = b"footer (v<b>0.5 AND 1=2-- </b>) end"

    result = analyze(
        pair(baseline),
        pair(true),
        pair(false),
        ("0.5", "0.5 AND 1=1-- ", "0.5 AND 1=2-- "),
    )

    assert result.verdict is Verdict.NOT_DETECTED
    assert result.reason_code == "no_boolean_difference"
    assert all(item.normalization_applied for item in result.observations)
    assert all(item.normalized_echo_count == 1 for item in result.observations)


def test_greet_raw_and_apostrophe_escaped_echoes_become_not_detected() -> None:
    padding = b"0123456789abcdef0123456789abcdef"
    baseline = b'value="Alice">' + padding + b"Hello, Alice!"
    true = b'value="Alice%&#39; AND 1=1-- ">' + padding + b"Hello, Alice%' AND 1=1-- !"
    false = b'value="Alice%&#39; AND 1=2-- ">' + padding + b"Hello, Alice%' AND 1=2-- !"

    result = analyze(
        pair(baseline),
        pair(true),
        pair(false),
        ("Alice", "Alice%' AND 1=1-- ", "Alice%' AND 1=2-- "),
    )

    assert result.verdict is Verdict.NOT_DETECTED
    assert result.reason_code == "no_boolean_difference"
    assert all(item.normalized_echo_count == 2 for item in result.observations)


def test_search_echo_normalization_preserves_real_result_difference() -> None:
    repeated_short_value = b"a" * 80
    prefix = repeated_short_value + b'name="q" value="'
    suffix = b'" placeholder="Search">'
    table = b"<table><tr><td>alice</td></tr><tr><td>admin</td></tr></table>"
    baseline = prefix + b"a" + suffix + table
    true = prefix + b"a%&#39; AND 1=1-- " + suffix + table
    false = prefix + b"a%&#39; AND 1=2-- " + suffix + b"<p>No results.</p>"

    result = analyze(
        pair(baseline),
        pair(true),
        pair(false),
        ("a", "a%' AND 1=1-- ", "a%' AND 1=2-- "),
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "boolean_candidate"
    baseline_observations = result.observations[:2]
    assert all(not item.normalization_applied for item in baseline_observations)
    assert all(item.normalized_echo_count == 0 for item in baseline_observations)
    assert all(item.normalization_applied for item in result.observations[2:])
    assert all(item.normalized_echo_count == 1 for item in result.observations[2:])


def test_short_values_are_not_normalized_even_when_they_repeat() -> None:
    result = analyze(
        pair(b"a" * 80 + b'<input value="a">'),
        pair(b"a" * 80 + b'<input value="b">'),
        pair(b"a" * 80 + b'<input value="c">'),
        ("a", "b", "c"),
    )

    assert result.reason_code == "unexpected_difference"
    assert all(not item.normalization_applied for item in result.observations)


@pytest.mark.parametrize("mismatch", ["count", "context"])
def test_context_mismatch_disables_normalization(mismatch: str) -> None:
    baseline = b'prefix-0123456789-value="Pets"-suffix-0123456789'
    true = b'prefix-0123456789-value="Pets TRUE"-suffix-0123456789'
    if mismatch == "count":
        true += b'prefix-0123456789-value="Pets TRUE"-suffix-0123456789'
    false_suffix = (
        b"-other--0123456789" if mismatch == "context" else b"-suffix-0123456789"
    )
    false = b'prefix-0123456789-value="Pets FALSE"' + false_suffix

    result = analyze(
        pair(baseline),
        pair(true),
        pair(false),
        ("Pets", "Pets TRUE", "Pets FALSE"),
    )

    assert result.reason_code == "unexpected_difference"
    assert all(not item.normalization_applied for item in result.observations)


@pytest.mark.parametrize(
    ("echoed_true", "echoed_false"),
    [
        (b"Pets TR", b"Pets FA"),
        (b"Pets%20TRUE", b"Pets%20FALSE"),
        (b"Pets&#x27;TRUE", b"Pets&#x27;FALSE"),
    ],
    ids=("partial", "url-encoded", "unknown-escape"),
)
def test_unreviewed_echo_forms_are_not_normalized(
    echoed_true: bytes, echoed_false: bytes
) -> None:
    result = analyze(
        pair(b'value="Pets"'),
        pair(b'value="' + echoed_true + b'"'),
        pair(b'value="' + echoed_false + b'"'),
        ("Pets", "Pets'TRUE", "Pets'FALSE"),
    )

    assert result.reason_code == "unexpected_difference"
    assert all(not item.normalization_applied for item in result.observations)


def test_non_echo_waf_difference_stays_inconclusive() -> None:
    result = analyze(
        pair(b"normal page"),
        pair(b"WAF blocked true predicate"),
        pair(b"WAF blocked false predicate"),
        ("Pets", "Pets TRUE", "Pets FALSE"),
    )

    assert result.reason_code == "unexpected_difference"


def test_repeat_context_mismatch_cannot_become_a_candidate() -> None:
    baseline = pair(b'prefix-0123456789-value="Pets"-suffix-0123456789')
    true = pair(
        b'prefix-0123456789-value="Pets TRUE"-suffix-0123456789',
        b'changed-0123456789-value="Pets TRUE"-suffix-0123456789',
    )
    false = pair(b'prefix-0123456789-value="Pets FALSE"-suffix-0123456789')

    result = analyze(baseline, true, false, ("Pets", "Pets TRUE", "Pets FALSE"))

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code in {"unstable_response", "possible_dynamic_response"}
    assert result.reason_code != "boolean_candidate"


def test_dynamic_facts_expose_only_normalization_flag_and_count() -> None:
    def dynamic(value: bytes, token: bytes) -> bytes:
        return (
            b'prefix-0123456789-value="'
            + value
            + b'"-0123456789abcdef0123456789abcdef-token='
            + token
            + b"-suffix-0123456789"
        )

    result = analyze(
        pair(dynamic(b"Pets", b"a"), dynamic(b"Pets", b"b")),
        pair(dynamic(b"Pets TRUE", b"a"), dynamic(b"Pets TRUE", b"b")),
        pair(dynamic(b"Pets FALSE", b"a"), dynamic(b"Pets FALSE", b"b")),
        ("Pets", "Pets TRUE", "Pets FALSE"),
    )

    assert isinstance(result.decision_facts, ResponseDynamicsDecisionFacts)
    assert result.decision_facts.normalization_applied is True
    assert result.decision_facts.normalized_echo_count == 6


def test_normalizer_replaces_only_the_context_bound_short_occurrence() -> None:
    repeated = b"a" * 80
    inputs = (
        EchoInput(repeated + b'<input value="a" placeholder="x">', "a"),
        EchoInput(
            repeated + b'<input value="a LONG TRUE" placeholder="x">',
            "a LONG TRUE",
        ),
        EchoInput(
            repeated + b'<input value="a LONG FALSE" placeholder="x">',
            "a LONG FALSE",
        ),
    )

    normalized = normalize_context_bound_echoes(inputs)

    assert normalized[0].body == inputs[0].body
    assert not normalized[0].applied
    assert normalized[1].body == inputs[0].body
    assert normalized[2].body == inputs[0].body
