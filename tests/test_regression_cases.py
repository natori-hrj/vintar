import os
import tomllib
from dataclasses import FrozenInstanceError, replace

import pytest

from vintar.checks.sqli.models import Verdict
from vintar.core.injector import inject
from vintar.core.request import InjectionMode, RequestTemplate
from vintar.core.scope import AllowedOrigin
from vintar.regression import AnyRegressionCase, RegressionCase
from vintar.regression import cases as cases_module
from vintar.regression.cases import (
    CASE_MAX_RESPONSE_SIZE,
    MAX_CASE_BYTES,
    ErrorRegressionCase,
    TimeRegressionCase,
    load_regression_case,
    parse_regression_case,
)

VALID_CASE = """
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

[[target.params]]
name = "category"
value = "Other"

[injection]
location = "query"
name = "category"
occurrence = 1
mode = "append"

[probes]
true_payload = "' AND 1=1-- "
false_payload = "' AND 1=2-- "

[limits]
max_requests = 6
requests_per_second = 2.0
timeout_seconds = 10.0
"""

CONFIRMED_CASE = VALID_CASE.replace(
    'false_payload = "\' AND 1=2-- "',
    'false_payload = "\' AND 1=2-- "\n\n'
    "[probes.confirmation]\n"
    'true_payload = "\' AND 2<3-- "\n'
    'false_payload = "\' AND 2>3-- "\n'
    'baseline_preserving_control = "\' AND 7=7-- "',
).replace("max_requests = 6", "max_requests = 18")

TIME_CASE = """
version = 1
id = "product-search-time-sqli"
type = "sqli.time"
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
delay_payload = "-delay"
control_payload = "-control"
expected_delay_seconds = 0.25

[limits]
max_requests = 9
requests_per_second = 10.0
timeout_seconds = 0.75
"""

ERROR_CASE = """
version = 1
id = "product-search-error-sqli"
type = "sqli.error"
expected_verdict = "inconclusive"

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
error_payload = "'"

[limits]
max_requests = 4
requests_per_second = 10.0
timeout_seconds = 1.0
"""


def test_valid_case_is_parsed():
    case = parse_regression_case(VALID_CASE)

    assert isinstance(case, RegressionCase)
    assert case.schema_version == 1
    assert case.check_type == "sqli.boolean"
    assert case.case_id == "product-search-sqli"
    assert case.expected_verdict is Verdict.NOT_DETECTED
    assert case.max_requests == 6
    assert case.max_response_size == CASE_MAX_RESPONSE_SIZE
    assert case.requests_per_second == 2.0
    assert case.timeout_seconds == 10.0
    assert case.point.occurrence == 1
    assert case.point.mode is InjectionMode.APPEND
    assert case.template.params == (
        ("category", "Pets"),
        ("category", "Other"),
    )
    assert case.confirmation is None


def test_optional_confirmation_case_is_parsed():
    case = parse_regression_case(CONFIRMED_CASE)

    assert case.max_requests == 18
    assert case.confirmation is not None
    assert case.confirmation.true_payload == "' AND 2<3-- "
    assert case.confirmation.false_payload == "' AND 2>3-- "
    assert case.confirmation.baseline_preserving_control == "' AND 7=7-- "


def test_valid_time_case_is_parsed_at_lower_boundaries():
    case = parse_regression_case(TIME_CASE)

    assert isinstance(case, TimeRegressionCase)
    assert isinstance(case, AnyRegressionCase)
    assert not isinstance(case, RegressionCase)
    assert case.check_type == "sqli.time"
    assert case.delay_payload == "-delay"
    assert case.control_payload == "-control"
    assert case.expected_delay_seconds == 0.25
    assert case.max_requests == 9
    assert case.timeout_seconds == 0.75


def test_valid_error_case_is_parsed():
    case = parse_regression_case(ERROR_CASE)

    assert isinstance(case, ErrorRegressionCase)
    assert isinstance(case, AnyRegressionCase)
    assert not isinstance(case, RegressionCase)
    assert case.check_type == "sqli.error"
    assert case.error_payload == "'"
    assert case.max_requests == 4
    assert case.max_response_size == CASE_MAX_RESPONSE_SIZE


@pytest.mark.parametrize("value", ["3", "5", "true"])
def test_error_case_requires_exact_four_request_budget(value):
    source = ERROR_CASE.replace("max_requests = 4", f"max_requests = {value}")

    with pytest.raises(ValueError, match=r"exactly 4.*max_requests = 4"):
        parse_regression_case(source)


@pytest.mark.parametrize(
    "replacement",
    [
        'error_payload = ""',
        f'error_payload = "{"x" * 513}"',
        'error_payload = "bad\\u0001value"',
        'error_payload = "sqlite3.OperationalError: unrecognized token:"',
    ],
)
def test_error_case_rejects_invalid_or_signature_bearing_payload(replacement):
    source = ERROR_CASE.replace('error_payload = "\'"', replacement)

    with pytest.raises(
        ValueError,
        match=r"error_payload.*nonempty.*512.*registered DBMS diagnostic",
    ):
        parse_regression_case(source)


@pytest.mark.parametrize(
    "replacement",
    [
        'true_payload = "x"',
        'delay_payload = "x"',
        'error_payload = "\'"\npreset = "sqlite"',
    ],
)
def test_error_case_rejects_mixed_or_unknown_probe_keys(replacement):
    source = ERROR_CASE.replace('error_payload = "\'"', replacement)

    with pytest.raises(
        ValueError,
        match=r"exactly error_payload.*Remove Boolean, Time, preset, or unknown",
    ):
        parse_regression_case(source)


def test_error_case_rejects_non_query_injection():
    source = ERROR_CASE.replace('location = "query"', 'location = "body"')

    with pytest.raises(ValueError, match=r"query injection only.*location = \"query\""):
        parse_regression_case(source)


def test_error_case_requires_distinct_baseline_and_probe():
    source = ERROR_CASE.replace('mode = "append"', 'mode = "replace"').replace(
        'error_payload = "\'"', 'error_payload = "Pets"'
    )

    with pytest.raises(
        ValueError,
        match=r"baseline and injected requests must differ.*injection target",
    ):
        parse_regression_case(source)


def test_valid_time_case_is_parsed_at_upper_boundaries():
    case = parse_regression_case(
        TIME_CASE.replace(
            "expected_delay_seconds = 0.25", "expected_delay_seconds = 2.0"
        ).replace("timeout_seconds = 0.75", "timeout_seconds = 8.0")
    )

    assert isinstance(case, TimeRegressionCase)
    assert case.expected_delay_seconds == 2.0
    assert case.timeout_seconds == 8.0


@pytest.mark.parametrize("value", ["0.24", "2.01", "true"])
def test_time_case_rejects_invalid_expected_delay(value):
    source = TIME_CASE.replace(
        "expected_delay_seconds = 0.25", f"expected_delay_seconds = {value}"
    )

    with pytest.raises(ValueError, match=r"0.25 through 2.0.*excluding booleans"):
        parse_regression_case(source)


@pytest.mark.parametrize("value", ["0.74", "8.01", "true"])
def test_time_case_rejects_invalid_timeout(value):
    source = TIME_CASE.replace("timeout_seconds = 0.75", f"timeout_seconds = {value}")

    with pytest.raises(
        ValueError, match=r"timeout_seconds.*expected_delay_seconds \+ 0.5"
    ):
        parse_regression_case(source)


def test_time_case_rejects_timeout_below_delay_margin():
    source = TIME_CASE.replace(
        "expected_delay_seconds = 0.25", "expected_delay_seconds = 1.0"
    )

    with pytest.raises(ValueError, match=r"too short.*expected_delay_seconds \+ 0.5"):
        parse_regression_case(source)


@pytest.mark.parametrize("value", ["0.09", "10.01", "true"])
def test_time_case_rejects_invalid_request_rate(value):
    source = TIME_CASE.replace(
        "requests_per_second = 10.0", f"requests_per_second = {value}"
    )

    with pytest.raises(ValueError, match=r"0.1 through 10.0.*excluding booleans"):
        parse_regression_case(source)


@pytest.mark.parametrize("value", ["8", "10", "true"])
def test_time_case_requires_exact_nine_request_budget(value):
    source = TIME_CASE.replace("max_requests = 9", f"max_requests = {value}")

    with pytest.raises(ValueError, match=r"exactly 9.*max_requests = 9"):
        parse_regression_case(source)


@pytest.mark.parametrize(
    "replacement",
    [
        'delay_payload = ""',
        f'delay_payload = "{"x" * 513}"',
        'delay_payload = "bad\\u0001value"',
    ],
)
def test_time_case_rejects_invalid_payload(replacement):
    source = TIME_CASE.replace('delay_payload = "-delay"', replacement)

    with pytest.raises(ValueError, match=r"nonempty strings.*512.*control characters"):
        parse_regression_case(source)


def test_time_case_requires_distinct_payloads():
    source = TIME_CASE.replace(
        'control_payload = "-control"', 'control_payload = "-delay"'
    )

    with pytest.raises(ValueError, match=r"must differ.*distinct"):
        parse_regression_case(source)


@pytest.mark.parametrize(
    "replacement",
    [
        'true_payload = "true"\nfalse_payload = "false"',
        'delay_payload = "-delay"\ncontrol_payload = "-control"\nexpected_delay_seconds = 0.25\nunknown = "value"',
    ],
)
def test_time_case_rejects_boolean_mixed_or_unknown_probe_keys(replacement):
    before = 'delay_payload = "-delay"\ncontrol_payload = "-control"\nexpected_delay_seconds = 0.25'

    with pytest.raises(ValueError, match=r"require exactly.*Remove Boolean or unknown"):
        parse_regression_case(TIME_CASE.replace(before, replacement))


def test_time_case_rejects_probe_matching_baseline_request():
    source = TIME_CASE.replace('mode = "append"', 'mode = "replace"').replace(
        'delay_payload = "-delay"', 'delay_payload = "Pets"'
    )

    with pytest.raises(ValueError, match=r"baseline, control, and delay.*distinct"):
        parse_regression_case(source)


def test_time_case_rejects_non_query_injection_actionably():
    source = TIME_CASE.replace('location = "query"', 'location = "header"')

    with pytest.raises(ValueError, match=r"query injection only.*location = \"query\""):
        parse_regression_case(source)


def test_time_case_validates_scope_for_baseline_control_and_delay(monkeypatch):
    observed = []
    original = cases_module.validate_scope

    def recording_validate_scope(url, scope):
        observed.append(url)
        return original(url, scope)

    monkeypatch.setattr(cases_module, "validate_scope", recording_validate_scope)

    parse_regression_case(TIME_CASE)

    assert observed == ["http://localhost:8000/products"] * 3


@pytest.mark.parametrize(
    "source",
    [
        CONFIRMED_CASE.replace("max_requests = 18", "max_requests = 6"),
        VALID_CASE.replace("max_requests = 6", "max_requests = 18"),
        CONFIRMED_CASE.replace('true_payload = "\' AND 2<3-- "\n', ""),
        CONFIRMED_CASE.replace("' AND 2<3-- ", "' AND 1=1-- "),
        CONFIRMED_CASE.replace(
            'baseline_preserving_control = "\' AND 7=7-- "',
            'baseline_preserving_control = "\' AND 7=7-- "\nunknown = true',
        ),
    ],
)
def test_confirmation_shape_budget_and_distinctness_are_enforced(source):
    with pytest.raises(ValueError, match="valid schema v1 TOML case"):
        parse_regression_case(source)


def test_injection_preserves_duplicate_parameters():
    case = parse_regression_case(VALID_CASE)

    injected = inject(
        case.template,
        case.point,
        case.true_payload,
    )

    assert injected.params[0] == ("category", "Pets")
    assert injected.params[1] == (
        "category",
        "Other' AND 1=1-- ",
    )
    assert case.template.params[1] == ("category", "Other")


def test_case_can_be_loaded_from_file(tmp_path):
    path = tmp_path / "case.toml"
    path.write_text(VALID_CASE, encoding="utf-8")

    case = load_regression_case(path)

    assert case.case_id == "product-search-sqli"


@pytest.mark.parametrize(
    "old,new",
    [
        ("version = 1", "version = 2"),
        ("version = 1", "version = true"),
        ('type = "sqli.boolean"', 'type = "unknown.check"'),
        ('expected_verdict = "not_detected"', 'expected_verdict = "unknown"'),
        ("max_requests = 6", "max_requests = 100"),
        ("max_requests = 6", "max_requests = true"),
        ("requests_per_second = 2.0", "requests_per_second = 100.0"),
        ("requests_per_second = 2.0", "requests_per_second = true"),
        ("timeout_seconds = 10.0", "timeout_seconds = 0.0"),
        ("timeout_seconds = 10.0", "timeout_seconds = true"),
        (
            'allowed_origin = "http://localhost:8000"',
            'allowed_origin = "http://example.com"',
        ),
        (
            'allowed_origin = "http://localhost:8000"',
            'allowed_origin = "http://localhost:0"',
        ),
        ("occurrence = 1", "occurrence = 5"),
        ('location = "query"', 'location = "header"'),
        ('mode = "append"', 'mode = "invalid"'),
        ('true_payload = "\' AND 1=1-- "', 'true_payload = "\' AND 1=2-- "'),
        ('name = "category"\noccurrence = 1', 'name = "missing"\noccurrence = 1'),
    ],
)
def test_invalid_cases_are_rejected(old, new):
    with pytest.raises(ValueError):
        parse_regression_case(VALID_CASE.replace(old, new, 1))


class IntSubclass(int):
    pass


class FloatSubclass(float):
    pass


@pytest.mark.parametrize(
    "field", ["max_requests", "requests_per_second", "timeout_seconds"]
)
@pytest.mark.parametrize("number_type", [IntSubclass, FloatSubclass])
def test_case_parser_rejects_numeric_subclasses_in_limits(
    monkeypatch, field, number_type
):
    data = tomllib.loads(VALID_CASE)
    data["limits"][field] = number_type(data["limits"][field])
    monkeypatch.setattr(cases_module.tomllib, "loads", lambda source: data)

    with pytest.raises(ValueError, match="Invalid or unsupported regression case"):
        parse_regression_case(VALID_CASE)


def test_invalid_case_file_explains_expected_format_without_exposing_input(tmp_path):
    path = tmp_path / "case.toml"
    path.write_text("invalid case with private content", encoding="utf-8")

    with pytest.raises(ValueError) as caught:
        load_regression_case(path)

    assert str(caught.value) == (
        "Invalid or unsupported regression case. Use a valid schema v1 TOML case."
    )


def test_unknown_top_level_field_is_rejected():
    with pytest.raises(ValueError):
        parse_regression_case(VALID_CASE + "\nunknown = true\n")


def test_unknown_nested_field_is_rejected():
    source = VALID_CASE.replace(
        'allowed_origin = "http://localhost:8000"',
        'allowed_origin = "http://localhost:8000"\nsecret = "abc"',
    )

    with pytest.raises(ValueError):
        parse_regression_case(source)


def test_duplicate_toml_key_is_rejected():
    source = VALID_CASE.replace(
        "version = 1",
        "version = 1\nversion = 1",
    )

    with pytest.raises(ValueError):
        parse_regression_case(source)


@pytest.mark.parametrize("value", ["nan", "+inf", "-inf"])
def test_non_finite_numeric_limits_are_rejected(value):
    source = VALID_CASE.replace(
        "requests_per_second = 2.0", f"requests_per_second = {value}"
    )

    with pytest.raises(ValueError, match="Invalid or unsupported"):
        parse_regression_case(source)


def test_huge_integer_is_rejected_with_public_error_contract():
    huge_integer = "1" + ("0" * 10_000)
    source = VALID_CASE.replace(
        "requests_per_second = 2.0",
        f"requests_per_second = {huge_integer}",
    )

    with pytest.raises(ValueError, match="Invalid or unsupported"):
        parse_regression_case(source)


@pytest.mark.parametrize(
    "source",
    [
        "x" * (MAX_CASE_BYTES + 1),
        "界" * ((MAX_CASE_BYTES // 3) + 1),
    ],
    ids=["ascii", "multibyte"],
)
def test_in_memory_source_size_is_bounded(source):
    with pytest.raises(ValueError, match="Invalid or unsupported"):
        parse_regression_case(source)


def test_parser_error_does_not_expose_source_contents():
    secret = "secret_payload_value"
    source = f'not valid TOML = "{secret}"'

    with pytest.raises(ValueError) as raised:
        parse_regression_case(source)

    assert secret not in str(raised.value)


@pytest.mark.parametrize("escaped", [r"\u0085", r"\u202e"])
def test_unicode_control_and_format_characters_are_rejected(escaped):
    source = VALID_CASE.replace('value = "Pets"', f'value = "{escaped}"')

    with pytest.raises(ValueError):
        parse_regression_case(source)


def test_unpaired_surrogate_is_rejected_without_encoding_error():
    source = VALID_CASE.replace("Pets", "\ud800")

    with pytest.raises(ValueError, match="Invalid or unsupported"):
        parse_regression_case(source)


def test_empty_parameter_value_is_preserved():
    source = VALID_CASE.replace('value = "Pets"', 'value = ""')

    case = parse_regression_case(source)

    assert case.template.params[0] == ("category", "")


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            'url = "http://localhost:8000/products"',
            'url = "http://localhost:8000/products#"',
        ),
        (
            'url = "http://localhost:8000/products"',
            'url = "http://localhost:8000/products?"',
        ),
        (
            'allowed_origin = "http://localhost:8000"',
            'allowed_origin = "http://localhost:8000?"',
        ),
        (
            'allowed_origin = "http://localhost:8000"',
            'allowed_origin = " http://localhost:8000"',
        ),
    ],
)
def test_ambiguous_url_delimiters_and_whitespace_are_rejected(old, new):
    with pytest.raises(ValueError):
        parse_regression_case(VALID_CASE.replace(old, new, 1))


def test_file_size_limit(tmp_path):
    path = tmp_path / "oversized.toml"
    path.write_bytes(b"x" * (MAX_CASE_BYTES + 1))

    with pytest.raises(ValueError, match="size limit"):
        load_regression_case(path)


def test_invalid_utf8_is_rejected(tmp_path):
    path = tmp_path / "invalid.toml"
    path.write_bytes(b"\xff\xfe")

    with pytest.raises(ValueError, match="UTF-8"):
        load_regression_case(path)


def test_symbolic_link_is_rejected(tmp_path):
    target = tmp_path / "target.toml"
    target.write_text(VALID_CASE, encoding="utf-8")
    link = tmp_path / "case.toml"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="Unable to read"):
        load_regression_case(link)


def test_directory_is_rejected_as_non_regular_file(tmp_path):
    with pytest.raises(ValueError, match="Unable to read"):
        load_regression_case(tmp_path)


def test_fifo_is_rejected_without_opening_it(tmp_path):
    fifo = tmp_path / "case.pipe"
    os.mkfifo(fifo)

    with pytest.raises(ValueError, match="Unable to read"):
        load_regression_case(fifo)


def test_path_is_not_exposed_by_read_error(tmp_path):
    secret_path = tmp_path / "secret-target-name.toml"

    with pytest.raises(ValueError) as raised:
        load_regression_case(secret_path)

    assert str(secret_path) not in str(raised.value)


@pytest.mark.parametrize("replacement", ["symlink", "fifo"])
def test_non_regular_replacement_just_before_open_is_rejected(
    tmp_path, monkeypatch, replacement
):
    path = tmp_path / "case.toml"
    path.write_text(VALID_CASE, encoding="utf-8")
    target = tmp_path / "target.toml"
    target.write_text(VALID_CASE, encoding="utf-8")
    real_open = os.open

    def replacing_open(file_path, flags):
        assert file_path == os.fspath(path)
        path.unlink()
        if replacement == "symlink":
            path.symlink_to(target)
        else:
            os.mkfifo(path)
            assert flags & os.O_NONBLOCK
        return real_open(file_path, flags)

    monkeypatch.setattr(cases_module.os, "open", replacing_open)

    with pytest.raises(ValueError, match="Unable to read"):
        load_regression_case(path)

    assert path.is_symlink() if replacement == "symlink" else path.is_fifo()


def test_case_repr_does_not_expose_payloads():
    case = parse_regression_case(VALID_CASE)

    assert "AND 1=1" not in repr(case)
    assert "AND 1=2" not in repr(case)
    assert "localhost" not in repr(case)


def test_expected_vulnerable_is_supported():
    source = VALID_CASE.replace(
        'expected_verdict = "not_detected"',
        'expected_verdict = "vulnerable"',
    )

    case = parse_regression_case(source)

    assert case.expected_verdict is Verdict.VULNERABLE


def test_expected_inconclusive_is_supported_but_remains_distinct():
    source = VALID_CASE.replace(
        'expected_verdict = "not_detected"',
        'expected_verdict = "inconclusive"',
    )

    case = parse_regression_case(source)

    assert case.expected_verdict is Verdict.INCONCLUSIVE
    assert case.expected_verdict is not Verdict.NOT_DETECTED


@pytest.mark.parametrize(
    ("url", "origin", "expected_origin"),
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
    ],
)
def test_origin_normalization_is_reproducible(url, origin, expected_origin):
    source = VALID_CASE.replace(
        'url = "http://localhost:8000/products"',
        f'url = "{url}"',
    ).replace(
        'allowed_origin = "http://localhost:8000"',
        f'allowed_origin = "{origin}"',
    )

    case = parse_regression_case(source)

    assert case.scope.allowed_origins == frozenset({expected_origin})


def test_regression_case_enforces_invariants_on_direct_construction():
    case = parse_regression_case(VALID_CASE)

    with pytest.raises(ValueError, match="six requests"):
        replace(case, max_requests=7)
    with pytest.raises(ValueError, match="response size"):
        replace(case, max_response_size=CASE_MAX_RESPONSE_SIZE + 1)
    with pytest.raises(ValueError, match="Invalid regression case string"):
        replace(case, true_payload="")
    with pytest.raises(ValueError):
        replace(
            case,
            template=RequestTemplate(
                method="GET",
                url="http://example.com/products",
                params=case.template.params,
            ),
        )


def test_regression_case_is_immutable():
    case = parse_regression_case(VALID_CASE)

    with pytest.raises(FrozenInstanceError):
        case.max_requests = 7


def test_no_network_execution_is_performed(monkeypatch):
    import httpx

    def forbidden(*args, **kwargs):
        raise AssertionError("Network use is forbidden")

    monkeypatch.setattr(httpx, "Client", forbidden)

    case = parse_regression_case(VALID_CASE)

    assert case.max_requests == 6


@pytest.mark.parametrize(
    ("changes", "error", "diagnostic"),
    [
        ({"schema_version": True}, ValueError, "require Schema v1. Set version = 1."),
        (
            {"check_type": None},
            ValueError,
            'require type = "sqli.error". Use that exact check type.',
        ),
        (
            {"case_id": ""},
            ValueError,
            "Invalid error case identifier. Use 1-64 letters",
        ),
        (
            {"case_id": "-bad"},
            ValueError,
            "Invalid error case identifier. Use 1-64 letters",
        ),
        ({"template": None}, TypeError, "template must be a RequestTemplate."),
        ({"point": None}, TypeError, "point must be an InjectionPoint."),
        ({"expected_verdict": None}, TypeError, "expected_verdict must be a Verdict."),
        ({"scope": None}, TypeError, "scope must be a ScopePolicy."),
        (
            {"error_payload": ""},
            ValueError,
            "Invalid error_payload. Supply an explicit nonempty reviewed string",
        ),
        (
            {"max_requests": True},
            ValueError,
            "require exactly 4 requests. Set limits.max_requests = 4.",
        ),
        (
            {"max_response_size": 1},
            ValueError,
            "require the fixed response-size limit. Use the Schema v1 loader default.",
        ),
        (
            {"requests_per_second": True},
            ValueError,
            "require numeric requests_per_second from 0.1 through 10.0",
        ),
        (
            {"timeout_seconds": 0},
            ValueError,
            "timeout_seconds from 0.1 through 60.0, excluding booleans.",
        ),
    ],
)
def test_error_case_rejects_invalid_direct_construction(changes, error, diagnostic):
    case = parse_regression_case(ERROR_CASE)
    assert isinstance(case, ErrorRegressionCase)

    with pytest.raises(error) as caught:
        replace(case, **changes)

    assert diagnostic in str(caught.value)
