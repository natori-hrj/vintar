import os
from dataclasses import FrozenInstanceError, replace

import pytest

from vintar.checks.sqli.models import Verdict
from vintar.core.injector import inject
from vintar.core.request import InjectionMode, RequestTemplate
from vintar.core.scope import AllowedOrigin
from vintar.regression import RegressionCase
from vintar.regression import cases as cases_module
from vintar.regression.cases import (
    CASE_MAX_RESPONSE_SIZE,
    MAX_CASE_BYTES,
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
        ("timeout_seconds = 10.0", "timeout_seconds = 0.0"),
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


def test_file_replacement_between_check_and_open_is_rejected(tmp_path, monkeypatch):
    path = tmp_path / "case.toml"
    path.write_text(VALID_CASE, encoding="utf-8")
    real_open = os.open
    replaced = False

    def replacing_open(file_path, flags):
        nonlocal replaced
        if not replaced:
            replaced = True
            path.unlink()
            path.write_text(VALID_CASE, encoding="utf-8")
        return real_open(file_path, flags)

    monkeypatch.setattr(cases_module.os, "open", replacing_open)

    with pytest.raises(ValueError, match="Unable to read"):
        load_regression_case(path)


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
