import pytest

from vintar.checks.sqli.dynamic import detect_dynamic_region
from vintar.core.models import HttpResult


def response(
    body: bytes,
    status_code: int = 200,
    truncated: bool = False,
) -> HttpResult:
    return HttpResult(
        status_code=status_code,
        elapsed=0.1,
        body=body,
        headers={},
        truncated=truncated,
    )


def test_detects_localized_dynamic_region():
    left = response(b"Welcome! request_id=abc12345; status=OK")
    right = response(b"Welcome! request_id=xyz98765; status=OK")

    region = detect_dynamic_region(left, right)

    assert region is not None
    assert region.first_changed_size == 7
    assert region.second_changed_size == 7
    assert region.prefix_size >= 8
    assert region.suffix_size >= 8


def test_identical_responses_have_no_dynamic_region():
    body = b"Welcome! request_id=abc12345; status=OK"

    assert (
        detect_dynamic_region(
            response(body),
            response(body),
        )
        is None
    )


def test_completely_different_responses_are_not_classified():
    assert (
        detect_dynamic_region(
            response(b"A" * 100),
            response(b"B" * 100),
        )
        is None
    )


def test_change_at_start_is_not_classified():
    assert (
        detect_dynamic_region(
            response(b"abc12345; common suffix content"),
            response(b"xyz98765; common suffix content"),
        )
        is None
    )


def test_change_at_end_is_not_classified():
    assert (
        detect_dynamic_region(
            response(b"common prefix content; abc12345"),
            response(b"common prefix content; xyz98765"),
        )
        is None
    )


def test_large_change_is_not_classified():
    prefix = b"common prefix:"
    suffix = b":common suffix"

    assert (
        detect_dynamic_region(
            response(prefix + b"A" * 256 + suffix),
            response(prefix + b"B" * 256 + suffix),
        )
        is None
    )


def test_different_http_status_is_not_classified():
    left = response(
        b"Welcome! request_id=abc12345; status=OK",
        status_code=200,
    )
    right = response(
        b"Welcome! request_id=xyz98765; status=OK",
        status_code=403,
    )

    assert detect_dynamic_region(left, right) is None


def test_truncated_response_is_not_classified():
    left = response(b"Welcome! request_id=abc12345; status=OK")
    right = response(
        b"Welcome! request_id=xyz98765; status=OK",
        truncated=True,
    )

    assert detect_dynamic_region(left, right) is None


def test_binary_body_is_supported():
    left = response(b"\x00" * 20 + b"AAAA" + b"\xff" * 20)
    right = response(b"\x00" * 20 + b"BBBB" + b"\xff" * 20)

    assert detect_dynamic_region(left, right) is not None


@pytest.mark.parametrize(
    "invalid",
    [None, b"content", "content", 123],
)
def test_invalid_response_type_is_rejected(invalid):
    with pytest.raises(TypeError):
        detect_dynamic_region(invalid, response(b"valid"))


def test_mutable_body_is_rejected():
    left = response(bytearray(b"mutable"))
    right = response(b"immutable")

    with pytest.raises(TypeError):
        detect_dynamic_region(left, right)


@pytest.mark.parametrize("body", [b"", b"A"])
def test_empty_and_one_byte_bodies_are_not_classified(body):
    other = b"B" if body else b"A"

    assert detect_dynamic_region(response(body), response(other)) is None


def test_different_length_changes_are_measured_without_overlap():
    prefix = b"common-prefix---"
    suffix = b"---common-suffix"

    region = detect_dynamic_region(
        response(prefix + b"A" + suffix),
        response(prefix + b"LONGER" + suffix),
    )

    assert region is not None
    assert region.prefix_size == len(prefix)
    assert region.suffix_size == len(suffix)
    assert region.first_changed_size == 1
    assert region.second_changed_size == 6
    assert region.prefix_size + region.suffix_size <= len(prefix + b"A" + suffix)


def test_deletion_can_produce_an_empty_changed_region():
    prefix = b"common-prefix---"
    suffix = b"---common-suffix"

    region = detect_dynamic_region(
        response(prefix + b"removed" + suffix),
        response(prefix + suffix),
    )

    assert region is not None
    assert region.first_changed_size == len(b"removed")
    assert region.second_changed_size == 0


def test_exact_change_size_and_ratio_boundaries_are_accepted():
    prefix = b"P" * 192
    suffix = b"S" * 192

    region = detect_dynamic_region(
        response(prefix + b"A" * 128 + suffix),
        response(prefix + b"B" * 128 + suffix),
    )

    assert region is not None
    assert region.first_changed_size == 128
    assert region.second_changed_size == 128


def test_change_above_size_boundary_is_rejected():
    prefix = b"P" * 256
    suffix = b"S" * 256

    assert (
        detect_dynamic_region(
            response(prefix + b"A" * 129 + suffix),
            response(prefix + b"B" * 129 + suffix),
        )
        is None
    )


def test_multiple_changes_are_only_reported_as_one_possible_envelope():
    prefix = b"P" * 40
    suffix = b"S" * 40
    first_middle = b"A---unchanged---B"
    second_middle = b"X---unchanged---Y"

    region = detect_dynamic_region(
        response(prefix + first_middle + suffix),
        response(prefix + second_middle + suffix),
    )

    assert region is not None
    assert region.first_changed_size == len(first_middle)
    assert region.second_changed_size == len(second_middle)


def test_utf8_json_is_compared_as_bytes():
    first_body = '{"page":"items","token":"東京-12345","status":"ok"}'.encode()
    second_body = '{"page":"items","token":"大阪-98765","status":"ok"}'.encode()

    region = detect_dynamic_region(response(first_body), response(second_body))

    assert region is not None


def test_one_megabyte_body_uses_bounded_metadata_only():
    prefix = b"P" * (512 * 1024)
    suffix = b"S" * (512 * 1024 - 8)
    secret = b"secret01"

    region = detect_dynamic_region(
        response(prefix + secret + suffix),
        response(prefix + b"changed!" + suffix),
    )

    assert region is not None
    assert region.first_changed_size == len(secret)
    assert region.second_changed_size == len(b"changed!")
    assert not hasattr(region, "body")
    assert secret.decode() not in repr(region)


@pytest.mark.parametrize(
    ("field", "invalid", "error"),
    [
        ("status_code", True, TypeError),
        ("status_code", 99, ValueError),
        ("status_code", 600, ValueError),
        ("truncated", 1, TypeError),
    ],
)
def test_invalid_http_metadata_is_rejected(field, invalid, error):
    valid = response(b"prefix----A----suffix")
    values = {
        "status_code": valid.status_code,
        "elapsed": valid.elapsed,
        "body": valid.body,
        "headers": valid.headers,
        "truncated": valid.truncated,
    }
    values[field] = invalid

    with pytest.raises(error):
        detect_dynamic_region(valid, HttpResult(**values))
