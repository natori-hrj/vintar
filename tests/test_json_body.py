from dataclasses import FrozenInstanceError
from time import perf_counter

import pytest

from vintar.core.json_body import (
    JSON_POINTER_TOO_LONG_MESSAGE,
    MAX_JSON_POINTER_CHARACTERS,
    JsonBody,
    JsonPointer,
    json_leaf_at,
    replace_json_leaf,
)
from vintar.core.strict_json import (
    JSON_INTEGER_TOO_LONG_MESSAGE,
    MAX_JSON_INTEGER_DIGITS,
    MAX_STRICT_JSON_BYTES,
    MAX_STRICT_JSON_NESTING,
    StrictJsonError,
)


@pytest.mark.parametrize(
    ("source", "serialized", "is_float"),
    [
        (b"null", b"null", False),
        (b"true", b"true", False),
        (b"false", b"false", False),
        (b"0", b"0", False),
        (b"-42", b"-42", False),
        (b'"text"', b'"text"', False),
        (b"0.1", b"0.1", True),
        (b"1e-7", b"1e-07", True),
        (b"1.0e0", b"1.0", True),
        (b"1.50", b"1.5", True),
        (b"-0.0", b"-0.0", True),
        (b"2.5e1", b"25.0", True),
    ],
)
def test_strict_json_leaf_serialization_rule(source, serialized, is_float):
    body = JsonBody.from_bytes(source)
    assert body.to_bytes() == serialized
    assert JsonBody.from_bytes(serialized).to_bytes() == serialized
    if is_float:
        value = float(serialized)
        assert float(repr(value)) == value


def test_integer_at_digit_limit_round_trips_exactly():
    digits = b"9" * MAX_JSON_INTEGER_DIGITS
    assert JsonBody.from_bytes(digits).to_bytes() == digits


def test_integer_over_digit_limit_is_rejected_with_fixed_message():
    digits = b"9" * (MAX_JSON_INTEGER_DIGITS + 1)
    with pytest.raises(StrictJsonError) as caught:
        JsonBody.from_bytes(digits)
    assert str(caught.value) == JSON_INTEGER_TOO_LONG_MESSAGE


def test_replacement_integer_over_digit_limit_uses_fixed_message():
    oversized = 10**MAX_JSON_INTEGER_DIGITS
    with pytest.raises(StrictJsonError) as caught:
        replace_json_leaf(JsonBody.from_bytes(b"0"), JsonPointer.parse(""), oversized)
    assert str(caught.value) == JSON_INTEGER_TOO_LONG_MESSAGE


def test_max_size_body_of_max_length_integers_has_bounded_work():
    integer = b"9" * MAX_JSON_INTEGER_DIGITS
    count = (MAX_STRICT_JSON_BYTES - 2) // (len(integer) + 1)
    compact = b"[" + b",".join([integer] * count) + b"]"
    source = compact + b" " * (MAX_STRICT_JSON_BYTES - len(compact))

    started = perf_counter()
    serialized = JsonBody.from_bytes(source).to_bytes()
    elapsed = perf_counter() - started

    assert serialized == compact
    assert elapsed < 5.0


@pytest.mark.parametrize("source", [b"1e400", b"-1e400"])
def test_rejects_float_overflow_with_fixed_message(source):
    with pytest.raises(StrictJsonError) as caught:
        JsonBody.from_bytes(source)
    assert str(caught.value) == (
        "JSON number is outside the finite float range. "
        "Use an integer or a finite float within Python's supported range."
    )


@pytest.mark.parametrize("source", [b"NaN", b"Infinity", b"-Infinity"])
def test_rejects_non_finite_constants(source):
    with pytest.raises(StrictJsonError, match="must be finite"):
        JsonBody.from_bytes(source)


def test_object_order_and_unicode_have_deterministic_bytes():
    first = JsonBody.from_bytes('{"界":"値","a":[1,2.0]}'.encode())
    second = JsonBody.from_bytes('{"a":[1,2.00],"界":"値"}'.encode())
    assert first.to_bytes() == second.to_bytes()
    assert first.to_bytes() == b'{"a":[1,2.0],"\\u754c":"\\u5024"}'


def test_equality_and_hash_follow_canonical_json_bytes():
    true_body = JsonBody.from_bytes(b"true")
    one_body = JsonBody.from_bytes(b"1")
    assert len({true_body, one_body}) == 2
    assert JsonBody.from_bytes(b"false") != JsonBody.from_bytes(b"0")
    assert JsonBody.from_bytes(b"1") != JsonBody.from_bytes(b"1.0")
    assert JsonBody.from_bytes(b"-0.0") != JsonBody.from_bytes(b"0.0")
    assert JsonBody.from_bytes(b"[true]") != JsonBody.from_bytes(b"[1]")
    assert JsonBody.from_bytes(b'{"a":1}') != JsonBody.from_bytes(b'{"a":1.0}')


def test_equal_bodies_with_different_key_order_have_equal_hashes():
    first = JsonBody.from_bytes(b'{"a":1,"b":true}')
    second = JsonBody.from_bytes(b'{"b":true,"a":1}')
    assert first == second
    assert hash(first) == hash(second)


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (b'{"a":1,"a":2}', "duplicate object member"),
        (b'{"a":{"b":1,"b":2}}', "duplicate object member"),
        (b"{} trailing", "trailing data"),
        (b"\xff", "UTF-8"),
    ],
)
def test_rejects_invalid_json_without_echoing_values(source, message):
    with pytest.raises(ValueError, match=message) as caught:
        JsonBody.from_bytes(source)
    assert "trailing" not in str(caught.value) or source == b"{} trailing"
    assert "PRIVATE-SENTINEL" not in str(caught.value)


def test_rejects_oversized_json():
    with pytest.raises(StrictJsonError, match="smaller JSON document"):
        JsonBody.from_bytes(b" " * (MAX_STRICT_JSON_BYTES + 1))


def test_rejects_excessive_nesting():
    source = (
        b"[" * (MAX_STRICT_JSON_NESTING + 1)
        + b"0"
        + b"]" * (MAX_STRICT_JSON_NESTING + 1)
    )
    with pytest.raises(StrictJsonError, match="flatter JSON document"):
        JsonBody.from_bytes(source)


def test_body_and_pointer_are_frozen():
    body = JsonBody.from_bytes(b"1")
    pointer = JsonPointer.parse("")
    with pytest.raises(FrozenInstanceError):
        body._value = None
    with pytest.raises(FrozenInstanceError):
        pointer.tokens = ("changed",)


def test_body_and_pointer_require_strict_factories():
    with pytest.raises(TypeError):
        JsonBody()
    with pytest.raises(TypeError):
        JsonPointer()


@pytest.mark.parametrize(
    ("source", "pointer", "expected"),
    [
        (b'"old"', "", b'"new"'),
        (b'{"a":{"b":"old"}}', "/a/b", b'{"a":{"b":"new"}}'),
        (b'{"a/b":{"~key":"old"}}', "/a~1b/~0key", b'{"a/b":{"~key":"new"}}'),
        (b'{"":"old"}', "/", b'{"":"new"}'),
        (b'[true,{"0":"old"}]', "/1/0", b'[true,{"0":"new"}]'),
    ],
)
def test_replaces_one_existing_leaf(source, pointer, expected):
    original = JsonBody.from_bytes(source)
    replaced = replace_json_leaf(original, JsonPointer.parse(pointer), "new")
    assert replaced.to_bytes() == expected
    assert original.to_bytes() == JsonBody.from_bytes(source).to_bytes()


def test_replacement_preserves_non_target_types_and_structure():
    original = JsonBody.from_bytes(
        b'{"a":[null,true,1,2.0,"old"],"object":{"x":"same"}}'
    )
    replaced = replace_json_leaf(original, JsonPointer.parse("/a/4"), "new")
    assert replaced.to_bytes() == (
        b'{"a":[null,true,1,2.0,"new"],"object":{"x":"same"}}'
    )
    assert original.to_bytes() == (
        b'{"a":[null,true,1,2.0,"old"],"object":{"x":"same"}}'
    )


@pytest.mark.parametrize(
    ("pointer", "message"),
    [
        ("a", "start with"),
        ("/~", "invalid escape"),
        ("/~2", "invalid escape"),
    ],
)
def test_rejects_invalid_pointer_syntax(pointer, message):
    with pytest.raises(ValueError, match=message):
        JsonPointer.parse(pointer)


def test_rejects_pointer_over_character_limit_with_fixed_message():
    with pytest.raises(ValueError) as caught:
        JsonPointer.parse("/" + "0" * MAX_JSON_POINTER_CHARACTERS)
    assert str(caught.value) == JSON_POINTER_TOO_LONG_MESSAGE


@pytest.mark.parametrize(
    ("pointer", "message"),
    [
        ("/-", "append syntax"),
        ("/*", "wildcards"),
        ("/-1", "non-negative decimal"),
        ("/01", "leading zero"),
        ("/one", "non-negative decimal"),
        ("/2", "does not exist"),
    ],
)
def test_rejects_non_explicit_or_missing_array_index(pointer, message):
    body = JsonBody.from_bytes(b'["zero","one"]')
    with pytest.raises(ValueError, match=message):
        replace_json_leaf(body, JsonPointer.parse(pointer), "new")


@pytest.mark.parametrize("pointer", ["/0", "/" + "9" * 100_000])
def test_empty_array_rejects_every_valid_index_as_out_of_range(pointer):
    with pytest.raises(ValueError, match="array index does not exist"):
        replace_json_leaf(JsonBody.from_bytes(b"[]"), JsonPointer.parse(pointer), "new")


def test_one_element_array_rejects_very_long_index_as_out_of_range():
    pointer = JsonPointer.parse("/" + "9" * 100_000)
    with pytest.raises(ValueError, match="array index does not exist"):
        replace_json_leaf(JsonBody.from_bytes(b"[0]"), pointer, "new")


def test_array_index_boundary_accepts_last_and_rejects_length():
    body = JsonBody.from_bytes(b'[0,1,2,3,4,5,6,7,8,"old"]')
    replaced = replace_json_leaf(body, JsonPointer.parse("/9"), "new")
    assert replaced.to_bytes() == b'[0,1,2,3,4,5,6,7,8,"new"]'
    with pytest.raises(ValueError, match="array index does not exist"):
        replace_json_leaf(body, JsonPointer.parse("/10"), "new")


@pytest.mark.parametrize(
    ("source", "pointer", "message"),
    [
        (b'{"a":"leaf"}', "/missing", "member does not exist"),
        (b'{"a":"leaf"}', "/a/child", "traverses through a leaf"),
        (b'{"a":{}}', "/a", "resolves to a container"),
        (b"[]", "", "resolves to a container"),
    ],
)
def test_pointer_must_resolve_to_existing_leaf(source, pointer, message):
    with pytest.raises(ValueError, match=message):
        replace_json_leaf(
            JsonBody.from_bytes(source), JsonPointer.parse(pointer), "new"
        )


def test_errors_never_echo_pointer_or_replacement_values():
    body = JsonBody.from_bytes(b'{"safe":"body-private-value"}')
    pointer = JsonPointer.parse("/pointer-private-value")
    with pytest.raises(ValueError) as caught:
        replace_json_leaf(body, pointer, "replacement-private-value")
    message = str(caught.value)
    assert "body-private-value" not in message
    assert "pointer-private-value" not in message
    assert "replacement-private-value" not in message


def test_json_leaf_at_reuses_concrete_pointer_rules_without_mutating_body():
    body = JsonBody.from_bytes(b'{"items":[{"name":"selected"}]}')

    selected = json_leaf_at(body, JsonPointer.parse("/items/0/name"))

    assert selected == "selected"
    assert body.to_bytes() == b'{"items":[{"name":"selected"}]}'


@pytest.mark.parametrize("pointer", ["/items/*/name", "/items/1/name", "/items"])
def test_json_leaf_at_rejects_nonconcrete_or_nonleaf_targets(pointer):
    body = JsonBody.from_bytes(b'{"items":[{"name":"selected"}]}')

    with pytest.raises(ValueError):
        json_leaf_at(body, JsonPointer.parse(pointer))
