from dataclasses import FrozenInstanceError

import pytest

from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)


def test_request_template_preserves_duplicate_params():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/filter",
        params=(
            ("category", "Pets"),
            ("id", "1"),
            ("id", "2"),
        ),
    )

    assert template.params == (
        ("category", "Pets"),
        ("id", "1"),
        ("id", "2"),
    )


def test_injection_point():
    point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="id",
        occurrence=1,
    )

    assert point.location == InjectionLocation.QUERY
    assert point.name == "id"
    assert point.occurrence == 1
    assert point.mode == InjectionMode.REPLACE


def test_injection_mode():
    assert InjectionMode.REPLACE.value == "replace"
    assert InjectionMode.APPEND.value == "append"


def test_request_template_is_frozen():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/",
    )

    with pytest.raises(FrozenInstanceError):
        template.method = "POST"


def test_injection_point_with_append_mode():
    point = InjectionPoint(
        location=InjectionLocation.QUERY,
        name="category",
        mode=InjectionMode.APPEND,
    )

    assert point.mode == InjectionMode.APPEND


@pytest.mark.parametrize(
    ("name", "occurrence"),
    [
        ("", 0),
        ("id", -1),
    ],
)
def test_invalid_injection_point(name: str, occurrence: int):
    with pytest.raises(ValueError):
        InjectionPoint(
            location=InjectionLocation.QUERY,
            name=name,
            occurrence=occurrence,
        )
