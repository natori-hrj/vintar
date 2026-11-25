import pytest

from vintar.core.injector import inject
from vintar.core.json_body import JsonBody, JsonPointer
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)


def test_replace_second_duplicate_parameter():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/filter",
        params=(("id", "1"), ("id", "2")),
    )
    result = inject(
        template=template,
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="id",
            occurrence=1,
        ),
        payload="test",
    )

    assert result.params == (("id", "1"), ("id", "test"))
    assert template.params == (("id", "1"), ("id", "2"))


def test_append_payload():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/filter",
        params=(("category", "Pets"),),
    )

    result = inject(
        template=template,
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payload="'",
    )

    assert result.params == (("category", "Pets'"),)
    assert template.params == (("category", "Pets"),)


def test_missing_injection_point():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/",
        params=(("id", "1"),),
    )

    with pytest.raises(ValueError, match="Injection point not found"):
        inject(
            template=template,
            point=InjectionPoint(
                location=InjectionLocation.QUERY,
                name="missing",
            ),
            payload="test",
        )


def test_second_occurrence_not_found():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/",
        params=(("id", "1"),),
    )

    with pytest.raises(ValueError, match="Injection point not found"):
        inject(
            template=template,
            point=InjectionPoint(
                location=InjectionLocation.QUERY,
                name="id",
                occurrence=1,
            ),
            payload="test",
        )


def test_injection_preserves_other_request_fields():
    template = RequestTemplate(
        method="POST",
        url="http://localhost/filter",
        headers=(("X-Test", "vintar"),),
        cookies=(("session", "abc123"),),
        params=(("category", "Pets"), ("page", "1")),
        body=b"hello",
    )

    result = inject(
        template=template,
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payload="'",
    )

    assert result.params == (
        ("category", "Pets'"),
        ("page", "1"),
    )

    assert result.method == template.method
    assert result.url == template.url
    assert result.headers == template.headers
    assert result.cookies == template.cookies
    assert result.body == template.body


def test_json_body_injection_replaces_one_leaf_and_preserves_template():
    body = JsonBody.from_bytes(b'{"count":1,"items":[{"name":"old"}]}')
    template = RequestTemplate(
        method="POST",
        url="http://localhost/items",
        headers=(("X-Test", "vintar"),),
        cookies=(("session", "abc123"),),
        params=(("dry-run", "true"),),
        json_body=body,
    )
    result = inject(
        template,
        InjectionPoint(
            location=InjectionLocation.JSON_BODY,
            pointer=JsonPointer.parse("/items/0/name"),
        ),
        "new",
    )
    assert result.json_body is not None
    assert result.json_body.to_bytes() == b'{"count":1,"items":[{"name":"new"}]}'
    assert body.to_bytes() == b'{"count":1,"items":[{"name":"old"}]}'
    assert result.method == template.method
    assert result.url == template.url
    assert result.headers == template.headers
    assert result.cookies == template.cookies
    assert result.params == template.params
    assert result.body is template.body


def test_json_body_injection_requires_body_without_echoing_payload():
    point = InjectionPoint(
        location=InjectionLocation.JSON_BODY,
        pointer=JsonPointer.parse("/value"),
    )
    with pytest.raises(ValueError, match=r"Supply template\.json_body") as caught:
        inject(RequestTemplate(method="POST", url="http://localhost/"), point, "SECRET")
    assert "SECRET" not in str(caught.value)
