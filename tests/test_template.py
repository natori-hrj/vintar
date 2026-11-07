import httpx
import pytest

from vintar.core.injector import inject
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.template import send_template, validate_template


def test_send_template_preserves_duplicate_params():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params.multi_items() == [
            ("id", "1"),
            ("id", "2"),
        ]
        return httpx.Response(200, text="ok")

    template = RequestTemplate(
        method="GET",
        url="http://localhost/filter",
        params=(("id", "1"), ("id", "2")),
    )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = send_template(template, client=client)

    assert result.status_code == 200


def test_injected_payload_is_encoded_once():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/filter",
        params=(("category", "Pets"),),
    )

    modified = inject(
        template=template,
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payload="' OR 1=1--",
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["category"] == "Pets' OR 1=1--"

        raw_query = request.url.query
        assert b"%2527" not in raw_query
        assert b"%27" in raw_query

        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = send_template(modified, client=client)

    assert result.status_code == 200
    assert template.params == (("category", "Pets"),)


def test_send_template_preserves_headers_and_cookies():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Test"] == "vintar"
        assert request.headers["Cookie"] == "session=abc123"
        assert request.content == b"hello"

        return httpx.Response(200, text="ok")

    template = RequestTemplate(
        method="POST",
        url="http://localhost/",
        headers=(("X-Test", "vintar"),),
        cookies=(("session", "abc123"),),
        body=b"hello",
    )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = send_template(template, client=client)

        assert result.status_code == 200


def test_reject_url_with_query():
    template = RequestTemplate(
        method="GET",
        url="http://localhost/?id=1",
        params=(("id", "2"),),
    )

    with pytest.raises(ValueError, match="URL query parameters"):
        send_template(template)


@pytest.mark.parametrize(
    "headers,cookies",
    [
        ((("X-Test", "one"), ("X-test", "two")), ()),
        ((), (("session", "one"), ("session", "two"))),
        ((("Cookie", "session=one"),), (("sessoion", "two"),)),
    ],
)
def test_reject_ambiguous_headers_and_cookies(headers, cookies):
    template = RequestTemplate(
        method="GET",
        url="http://localhost/",
        headers=headers,
        cookies=cookies,
    )

    with pytest.raises(ValueError):
        send_template(template)


@pytest.mark.parametrize(
    "template",
    [
        RequestTemplate(method="BAD METHOD", url="http://localhost/"),
        RequestTemplate(
            method="GET",
            url="http://localhost/",
            headers=(("Bad Header", "value"),),
        ),
        RequestTemplate(
            method="GET",
            url="http://localhost/",
            headers=(("X-Test", "unsafe\r\nvalue"),),
        ),
        RequestTemplate(
            method="GET",
            url="http://localhost/",
            headers=(("Host", "example.com"),),
        ),
        RequestTemplate(
            method="GET",
            url="http://localhost/",
            cookies=(("session", "unsafe\nvalue"),),
        ),
    ],
)
def test_reject_invalid_http_tokens_before_send(template):
    with pytest.raises(ValueError):
        validate_template(template)
