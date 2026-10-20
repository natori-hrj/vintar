import httpx
import pytest

from vintar.core.http import send_request


def test_get_request():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "http://localhost/"
        return httpx.Response(200, text="hello")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            "GET",
            "http://localhost/",
            client=client,
        )

    assert result.status_code == 200
    assert result.elapsed >= 0
    assert result.size == 5
    assert result.body == b"hello"


def test_post_request_body():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.content == b'{"message":"hello vintar"}'
        return httpx.Response(201, text="created")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            "POST",
            "http://localhost/",
            body='{"message":"hello vintar"}',
            client=client,
        )

    assert result.status_code == 201
    assert result.elapsed >= 0
    assert result.size == 7


def test_custom_headers_and_cookies():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Test"] == "vintar"
        assert "session=test123" in request.headers["Cookie"]

        return httpx.Response(200, text="success")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            headers={"X-Test": "vintar"},
            cookies={"session": "test123"},
            client=client,
        )

    assert result.status_code == 200
    assert result.elapsed >= 0
    assert result.size == 7


def test_query_parameters():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.params.get("category") == "Pets"
        assert request.url.params.get("page") == "1"

        return httpx.Response(200, text="success")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            params=[("category", "Pets"), ("page", "1")],
            client=client,
        )

        assert result.status_code == 200
        assert result.elapsed >= 0
        assert result.size == 7


def test_response_headers():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"X-Test-Response": "vintar"},
            text="hello",
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            client=client,
        )

    assert result.status_code == 200
    assert result.headers["x-test-response"] == "vintar"
    assert result.body == b"hello"
    assert result.size == 5


@pytest.mark.parametrize("timeout", [-1.0, 0.0, 61.0])
def test_invalid_timeout(timeout: float):
    with pytest.raises(ValueError, match="Timeout must be"):
        send_request(
            method="GET",
            url="http://localhost/",
            timeout=timeout,
        )


def test_timeout_is_applied():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.extensions["timeout"] == {
            "connect": 15.0,
            "read": 15.0,
            "write": 15.0,
            "pool": 15.0,
        }
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            timeout=15.0,
            client=client,
        )

    assert result.status_code == 200


@pytest.mark.parametrize(
    ("body", "limit", "expected_body", "truncated"),
    [
        (b"hello", 10, b"hello", False),
        (b"hello", 5, b"hello", False),
        (b"hello world", 5, b"hello", True),
    ],
)
def test_response_size_limit(
    body: bytes,
    limit: int,
    expected_body: bytes,
    truncated: bool,
):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            client=client,
            max_response_size=limit,
        )

    assert result.body == expected_body
    assert result.size == len(expected_body)
    assert result.truncated is truncated
