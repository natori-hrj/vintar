import httpx

from vintar.core.http import send_request


def test_get_request():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert str(request.url) == "http://localhost/"
        return httpx.Response(200, text="hello")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        status, elapsed, size = send_request(
            "GET",
            "http://localhost/",
            client=client,
        )

    assert status == 200
    assert elapsed >= 0
    assert size == 5


def test_post_request_body():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.content == b'{"message":"hello vintar"}'
        return httpx.Response(201, text="created")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        status, elapsed, size = send_request(
            "POST",
            "http://localhost/",
            body='{"message":"hello vintar"}',
            client=client,
        )

    assert status == 201
    assert elapsed >= 0
    assert size == 7


def test_custom_headers_and_cookies():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Test"] == "vintar"
        assert "session=test123" in request.headers["Cookie"]

        return httpx.Response(200, text="success")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        status, elapsed, size = send_request(
            method="GET",
            url="http://localhost/",
            headers={"X-Test": "vintar"},
            cookies={"session": "test123"},
            client=client,
        )

    assert status == 200
    assert elapsed >= 0
    assert size == 7
