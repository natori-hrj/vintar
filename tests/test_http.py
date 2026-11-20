import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import unquote

import httpx
import pytest

from vintar.core.http import send_request


class _PercentOnlyServer(HTTPServer):
    """Loopback fixture that decodes percent escapes but not plus-as-space."""

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _PercentOnlyHandler)
        self.observed_value: str | None = None
        self.handler_failed = False

    def handle_error(self, request: object, client_address: tuple[str, int]) -> None:
        self.handler_failed = True


class _PercentOnlyHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server = self.server
        if not isinstance(server, _PercentOnlyServer):
            raise TypeError("Unexpected percent-only fixture server.")
        raw_query = self.path.partition("?")[2]
        name, separator, raw_value = raw_query.partition("=")
        if name != "probe" or separator != "=":
            server.handler_failed = True
            self.send_error(400)
            return
        server.observed_value = unquote(raw_value)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        """Keep probe values out of test output."""


@contextmanager
def _running_percent_only_server():
    server = _PercentOnlyServer()
    started = threading.Event()

    def serve() -> None:
        started.set()
        server.serve_forever(poll_interval=0.05)

    thread = threading.Thread(target=serve, name="percent-only-query-fixture")
    thread.start()
    assert started.wait(timeout=5), (
        "The percent-only query fixture did not start. Check loopback socket and thread setup."
    )
    try:
        port = server.server_address[1]
        yield server, f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), (
            "The percent-only query fixture did not stop. Check outstanding loopback requests."
        )


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


def test_query_parameters_preserve_repeated_key_order():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.params.multi_items() == [
            ("category", "Pets"),
            ("category", "Toys"),
            ("page", "1"),
        ]

        return httpx.Response(200, text="success")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            params=[("category", "Pets"), ("category", "Toys"), ("page", "1")],
            client=client,
        )

        assert result.status_code == 200
        assert result.elapsed >= 0
        assert result.size == 7


def test_query_serialization_uses_rfc3986_percent_encoding():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.query == (b"probe=%20A%2BB%2FC%3FD%3DE%26F%23G%25H")
        assert request.url.params["probe"] == " A+B/C?D=E&F#G%H"
        return httpx.Response(200, text="ok")

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            params=[("probe", " A+B/C?D=E&F#G%H")],
            client=client,
        )

    assert result.status_code == 200


def test_loopback_query_reaches_percent_only_decoder_with_spaces_intact():
    value = "Pets AND 1=1-- +literal"
    with _running_percent_only_server() as (server, origin):
        result = send_request(
            method="GET",
            url=origin,
            params=[("probe", value)],
        )

    assert result.status_code == 200
    assert server.observed_value == value
    assert server.handler_failed is False


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


def test_binary_request_body():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.content == b"\x00\x01\xff"
        return httpx.Response(200, text="ok")

    transport = httpx.MockTransport(handler)

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="POST",
            url="http://localhost/",
            body=b"\x00\x01\xff",
            client=client,
        )

    assert result.status_code == 200


def test_rate_limited_response_body_is_not_read():
    class UnreadableStream(httpx.SyncByteStream):
        def __iter__(self):
            raise AssertionError("HTTP 429 body must not be read.")

    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            429,
            headers={"Retry-After": "120", "X-Secret": "sensitive"},
            stream=UnreadableStream(),
        )
    )

    with httpx.Client(transport=transport) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            client=client,
        )

    assert result.status_code == 429
    assert result.body == b""
    assert result.size == 0
    assert result.truncated is True


@pytest.mark.parametrize("status_code", [301, 302, 303, 307, 308])
def test_redirect_is_not_followed(status_code: int):
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))

        return httpx.Response(
            302,
            headers={"Location": "https://example.com"},
        )

    transport = httpx.MockTransport(handler)

    with httpx.Client(
        transport=transport,
        follow_redirects=True,
    ) as client:
        result = send_request(
            method="GET",
            url="http://localhost/",
            client=client,
        )

    assert result.status_code == 302
    assert result.headers["location"] == "https://example.com"
    assert requested_urls == ["http://localhost/"]
