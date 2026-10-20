import time

import httpx

from vintar.core.models import HttpResult


def send_request(
    method: str,
    url: str,
    body: str | None = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    client: httpx.Client | None = None,
    params: list[tuple[str, str]] | None = None,
) -> HttpResult:
    """Send a GET request and return status, duration, and body size."""

    request_headers = dict(headers or {})

    if cookies:
        cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())
        request_headers["Cookie"] = cookie_header

    def execute(active_client: httpx.Client) -> HttpResult:
        start = time.perf_counter()
        response = active_client.request(
            method=method,
            url=url,
            content=body,
            headers=request_headers,
            params=params,
        )
        elapsed = time.perf_counter() - start
        return HttpResult(
            status_code=response.status_code,
            elapsed=elapsed,
            body=response.content,
            headers=dict(response.headers),
        )

    if client is not None:
        return execute(client)
    with httpx.Client(
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    ) as new_client:
        return execute(new_client)
