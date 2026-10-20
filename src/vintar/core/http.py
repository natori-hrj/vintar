import time

import httpx


def send_request(
    method: str,
    url: str,
    body: str | None = None,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    client: httpx.Client | None = None,
) -> tuple[int, float, int]:
    """Send a GET request and return status, duration, and body size."""

    request_headers = dict(headers or {})

    if cookies:
        cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())
        request_headers["Cookie"] = cookie_header

    def execute(active_client: httpx.Client) -> tuple[int, float, int]:
        start = time.perf_counter()
        response = active_client.request(
            method=method,
            url=url,
            content=body,
            headers=request_headers,
        )
        elapsed = time.perf_counter() - start
        return response.status_code, elapsed, len(response.content)

    if client is not None:
        return execute(client)
    with httpx.Client(
        timeout=10.0,
        follow_redirects=False,
        trust_env=False,
    ) as new_client:
        return execute(new_client)
