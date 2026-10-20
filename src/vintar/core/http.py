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
    timeout: float = 10.0,
    max_response_size: int = 1_048_576,
) -> HttpResult:
    """Send a GET request and return status, duration, and body size."""

    if not 0 < timeout <= 60:
        raise ValueError("Timeout must be between 0 and 60 seconds.")

    if max_response_size <= 0:
        raise ValueError("Maximum response size must be positive.")

    request_headers = dict(headers or {})

    if cookies:
        cookie_header = "; ".join(f"{name}={value}" for name, value in cookies.items())
        request_headers["Cookie"] = cookie_header

    def execute(active_client: httpx.Client) -> HttpResult:
        start = time.perf_counter()

        with active_client.stream(
            method=method,
            url=url,
            content=body,
            headers=request_headers,
            params=params,
            timeout=timeout,
        ) as response:
            chunks = bytearray()
            truncated = False

            for chunk in response.iter_bytes():
                remaining = max_response_size - len(chunks)

                if len(chunk) > remaining:
                    chunks.extend(chunk[:remaining])
                    truncated = True
                    break

                chunks.extend(chunk)

            elapsed = time.perf_counter() - start
            return HttpResult(
                status_code=response.status_code,
                elapsed=elapsed,
                body=bytes(chunks),
                headers=dict(response.headers),
                truncated=truncated,
            )

    if client is not None:
        return execute(client)
    with httpx.Client(
        timeout=timeout,
        follow_redirects=False,
        trust_env=False,
    ) as new_client:
        return execute(new_client)
