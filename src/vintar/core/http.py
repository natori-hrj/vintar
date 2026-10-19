import time
import httpx

def send_request(
    method: str,
    url: str,
    body: str | None = None,
) -> tuple[int, float, int]:
    """Send a GET request and return status, duration, and body size."""
    with httpx.Client(
        timeout=10.0,
        follow_redirects=False,
    ) as client:
        start = time.perf_counter()
        response = client.request(
            method=method,
            url=url,
            content=body,
        )
        elapsed = time.perf_counter() - start

    return response.status_code, elapsed, len(response.content)
