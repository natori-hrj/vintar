import time
import httpx

def send_get(url: str) -> tuple[int, float, int]:
    """Send a GET request and return status, duration, and body size."""
    with httpx.Client(
        timeout=10.0,
        follow_redirects=False,
    ) as client:
        start = time.perf_counter()
        response = client.get(url)
        elapsed = time.perf_counter() - start

    return response.status_code, elapsed, len(response.content)
