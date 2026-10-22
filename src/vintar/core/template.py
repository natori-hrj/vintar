import httpx

from vintar.core.http import send_request
from vintar.core.models import HttpResult
from vintar.core.request import RequestTemplate


def send_template(
    template: RequestTemplate,
    client: httpx.Client | None = None,
    timeout: float = 10.0,
    max_response_size: int = 1_048_576,
) -> HttpResult:
    """Send a request template through the shared HTTP client."""

    url = httpx.URL(template.url)

    if url.query:
        raise ValueError(
            "URL query parameters must be provided through template.params."
        )

    headers: dict[str, str] = {}

    for name, value in template.headers:
        if name.lower() in (key.lower() for key in headers):
            raise ValueError(f"Duplicate HTTP header: {name}")

        headers[name] = value

    if template.cookies and any(name.lower() == "cookie" for name in headers):
        raise ValueError("cannot combine a Cookie header with template.cookies.")

    cookies: dict[str, str] = {}

    for name, value in template.cookies:
        if name in cookies:
            raise ValueError(f"Duplicate cookie: {name}")

        cookies[name] = value

    return send_request(
        method=template.method,
        url=template.url,
        body=template.body,
        headers=headers or None,
        cookies=cookies or None,
        params=list(template.params) if template.params else None,
        client=client,
        timeout=timeout,
        max_response_size=max_response_size,
    )
