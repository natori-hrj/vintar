import httpx

from vintar.core.http import send_request
from vintar.core.models import HttpResult
from vintar.core.request import RequestTemplate


def validate_template(template: RequestTemplate) -> None:
    """Validate request fields before reserving a request budget."""

    url = httpx.URL(template.url)
    if url.query:
        raise ValueError(
            "URL query parameters must be provided through template.params."
        )

    header_names: set[str] = set()

    for name, _ in template.headers:
        normalized = name.lower()

        if normalized in header_names:
            raise ValueError(f"Duplicate HTTP header: {name}")

        header_names.add(normalized)

    if template.cookies and "cookie" in header_names:
        raise ValueError("Cannot combine a Cookie header with template.cookies.")

    cookie_names: set[str] = set()

    for name, _ in template.cookies:
        if name in cookie_names:
            raise ValueError(f"Duplicate cookie: {name}")

        cookie_names.add(name)


def send_template(
    template: RequestTemplate,
    client: httpx.Client | None = None,
    timeout: float = 10.0,
    max_response_size: int = 1_048_576,
) -> HttpResult:
    """Send a request template through the shared HTTP client."""

    validate_template(template)

    headers = dict(template.headers)
    cookies = dict(template.cookies)

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
