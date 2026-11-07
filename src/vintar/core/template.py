import re

import httpx

from vintar.core.http import send_request
from vintar.core.models import HttpResult
from vintar.core.request import RequestTemplate

_HTTP_TOKEN_PATTERN = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")


def _validate_string_pairs(
    name: str,
    values: object,
) -> tuple[tuple[str, str], ...]:
    if not isinstance(values, tuple):
        raise TypeError(f"template.{name} must be a tuple.")

    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            raise TypeError(f"template.{name} must contain two-item tuples.")
        if not all(type(value) is str for value in item):
            raise TypeError(f"template.{name} names and values must be strings.")

    return values


def _validate_header_value(name: str, value: str) -> None:
    if "\r" in value or "\n" in value:
        raise ValueError(f"Invalid {name} value.")
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} values must contain only ASCII characters.") from exc


def validate_template(template: RequestTemplate) -> None:
    """Validate request fields before reserving a request budget."""

    if not isinstance(template, RequestTemplate):
        raise TypeError("template must be a RequestTemplate.")

    if type(template.method) is not str:
        raise TypeError("template.method must be a string.")
    if _HTTP_TOKEN_PATTERN.fullmatch(template.method) is None:
        raise ValueError("Invalid HTTP method.")

    if type(template.url) is not str:
        raise TypeError("template.url must be a string.")

    headers = _validate_string_pairs("headers", template.headers)
    cookies = _validate_string_pairs("cookies", template.cookies)
    _validate_string_pairs("params", template.params)

    if template.body is not None and type(template.body) is not bytes:
        raise TypeError("template.body must be bytes or None.")

    url = httpx.URL(template.url)
    if url.query:
        raise ValueError(
            "URL query parameters must be provided through template.params."
        )

    header_names: set[str] = set()

    for name, value in headers:
        if _HTTP_TOKEN_PATTERN.fullmatch(name) is None:
            raise ValueError(f"Invalid HTTP header name: {name}")
        _validate_header_value("HTTP header", value)

        normalized = name.lower()

        if normalized == "host":
            raise ValueError("The Host header cannot be overridden.")

        if normalized in header_names:
            raise ValueError(f"Duplicate HTTP header: {name}")

        header_names.add(normalized)

    if cookies and "cookie" in header_names:
        raise ValueError("Cannot combine a Cookie header with template.cookies.")

    cookie_names: set[str] = set()

    for name, value in cookies:
        if _HTTP_TOKEN_PATTERN.fullmatch(name) is None:
            raise ValueError(f"Invalid cookie name: {name}")
        _validate_header_value("Cookie", value)

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
