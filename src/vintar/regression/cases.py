"""Strict regression case specifications; no network operations."""

import math
import os
import re
import stat
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path

import httpx

from vintar.checks.sqli.models import Verdict
from vintar.core.injector import inject
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy, validate_scope
from vintar.core.template import validate_template

CASE_VERSION = 1
MAX_CASE_BYTES = 65_536
CASE_MAX_RESPONSE_SIZE = 1_048_576
_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


@dataclass(frozen=True, slots=True, repr=False)
class RegressionCase:
    """Validated, immutable inputs for a repeatable security check.

    ``expected_verdict`` is a declared comparison target, not an observed
    result or a claim that the target is safe. In particular, NOT_DETECTED
    does not prove absence of a vulnerability, and INCONCLUSIVE is not a
    successful security outcome. Schema v1 permits VULNERABLE as a desired
    regression outcome, although the current Boolean analyzer does not emit it.
    """

    schema_version: int
    case_id: str
    check_type: str
    template: RequestTemplate
    point: InjectionPoint
    true_payload: str
    false_payload: str
    expected_verdict: Verdict
    scope: ScopePolicy
    max_requests: int
    max_response_size: int
    requests_per_second: float
    timeout_seconds: float

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != CASE_VERSION:
            raise ValueError("Unsupported case version.")
        if type(self.check_type) is not str or self.check_type != "sqli.boolean":
            raise ValueError("Unsupported check type.")

        case_id = _string(self.case_id, max_length=64)
        if _ID_PATTERN.fullmatch(case_id) is None:
            raise ValueError("Invalid case identifier.")

        if not isinstance(self.template, RequestTemplate):
            raise TypeError("template must be a RequestTemplate.")
        if not isinstance(self.point, InjectionPoint):
            raise TypeError("point must be an InjectionPoint.")
        if not isinstance(self.expected_verdict, Verdict):
            raise TypeError("expected_verdict must be a Verdict.")
        if not isinstance(self.scope, ScopePolicy):
            raise TypeError("scope must be a ScopePolicy.")

        true_payload = _string(self.true_payload, max_length=512)
        false_payload = _string(self.false_payload, max_length=512)
        if true_payload == false_payload:
            raise ValueError("Probe payloads must differ.")

        if type(self.max_requests) is not int or self.max_requests != 6:
            raise ValueError("Boolean SQLi cases require exactly six requests.")
        if (
            type(self.max_response_size) is not int
            or self.max_response_size != CASE_MAX_RESPONSE_SIZE
        ):
            raise ValueError("Invalid response size limit for schema version 1.")

        rps = _positive_number(self.requests_per_second, 0.1, 10.0)
        timeout = _positive_number(self.timeout_seconds, 0.1, 60.0)
        object.__setattr__(self, "requests_per_second", rps)
        object.__setattr__(self, "timeout_seconds", timeout)

        _validate_plan(
            self.template,
            self.point,
            true_payload,
            false_payload,
            self.scope,
        )


def _table(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError("Invalid regression case schema.")

    table: dict[str, object] = {}
    for key, item in value.items():
        if type(key) is not str:
            raise ValueError("Invalid regression case schema.")
        table[key] = item

    if table.keys() != keys:
        raise ValueError("Invalid regression case schema.")
    return table


def _string(
    value: object,
    *,
    max_length: int = 2048,
    allow_empty: bool = False,
) -> str:
    minimum_length = 0 if allow_empty else 1
    if type(value) is not str or not minimum_length <= len(value) <= max_length:
        raise ValueError("Invalid regression case string.")

    if any(unicodedata.category(ch).startswith("C") for ch in value):
        raise ValueError("Control or non-text characters are not permitted.")

    return value


def _origin(value: str) -> AllowedOrigin:
    """Parse an explicit HTTP(S) origin without path or credentials."""
    if value != value.strip() or "?" in value or "#" in value:
        raise ValueError("Invalid allowed origin.")

    parsed = httpx.URL(value)

    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.host
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid allowed origin.")

    port = (
        parsed.port
        if parsed.port is not None
        else (443 if parsed.scheme == "https" else 80)
    )

    return AllowedOrigin(
        scheme=parsed.scheme,
        host=parsed.host,
        port=port,
    )


def _positive_number(
    value: object,
    minimum: float,
    maximum: float,
) -> float:
    if type(value) is not int and type(value) is not float:
        raise ValueError("Invalid numeric limit.")

    if not minimum <= value <= maximum:
        raise ValueError("Numeric limit is outside permitted bounds.")

    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Numeric limit is outside permitted bounds.")

    return number


def _validate_plan(
    template: RequestTemplate,
    point: InjectionPoint,
    true_payload: str,
    false_payload: str,
    scope: ScopePolicy,
) -> None:
    """Validate the baseline and both distinct probe templates without I/O."""
    validate_template(template)
    validate_scope(template.url, scope)

    true_template = inject(template, point, true_payload)
    false_template = inject(template, point, false_payload)

    if true_template == template or false_template == template:
        raise ValueError("A probe matches the baseline.")

    for planned in (true_template, false_template):
        validate_template(planned)
        validate_scope(planned.url, scope)


class ReviewDraftError(ValueError):
    """A review draft requires human decisions before verification."""


def parse_regression_case(source: str) -> RegressionCase:
    """Validate a version-1 TOML case without executing HTTP requests."""
    try:
        if type(source) is not str:
            raise ValueError("Invalid regression case source.")

        if len(source) > MAX_CASE_BYTES:
            raise ValueError("Invalid regression case size.")

        if len(source.encode("utf-8")) > MAX_CASE_BYTES:
            raise ValueError("Invalid regression case size.")

        data: object = tomllib.loads(source)
        if isinstance(data, dict) and data.get("kind") == "vintar_review_draft":
            raise ReviewDraftError(
                "Review draft cannot be verified. Resolve route mapping, baseline query values, "
                "target and authorization, credential requirements, check configuration and probe inputs, "
                "expected verdict, and trusted limits. Use a reviewed Schema v1 case."
            )

        root = _table(
            data,
            {
                "version",
                "id",
                "type",
                "expected_verdict",
                "target",
                "injection",
                "probes",
                "limits",
            },
        )

        if type(root["version"]) is not int:
            raise ValueError("Invalid case version.")

        if root["version"] != CASE_VERSION:
            raise ValueError("Unsupported case version.")

        if type(root["type"]) is not str:
            raise ValueError("Invalid check type.")

        if root["type"] != "sqli.boolean":
            raise ValueError("Unsupported check type.")

        case_id = _string(
            root["id"],
            max_length=64,
        )

        if _ID_PATTERN.fullmatch(case_id) is None:
            raise ValueError("Invalid case identifier.")

        expected = root["expected_verdict"]
        if type(expected) is not str:
            raise ValueError("Invalid expected verdict.")

        try:
            expected_verdict = Verdict(expected)
        except ValueError:
            raise ValueError("Invalid expected verdict.") from None

        target = _table(
            root["target"],
            {"url", "allowed_origin", "params"},
        )

        injection = _table(
            root["injection"],
            {"location", "name", "occurrence", "mode"},
        )

        probes = _table(
            root["probes"],
            {"true_payload", "false_payload"},
        )

        limits = _table(
            root["limits"],
            {
                "max_requests",
                "requests_per_second",
                "timeout_seconds",
            },
        )

        # Boolean SQLi verification currently requires six probes.
        max_requests = limits["max_requests"]
        if type(max_requests) is not int:
            raise ValueError("Invalid request budget.")

        if max_requests != 6:
            raise ValueError("This check requires exactly six requests.")

        rps = _positive_number(
            limits["requests_per_second"],
            0.1,
            10.0,
        )

        timeout = _positive_number(
            limits["timeout_seconds"],
            0.1,
            60.0,
        )

        url = _string(target["url"])

        if url != url.strip() or "?" in url or "#" in url:
            raise ValueError("Invalid target URL.")

        parsed_url = httpx.URL(url)

        if parsed_url.fragment:
            raise ValueError("URL fragments are unsupported.")

        allowed_origin = _origin(_string(target["allowed_origin"]))

        scope = ScopePolicy(allowed_origins=frozenset({allowed_origin}))

        raw_params = target["params"]

        if type(raw_params) is not list or len(raw_params) > 32:
            raise ValueError("Invalid query parameter list.")

        params: list[tuple[str, str]] = []

        for item in raw_params:
            pair = _table(
                item,
                {"name", "value"},
            )

            name = _string(
                pair["name"],
                max_length=128,
            )

            value = _string(pair["value"], allow_empty=True)

            params.append((name, value))

        template = RequestTemplate(
            method="GET",
            url=url,
            params=tuple(params),
        )

        location = injection["location"]
        if type(location) is not str or location != "query":
            raise ValueError("Unsupported injection location.")

        mode = injection["mode"]
        if type(mode) is not str or mode not in {"append", "replace"}:
            raise ValueError("Unsupported injection mode.")

        occurrence = injection["occurrence"]
        if type(occurrence) is not int or occurrence < 0:
            raise ValueError("Invalid occurrence.")

        point = InjectionPoint(
            location=InjectionLocation.QUERY,
            name=_string(
                injection["name"],
                max_length=128,
            ),
            occurrence=occurrence,
            mode=InjectionMode(mode),
        )

        true_payload = _string(
            probes["true_payload"],
            max_length=512,
        )

        false_payload = _string(
            probes["false_payload"],
            max_length=512,
        )

        if true_payload == false_payload:
            raise ValueError("Probe payloads must differ.")

        return RegressionCase(
            schema_version=CASE_VERSION,
            case_id=case_id,
            check_type="sqli.boolean",
            template=template,
            point=point,
            true_payload=true_payload,
            false_payload=false_payload,
            expected_verdict=expected_verdict,
            scope=scope,
            max_requests=max_requests,
            max_response_size=CASE_MAX_RESPONSE_SIZE,
            requests_per_second=rps,
            timeout_seconds=timeout,
        )

    except ReviewDraftError:
        raise
    except (TypeError, ValueError, OverflowError, UnicodeError, httpx.HTTPError):
        # Do not expose payloads, URLs, or parser details.
        raise ValueError(
            "Invalid or unsupported regression case. Use a valid schema v1 TOML case."
        ) from None


def load_regression_case(path: str | Path) -> RegressionCase:
    """Read one stable, bounded regular file without following symlinks."""
    try:
        raw = _read_case_file(path)
    except _CaseTooLargeError:
        raise ValueError("Regression case exceeds size limit.") from None
    except (OSError, TypeError, ValueError):
        raise ValueError("Unable to read regression case.") from None

    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Regression case must be UTF-8.") from None

    return parse_regression_case(source)


class _CaseTooLargeError(Exception):
    """Internal signal for a safely detected oversized case file."""


def _read_case_file(path: str | Path) -> bytes:
    """Read a regular file through one verified descriptor."""
    file_path = os.fspath(path)
    path_stat = os.lstat(file_path)

    if not stat.S_ISREG(path_stat.st_mode):
        raise ValueError("Not a regular file.")
    if path_stat.st_size > MAX_CASE_BYTES:
        raise _CaseTooLargeError

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)

    descriptor = os.open(file_path, flags)
    try:
        opened_before = os.fstat(descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            raise ValueError("Not a regular file.")
        if opened_before.st_size > MAX_CASE_BYTES:
            raise _CaseTooLargeError

        chunks = bytearray()
        while len(chunks) <= MAX_CASE_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, MAX_CASE_BYTES + 1 - len(chunks)),
            )
            if not chunk:
                break
            chunks.extend(chunk)

        if len(chunks) > MAX_CASE_BYTES:
            raise _CaseTooLargeError

        opened_after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(opened_before, field) != getattr(opened_after, field)
            for field in stable_fields
        ):
            raise ValueError("File changed while it was read.")

        return bytes(chunks)
    finally:
        os.close(descriptor)
