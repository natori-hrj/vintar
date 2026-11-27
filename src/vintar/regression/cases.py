"""Strict regression case specifications; no network operations."""

import json
import math
import os
import re
import stat
import tomllib
import unicodedata
from dataclasses import dataclass
from pathlib import Path

import httpx

from vintar.checks.sqli.error_analyzer import validate_error_probe_payload
from vintar.checks.sqli.models import Verdict
from vintar.checks.sqli.probe_families import BooleanConfirmationPreset
from vintar.core.injector import inject
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy, validate_scope
from vintar.core.template import validate_template
from vintar.regression.cases_v2 import (
    CaseV2ValidationError,
    PostJsonRegressionCase,
    QueryRegressionCaseV2,
    parse_case_v2_mapping,
)

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
    confirmation: BooleanConfirmationPreset | None = None

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

        if (
            self.confirmation is not None
            and type(self.confirmation) is not BooleanConfirmationPreset
        ):
            raise TypeError("Invalid Boolean confirmation configuration.")
        expected_requests = 18 if self.confirmation is not None else 6
        if type(self.max_requests) is not int or self.max_requests != expected_requests:
            message = (
                "Boolean SQLi cases require exactly eighteen requests when confirmation is configured."
                if self.confirmation is not None
                else "Boolean SQLi cases require exactly six requests."
            )
            raise ValueError(message)
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
            self.confirmation,
            self.scope,
        )


class TimeCaseValidationError(ValueError):
    """A redacted, actionable time-case validation error."""


class ErrorCaseValidationError(ValueError):
    """A redacted, actionable error-case validation error."""


@dataclass(frozen=True, slots=True, repr=False)
class TimeRegressionCase:
    """Validated inputs for one bounded time-based SQLi check."""

    schema_version: int
    case_id: str
    check_type: str
    template: RequestTemplate
    point: InjectionPoint
    delay_payload: str
    control_payload: str
    expected_delay_seconds: float
    expected_verdict: Verdict
    scope: ScopePolicy
    max_requests: int
    max_response_size: int
    requests_per_second: float
    timeout_seconds: float

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != CASE_VERSION:
            raise TimeCaseValidationError(
                "Time SQLi cases require Schema v1. Set version = 1."
            )
        if type(self.check_type) is not str or self.check_type != "sqli.time":
            raise TimeCaseValidationError(
                'Time SQLi cases require type = "sqli.time". Use that exact check type.'
            )

        case_id = _string(self.case_id, max_length=64)
        if _ID_PATTERN.fullmatch(case_id) is None:
            raise TimeCaseValidationError(
                "Invalid time case identifier. Use 1-64 letters, digits, dots, underscores, or hyphens, beginning with a letter or digit."
            )
        if not isinstance(self.template, RequestTemplate):
            raise TypeError("template must be a RequestTemplate.")
        if not isinstance(self.point, InjectionPoint):
            raise TypeError("point must be an InjectionPoint.")
        if not isinstance(self.expected_verdict, Verdict):
            raise TypeError("expected_verdict must be a Verdict.")
        if not isinstance(self.scope, ScopePolicy):
            raise TypeError("scope must be a ScopePolicy.")

        try:
            delay_payload = _string(self.delay_payload, max_length=512)
            control_payload = _string(self.control_payload, max_length=512)
        except ValueError:
            raise TimeCaseValidationError(
                "Time probe payloads must be nonempty strings of at most 512 characters without control characters. Supply reviewed delay_payload and control_payload values."
            ) from None
        if delay_payload == control_payload:
            raise TimeCaseValidationError(
                "Time probe payloads must differ. Supply distinct delay_payload and control_payload values."
            )

        try:
            expected_delay = _positive_number(self.expected_delay_seconds, 0.25, 2.0)
        except ValueError:
            raise TimeCaseValidationError(
                "expected_delay_seconds must be a number from 0.25 through 2.0, excluding booleans. Supply a bounded expected delay."
            ) from None

        if type(self.max_requests) is not int or self.max_requests != 9:
            raise TimeCaseValidationError(
                "Time SQLi cases require exactly 9 requests. Set limits.max_requests = 9."
            )
        if (
            type(self.max_response_size) is not int
            or self.max_response_size != CASE_MAX_RESPONSE_SIZE
        ):
            raise TimeCaseValidationError(
                "Time SQLi Schema v1 cases require the fixed response-size limit. Use the Schema v1 loader default."
            )

        try:
            rps = _positive_number(self.requests_per_second, 0.1, 10.0)
        except ValueError:
            raise TimeCaseValidationError(
                "requests_per_second must be a number from 0.1 through 10.0, excluding booleans. Supply a bounded request rate."
            ) from None
        try:
            timeout = _positive_number(self.timeout_seconds, 0.75, 8.0)
        except ValueError:
            raise TimeCaseValidationError(
                "Time timeout_seconds must be a number no greater than 8.0, excluding booleans. Supply at least expected_delay_seconds + 0.5."
            ) from None
        if timeout < expected_delay + 0.5:
            raise TimeCaseValidationError(
                "Time timeout_seconds is too short for the expected delay. Set it to at least expected_delay_seconds + 0.5 and no more than 8.0."
            )

        object.__setattr__(self, "expected_delay_seconds", expected_delay)
        object.__setattr__(self, "requests_per_second", rps)
        object.__setattr__(self, "timeout_seconds", timeout)

        _validate_time_plan(
            self.template,
            self.point,
            delay_payload,
            control_payload,
            self.scope,
        )


@dataclass(frozen=True, slots=True, repr=False)
class ErrorRegressionCase:
    """Validated inputs for one bounded error-signature SQLi check."""

    schema_version: int
    case_id: str
    check_type: str
    template: RequestTemplate
    point: InjectionPoint
    error_payload: str
    expected_verdict: Verdict
    scope: ScopePolicy
    max_requests: int
    max_response_size: int
    requests_per_second: float
    timeout_seconds: float

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != CASE_VERSION:
            raise ErrorCaseValidationError(
                "Error SQLi cases require Schema v1. Set version = 1."
            )
        if type(self.check_type) is not str or self.check_type != "sqli.error":
            raise ErrorCaseValidationError(
                'Error SQLi cases require type = "sqli.error". Use that exact check type.'
            )
        try:
            case_id = _string(self.case_id, max_length=64)
        except ValueError:
            raise ErrorCaseValidationError(
                "Invalid error case identifier. Use 1-64 letters, digits, dots, underscores, or hyphens, beginning with a letter or digit."
            ) from None
        if _ID_PATTERN.fullmatch(case_id) is None:
            raise ErrorCaseValidationError(
                "Invalid error case identifier. Use 1-64 letters, digits, dots, underscores, or hyphens, beginning with a letter or digit."
            )
        if type(self.template) is not RequestTemplate:
            raise TypeError("template must be a RequestTemplate.")
        if type(self.point) is not InjectionPoint:
            raise TypeError("point must be an InjectionPoint.")
        if not isinstance(self.expected_verdict, Verdict):
            raise TypeError("expected_verdict must be a Verdict.")
        if type(self.scope) is not ScopePolicy:
            raise TypeError("scope must be a ScopePolicy.")
        try:
            payload = validate_error_probe_payload(self.error_payload)
        except (TypeError, ValueError):
            raise ErrorCaseValidationError(
                "Invalid error_payload. Supply an explicit nonempty reviewed string of at most 512 characters, without control characters or registered DBMS diagnostic text."
            ) from None
        if type(self.max_requests) is not int or self.max_requests != 4:
            raise ErrorCaseValidationError(
                "Error SQLi cases require exactly 4 requests. Set limits.max_requests = 4."
            )
        if (
            type(self.max_response_size) is not int
            or self.max_response_size != CASE_MAX_RESPONSE_SIZE
        ):
            raise ErrorCaseValidationError(
                "Error SQLi Schema v1 cases require the fixed response-size limit. Use the Schema v1 loader default."
            )
        try:
            rps = _positive_number(self.requests_per_second, 0.1, 10.0)
            timeout = _positive_number(self.timeout_seconds, 0.1, 60.0)
        except ValueError:
            raise ErrorCaseValidationError(
                "Error SQLi limits require numeric requests_per_second from 0.1 through 10.0 and timeout_seconds from 0.1 through 60.0, excluding booleans."
            ) from None
        object.__setattr__(self, "requests_per_second", rps)
        object.__setattr__(self, "timeout_seconds", timeout)
        _validate_error_plan(self.template, self.point, payload, self.scope)


BooleanRegressionCase = RegressionCase
AnyRegressionCase = (
    RegressionCase
    | TimeRegressionCase
    | ErrorRegressionCase
    | PostJsonRegressionCase
    | QueryRegressionCaseV2
)


def _table(value: object, keys: set[str]) -> dict[str, object]:
    table = _mapping_table(value)

    if table.keys() != keys:
        raise ValueError("Invalid regression case schema.")
    return table


def _mapping_table(value: object) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError("Invalid regression case schema.")
    table: dict[str, object] = {}
    for key, item in value.items():
        if type(key) is not str:
            raise ValueError("Invalid regression case schema.")
        table[key] = item
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
    confirmation: BooleanConfirmationPreset | None,
    scope: ScopePolicy,
) -> None:
    """Validate the baseline and both distinct probe templates without I/O."""
    validate_template(template)
    validate_scope(template.url, scope)

    payloads = [true_payload, false_payload]
    if confirmation is not None:
        payloads.extend(
            (
                confirmation.true_payload,
                confirmation.false_payload,
                confirmation.baseline_preserving_control,
            )
        )
    if len(set(payloads)) != len(payloads):
        raise ValueError("Initial and confirmation payloads must all differ.")

    planned_templates = tuple(inject(template, point, payload) for payload in payloads)
    if len({template, *planned_templates}) != len(planned_templates) + 1:
        raise ValueError("A probe matches another planned request or the baseline.")

    for planned in planned_templates:
        validate_template(planned)
        validate_scope(planned.url, scope)


def _validate_time_plan(
    template: RequestTemplate,
    point: InjectionPoint,
    delay_payload: str,
    control_payload: str,
    scope: ScopePolicy,
) -> None:
    """Preflight the three distinct timing templates without network I/O."""
    try:
        validate_template(template)
        validate_scope(template.url, scope)
        control = inject(template, point, control_payload)
        delay = inject(template, point, delay_payload)
        if len({template, control, delay}) != 3:
            raise ValueError
        for planned in (control, delay):
            validate_template(planned)
            validate_scope(planned.url, scope)
    except (TypeError, ValueError, httpx.HTTPError):
        raise TimeCaseValidationError(
            "Time baseline, control, and delay requests must be distinct and inside the allowed origin. Check the query injection target, occurrence, mode, and reviewed payloads."
        ) from None


def _validate_error_plan(
    template: RequestTemplate,
    point: InjectionPoint,
    error_payload: str,
    scope: ScopePolicy,
) -> None:
    """Preflight distinct baseline and error-probe templates without I/O."""
    try:
        validate_template(template)
        validate_scope(template.url, scope)
        probe = inject(template, point, error_payload)
        if probe == template:
            raise ValueError
        validate_template(probe)
        validate_scope(probe.url, scope)
    except (TypeError, ValueError, httpx.HTTPError):
        raise ErrorCaseValidationError(
            "Error baseline and injected requests must differ and stay inside the allowed origin. Check the query injection target, occurrence, mode, and explicit error_payload."
        ) from None


class ReviewDraftError(ValueError):
    """A review draft requires human decisions before verification."""


class AuthorizationExecutionUnavailableError(ValueError):
    """Authorization cases remain non-executable until their dedicated CLI ships."""


def parse_regression_case(source: str) -> AnyRegressionCase:
    """Validate one versioned TOML case without executing HTTP requests."""
    try:
        if type(source) is not str:
            raise ValueError("Invalid regression case source.")

        if len(source) > MAX_CASE_BYTES:
            raise ValueError("Invalid regression case size.")

        if len(source.encode("utf-8")) > MAX_CASE_BYTES:
            raise ValueError("Invalid regression case size.")

        if source.lstrip().startswith("{"):
            report: object = json.loads(source)
            if (
                isinstance(report, dict)
                and report.get("report_type") == "discovery_draft_review"
            ):
                raise ReviewDraftError(
                    "A draft review report cannot be verified. Supply a separately reviewed Schema v1 TOML case to --cases."
                )
        data: object = tomllib.loads(source)
        if isinstance(data, dict) and data.get("type") == "authorization.access":
            raise AuthorizationExecutionUnavailableError(
                "authorization_execution_unavailable: Why: authorization Case v1 is an offline-only artifact in this release. Instead: validate and review the case, then wait for the dedicated authorization command before execution."
            )
        if isinstance(data, dict) and data.get("kind") == "vintar_review_draft":
            raise ReviewDraftError(
                "Review draft cannot be verified. Resolve route mapping, baseline query values, "
                "target and authorization, credential requirements, check configuration and probe inputs, "
                "expected verdict, and trusted limits. Use a reviewed Schema v1 case."
            )

        if isinstance(data, dict) and data.get("version") == 2:
            return parse_case_v2_mapping(data)

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

        check_type = root["type"]
        if check_type not in {"sqli.boolean", "sqli.time", "sqli.error"}:
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

        probes = _mapping_table(root["probes"])
        if check_type == "sqli.boolean":
            if probes.keys() not in (
                {"true_payload", "false_payload"},
                {"true_payload", "false_payload", "confirmation"},
            ):
                raise ValueError("Invalid regression case schema.")
        elif check_type == "sqli.time" and probes.keys() != {
            "delay_payload",
            "control_payload",
            "expected_delay_seconds",
        }:
            raise TimeCaseValidationError(
                "Time probes require exactly delay_payload, control_payload, and expected_delay_seconds. Remove Boolean or unknown probe keys and supply the explicit time fields."
            )
        elif check_type == "sqli.error" and probes.keys() != {"error_payload"}:
            raise ErrorCaseValidationError(
                "Error probes require exactly error_payload. Remove Boolean, Time, preset, or unknown probe keys and supply one explicit reviewed payload."
            )

        limits = _table(
            root["limits"],
            {
                "max_requests",
                "requests_per_second",
                "timeout_seconds",
            },
        )

        max_requests = limits["max_requests"]
        if type(max_requests) is not int:
            if check_type == "sqli.time":
                raise TimeCaseValidationError(
                    "Time SQLi cases require exactly 9 requests. Set limits.max_requests = 9 using an integer, not a boolean."
                )
            if check_type == "sqli.error":
                raise ErrorCaseValidationError(
                    "Error SQLi cases require exactly 4 requests. Set limits.max_requests = 4 using an integer, not a boolean."
                )
            raise ValueError("Invalid request budget.")

        try:
            rps = _positive_number(
                limits["requests_per_second"],
                0.1,
                10.0,
            )
        except ValueError:
            if check_type == "sqli.time":
                raise TimeCaseValidationError(
                    "requests_per_second must be a number from 0.1 through 10.0, excluding booleans. Supply a bounded request rate."
                ) from None
            if check_type == "sqli.error":
                raise ErrorCaseValidationError(
                    "Error requests_per_second must be a number from 0.1 through 10.0, excluding booleans. Supply a bounded request rate."
                ) from None
            raise

        try:
            timeout = _positive_number(
                limits["timeout_seconds"],
                0.1,
                60.0,
            )
        except ValueError:
            if check_type == "sqli.time":
                raise TimeCaseValidationError(
                    "Time timeout_seconds must be numeric, excluding booleans. Supply at least expected_delay_seconds + 0.5 and no more than 8.0."
                ) from None
            if check_type == "sqli.error":
                raise ErrorCaseValidationError(
                    "Error timeout_seconds must be a number from 0.1 through 60.0, excluding booleans. Supply a bounded timeout."
                ) from None
            raise

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
            if check_type == "sqli.time":
                raise TimeCaseValidationError(
                    'Time SQLi supports query injection only. Set injection.location = "query".'
                )
            if check_type == "sqli.error":
                raise ErrorCaseValidationError(
                    'Error SQLi supports query injection only. Set injection.location = "query".'
                )
            raise ValueError("Unsupported injection location.")

        mode = injection["mode"]
        if type(mode) is not str or mode not in {"append", "replace"}:
            if check_type == "sqli.time":
                raise TimeCaseValidationError(
                    'Unsupported time injection mode. Use injection.mode = "append" or "replace".'
                )
            if check_type == "sqli.error":
                raise ErrorCaseValidationError(
                    'Unsupported error injection mode. Use injection.mode = "append" or "replace".'
                )
            raise ValueError("Unsupported injection mode.")

        occurrence = injection["occurrence"]
        if type(occurrence) is not int or occurrence < 0:
            if check_type == "sqli.time":
                raise TimeCaseValidationError(
                    "Invalid time injection occurrence. Supply a non-negative integer, not a boolean."
                )
            if check_type == "sqli.error":
                raise ErrorCaseValidationError(
                    "Invalid error injection occurrence. Supply a non-negative integer, not a boolean."
                )
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

        if check_type == "sqli.time":
            try:
                delay_payload = _string(probes["delay_payload"], max_length=512)
                control_payload = _string(probes["control_payload"], max_length=512)
            except ValueError:
                raise TimeCaseValidationError(
                    "Time probe payloads must be nonempty strings of at most 512 characters without control characters. Supply reviewed delay_payload and control_payload values."
                ) from None
            try:
                expected_delay = _positive_number(
                    probes["expected_delay_seconds"], 0.25, 2.0
                )
            except ValueError:
                raise TimeCaseValidationError(
                    "expected_delay_seconds must be a number from 0.25 through 2.0, excluding booleans. Supply a bounded expected delay."
                ) from None
            return TimeRegressionCase(
                schema_version=CASE_VERSION,
                case_id=case_id,
                check_type=check_type,
                template=template,
                point=point,
                delay_payload=delay_payload,
                control_payload=control_payload,
                expected_delay_seconds=expected_delay,
                expected_verdict=expected_verdict,
                scope=scope,
                max_requests=max_requests,
                max_response_size=CASE_MAX_RESPONSE_SIZE,
                requests_per_second=rps,
                timeout_seconds=timeout,
            )

        if check_type == "sqli.error":
            try:
                error_payload = validate_error_probe_payload(probes["error_payload"])
            except (TypeError, ValueError):
                raise ErrorCaseValidationError(
                    "Invalid error_payload. Supply an explicit nonempty reviewed string of at most 512 characters, without control characters or registered DBMS diagnostic text."
                ) from None
            return ErrorRegressionCase(
                schema_version=CASE_VERSION,
                case_id=case_id,
                check_type=check_type,
                template=template,
                point=point,
                error_payload=error_payload,
                expected_verdict=expected_verdict,
                scope=scope,
                max_requests=max_requests,
                max_response_size=CASE_MAX_RESPONSE_SIZE,
                requests_per_second=rps,
                timeout_seconds=timeout,
            )

        true_payload = _string(probes["true_payload"], max_length=512)
        false_payload = _string(probes["false_payload"], max_length=512)
        if true_payload == false_payload:
            raise ValueError("Probe payloads must differ.")

        confirmation: BooleanConfirmationPreset | None = None
        if "confirmation" in probes:
            confirmation_table = _table(
                probes["confirmation"],
                {"true_payload", "false_payload", "baseline_preserving_control"},
            )
            confirmation = BooleanConfirmationPreset(
                true_payload=_string(
                    confirmation_table["true_payload"], max_length=512
                ),
                false_payload=_string(
                    confirmation_table["false_payload"], max_length=512
                ),
                baseline_preserving_control=_string(
                    confirmation_table["baseline_preserving_control"], max_length=512
                ),
            )

        expected_requests = 18 if confirmation is not None else 6
        if max_requests != expected_requests:
            raise ValueError(
                f"This confirmation configuration requires exactly {expected_requests} requests."
            )

        return RegressionCase(
            schema_version=CASE_VERSION,
            case_id=case_id,
            check_type="sqli.boolean",
            template=template,
            point=point,
            true_payload=true_payload,
            false_payload=false_payload,
            confirmation=confirmation,
            expected_verdict=expected_verdict,
            scope=scope,
            max_requests=max_requests,
            max_response_size=CASE_MAX_RESPONSE_SIZE,
            requests_per_second=rps,
            timeout_seconds=timeout,
        )

    except (
        ReviewDraftError,
        AuthorizationExecutionUnavailableError,
        TimeCaseValidationError,
        ErrorCaseValidationError,
        CaseV2ValidationError,
    ):
        raise
    except (
        TypeError,
        ValueError,
        OverflowError,
        RecursionError,
        UnicodeError,
        httpx.HTTPError,
    ):
        # Do not expose payloads, URLs, or parser details.
        raise ValueError(
            "Invalid or unsupported regression case. Use a valid schema v1 TOML case."
        ) from None


def load_regression_case(path: str | Path) -> AnyRegressionCase:
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
