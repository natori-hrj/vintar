"""Materialize reviewed discovery decisions into a Schema v1 case."""

import errno
import json
import math
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

from vintar.checks.sqli.presets import (
    BOOLEAN_PROBE_PRESET_NAMES,
    BooleanConfirmationPreset,
    get_boolean_confirmation_preset,
    get_boolean_probe_preset,
)
from vintar.core.strict_json import canonical_strict_json_bytes
from vintar.regression.cases import (
    ErrorCaseValidationError,
    ErrorRegressionCase,
    TimeRegressionCase,
    load_regression_case,
    parse_regression_case,
)
from vintar.regression.discovery import JSON, DiscoveryError, Source, _read, _read_json
from vintar.regression.discovery_review import (
    ReviewMaterial,
    ReviewScalar,
    resolve_review,
)


class CaseMaterializationError(ValueError):
    """A redacted, actionable case materialization diagnostic."""


@dataclass(frozen=True, slots=True, repr=False)
class MaterializedCase:
    """Validated case bytes and safe summary metadata."""

    content: bytes
    case_id: str
    confirmation_configured: bool
    max_requests: int


def _materialized_case_id(material: ReviewMaterial, check_type: str) -> str:
    if check_type == "sqli.boolean":
        return material.case_id
    if check_type == "sqli.time":
        suffix = "-time"
        label = "Time"
        maximum = 59
    else:
        suffix = "-error"
        label = "Error"
        maximum = 58
    candidate = material.case_id + suffix
    if len(candidate) > 64:
        raise CaseMaterializationError(
            f"{label} case ID exceeds the 64-character Schema v1 limit after adding the {suffix} suffix. Use reviewed material with a base case ID of at most {maximum} characters."
        )
    return candidate


def _table(value: object, keys: set[str], message: str) -> dict[str, object]:
    result = _mapping(value, message)
    if result.keys() != keys:
        raise CaseMaterializationError(message)
    return result


def _mapping(value: object, message: str) -> dict[str, object]:
    if type(value) is not dict:
        raise CaseMaterializationError(message)
    result: dict[str, object] = {}
    for key, item in value.items():
        if type(key) is not str:
            raise CaseMaterializationError(message)
        result[key] = item
    return result


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value:
        raise CaseMaterializationError(
            f"Invalid {field}. Supply a nonempty Schema v1 compatible string in --config."
        )
    return value


def _number(
    value: object,
    field: str,
    *,
    allowed_range: str | None = None,
) -> int | float:
    if type(value) is int:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            guidance = f" from {allowed_range}" if allowed_range is not None else ""
            raise CaseMaterializationError(
                f"Invalid {field}. Supply a finite number{guidance}, excluding booleans."
            )
        return value
    raise CaseMaterializationError(
        f"Invalid {field}. Supply a numeric Schema v1 limit in --config."
    )


def _toml_string(value: str) -> str:
    escapes = {
        '"': '\\"',
        "\\": "\\\\",
        "\b": "\\b",
        "\t": "\\t",
        "\n": "\\n",
        "\f": "\\f",
        "\r": "\\r",
    }
    encoded = []
    for character in value:
        codepoint = ord(character)
        if character in escapes:
            encoded.append(escapes[character])
        elif codepoint <= 0x1F or codepoint == 0x7F:
            encoded.append(f"\\u{codepoint:04X}")
        elif 0xD800 <= codepoint <= 0xDFFF:
            raise CaseMaterializationError(
                "Invalid Unicode string in reviewed inputs. Supply valid Unicode scalar values and rerun review-draft."
            )
        else:
            encoded.append(character)
    return f'"{"".join(encoded)}"'


def _query_value(value: ReviewScalar) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )


def _load_config(path: Path) -> dict[str, object]:
    try:
        parsed: object = tomllib.loads(_read(path).decode("utf-8"))
    except (DiscoveryError, UnicodeError, ValueError, RecursionError) as exc:
        raise CaseMaterializationError(
            "Cannot read materialization config. Supply bounded UTF-8 TOML with the documented version 1 fields."
        ) from exc
    message = (
        "Invalid materialization config keys. Use only config_version, optional "
        "type, input_id, target, injection, probes, and limits."
    )
    result = _mapping(parsed, message)
    required = {
        "config_version",
        "input_id",
        "target",
        "injection",
        "probes",
        "limits",
    }
    if result.keys() not in (required, required | {"type"}):
        raise CaseMaterializationError(message)
    return result


def _materialization_type(config: dict[str, object]) -> str:
    value = config.get("type", "sqli.boolean")
    if type(value) is not str or value not in {
        "sqli.boolean",
        "sqli.time",
        "sqli.error",
    }:
        raise CaseMaterializationError(
            'Invalid materialization type. Omit type for Boolean SQLi, or set type = "sqli.time" or type = "sqli.error" for an explicit reviewed case.'
        )
    return value


def _load_review(path: Path) -> dict[str, JSON]:
    try:
        parsed = _read_json(_read(path), Source(path))
    except DiscoveryError as exc:
        raise CaseMaterializationError(
            "Cannot read review report. Supply the bounded JSON output from review-draft."
        ) from exc
    if not isinstance(parsed, dict):
        raise CaseMaterializationError(
            "Invalid review report. Supply the current JSON output from review-draft."
        )
    return parsed


def _confirmation_payloads(value: object) -> BooleanConfirmationPreset:
    table = _table(
        value,
        {"true_payload", "false_payload", "baseline_preserving_control"},
        "Invalid explicit confirmation config. Supply exactly true_payload, false_payload, and baseline_preserving_control, or omit the block.",
    )
    try:
        return BooleanConfirmationPreset(
            true_payload=_text(table["true_payload"], "confirmation TRUE payload"),
            false_payload=_text(table["false_payload"], "confirmation FALSE payload"),
            baseline_preserving_control=_text(
                table["baseline_preserving_control"],
                "baseline-preserving confirmation predicate",
            ),
        )
    except ValueError as exc:
        raise CaseMaterializationError(
            "Invalid confirmation payloads. Supply three distinct nonempty values that also differ from the initial probe pair."
        ) from exc


def _probe_payloads(
    value: object,
) -> tuple[str, str, BooleanConfirmationPreset | None]:
    message = (
        'Invalid probes config. Use selection = "explicit" with only true_payload '
        'and false_payload, or selection = "preset" with only preset.'
    )
    probes = _mapping(value, message)
    selection = probes.get("selection")
    if type(selection) is not str or selection not in {"explicit", "preset"}:
        raise CaseMaterializationError(
            'Invalid probe selection. Use selection = "explicit" or selection = "preset".'
        )
    if selection == "explicit":
        if probes.keys() not in (
            {"selection", "true_payload", "false_payload"},
            {"selection", "true_payload", "false_payload", "confirmation"},
        ):
            raise CaseMaterializationError(
                "Invalid explicit probes config. Supply true_payload and false_payload, with an optional complete confirmation table."
            )
        true_payload = _text(probes["true_payload"], "TRUE payload")
        false_payload = _text(probes["false_payload"], "FALSE payload")
        if true_payload == false_payload:
            raise CaseMaterializationError(
                "Probe payloads are identical. Supply distinct true_payload and false_payload values in --config."
            )
        confirmation = (
            _confirmation_payloads(probes["confirmation"])
            if "confirmation" in probes
            else None
        )
        if (
            confirmation is not None
            and len(
                {
                    true_payload,
                    false_payload,
                    confirmation.true_payload,
                    confirmation.false_payload,
                    confirmation.baseline_preserving_control,
                }
            )
            != 5
        ):
            raise CaseMaterializationError(
                "Initial and confirmation payloads overlap. Supply five distinct nonempty payloads in --config."
            )
        return true_payload, false_payload, confirmation

    if probes.keys() != {"selection", "preset"}:
        raise CaseMaterializationError(
            'Invalid preset probes config. Use only selection = "preset" and preset.'
        )
    try:
        preset = get_boolean_probe_preset(probes["preset"])
    except ValueError as exc:
        valid = ", ".join(BOOLEAN_PROBE_PRESET_NAMES)
        raise CaseMaterializationError(
            f"Invalid probe preset. Use one of: {valid}."
        ) from exc
    confirmation = get_boolean_confirmation_preset(probes["preset"])
    return preset.true_payload, preset.false_payload, confirmation


def _time_probe_payloads(value: object) -> tuple[str, str, float]:
    message = (
        'Invalid time probes config. Use selection = "explicit" with only '
        "delay_payload, control_payload, and expected_delay_seconds. Time presets "
        "are not available; write explicit reviewed payloads instead."
    )
    probes = _mapping(value, message)
    selection = probes.get("selection")
    if type(selection) is not str or selection != "explicit":
        raise CaseMaterializationError(
            'Unsupported time probe selection. Use selection = "explicit" and supply delay_payload, control_payload, and expected_delay_seconds; presets are not available for time cases.'
        )
    if probes.keys() != {
        "selection",
        "delay_payload",
        "control_payload",
        "expected_delay_seconds",
    }:
        raise CaseMaterializationError(message)
    delay_payload = _text(probes["delay_payload"], "time delay payload")
    control_payload = _text(probes["control_payload"], "time control payload")
    if delay_payload == control_payload:
        raise CaseMaterializationError(
            "Time probe payloads are identical. Supply distinct explicit delay_payload and control_payload values in --config."
        )
    expected_delay = _number(
        probes["expected_delay_seconds"],
        "expected_delay_seconds",
        allowed_range="0.25 through 2.0",
    )
    if not 0.25 <= expected_delay <= 2.0:
        raise CaseMaterializationError(
            "Invalid expected_delay_seconds. Supply a number from 0.25 through 2.0, excluding booleans."
        )
    return delay_payload, control_payload, float(expected_delay)


def _error_probe_payload(value: object) -> str:
    message = (
        'Invalid Error probes config. Use selection = "explicit" with only '
        "error_payload. Error SQLi presets are not available; supply an explicit "
        "reviewed error_payload."
    )
    probes = _mapping(value, message)
    selection = probes.get("selection")
    if type(selection) is not str or selection != "explicit":
        raise CaseMaterializationError(
            "Error SQLi presets are not available; supply an explicit reviewed error_payload."
        )
    if probes.keys() != {"selection", "error_payload"}:
        raise CaseMaterializationError(message)
    return _text(probes["error_payload"], "Error SQLi payload")


def _render(
    material: ReviewMaterial,
    config: dict[str, object],
    case_id: str,
) -> bytes:
    version = config["config_version"]
    if type(version) is not int or version != 1:
        raise CaseMaterializationError(
            "Unsupported materialization config version. Set config_version = 1."
        )
    input_id = config["input_id"]
    if type(input_id) is not str or input_id != material.report["input_id"]:
        raise CaseMaterializationError(
            "Config input ID does not match the reviewed draft. Copy input_id from the current review report."
        )

    target = _table(
        config["target"],
        {"url", "allowed_origin"},
        "Invalid target config. Supply only explicit url and allowed_origin fields.",
    )
    injection = _table(
        config["injection"],
        {"location", "name", "occurrence", "mode"},
        "Invalid injection config. Supply location, name, occurrence, and mode.",
    )
    check_type = _materialization_type(config)
    limits = _table(
        config["limits"],
        {"max_requests", "requests_per_second", "timeout_seconds"},
        "Invalid limits config. Supply max_requests, requests_per_second, and timeout_seconds.",
    )

    location = injection["location"]
    name = injection["name"]
    occurrence = injection["occurrence"]
    mode = injection["mode"]
    if type(location) is not str or location != "query":
        raise CaseMaterializationError(
            'Unsupported injection location. Use location = "query" for Schema v1.'
        )
    if type(name) is not str or name != material.selected_parameter:
        raise CaseMaterializationError(
            "Injection parameter does not match the reviewed input. Use the query parameter named by the current draft."
        )
    if name in material.omitted:
        raise CaseMaterializationError(
            "The reviewed injection parameter was omitted. Supply a concrete value in --answers and rerun review-draft."
        )
    if type(occurrence) is not int or occurrence < 0:
        raise CaseMaterializationError(
            "Invalid injection occurrence. Supply the zero-based occurrence of the reviewed parameter."
        )
    if type(mode) is not str or mode not in {"append", "replace"}:
        raise CaseMaterializationError(
            'Unsupported injection mode. Use mode = "append" or mode = "replace".'
        )

    params = [(key, _query_value(value)) for key, value in material.values.items()]
    matches = sum(parameter == name for parameter, _ in params)
    if occurrence >= matches:
        raise CaseMaterializationError(
            "Injection occurrence does not identify a retained target parameter. Supply its zero-based occurrence or resolve the parameter in --answers."
        )

    url = _text(target["url"], "target URL")
    allowed_origin = _text(target["allowed_origin"], "allowed origin")
    max_requests = limits["max_requests"]
    requests_per_second = _number(
        limits["requests_per_second"],
        "requests_per_second",
        allowed_range="0.1 through 10.0",
    )
    timeout_range = (
        "expected_delay_seconds + 0.5 through 8.0"
        if check_type == "sqli.time"
        else "0.1 through 60.0"
    )
    timeout_seconds = _number(
        limits["timeout_seconds"],
        "timeout_seconds",
        allowed_range=timeout_range,
    )
    confirmation: BooleanConfirmationPreset | None = None
    true_payload = ""
    false_payload = ""
    delay_payload = ""
    control_payload = ""
    expected_delay = 0.0
    error_payload = ""
    expected_requests: int | float
    if check_type == "sqli.time":
        delay_payload, control_payload, expected_delay = _time_probe_payloads(
            config["probes"]
        )
        expected_requests = 9
        if type(max_requests) is not int or max_requests != expected_requests:
            raise CaseMaterializationError(
                "Invalid time request limit. Set max_requests = 9 for Schema v1 time cases."
            )
        if not 0.1 <= requests_per_second <= 10.0:
            raise CaseMaterializationError(
                "Invalid time requests_per_second. Supply a number from 0.1 through 10.0, excluding booleans."
            )
        if not expected_delay + 0.5 <= timeout_seconds <= 8.0:
            raise CaseMaterializationError(
                "Invalid time timeout_seconds. Set it to at least expected_delay_seconds + 0.5 and no more than 8.0."
            )
    elif check_type == "sqli.error":
        error_payload = _error_probe_payload(config["probes"])
        if type(max_requests) is not int or max_requests != 4:
            raise CaseMaterializationError(
                "Error SQLi cases require exactly 4 requests. Set limits.max_requests = 4."
            )
        if not 0.1 <= requests_per_second <= 10.0:
            raise CaseMaterializationError(
                "Error requests_per_second must be a number from 0.1 through 10.0, excluding booleans. Supply a bounded request rate."
            )
        if not 0.1 <= timeout_seconds <= 60.0:
            raise CaseMaterializationError(
                "Error timeout_seconds must be a number from 0.1 through 60.0, excluding booleans. Supply a bounded timeout."
            )
        expected_requests = 4
    else:
        true_payload, false_payload, confirmation = _probe_payloads(config["probes"])
        expected_requests = 18 if confirmation is not None else 6
        if type(max_requests) is not int or max_requests != expected_requests:
            raise CaseMaterializationError(
                f"Invalid request limit. Set max_requests = {expected_requests} for this confirmation configuration."
            )
    expected = material.report["expected_verdict"]
    if not isinstance(expected, str):
        raise CaseMaterializationError(
            "Review expected verdict is invalid. Rerun review-draft with an explicit expected verdict."
        )

    lines = [
        "version = 1",
        f"id = {_toml_string(case_id)}",
        f"type = {_toml_string(check_type)}",
        f"expected_verdict = {_toml_string(expected)}",
        "",
        "[target]",
        f"url = {_toml_string(url)}",
        f"allowed_origin = {_toml_string(allowed_origin)}",
    ]
    if not params:
        lines.append("params = []")
    for parameter, value in params:
        lines.extend(
            (
                "",
                "[[target.params]]",
                f"name = {_toml_string(parameter)}",
                f"value = {_toml_string(value)}",
            )
        )
    lines.extend(
        (
            "",
            "[injection]",
            'location = "query"',
            f"name = {_toml_string(name)}",
            f"occurrence = {occurrence}",
            f"mode = {_toml_string(mode)}",
            "",
            "[probes]",
        )
    )
    if check_type == "sqli.time":
        lines.extend(
            (
                f"delay_payload = {_toml_string(delay_payload)}",
                f"control_payload = {_toml_string(control_payload)}",
                (
                    "expected_delay_seconds = "
                    f"{json.dumps(expected_delay, allow_nan=False)}"
                ),
            )
        )
    elif check_type == "sqli.error":
        lines.append(f"error_payload = {_toml_string(error_payload)}")
    else:
        lines.extend(
            (
                f"true_payload = {_toml_string(true_payload)}",
                f"false_payload = {_toml_string(false_payload)}",
            )
        )
    if confirmation is not None:
        lines.extend(
            (
                "",
                "[probes.confirmation]",
                f"true_payload = {_toml_string(confirmation.true_payload)}",
                f"false_payload = {_toml_string(confirmation.false_payload)}",
                (
                    "baseline_preserving_control = "
                    f"{_toml_string(confirmation.baseline_preserving_control)}"
                ),
            )
        )
    lines.extend(
        (
            "",
            "[limits]",
            f"max_requests = {json.dumps(expected_requests, allow_nan=False)}",
            f"requests_per_second = {json.dumps(requests_per_second, allow_nan=False)}",
            f"timeout_seconds = {json.dumps(timeout_seconds, allow_nan=False)}",
        )
    )
    return ("\n".join(lines) + "\n").encode("utf-8")


def materialize_case(
    spec: Path,
    draft: Path,
    answers: Path,
    review: Path,
    config: Path,
) -> MaterializedCase:
    """Revalidate reviewed inputs and render deterministic Schema v1 TOML."""
    material = resolve_review(spec, draft, answers)
    supplied_review = _load_review(review)
    if canonical_strict_json_bytes(supplied_review) != canonical_strict_json_bytes(
        material.report
    ):
        raise CaseMaterializationError(
            "The review report no longer matches the current spec, draft, or answers. Rerun review-draft and supply its current --review output."
        )
    schema_version = supplied_review.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise CaseMaterializationError(
            "Invalid review schema version. Supply the current version 1 JSON output from review-draft."
        )
    loaded_config = _load_config(config)
    check_type = _materialization_type(loaded_config)
    case_id = _materialized_case_id(material, check_type)
    content = _render(material, loaded_config, case_id)
    if check_type == "sqli.time":
        try:
            loaded = parse_regression_case(content.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise CaseMaterializationError(
                "Generated time case failed Schema v1 validation. Check the explicit target, query injection, time probes, and nine-request limits in --config."
            ) from exc
        if not isinstance(loaded, TimeRegressionCase):
            raise CaseMaterializationError(
                'Generated case type is inconsistent. Set type = "sqli.time" and supply only time probe fields.'
            )
        return MaterializedCase(
            content=content,
            case_id=case_id,
            confirmation_configured=False,
            max_requests=loaded.max_requests,
        )
    if check_type == "sqli.error":
        try:
            loaded = parse_regression_case(content.decode("utf-8"))
        except ErrorCaseValidationError as exc:
            raise CaseMaterializationError(str(exc)) from exc
        except (UnicodeError, ValueError) as exc:
            raise CaseMaterializationError(
                "Generated Error case failed Schema v1 validation. Check the explicit target, query injection, Error payload, and four-request limits in --config."
            ) from exc
        if not isinstance(loaded, ErrorRegressionCase):
            raise CaseMaterializationError(
                'Generated case type is inconsistent. Set type = "sqli.error" and supply only an explicit error_payload.'
            )
        return MaterializedCase(
            content=content,
            case_id=case_id,
            confirmation_configured=False,
            max_requests=loaded.max_requests,
        )
    _, _, confirmation = _probe_payloads(loaded_config["probes"])
    return MaterializedCase(
        content=content,
        case_id=case_id,
        confirmation_configured=confirmation is not None,
        max_requests=18 if confirmation is not None else 6,
    )


def _check_destination(output: Path, inputs: tuple[Path, ...]) -> Path:
    output = output.absolute()
    if output.suffix != ".toml":
        raise CaseMaterializationError(
            "Case output requires a .toml filename. Pass a TOML path to --output."
        )
    for parent in (*output.parent.parents, output.parent):
        if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
            raise CaseMaterializationError(
                "Case output traverses a symlink or non-directory. Choose a real output directory."
            )
    if output.is_symlink():
        raise CaseMaterializationError(
            "Case output is a symlink. Choose a different --output path."
        )
    if any(output.resolve() == source.resolve() for source in inputs):
        raise CaseMaterializationError(
            "Case output aliases an input file. Choose a different --output path."
        )
    if output.exists() and any(output.samefile(source) for source in inputs):
        raise CaseMaterializationError(
            "Case output aliases an input file. Choose a different --output path."
        )
    return output


def write_materialized_case(
    output: Path,
    case: MaterializedCase,
    inputs: tuple[Path, ...],
) -> None:
    """Validate and exclusively publish one materialized case."""
    path = _check_destination(output, inputs)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with NamedTemporaryFile(
            dir=path.parent, prefix=".vintar-case-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            if stream.write(case.content) != len(case.content):
                raise OSError("Incomplete case write.")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            loaded = load_regression_case(temporary)
        except ValueError as exc:
            raise CaseMaterializationError(
                "Generated case failed Schema v1 validation. Check the target, injection, probes, and limits in --config."
            ) from exc
        if loaded.case_id != case.case_id:
            raise CaseMaterializationError(
                "Generated case ID changed during validation. Rerun discovery and materialize the current draft."
            )
        if path.exists():
            if path.is_file() and path.stat().st_size == len(case.content):
                with path.open("rb") as stream:
                    if stream.read(len(case.content) + 1) == case.content:
                        return
            raise CaseMaterializationError(
                "Case output already has different content. Move it or choose a different --output path."
            )
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise CaseMaterializationError(
                "Case output appeared during materialization. Review it or choose a different --output path."
            ) from exc
        except OSError as exc:
            if exc.errno not in {
                errno.EPERM,
                errno.ENOTSUP,
                errno.EOPNOTSUPP,
                errno.EXDEV,
            }:
                raise
            raise CaseMaterializationError(
                "The output directory must support hard links, such as ext4, APFS, or NTFS. Choose another --output path if it is on exFAT or FAT32."
            ) from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
