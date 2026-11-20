"""Materialize reviewed discovery decisions into a Schema v1 case."""

import errno
import json
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile

from vintar.checks.sqli.presets import (
    BOOLEAN_PROBE_PRESET_NAMES,
    get_boolean_probe_preset,
)
from vintar.regression.cases import load_regression_case
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


def _number(value: object, field: str) -> int | float:
    if type(value) is int:
        return value
    if type(value) is float:
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
    return _table(
        parsed,
        {
            "config_version",
            "input_id",
            "target",
            "injection",
            "probes",
            "limits",
        },
        "Invalid materialization config keys. Use only config_version, input_id, target, injection, probes, and limits.",
    )


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


def _probe_payloads(value: object) -> tuple[str, str]:
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
        if probes.keys() != {"selection", "true_payload", "false_payload"}:
            raise CaseMaterializationError(
                'Invalid explicit probes config. Use only selection = "explicit", true_payload, and false_payload.'
            )
        true_payload = _text(probes["true_payload"], "TRUE payload")
        false_payload = _text(probes["false_payload"], "FALSE payload")
        if true_payload == false_payload:
            raise CaseMaterializationError(
                "Probe payloads are identical. Supply distinct true_payload and false_payload values in --config."
            )
        return true_payload, false_payload

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
    return preset.true_payload, preset.false_payload


def _render(material: ReviewMaterial, config: dict[str, object]) -> bytes:
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
    true_payload, false_payload = _probe_payloads(config["probes"])
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
    if type(max_requests) is not int or max_requests != 6:
        raise CaseMaterializationError(
            "Invalid request limit. Set max_requests = 6 for the Schema v1 Boolean check."
        )
    requests_per_second = _number(limits["requests_per_second"], "requests_per_second")
    timeout_seconds = _number(limits["timeout_seconds"], "timeout_seconds")
    expected = material.report["expected_verdict"]
    if not isinstance(expected, str):
        raise CaseMaterializationError(
            "Review expected verdict is invalid. Rerun review-draft with an explicit expected verdict."
        )

    lines = [
        "version = 1",
        f"id = {_toml_string(material.case_id)}",
        'type = "sqli.boolean"',
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
            f"true_payload = {_toml_string(true_payload)}",
            f"false_payload = {_toml_string(false_payload)}",
            "",
            "[limits]",
            "max_requests = 6",
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
    schema_version = supplied_review.get("schema_version")
    if type(schema_version) is not int or schema_version != 1:
        raise CaseMaterializationError(
            "Invalid review schema version. Supply the current version 1 JSON output from review-draft."
        )
    if supplied_review != material.report:
        raise CaseMaterializationError(
            "The review report no longer matches the current spec, draft, or answers. Rerun review-draft and supply its current --review output."
        )
    content = _render(material, _load_config(config))
    return MaterializedCase(content=content, case_id=material.case_id)


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
