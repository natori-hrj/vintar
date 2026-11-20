"""Validate a Vintar CI report without disclosing report contents."""

import json
import os
import stat
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

_SCHEMA = (
    Path(__file__).resolve().parents[1]
    / "schemas"
    / "regression-batch-report-v1.schema.json"
)
_ALLOWED_EXIT_CODES = {
    0: "pass",
    1: "fail",
    3: "inconclusive",
}
_MAX_REPORT_BYTES = 2_097_152
_ERROR_MESSAGE = "Vintar: CI report validation failed."
_EXTENDED_OUTCOME_FIELDS = {
    "actual_reason_code",
    "request_count",
    "confirmation",
}
_OPERATIONAL_CONFIRMATION_REASONS = {
    "confirmation_budget_unavailable",
    "confirmation_preflight_failed",
    "confirmation_budget_exceeded",
    "confirmation_rate_limit_interrupted",
    "confirmation_timeout",
    "confirmation_request_failed",
    "confirmation_rate_limited",
    "confirmation_truncated",
    "confirmation_non_success_status",
    "confirmation_unstable",
    "confirmation_cross_phase_mismatch",
}


def _read_report(path: Path) -> bytes:
    """Read one bounded, stable regular file without following symlinks."""
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("Invalid report file.")
    if before.st_size > _MAX_REPORT_BYTES:
        raise ValueError("Report exceeds size limit.")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)

    descriptor = os.open(path, flags)
    try:
        opened_before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened_before.st_mode)
            or (before.st_dev, before.st_ino)
            != (opened_before.st_dev, opened_before.st_ino)
            or opened_before.st_size > _MAX_REPORT_BYTES
        ):
            raise ValueError("Invalid report file.")

        chunks = bytearray()
        while len(chunks) <= _MAX_REPORT_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, _MAX_REPORT_BYTES + 1 - len(chunks)),
            )
            if not chunk:
                break
            chunks.extend(chunk)

        if len(chunks) > _MAX_REPORT_BYTES:
            raise ValueError("Report exceeds size limit.")

        opened_after = os.fstat(descriptor)
        stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(opened_before, field) != getattr(opened_after, field)
            for field in stable_fields
        ):
            raise ValueError("Report changed while it was read.")

        return bytes(chunks)
    finally:
        os.close(descriptor)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON member names at every object depth."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member name.")
        result[key] = value
    return result


def _validate(path: Path, exit_code: int) -> None:
    if type(exit_code) is not int or exit_code not in _ALLOWED_EXIT_CODES:
        raise ValueError("Invalid CI exit code.")

    try:
        raw = _read_report(path)
    except FileNotFoundError:
        raise ValueError("Report is missing.") from None
    report = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
    )

    if isinstance(report, dict) and isinstance(report.get("outcomes"), list):
        for item in report["outcomes"]:
            if not isinstance(item, dict):
                continue
            present = _EXTENDED_OUTCOME_FIELDS & item.keys()
            if present and present != _EXTENDED_OUTCOME_FIELDS:
                raise ValueError(
                    "Invalid extended outcome fields. Supply actual_reason_code, request_count, and confirmation together, or omit all three for a legacy v1 report."
                )

    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    validator = Draft202012Validator(schema)
    try:
        validator.validate(report)
    except ValidationError:
        if isinstance(report, dict) and isinstance(report.get("outcomes"), list):
            for item in report["outcomes"]:
                if not isinstance(item, dict):
                    continue
                confirmation = item.get("confirmation")
                if not isinstance(confirmation, dict):
                    continue
                status = confirmation.get("status")
                configured = confirmation.get("configured")
                reason = confirmation.get("reason_code")
                count = confirmation.get("request_count")
                expected: str | None = None
                if status == "not_configured" and (
                    configured is not False or reason is not None or count != 0
                ):
                    expected = (
                        "Expect configured=false, null reason, and zero requests."
                    )
                elif status == "not_eligible" and (
                    configured is not True
                    or reason != "initial_not_eligible"
                    or count != 0
                ):
                    expected = "Expect configured=true, initial_not_eligible, and zero requests."
                elif status == "matched" and (
                    configured is not True
                    or reason != "confirmation_pattern_matched"
                    or count != 12
                ):
                    expected = "Expect configured=true, confirmation_pattern_matched, and 12 requests."
                elif status == "mismatch" and (
                    configured is not True
                    or reason != "candidate_confirmation_mismatch"
                ):
                    expected = (
                        "Expect configured=true and candidate_confirmation_mismatch."
                    )
                elif status == "operational" and (
                    configured is not True
                    or type(reason) is not str
                    or reason not in _OPERATIONAL_CONFIRMATION_REASONS
                    or type(count) is not int
                    or not 0 <= count <= 12
                ):
                    expected = "Expect configured=true, an operational reason, and zero to 12 requests."
                if expected is not None:
                    raise ValueError(
                        f"Invalid {status} confirmation combination. {expected}"
                    ) from None
        raise

    if report["exit_code"] != exit_code:
        raise ValueError("Process/report exit code mismatch.")

    if report["status"] != _ALLOWED_EXIT_CODES[exit_code]:
        raise ValueError("Process/report status mismatch.")

    planned = report["planned_case_ids"]
    executed = report["executed_case_ids"]
    not_run = report["not_run_case_ids"]
    outcomes = report["outcomes"]
    counts = report["counts"]

    if not planned or not executed:
        raise ValueError("Invalid case set.")

    if planned != executed + not_run:
        raise ValueError("Inconsistent case ordering.")

    if report["planned_count"] != len(planned):
        raise ValueError("Inconsistent planned count.")

    if report["executed_count"] != len(executed):
        raise ValueError("Inconsistent executed count.")

    if report["complete"] != (len(not_run) == 0):
        raise ValueError("Inconsistent completion state.")

    if [item["case_id"] for item in outcomes] != executed:
        raise ValueError("Inconsistent outcome ordering.")

    if counts["not_run"] != len(not_run):
        raise ValueError("Inconsistent not-run count.")

    for status in ("pass", "fail", "inconclusive"):
        actual = sum(item["status"] == status for item in outcomes)
        if counts[status] != actual:
            raise ValueError("Inconsistent status count.")

    used = sum(
        item.get("request_count", item["verification"]["request_count"])
        for item in outcomes
    )
    if report["requests_used"] != used:
        raise ValueError("Inconsistent request accounting.")

    if any(
        item["expectation_match"]
        != (item["expected_verdict"] == item["actual_verdict"])
        for item in outcomes
    ):
        raise ValueError("Inconsistent expectation match.")

    for item in outcomes:
        verdict = item["actual_verdict"]
        matched = item["expectation_match"]
        verification = item["verification"]
        observations = verification["observations"]
        failures = verification["failures"]
        if "confirmation" not in item:
            if item["actual_verdict"] != verification["verdict"]:
                raise ValueError(
                    "Invalid legacy v1 outcome. Expect actual_verdict to equal the verification verdict when confirmation fields are omitted."
                )
        else:
            confirmation = item["confirmation"]
            if item["request_count"] != (
                verification["request_count"] + confirmation["request_count"]
            ):
                raise ValueError(
                    "Invalid confirmation request accounting. Expect request_count to equal the initial and confirmation request counts."
                )

            confirmation_status = confirmation["status"]
            if confirmation_status == "not_configured":
                if (
                    confirmation["configured"] is not False
                    or confirmation["reason_code"] is not None
                    or confirmation["request_count"] != 0
                    or item["request_count"] != verification["request_count"]
                    or item["actual_verdict"] != verification["verdict"]
                    or item["actual_reason_code"] != verification["reason_code"]
                ):
                    raise ValueError(
                        "Invalid not_configured confirmation. Expect configured=false, null reason, zero confirmation requests, and final verdict/reason/count equal to the initial verification."
                    )
            elif confirmation_status == "not_eligible":
                initial_is_candidate = (
                    verification["verdict"] == "inconclusive"
                    and verification["reason_code"] == "boolean_candidate"
                )
                if (
                    confirmation["configured"] is not True
                    or confirmation["reason_code"] != "initial_not_eligible"
                    or confirmation["request_count"] != 0
                    or initial_is_candidate
                    or item["actual_verdict"] != verification["verdict"]
                    or item["actual_reason_code"] != verification["reason_code"]
                ):
                    raise ValueError(
                        "Invalid not_eligible confirmation. Expect configured=true, initial_not_eligible, zero confirmation requests, a non-candidate initial result, and an unchanged final result."
                    )
            elif confirmation_status == "matched":
                if (
                    confirmation["configured"] is not True
                    or confirmation["reason_code"] != "confirmation_pattern_matched"
                    or confirmation["request_count"] != 12
                    or item["request_count"] != 18
                    or item["actual_verdict"] != "inconclusive"
                    or item["actual_reason_code"] != "boolean_candidate"
                ):
                    raise ValueError(
                        "Invalid matched confirmation. Expect configured=true, confirmation_pattern_matched, 12 confirmation and 18 total requests, and final INCONCLUSIVE/boolean_candidate."
                    )
            elif confirmation_status == "mismatch":
                if (
                    confirmation["configured"] is not True
                    or confirmation["reason_code"] != "candidate_confirmation_mismatch"
                    or item["actual_verdict"] != "inconclusive"
                    or item["actual_reason_code"] != "candidate_confirmation_mismatch"
                ):
                    raise ValueError(
                        "Invalid mismatch confirmation. Expect configured=true and final INCONCLUSIVE/candidate_confirmation_mismatch."
                    )
            elif confirmation_status == "operational":
                reason = confirmation["reason_code"]
                if (
                    confirmation["configured"] is not True
                    or type(reason) is not str
                    or reason not in _OPERATIONAL_CONFIRMATION_REASONS
                    or not 0 <= confirmation["request_count"] <= 12
                    or item["actual_verdict"] != "inconclusive"
                    or item["actual_reason_code"] != reason
                ):
                    raise ValueError(
                        "Invalid operational confirmation. Expect configured=true, an operational confirmation reason, zero to 12 confirmation requests, and the same final INCONCLUSIVE reason."
                    )

        if verification["request_count"] != len(observations) + len(failures):
            raise ValueError("Inconsistent verification request count.")

        observed_kinds = {observation["kind"] for observation in observations}
        required_kinds = {"baseline", "true", "false"}
        if verification["evidence"] is not None and not required_kinds.issubset(
            observed_kinds
        ):
            raise ValueError("Evidence lacks required observations.")

        if verdict != "inconclusive":
            if failures or any(
                observation["truncated"] for observation in observations
            ):
                raise ValueError("Invalid conclusive verification.")
            if not required_kinds.issubset(observed_kinds):
                raise ValueError("Conclusive verification lacks observations.")
            if verification["evidence"] is None:
                raise ValueError("Conclusive verification lacks evidence.")

        if verdict == "inconclusive":
            expected_status = "inconclusive"
        elif verdict == "vulnerable":
            expected_status = "fail"
        elif matched:
            expected_status = "pass"
        else:
            expected_status = "fail"

        if item["status"] != expected_status:
            raise ValueError("Inconsistent case status.")

    if counts["fail"]:
        expected_batch_status = "fail"
    elif not report["complete"] or counts["inconclusive"]:
        expected_batch_status = "inconclusive"
    else:
        expected_batch_status = "pass"

    if report["status"] != expected_batch_status:
        raise ValueError("Inconsistent batch status.")


def main() -> int:
    """Return zero for a valid report; two for all invalid reports."""
    try:
        if len(sys.argv) != 3:
            raise ValueError("Invalid arguments.")

        code = int(sys.argv[2])

        _validate(Path(sys.argv[1]), code)
        return 0

    except (OSError, ValueError, ValidationError, SchemaError):
        print(_ERROR_MESSAGE, file=sys.stderr)
        return 2


if __name__ == "__main__":
    try:
        exit_code = main()
    except Exception as exc:
        print(_ERROR_MESSAGE, file=sys.stderr)
        raise SystemExit(2) from exc
    raise SystemExit(exit_code)
