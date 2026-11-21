"""Validate a Vintar CI report without disclosing report contents."""

import json
import os
import stat
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from vintar.checks.sqli.confirmation import confirmation_eligible
from vintar.checks.sqli.confirmation_runner import (
    CONFIRMATION_RESULT_RULES,
    ConfirmationStatus,
)
from vintar.checks.sqli.error_contract import ERROR_RESULT_RULES
from vintar.checks.sqli.error_signatures import ERROR_SIGNATURES
from vintar.checks.sqli.models import (
    BooleanEvidence,
    Observation,
    ProbeError,
    ProbeFailure,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.checks.sqli.time_contract import TIME_RESULT_RULES

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
_TIME_OUTCOME_FIELDS = {
    "check_type",
    "timing",
}
_ERROR_OUTCOME_FIELDS = {
    "check_type",
    "error",
}
_CONFIRMATION_RULES = CONFIRMATION_RESULT_RULES
_OPERATIONAL_CONFIRMATION_REASONS = frozenset(
    reason
    for reason, rule in _CONFIRMATION_RULES.items()
    if rule.status is ConfirmationStatus.INCONCLUSIVE
    and reason != "candidate_confirmation_mismatch"
)


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


def _verification_result(item: dict[str, object]) -> VerificationResult:
    verification = item["verification"]
    if not isinstance(verification, dict):
        raise TypeError("Invalid verification report object.")
    observations = tuple(
        Observation(
            kind=ProbeKind(observation["kind"]),
            status_code=observation["status_code"],
            body_size=observation["body_size"],
            elapsed=observation["elapsed"],
            body_digest=observation["body_digest"],
            truncated=observation["truncated"],
        )
        for observation in verification["observations"]
    )
    failures = tuple(
        ProbeFailure(
            kind=ProbeKind(failure["kind"]),
            error=ProbeError(failure["error"]),
            elapsed=failure["elapsed"],
        )
        for failure in verification["failures"]
    )
    evidence_data = verification["evidence"]
    evidence = (
        None
        if evidence_data is None
        else BooleanEvidence(
            baseline_true_similarity=evidence_data["baseline_true_similarity"],
            baseline_false_similarity=evidence_data["baseline_false_similarity"],
            true_false_similarity=evidence_data["true_false_similarity"],
        )
    )
    return VerificationResult(
        check_id=item["case_id"],
        verdict=Verdict(verification["verdict"]),
        observations=observations,
        failures=failures,
        request_count=verification["request_count"],
        reason_code=verification["reason_code"],
        reason="Validated report result.",
        evidence=evidence,
        confidence=verification["confidence"],
    )


def _validate(
    path: Path,
    exit_code: int,
    schema_path: Path = _SCHEMA,
) -> None:
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
            is_time = item.get("check_type") == "sqli.time"
            if (is_time and "timing" not in item) or (not is_time and "timing" in item):
                raise ValueError(
                    "Invalid time outcome fields. Supply check_type and timing together for a time outcome, or omit both for a Boolean outcome."
                )
            is_error = item.get("check_type") == "sqli.error"
            if (is_error and "error" not in item) or (not is_error and "error" in item):
                raise ValueError(
                    "Invalid Error SQLi outcome fields. Supply check_type and error together for an Error outcome, or omit both for another check type."
                )
            present = _EXTENDED_OUTCOME_FIELDS & item.keys()
            if (
                "timing" not in item
                and "error" not in item
                and present
                and present != _EXTENDED_OUTCOME_FIELDS
            ):
                raise ValueError(
                    "Invalid extended outcome fields. Supply actual_reason_code, request_count, and confirmation together, or omit all three for a legacy v1 report."
                )

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
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
                elif status in {
                    "not_eligible",
                    "matched",
                    "mismatch",
                    "operational",
                }:
                    rule = (
                        _CONFIRMATION_RULES.get(reason) if type(reason) is str else None
                    )
                    expected_status = {
                        "not_eligible": ConfirmationStatus.SKIPPED,
                        "matched": ConfirmationStatus.CANDIDATE,
                        "mismatch": ConfirmationStatus.INCONCLUSIVE,
                        "operational": ConfirmationStatus.INCONCLUSIVE,
                    }[status]
                    if (
                        configured is not True
                        or rule is None
                        or rule.status is not expected_status
                        or (
                            status == "operational"
                            and reason not in _OPERATIONAL_CONFIRMATION_REASONS
                        )
                        or type(count) is not int
                        or not rule.minimum_requests <= count <= rule.maximum_requests
                    ):
                        expected = "Expect the runner-defined reason, status, and request-count range."
                    elif rule.requires_eligible_initial:
                        try:
                            eligible = confirmation_eligible(_verification_result(item))
                        except (KeyError, TypeError, ValueError):
                            eligible = True
                        if not eligible:
                            expected = "Expect an eligible six-request INCONCLUSIVE/boolean_candidate initial result."
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
        item.get(
            "request_count",
            item.get("verification", {}).get("request_count", 0),
        )
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
        if item.get("check_type") == "sqli.time":
            timing = item["timing"]
            reason = timing["reason_code"]
            rule = TIME_RESULT_RULES.get(reason)
            if rule is None:
                raise ValueError(
                    "Invalid time outcome reason. Use a reason declared in TIME_RESULT_RULES."
                )
            if timing["status"] != rule.analysis_status.value:
                raise ValueError(
                    "Invalid time outcome status. Use the analysis status required by TIME_RESULT_RULES."
                )
            if item["actual_verdict"] != rule.product_verdict.value:
                raise ValueError(
                    "Invalid time outcome verdict. Use the product verdict required by TIME_RESULT_RULES."
                )
            request_count = timing["request_count"]
            if not rule.minimum_requests <= request_count <= rule.maximum_requests:
                raise ValueError(
                    "Invalid time outcome request count. Use the bounded request range required by TIME_RESULT_RULES."
                )
            if (
                item["actual_reason_code"] != reason
                or item["request_count"] != request_count
            ):
                raise ValueError(
                    "Invalid time outcome summary. Match the top-level reason and request count to the timing result."
                )
            if verdict == "inconclusive":
                expected_status = "inconclusive"
            elif matched:
                expected_status = "pass"
            else:
                expected_status = "fail"
            if item["status"] != expected_status:
                raise ValueError(
                    "Inconsistent time case status. Use the existing regression status mapping for the final verdict and expectation match."
                )
            continue

        if item.get("check_type") == "sqli.error":
            error = item["error"]
            reason = error["reason_code"]
            rule = ERROR_RESULT_RULES.get(reason)
            if rule is None:
                raise ValueError(
                    "Invalid Error SQLi outcome reason. Use a reason declared in ERROR_RESULT_RULES."
                )
            if error["status"] != rule.analysis_status.value:
                raise ValueError(
                    "Invalid Error SQLi outcome status. Use the analysis status required by ERROR_RESULT_RULES."
                )
            if item["actual_verdict"] != rule.product_verdict.value:
                raise ValueError(
                    "Invalid Error SQLi outcome verdict. Use the product verdict required by ERROR_RESULT_RULES."
                )
            request_count = error["request_count"]
            if not rule.minimum_requests <= request_count <= rule.maximum_requests:
                raise ValueError(
                    "Invalid Error SQLi outcome request count. Use the bounded request range required by ERROR_RESULT_RULES."
                )
            if (
                item["actual_reason_code"] != reason
                or item["request_count"] != request_count
            ):
                raise ValueError(
                    "Invalid Error SQLi outcome summary. Match the top-level reason and request count to the error result."
                )
            evidence_fields = {"dbms", "signature_id"} & error.keys()
            if rule.requires_evidence:
                if evidence_fields != {"dbms", "signature_id"}:
                    raise ValueError(
                        "Invalid Error SQLi evidence. Supply DBMS and signature ID together when ERROR_RESULT_RULES requires evidence."
                    )
                signature = ERROR_SIGNATURES.get(error["signature_id"])
                if signature is None or signature.dbms != error["dbms"]:
                    raise ValueError(
                        "Invalid Error SQLi evidence pair. Use a reviewed DBMS and signature ID pair from ERROR_SIGNATURES."
                    )
            elif evidence_fields:
                raise ValueError(
                    "Unexpected Error SQLi evidence. Omit DBMS and signature ID when ERROR_RESULT_RULES does not require evidence."
                )
            if verdict == "inconclusive":
                expected_status = "inconclusive"
            elif matched:
                expected_status = "pass"
            else:
                expected_status = "fail"
            if item["status"] != expected_status:
                raise ValueError(
                    "Inconsistent Error SQLi case status. Use the existing regression status mapping for the final verdict and expectation match."
                )
            continue

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
            else:
                reason = confirmation["reason_code"]
                rule = _CONFIRMATION_RULES.get(reason)
                expected_status = {
                    "not_eligible": ConfirmationStatus.SKIPPED,
                    "matched": ConfirmationStatus.CANDIDATE,
                    "mismatch": ConfirmationStatus.INCONCLUSIVE,
                    "operational": ConfirmationStatus.INCONCLUSIVE,
                }[confirmation_status]
                if (
                    confirmation["configured"] is not True
                    or type(reason) is not str
                    or rule is None
                    or rule.status is not expected_status
                    or (
                        confirmation_status == "operational"
                        and reason not in _OPERATIONAL_CONFIRMATION_REASONS
                    )
                    or not rule.minimum_requests
                    <= confirmation["request_count"]
                    <= rule.maximum_requests
                ):
                    raise ValueError(
                        f"Invalid {confirmation_status} confirmation. Expect the runner-defined reason, status, and request-count range."
                    )

                initial = _verification_result(item)
                eligible = confirmation_eligible(initial)
                if eligible is not rule.requires_eligible_initial:
                    expected_initial = (
                        "an eligible six-request INCONCLUSIVE/boolean_candidate initial result"
                        if rule.requires_eligible_initial
                        else "an initial result that is not confirmation-eligible"
                    )
                    raise ValueError(
                        f"Invalid {confirmation_status} confirmation initial result. Expect {expected_initial}."
                    )

                if confirmation_status == "not_eligible":
                    valid_final = (
                        item["actual_verdict"] == verification["verdict"]
                        and item["actual_reason_code"] == verification["reason_code"]
                    )
                    expected_final = "the unchanged initial verdict and reason"
                elif confirmation_status == "matched":
                    valid_final = (
                        item["actual_verdict"] == "inconclusive"
                        and item["actual_reason_code"] == "boolean_candidate"
                    )
                    expected_final = "final INCONCLUSIVE/boolean_candidate"
                else:
                    valid_final = (
                        item["actual_verdict"] == "inconclusive"
                        and item["actual_reason_code"] == reason
                    )
                    expected_final = f"final INCONCLUSIVE/{reason}"
                if not valid_final:
                    raise ValueError(
                        f"Invalid {confirmation_status} confirmation final result. Expect {expected_final}."
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
