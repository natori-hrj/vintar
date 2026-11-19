import ast
import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from vintar.checks.sqli import analyzer as sqli_analyzer
from vintar.checks.sqli import report as sqli_report
from vintar.checks.sqli.models import (
    BooleanEvidence,
    Observation,
    ProbeError,
    ProbeFailure,
    ProbeKind,
    Verdict,
    VerificationResult,
)
from vintar.checks.sqli.report import (
    REPORT_SCHEMA_VERSION,
    verification_report_dict,
    verification_report_json,
)

EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@dataclass(frozen=True, slots=True)
class ExtendedVerificationResult(VerificationResult):
    future_secret: str = "SECRET_FROM_FUTURE_MODEL"


def make_result(**overrides) -> VerificationResult:
    values = {
        "check_id": "internal-check-id",
        "verdict": Verdict.INCONCLUSIVE,
        "observations": (),
        "request_count": 0,
        "reason_code": "budget_unavailable",
        "reason": "Insufficient request budget.",
    }
    values.update(overrides)
    return VerificationResult(**values)


def observation(kind: ProbeKind) -> Observation:
    return Observation(
        kind=kind,
        status_code=200,
        body_size=0,
        elapsed=0.1,
        body_digest=EMPTY_DIGEST,
    )


def test_schema_version_and_fields():
    report = verification_report_dict(make_result())

    assert report["schema_version"] == REPORT_SCHEMA_VERSION
    assert report["check_type"] == "sqli_boolean"
    assert report["verdict"] == "inconclusive"
    assert report["reason_code"] == "budget_unavailable"
    assert report["request_count"] == 0
    assert report["observations"] == []
    assert report["failures"] == []
    assert report["evidence"] is None
    assert report["confidence"] is None
    assert set(report) == {
        "schema_version",
        "check_type",
        "verdict",
        "reason_code",
        "request_count",
        "observations",
        "failures",
        "evidence",
        "confidence",
    }


def test_sensitive_free_text_fields_are_omitted():
    secret = "SECRET_NEVER_EXPORT_123"
    result = make_result(
        check_id=secret,
        reason=f"Internal debug information: {secret}",
    )

    payload = verification_report_json(result)

    assert secret not in payload
    assert "check_id" not in payload
    assert '"reason"' not in payload


def test_unknown_reason_code_is_not_exported():
    secret = "secret_cookie_value"
    result = make_result(reason_code=secret)

    with pytest.raises(ValueError, match="not supported"):
        verification_report_json(result)


def test_reason_code_contracts_do_not_drift():
    schema_path = (
        Path(__file__).parents[1] / "schemas" / "regression-batch-report-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    schema_reasons = set(
        schema["$defs"]["verification"]["properties"]["reason_code"]["enum"]
    )

    assert schema_reasons == sqli_report._REPORT_REASON_CODES

    analyzer_path = Path(sqli_analyzer.__file__)
    tree = ast.parse(analyzer_path.read_text(encoding="utf-8"))
    analyzer_reasons = {
        node.args[1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "result"
        and len(node.args) >= 2
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
    }

    assert analyzer_reasons <= schema_reasons
    assert "no_boolean_difference_literal_input" in analyzer_reasons


@pytest.mark.parametrize("reason_code", ["insufficient_evidence", "connection_error"])
def test_step_39_reason_codes_remain_supported(reason_code):
    report = verification_report_dict(make_result(reason_code=reason_code))

    assert report["reason_code"] == reason_code


def test_literal_input_reason_code_is_supported():
    report = verification_report_dict(
        make_result(
            verdict=Verdict.NOT_DETECTED,
            observations=(
                observation(ProbeKind.BASELINE),
                observation(ProbeKind.TRUE),
                observation(ProbeKind.FALSE),
            ),
            request_count=3,
            reason_code="no_boolean_difference_literal_input",
            evidence=BooleanEvidence(0.0, 0.0, 1.0),
        )
    )

    assert report["reason_code"] == "no_boolean_difference_literal_input"


def test_future_model_fields_are_not_implicitly_exported():
    result = ExtendedVerificationResult(
        check_id="internal",
        verdict=Verdict.INCONCLUSIVE,
        observations=(),
        request_count=0,
        reason_code="budget_unavailable",
        reason="Internal reason.",
    )

    payload = verification_report_json(result)

    assert result.future_secret not in payload
    assert "future_secret" not in payload


def test_observations_are_explicitly_serialized():
    result = make_result(
        observations=(observation(ProbeKind.BASELINE),),
        request_count=1,
    )

    report = verification_report_dict(result)
    item = report["observations"][0]

    assert item == {
        "kind": "baseline",
        "status_code": 200,
        "body_size": 0,
        "elapsed": 0.1,
        "body_digest": EMPTY_DIGEST,
        "truncated": False,
    }


def test_probe_failures_are_serialized():
    failure = ProbeFailure(
        kind=ProbeKind.TRUE,
        error=ProbeError.TIMEOUT,
        elapsed=None,
    )
    result = make_result(
        failures=(failure,),
        request_count=1,
        reason_code="probe_failed",
    )

    report = verification_report_dict(result)

    assert report["failures"] == [
        {
            "kind": "true",
            "error": "timeout",
            "elapsed": None,
        }
    ]


def test_boolean_evidence_is_serialized():
    observations = (
        observation(ProbeKind.BASELINE),
        observation(ProbeKind.TRUE),
        observation(ProbeKind.FALSE),
    )

    result = make_result(
        verdict=Verdict.NOT_DETECTED,
        observations=observations,
        request_count=3,
        reason_code="no_boolean_difference",
        evidence=BooleanEvidence(
            baseline_true_similarity=1.0,
            baseline_false_similarity=1.0,
            true_false_similarity=1.0,
        ),
    )

    report = verification_report_dict(result)

    assert report["verdict"] == "not_detected"
    assert report["evidence"] == {
        "baseline_true_similarity": 1.0,
        "baseline_false_similarity": 1.0,
        "true_false_similarity": 1.0,
    }


def test_json_is_deterministic():
    result = make_result()

    first = verification_report_json(result)
    second = verification_report_json(result)

    assert first == second
    assert json.loads(first)["schema_version"] == 1


def test_pretty_json_round_trip():
    result = make_result()

    compact = verification_report_json(result)
    pretty = verification_report_json(result, pretty=True)

    assert json.loads(compact) == json.loads(pretty)
    assert "\n" in pretty
    assert len(pretty) > len(compact)
    assert pretty == verification_report_json(result, pretty=True)
    assert "\n" not in compact
    assert ": " not in compact


@pytest.mark.parametrize(
    "invalid",
    [None, {}, "not-a-result", 123],
)
def test_invalid_result_is_rejected(invalid):
    with pytest.raises(TypeError):
        verification_report_dict(invalid)


@pytest.mark.parametrize("invalid", [None, 0, "true"])
def test_invalid_pretty_flag_is_rejected(invalid):
    with pytest.raises(TypeError):
        verification_report_json(
            make_result(),
            pretty=invalid,
        )


def test_rate_limited_result_is_serializable():
    result = make_result(
        observations=(
            Observation(
                kind=ProbeKind.BASELINE,
                status_code=429,
                body_size=0,
                elapsed=0.02,
                body_digest=EMPTY_DIGEST,
                truncated=True,
            ),
        ),
        request_count=1,
        reason_code="rate_limited",
    )

    report = json.loads(verification_report_json(result))

    assert report["verdict"] == "inconclusive"
    assert report["reason_code"] == "rate_limited"
    assert report["observations"][0]["status_code"] == 429
    assert report["observations"][0]["truncated"] is True
    assert report["failures"] == []


@pytest.mark.parametrize("verdict", list(Verdict))
def test_all_verdicts_are_serialized(verdict):
    if verdict is Verdict.INCONCLUSIVE:
        result = make_result(verdict=verdict)
    else:
        observations = (
            observation(ProbeKind.BASELINE),
            observation(ProbeKind.TRUE),
            observation(ProbeKind.FALSE),
        )
        result = make_result(
            verdict=verdict,
            observations=observations,
            request_count=3,
            reason_code=(
                "boolean_differential"
                if verdict is Verdict.VULNERABLE
                else "no_boolean_difference"
            ),
            evidence=BooleanEvidence(1.0, 0.0, 0.0),
        )

    report = verification_report_dict(result)

    assert report["verdict"] == verdict.value


@pytest.mark.parametrize("error", list(ProbeError))
def test_all_probe_errors_are_serialized(error):
    failure = ProbeFailure(
        kind=ProbeKind.TRUE,
        error=error,
        elapsed=1,
    )
    result = make_result(
        failures=(failure,),
        request_count=1,
        reason_code="probe_failed",
    )

    report = verification_report_dict(result)

    assert report["failures"][0]["error"] == error.value
    assert report["failures"][0]["elapsed"] == 1.0
    assert type(report["failures"][0]["elapsed"]) is float


def test_numeric_measurements_are_normalized_to_json_floats():
    observation_with_large_elapsed = Observation(
        kind=ProbeKind.BASELINE,
        status_code=200,
        body_size=0,
        elapsed=10**300,
        body_digest=EMPTY_DIGEST,
    )
    result = make_result(
        observations=(observation_with_large_elapsed,),
        request_count=1,
        confidence=1,
    )

    report = verification_report_dict(result)
    payload = verification_report_json(result)

    assert report["observations"][0]["elapsed"] == 1e300
    assert type(report["observations"][0]["elapsed"]) is float
    assert report["confidence"] == 1.0
    assert type(report["confidence"]) is float
    assert "1e+300" in payload


def test_mutating_report_does_not_change_result_or_future_reports():
    original_observation = observation(ProbeKind.BASELINE)
    result = make_result(
        observations=(original_observation,),
        request_count=1,
    )
    report = verification_report_dict(result)

    report["observations"][0]["status_code"] = 500
    report["observations"].append({"secret": "added by caller"})

    fresh_report = verification_report_dict(result)

    assert result.observations == (original_observation,)
    assert fresh_report["observations"][0]["status_code"] == 200
    assert len(fresh_report["observations"]) == 1
