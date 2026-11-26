"""POST JSON review schema validator contracts."""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_post_json_review import SENTINEL, inputs, refresh_inventory_and_answer

from vintar.regression.post_json_review import (
    PostJsonReviewError,
    resolve_post_json_review,
)

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = ROOT / "scripts" / "validate_post_json_review.py"


def run(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(VALIDATOR), str(path)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_review_validator_accepts_generated_redacted_artifact(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path)
    report = resolve_post_json_review(spec, inventory, answers).report
    path = tmp_path / "review.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    completed = run(path)

    assert (completed.returncode, completed.stdout, completed.stderr) == (0, "", "")


def test_review_validator_retains_v1_backward_compatibility(tmp_path):
    spec, inventory, answers, _ = inputs(tmp_path)
    report = resolve_post_json_review(spec, inventory, answers).report
    report["schema_version"] = 1
    report.pop("identity_id")
    path = tmp_path / "legacy-review-v1.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    completed = run(path)

    assert (completed.returncode, completed.stdout, completed.stderr) == (0, "", "")
    assert SENTINEL not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update(private=SENTINEL),
        lambda report: report["operation"].update(approved=1),
        lambda report: report["side_effect"].update(confirmed="true"),
        lambda report: report["environment"].update(confirmed=1),
        lambda report: report["field"].update(concrete_json_pointer="/items/*"),
        lambda report: report["field"].update(literal_star_positions=[0]),
        lambda report: report["field"].update(
            json_pointer_pattern="/items/*", concrete_json_pointer="/items/*"
        ),
    ],
)
def test_review_validator_rejects_mutations_without_echo(tmp_path, mutation):
    spec, inventory, answers, _ = inputs(tmp_path)
    report = resolve_post_json_review(spec, inventory, answers).report
    mutation(report)
    path = tmp_path / "review.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    completed = run(path)

    assert completed.returncode == 2 and completed.stdout == ""
    assert SENTINEL not in completed.stderr


@pytest.mark.parametrize(
    ("schema", "body", "pointer", "valid"),
    [
        ({"properties": {"*": {"type": "string"}}}, {"*": "a"}, "/*", True),
        ({"properties": {"*": {"type": "string"}}}, ["a"], "/0", False),
        ({"properties": {"0": {"type": "string"}}}, ["a"], "/0", False),
        ({"properties": {"0": {"type": "string"}}}, {"0": "a"}, "/0", True),
        ({"properties": {"a*/~": {"type": "string"}}}, {"a*/~": "a"}, "/a*~1~0", True),
        (
            {"items": {"items": {"properties": {"*": {"type": "string"}}}}},
            [[{"*": "a"}]],
            "/0/0/*",
            True,
        ),
    ],
)
def test_review_pointer_matches_schema_container(
    tmp_path, schema, body, pointer, valid
):
    spec, inventory, answers, answer = inputs(tmp_path)
    document = json.loads(spec.read_text())
    media = document["paths"]["/items"]["post"]["requestBody"]["content"][
        "application/json"
    ]
    media.update(schema=schema, example=body)
    spec.write_text(json.dumps(document))
    answer["concrete_pointer"] = pointer
    answer["baseline"] = {
        "value": body,
        "body_sha256": hashlib.sha256(
            json.dumps(body, separators=(",", ":")).encode()
        ).hexdigest(),
    }
    refresh_inventory_and_answer(spec, inventory, answers, answer)
    if not valid:
        with pytest.raises(PostJsonReviewError):
            resolve_post_json_review(spec, inventory, answers)
        return
    report = resolve_post_json_review(spec, inventory, answers).report
    output = tmp_path / "review.json"
    output.write_text(json.dumps(report))
    assert run(output).returncode == 0
