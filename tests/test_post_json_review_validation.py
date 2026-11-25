"""POST JSON review schema validator contracts."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
from test_post_json_review import SENTINEL, inputs

from vintar.regression.post_json_review import resolve_post_json_review

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
    assert SENTINEL not in path.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update(private=SENTINEL),
        lambda report: report["operation"].update(approved=1),
        lambda report: report["side_effect"].update(confirmed="true"),
        lambda report: report["environment"].update(confirmed=1),
        lambda report: report["field"].update(concrete_json_pointer="/items/*"),
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
