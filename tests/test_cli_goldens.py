"""Compare deterministic CLI results with the committed golden files."""

import json
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

_UPDATE = runpy.run_path(
    str(Path(__file__).resolve().parents[1] / "scripts/update_cli_goldens.py")
)
GOLDEN_DIR = _UPDATE["GOLDEN_DIR"]
SCENARIOS = _UPDATE["SCENARIOS"]
UPDATE_COMMAND = _UPDATE["UPDATE_COMMAND"]
capture = _UPDATE["capture"]


def test_cli_golden_inventory():
    actual = {
        path.relative_to(GOLDEN_DIR).as_posix()
        for path in GOLDEN_DIR.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    expected = set(SCENARIOS)
    assert actual == expected, (
        f"CLI golden inventory differs. Missing: {sorted(expected - actual)}. "
        f"Unexpected: {sorted(actual - expected)}. "
        f"If intentional, remove obsolete files and run {UPDATE_COMMAND}."
    )


@pytest.mark.parametrize("name", SCENARIOS)
def test_cli_golden(name, tmp_path):
    path = GOLDEN_DIR / name
    update = f"If intentional, run {UPDATE_COMMAND}."
    assert path.is_file(), f"Missing CLI golden {name}. {update}"
    try:
        actual = capture(name, SCENARIOS[name], tmp_path)
    except ValueError as error:
        pytest.fail(f"CLI contract failed for {name}: {error} {update}")

    assert actual == path.read_text(encoding="utf-8"), (
        f"CLI output differs from golden {name}. {update}"
    )


def test_every_verify_golden_report_passes_ci_validator(tmp_path):
    validator = Path("scripts/validate_ci_report.py").resolve()
    validated = []
    for name, scenario in SCENARIOS.items():
        if not name.startswith("verify/"):
            continue
        capture_data = json.loads((GOLDEN_DIR / name).read_text(encoding="utf-8"))
        report = capture_data["stdout_json"]
        if report is None:
            continue
        path = tmp_path / name.replace("/", "-")
        path.write_text(json.dumps(report), encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, str(validator), str(path), str(scenario.exit_code)],
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 0, name
        assert completed.stdout == ""
        assert completed.stderr == ""
        validated.append(name)

    assert validated == [
        name
        for name in SCENARIOS
        if name.startswith("verify/") and SCENARIOS[name].exit_code != 2
    ]
