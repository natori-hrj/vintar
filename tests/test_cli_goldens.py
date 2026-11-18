"""Compare deterministic CLI results with the committed golden files."""

import runpy
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
