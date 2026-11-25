"""Test the release gate against the repository's pyproject.toml."""

import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_release_tag.py"


@pytest.fixture
def version():
    with (ROOT / "pyproject.toml").open("rb") as pyproject:
        return tomllib.load(pyproject)["project"]["version"]


def test_matching_tag_passes(version):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--", f"v{version}"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stderr == ""


@pytest.mark.parametrize("tag_pattern", ["v999.999.999", "{}", "v{}rc1", "v0{}"])
def test_invalid_tags_fail_with_fixed_message(version, tag_pattern):
    tag = tag_pattern.format(version)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--", tag],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr == (
        f"Release tag {tag!r} and package version {version!r} disagree. "
        "Tag the merged release commit instead.\n"
    )
