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


def test_mismatched_tag_fails_with_fixed_message(version):
    tag = "v999.999.999"
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


@pytest.mark.parametrize("tag_pattern", ["{}", "v{}rc1", "v0{}"])
def test_malformed_tags_fail_with_format_error(version, tag_pattern):
    tag = tag_pattern.format(version)
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--", tag],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr == (
        f"Release tag {tag!r} is not a stable release tag. Use vMAJOR.MINOR.PATCH.\n"
    )


@pytest.mark.parametrize(
    ("tag", "message"),
    [
        (
            "v1.2.3",
            (
                "Package version '1.2.3rc1' is not a stable release version. "
                "Set a MAJOR.MINOR.PATCH version before tagging."
            ),
        ),
        (
            "v1.2.3rc1",
            "Release tag 'v1.2.3rc1' is not a stable release tag. Use vMAJOR.MINOR.PATCH.",
        ),
    ],
)
def test_malformed_package_version_and_tag_format_errors(tmp_path, tag, message):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    script = scripts / SCRIPT.name
    script.write_bytes(SCRIPT.read_bytes())
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nversion = "1.2.3rc1"\n', encoding="utf-8"
    )
    result = subprocess.run(
        [sys.executable, str(script), "--", tag],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert result.stderr == f"{message}\n"
