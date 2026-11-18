"""Exercise distribution inspection with local synthetic archives."""

import runpy
import tarfile
from io import BytesIO
from zipfile import ZipFile

import pytest

inspect_distributions = runpy.run_path("scripts/check_distributions.py")[
    "inspect_distributions"
]

DIST = "vintar-0.1.0"
INFO = f"{DIST}.dist-info"
SUMMARY = "Run regression checks in CI."
LICENSE_TEXT = b"Synthetic license file for archive inspection tests.\n"
PROJECT = f"""[project]
name = "vintar"
version = "0.1.0"
description = "{SUMMARY}"
requires-python = ">=3.13"
license = "Apache-2.0"
license-files = ["LICENSE"]
dependencies = ["httpx>=0.28.1"]

[project.scripts]
vintar = "vintar.cli:app"
""".encode()
METADATA = f"""Metadata-Version: 2.4
Name: vintar
Version: 0.1.0
Summary: {SUMMARY}
Requires-Python: >=3.13
Requires-Dist: httpx>=0.28.1
License-Expression: Apache-2.0
License-File: LICENSE

""".encode()


@pytest.fixture
def archive_inputs(tmp_path):
    modules = {
        "vintar/__init__.py": b"",
        "vintar/cli.py": b"def app():\n    return None\n",
    }
    for name, contents in modules.items():
        path = tmp_path / "src" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
    (tmp_path / "pyproject.toml").write_bytes(PROJECT)
    (tmp_path / "LICENSE").write_bytes(LICENSE_TEXT)

    wheel = {
        **modules,
        f"{INFO}/METADATA": METADATA,
        f"{INFO}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{INFO}/RECORD": b"",
        f"{INFO}/entry_points.txt": b"[console_scripts]\nvintar = vintar.cli:app\n",
        f"{INFO}/licenses/LICENSE": LICENSE_TEXT,
    }
    sdist = {
        **{f"src/{name}": contents for name, contents in modules.items()},
        "PKG-INFO": METADATA,
        "README.md": b"# Vintar\n",
        "CHANGELOG.md": b"# Changelog\n",
        "pyproject.toml": PROJECT,
        "pyproject.toml.orig": PROJECT,
        "LICENSE": LICENSE_TEXT,
    }
    return {"wheel": list(wheel.items()), "sdist": list(sdist.items())}


def write_archives(output, archive_inputs):
    output.mkdir()
    wheel = output / f"{DIST}-py3-none-any.whl"
    with ZipFile(wheel, "w") as archive:
        for name, data in archive_inputs["wheel"]:
            if name in archive.namelist():
                with pytest.warns(UserWarning, match="Duplicate name"):
                    archive.writestr(name, data)
            else:
                archive.writestr(name, data)

    sdist = output / f"{DIST}.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, data in archive_inputs["sdist"]:
            item = tarfile.TarInfo(f"{DIST}/{name}")
            item.size = len(data)
            archive.addfile(item, BytesIO(data))
    return wheel, sdist


def test_accepts_valid_wheel_and_sdist(tmp_path, archive_inputs, capsys):
    output = tmp_path / "dist"
    expected = write_archives(output, archive_inputs)

    assert inspect_distributions(tmp_path, output) == expected
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize(
    ("kind", "filename", "operation", "reason", "remediation"),
    [
        (
            "wheel",
            "vintar/__pycache__/cli.pyc",
            "extra",
            "Unexpected: ['vintar/__pycache__/cli.pyc']",
            "Fix the build inputs",
        ),
        (
            "sdist",
            "PROJECT_VISION.md",
            "extra",
            f"Unexpected: ['{DIST}/PROJECT_VISION.md']",
            "Fix the build inputs",
        ),
        (
            "wheel",
            f"{INFO}/licenses/LICENSE",
            "missing",
            f"Missing: ['{INFO}/licenses/LICENSE']",
            "Fix the build inputs",
        ),
        (
            "sdist",
            "LICENSE",
            "missing",
            f"Missing: ['{DIST}/LICENSE']",
            "Fix the build inputs",
        ),
        (
            "wheel",
            "vintar/cli.py",
            "duplicate",
            "Duplicates: ['vintar/cli.py']",
            "Fix the build inputs",
        ),
        (
            "sdist",
            "src/vintar/cli.py",
            "duplicate",
            f"Duplicates: ['{DIST}/src/vintar/cli.py']",
            "Fix the build inputs",
        ),
        (
            "wheel",
            f"{INFO}/entry_points.txt",
            "entry point",
            "The wheel has an incorrect console entry point.",
            "Set project.scripts.vintar to vintar.cli:app.",
        ),
        (
            "sdist",
            "pyproject.toml",
            "entry point",
            "The sdist has an incorrect console entry point.",
            "Set project.scripts.vintar to vintar.cli:app.",
        ),
        (
            "wheel",
            f"{INFO}/METADATA",
            "summary",
            "Wheel has a missing, placeholder, or mismatched summary.",
            "Set a real one-line project.description and rebuild.",
        ),
        (
            "sdist",
            "PKG-INFO",
            "summary",
            "Sdist has a missing, placeholder, or mismatched summary.",
            "Set a real one-line project.description and rebuild.",
        ),
    ],
)
def test_rejects_invalid_archive_with_actionable_diagnostic(
    tmp_path, archive_inputs, capsys, kind, filename, operation, reason, remediation
):
    members = archive_inputs[kind]
    if operation == "extra":
        members.append((filename, b"Unexpected fixture data"))
    elif operation == "missing":
        members.remove((filename, LICENSE_TEXT))
    else:
        index = next(
            index for index, (name, _) in enumerate(members) if name == filename
        )
        _, data = members[index]
        if operation == "duplicate":
            members.append((filename, data))
        elif operation == "entry point":
            members[index] = (
                filename,
                data.replace(b"vintar.cli:app", b"vintar.cli:wrong"),
            )
        else:
            placeholder = b"Add your description here"
            members[index] = (filename, data.replace(SUMMARY.encode(), placeholder))
            if kind == "wheel":
                (tmp_path / "pyproject.toml").write_bytes(
                    PROJECT.replace(SUMMARY.encode(), placeholder)
                )
    output = tmp_path / "dist"
    write_archives(output, archive_inputs)

    assert inspect_distributions(tmp_path, output) is None
    diagnostic = capsys.readouterr().err
    assert diagnostic.startswith("Distribution check failed:")
    assert reason in diagnostic
    assert remediation in diagnostic
