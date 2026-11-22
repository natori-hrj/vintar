"""Exercise the documentation drift guard in an isolated Git checkout."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    ("test_body", "exit_code", "summary"),
    [
        (
            (
                "def test_probe(tmp_path):\n"
                '    doc = tmp_path / "CHANGELOG.md"\n'
                '    doc.write_text("generated")\n'
                '    assert doc.read_text() == "generated"\n'
            ),
            0,
            "1 passed",
        ),
        (
            'def test_probe():\n    assert Path("README.md").read_text()\n',
            1,
            "without the doc_drift marker",
        ),
        (
            (
                "@pytest.mark.doc_drift\n"
                "def test_probe():\n"
                "    assert Path(__file__).is_file()\n"
            ),
            1,
            "marked doc_drift but read no Git-tracked",
        ),
    ],
)
def test_doc_drift_tracks_only_indexed_markdown(
    tmp_path, test_body, exit_code, summary
):
    checkout = tmp_path / "checkout"
    tests = checkout / "tests"
    tests.mkdir(parents=True)
    shutil.copyfile(Path(__file__).with_name("conftest.py"), tests / "conftest.py")
    (checkout / "README.md").write_text("tracked")
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True, timeout=10)
    subprocess.run(
        ["git", "add", "--", "README.md"], cwd=checkout, check=True, timeout=10
    )
    (tests / "test_probe.py").write_text(
        f"from pathlib import Path\nimport pytest\n\n{test_body}"
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-o",
            "markers=doc_drift: checks documentation",
            f"--basetemp={checkout / 'basetemp'}",
        ],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == exit_code, result.stdout + result.stderr
    assert summary in result.stdout, result.stdout + result.stderr
