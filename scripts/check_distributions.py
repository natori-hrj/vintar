"""Build and verify the wheel and source distribution for CI."""

import os
import subprocess
import sys
import tarfile
import tomllib
from collections import Counter
from configparser import ConfigParser
from configparser import Error as ConfigError
from email import message_from_bytes
from pathlib import Path
from tempfile import TemporaryDirectory
from zipfile import BadZipFile, ZipFile

from packaging.requirements import Requirement

ROOT = Path(__file__).resolve().parents[1]
ENTRY_POINT = "vintar.cli:app"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def check_members(label: str, names: list[str], expected: set[str]) -> None:
    counts = Counter(names)
    missing = sorted(expected - counts.keys())
    unexpected = sorted(counts.keys() - expected)
    duplicates = sorted(name for name, count in counts.items() if count > 1)
    require(
        not (missing or unexpected or duplicates),
        f"{label} contents differ from the expected distribution. "
        f"Missing: {missing}. Unexpected: {unexpected}. Duplicates: {duplicates}. "
        "Fix the build inputs so the archive contains the package and required release files only.",
    )


def check_metadata(label: str, raw: bytes, project: dict) -> None:
    metadata = message_from_bytes(raw)
    summary = metadata["Summary"]
    require(
        bool(summary and summary.strip() and summary != "Add your description here")
        and summary == project["description"],
        f"{label} has a missing, placeholder, or mismatched summary. "
        "Set a real one-line project.description and rebuild.",
    )
    for field, expected in (
        ("Name", "vintar"),
        ("Version", project["version"]),
        ("Requires-Python", project["requires-python"]),
        ("License-Expression", "Apache-2.0"),
    ):
        require(
            metadata[field] == expected,
            f"{label} has incorrect {field}. Set it to {expected!r} in the project metadata and rebuild.",
        )
    require(
        metadata.get_all("License-File", []) == ["LICENSE"],
        f"{label} must declare LICENSE. Set project.license-files and rebuild.",
    )
    actual_dependencies = Counter(
        Requirement(value) for value in metadata.get_all("Requires-Dist", [])
    )
    expected_dependencies = Counter(
        Requirement(value) for value in project["dependencies"]
    )
    require(
        actual_dependencies == expected_dependencies,
        f"{label} runtime dependencies differ from project.dependencies. "
        "Declare runtime dependencies there and rebuild.",
    )


def check_distributions(root: Path, output: Path) -> tuple[Path, Path]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]
    license_text = (root / "LICENSE").read_bytes()
    source_files = {
        file.relative_to(root / "src").as_posix()
        for file in (root / "src" / "vintar").rglob("*")
        if file.is_file()
        and (
            file.suffix == ".py"
            or file.relative_to(root / "src").as_posix()
            == "vintar/schemas/regression-case-v2.schema.json"
        )
    }
    require(
        {"vintar/__init__.py", "vintar/cli.py"} <= source_files,
        "The vintar package or CLI module is missing. Restore it under src/vintar and rebuild.",
    )
    wheels = list(output.glob("*.whl"))
    sdists = list(output.glob("*.tar.gz"))
    require(
        len(wheels) == len(sdists) == 1,
        "Missing or duplicate release archives. Build one wheel and one sdist into an empty directory.",
    )
    distribution = f"vintar-{project['version']}"
    info = f"{distribution}.dist-info"
    wheel_license = f"{info}/licenses/LICENSE"

    with ZipFile(wheels[0]) as wheel:
        check_members(
            "Wheel",
            [member.filename for member in wheel.infolist() if not member.is_dir()],
            source_files
            | {
                wheel_license,
                *(
                    f"{info}/{name}"
                    for name in ("METADATA", "WHEEL", "RECORD", "entry_points.txt")
                ),
            },
        )
        check_metadata("Wheel", wheel.read(f"{info}/METADATA"), project)
        require(
            wheel.read(wheel_license) == license_text,
            "The wheel license differs from LICENSE. Include the repository license and rebuild.",
        )
        entries = ConfigParser(interpolation=None)
        entries.read_string(wheel.read(f"{info}/entry_points.txt").decode("utf-8"))
        require(
            entries.get("console_scripts", "vintar", fallback=None) == ENTRY_POINT,
            "The wheel has an incorrect console entry point. Set project.scripts.vintar to vintar.cli:app.",
        )

    with tarfile.open(sdists[0], "r:gz") as sdist:
        members = [member for member in sdist.getmembers() if not member.isdir()]
        require(
            all(member.isfile() for member in members),
            "The sdist contains a non-regular file. Remove links and special files from the build inputs.",
        )
        expected = {
            "LICENSE",
            "README.md",
            "CHANGELOG.md",
            "pyproject.toml",
            "pyproject.toml.orig",
            "PKG-INFO",
        }
        expected.update(f"src/{name}" for name in source_files)
        check_members(
            "Sdist",
            [member.name for member in members],
            {f"{distribution}/{name}" for name in expected},
        )
        check_metadata("Sdist", read_sdist(sdist, f"{distribution}/PKG-INFO"), project)
        require(
            read_sdist(sdist, f"{distribution}/LICENSE") == license_text,
            "The sdist license differs from LICENSE. Include the repository license and rebuild.",
        )
        packaged_project = tomllib.loads(
            read_sdist(sdist, f"{distribution}/pyproject.toml").decode("utf-8")
        )["project"]
        require(
            packaged_project.get("scripts", {}).get("vintar") == ENTRY_POINT,
            "The sdist has an incorrect console entry point. Set project.scripts.vintar to vintar.cli:app.",
        )
    return wheels[0], sdists[0]


def read_sdist(archive: tarfile.TarFile, name: str) -> bytes:
    stream = archive.extractfile(name)
    if stream is None:
        raise ValueError(f"Cannot read {name}. Rebuild the sdist from regular files.")
    with stream:
        return stream.read()


def inspect_distributions(root: Path, output: Path) -> tuple[Path, Path] | None:
    try:
        return check_distributions(root, output)
    except (
        ValueError,
        OSError,
        KeyError,
        ConfigError,
        BadZipFile,
        tarfile.TarError,
    ) as error:
        print(
            f"Distribution check failed: {error} "
            "Correct the build inputs and rebuild with uv build --no-sources.",
            file=sys.stderr,
        )
        return None


def smoke_command(
    command: list[str],
    *,
    directory: Path,
    environment: dict[str, str],
    failure: str,
    expected_exit: int = 0,
    show_stdout: bool = False,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            cwd=directory,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as error:
        raise ValueError(f"{failure} Could not start {command[0]}: {error}") from error
    if result.returncode != expected_exit:
        diagnostic = (
            f"{failure} Expected exit {expected_exit}, got {result.returncode}. "
            f"{result.stderr.strip()}"
        )
        if show_stdout:
            diagnostic += f"\n{help_excerpt(result.stdout)}"
        raise ValueError(diagnostic)
    return result


def help_excerpt(output: str) -> str:
    return f"Captured help stdout (last 2000 characters): {output[-2000:]!r}"


def smoke_wheel(wheel: Path, directory: Path, *, python_version: str = "3.13") -> Path:
    require(
        not directory.resolve().is_relative_to(ROOT),
        "The wheel smoke directory is inside the checkout. Set TMPDIR to a location outside the repository.",
    )
    environment = os.environ.copy()
    for name in (
        "PYTHONPATH",
        "PYTHONHOME",
        "VIRTUAL_ENV",
        "VINTAR_TARGET_ORIGIN",
        "VINTAR_ALLOWED_ORIGIN",
    ):
        environment.pop(name, None)
    environment["NO_COLOR"] = "1"

    venv = directory / "wheel-venv"
    python = str(venv / "bin" / "python")
    cli = str(venv / "bin" / "vintar")

    def run(
        command: list[str],
        failure: str,
        *,
        expected_exit: int = 0,
        show_stdout: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        return smoke_command(
            command,
            directory=directory,
            environment=environment,
            failure=failure,
            expected_exit=expected_exit,
            show_stdout=show_stdout,
        )

    run(
        ["uv", "venv", "--python", f"cpython@{python_version}", str(venv)],
        f"Could not create the smoke-test environment. Install Python {python_version} and retry.",
    )
    run(
        ["uv", "pip", "install", "--python", python, str(wheel)],
        "The wheel could not be installed. Fix its package metadata or restore access to the dependency index.",
    )
    run(
        ["uv", "pip", "check", "--python", python],
        "The wheel's installed dependencies are inconsistent. Fix the runtime dependency declarations.",
    )

    environment = {
        "NO_COLOR": "1",
        "TERM": "dumb",
        "COLUMNS": "100",
        "PYTHONIOENCODING": "utf-8",
    }
    installed = run(
        [
            python,
            "-I",
            "-c",
            "from importlib.metadata import version; print(version('vintar'))",
        ],
        "Could not read the installed version. Ensure the wheel includes vintar distribution metadata.",
    ).stdout.strip()
    version = run(
        [cli, "version"],
        "The installed version command failed. Fix the console entry point and rebuild the wheel.",
    )
    require(
        bool(installed) and version.stdout == f"Vintar v{installed}\n",
        "The CLI version differs from the installed metadata. Read the version from importlib.metadata.",
    )
    help_output = run(
        [cli, "verify", "--help"],
        "The installed verify help command failed. Ensure the wheel includes the verify command.",
        show_stdout=True,
    )
    require(
        "--cases" in help_output.stdout and "--authorized" in help_output.stdout,
        "Installed verify help is missing the expected options. Restore --cases and --authorized.\n"
        f"{help_excerpt(help_output.stdout)}",
    )
    unauthorized = run(
        [cli, "verify", "--cases", "case.toml"],
        "The installed CLI returned the wrong status without authorization. Reject before verification with exit 2.",
        expected_exit=2,
    )
    require(
        unauthorized.stdout == ""
        and unauthorized.stderr
        == "Error: explicit testing authorization is required.\n",
        "Unexpected output without authorization. Emit only the authorization diagnostic on stderr.",
    )
    return venv


def build_distributions(output: Path) -> tuple[Path, Path] | None:
    try:
        subprocess.run(
            ["uv", "build", "--no-sources", "--out-dir", str(output)],
            cwd=ROOT,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        print(
            "Distribution build failed. Fix the uv build errors and rebuild.",
            file=sys.stderr,
        )
        return None

    distributions = inspect_distributions(ROOT, output)
    if distributions is None:
        return None
    try:
        subprocess.run(
            [
                sys.executable,
                "-m",
                "twine",
                "check",
                "--strict",
                *map(str, distributions),
            ],
            check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        print(
            "Twine rejected the distributions. Fix the reported package metadata or README and rebuild.",
            file=sys.stderr,
        )
        return None
    return distributions


def main() -> int:
    with TemporaryDirectory(prefix="vintar-distributions-") as directory:
        output = Path(directory)
        distributions = build_distributions(output)
        if distributions is None:
            return 1
        wheel, _ = distributions
        try:
            smoke_wheel(wheel, output)
        except ValueError as error:
            print(f"Installed-wheel smoke test failed: {error}", file=sys.stderr)
            return 1
        print("Installed-wheel smoke test passed on Python 3.13.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
