"""Verify one release build before it can be uploaded as a CI artifact."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
from pathlib import Path
from zipfile import ZipFile

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from scripts.check_distributions import build_distributions, smoke_wheel
from scripts.run_ci_e2e import run_e2e
from scripts.scan_git_history import main as scan_secrets

ROOT = Path(__file__).resolve().parents[1]


class AuditExecutionError(RuntimeError):
    """The auditor could not verify the dependency set."""


class AuditFindings(RuntimeError):
    """The auditor identified vulnerable dependencies."""


def release_version(root: Path) -> str:
    version = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"
    ]["version"]
    sections = re.split(
        r"(?m)^#{2,6} ", (root / "CHANGELOG.md").read_text(encoding="utf-8")
    )
    matching = [
        section
        for section in sections[1:]
        if section.partition("\n")[0].strip() == version
    ]
    if len(matching) != 1 or not re.search(r"(?m)^- \S", matching[0]):
        raise ValueError(
            f"CHANGELOG.md needs one populated section for project version {version}. "
            "Add or update the matching version heading and its release notes."
        )
    return version


def command(args: list[str], guidance: str) -> str:
    try:
        return subprocess.run(
            args, check=True, capture_output=True, text=True, timeout=300
        ).stdout
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{guidance}\n{exc.stderr[-2000:]}") from exc
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(guidance) from exc


def supported_interpreters() -> list[str]:
    guidance = (
        "Could not determine supported CPython versions from uv. "
        "Update the pinned uv catalog and make CPython 3.13 available."
    )
    catalog = command(
        ["uv", "python", "list", ">=3.13", "--all-versions", "--output-format", "json"],
        guidance,
    )
    minors = set()
    try:
        for entry in json.loads(catalog):
            if (
                entry["implementation"] == "cpython"
                and entry["variant"] == "default"
                and (match := re.fullmatch(r"3\.(\d+)\.\d+", entry["version"]))
            ):
                minors.add(int(match[1]))
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError(guidance) from exc
    if 13 not in minors:
        raise RuntimeError(guidance)
    return [f"3.{minor}" for minor in sorted(minors) if minor >= 13]


def audit(requirements: Path, label: str) -> dict[str, str]:
    failure = (
        f"Dependency audit could not verify {label}. "
        "Check the dependency input and vulnerability service, then rerun the rehearsal."
    )
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--strict",
                "--disable-pip",
                "--no-deps",
                "--format",
                "json",
                "--requirement",
                str(requirements),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditExecutionError(failure) from exc

    try:
        records = json.loads(result.stdout)["dependencies"]
        if not isinstance(records, list) or not records:
            raise ValueError
        packages = {}
        findings = []
        for record in records:
            name, version, vulns = record["name"], record["version"], record["vulns"]
            if (
                "skip_reason" in record
                or not isinstance(name, str)
                or not name
                or not isinstance(version, str)
                or not version
                or not isinstance(vulns, list)
            ):
                raise ValueError
            name = canonicalize_name(name)
            if name in packages:
                raise ValueError
            packages[name] = version
            for vulnerability in vulns:
                identifier = vulnerability["id"]
                if not isinstance(identifier, str) or not identifier:
                    raise ValueError
                findings.append(f"{name}=={version}: {identifier}")
    except (KeyError, TypeError, ValueError) as exc:
        raise AuditExecutionError(f"{failure}\n{result.stderr[-2000:]}") from exc

    if result.returncode == 1 and findings:
        raise AuditFindings(
            f"Vulnerable dependencies in {label}. Update the affected dependencies "
            f"and regenerate uv.lock before rerunning:\n" + "\n".join(findings)
        )
    if result.returncode != 0 or findings:
        raise AuditExecutionError(f"{failure}\n{result.stderr[-2000:]}")
    print(f"Dependency audit verified {len(packages)} packages in {label}.", flush=True)
    return packages


def installed_packages(python: Path, version: str) -> tuple[str, dict[str, str]]:
    inventory = command(
        [
            str(python),
            "-I",
            "-c",
            (
                "import json, platform; from importlib.metadata import distributions; "
                "print(json.dumps([platform.python_version(), "
                "[(d.metadata['Name'], d.version) for d in distributions()]]))"
            ),
        ],
        "Could not inspect installed wheel metadata. Fix the wheel install and rerun.",
    )
    interpreter, records = json.loads(inventory)
    packages = {}
    for name, installed_version in records:
        name = canonicalize_name(name)
        if name in packages:
            raise ValueError(
                f"The clean install contains duplicate metadata for {name}. "
                "Fix the wheel or its dependencies before rerunning."
            )
        packages[name] = installed_version
    if packages.pop("vintar", None) != version or not packages:
        raise ValueError(
            f"The clean wheel install must contain vintar {version} and its runtime "
            "dependencies. Fix the wheel metadata and rebuild."
        )
    return interpreter, packages


def locked_packages(requirements: Path, interpreter: str) -> dict[str, str]:
    environment = {
        "python_version": interpreter.rsplit(".", 1)[0],
        "python_full_version": interpreter,
        "implementation_version": interpreter,
    }
    packages = {}
    for line in requirements.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        requirement = Requirement(line)
        if requirement.marker and not requirement.marker.evaluate(environment):
            continue
        name = canonicalize_name(requirement.name)
        specifiers = list(requirement.specifier)
        if (
            name in packages
            or requirement.url
            or len(specifiers) != 1
            or specifiers[0].operator != "=="
            or "*" in specifiers[0].version
        ):
            raise AuditExecutionError(
                f"The lock export has an ambiguous or unpinned entry for {name}. "
                "Regenerate uv.lock with exactly one pinned version per interpreter."
            )
        packages[name] = specifiers[0].version
    return packages


def audit_inventory(path: Path, label: str, packages: dict[str, str]) -> None:
    path.write_text(
        "".join(f"{name}=={release}\n" for name, release in sorted(packages.items())),
        encoding="utf-8",
    )
    if audit(path, label) != packages:
        raise AuditExecutionError(
            f"The audit inventory differs from the expected {label}. "
            "Fix the audit dependency input before rerunning."
        )


def write_sbom(path: Path, version: str, packages: dict[str, str]) -> None:
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {"type": "application", "name": "vintar", "version": version}
        },
        "components": [
            {
                "type": "library",
                "name": name,
                "version": release,
                "purl": f"pkg:pypi/{name}@{release}",
            }
            for name, release in sorted(packages.items())
        ],
    }
    serialized = json.dumps(document, indent=2) + "\n"
    if error := JsonStrictValidator(SchemaVersion.V1_6).validate_str(serialized):
        raise ValueError(f"CycloneDX SBOM is invalid. Fix the SBOM generator: {error}")
    path.write_text(serialized, encoding="utf-8")


def distribution_hashes(distributions: tuple[Path, Path]) -> str:
    lines = []
    for path in sorted(distributions):
        with path.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        lines.append(f"{digest}  {path.name}\n")
    return "".join(lines)


def verify_contents(wheel: Path, sdist: Path, destination: Path) -> int:
    with ZipFile(wheel) as archive:
        archive.extractall(destination / "wheel")
    with tarfile.open(sdist, "r:gz") as archive:
        archive.extractall(destination / "sdist", filter="data")
    return scan_secrets(release_contents=destination)


def verify_install(
    wheel: Path, workspace: Path, version: str, python_version: str, locked: Path
) -> None:
    print(f"Verifying installed wheel on CPython {python_version}.", flush=True)
    environment = smoke_wheel(wheel, workspace, python_version=python_version)
    try:
        run_e2e(workspace / "loopback", executable=environment / "bin" / "vintar")
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(
            f"Installed loopback E2E failed on CPython {python_version}. "
            f"Fix the wheel CLI or its exit/report contract: {exc}"
        ) from exc
    interpreter, packages = installed_packages(environment / "bin" / "python", version)
    if interpreter.rsplit(".", 1)[0] != python_version:
        raise RuntimeError(
            f"The wheel install used CPython {interpreter}; expected {python_version}. "
            "Install the requested interpreter and rerun."
        )
    audit_inventory(
        workspace / "locked.txt",
        f"CPython {python_version} locked runtime dependencies",
        locked_packages(locked, interpreter),
    )
    audit_inventory(
        workspace / "installed.txt",
        f"CPython {python_version} wheel dependencies",
        packages,
    )
    write_sbom(
        wheel.parent / f"sbom-cpython-{python_version}.cdx.json", version, packages
    )


def rehearse(output: Path, interpreters: list[str]) -> int:
    if output.is_relative_to(ROOT) or output.exists():
        raise ValueError(
            "The artifact directory must be new and outside the checkout. Pick a fresh path."
        )
    if len(set(interpreters)) != len(interpreters) or any(
        not re.fullmatch(r"3\.\d+", version) for version in interpreters
    ):
        raise ValueError(
            "The interpreter matrix is invalid. Supply distinct CPython minor versions."
        )
    version = release_version(ROOT)
    output.mkdir(parents=True)
    distributions = build_distributions(output)
    if distributions is None:
        return 2
    hashes = distribution_hashes(distributions)
    wheel, sdist = distributions
    with tempfile.TemporaryDirectory(prefix="vintar-release-") as temporary:
        work = Path(temporary)
        result = verify_contents(wheel, sdist, work / "contents")
        if result != 0:
            return result
        locked = work / "runtime-locked.txt"
        command(
            [
                "uv",
                "export",
                "--locked",
                "--no-dev",
                "--no-emit-project",
                "--no-hashes",
                "--format",
                "requirements.txt",
                "--output-file",
                str(locked),
            ],
            "Could not export locked runtime dependencies. Regenerate uv.lock and rerun.",
        )
        for python_version in interpreters:
            installation = work / f"cpython-{python_version}"
            installation.mkdir()
            verify_install(wheel, installation, version, python_version, locked)
    if distribution_hashes(distributions) != hashes:
        raise ValueError(
            "The build changed during verification. Fix the artifact mutation and rebuild."
        )
    (output / "SHA256SUMS").write_text(hashes, encoding="utf-8")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        return rehearse(args.output.resolve(), supported_interpreters())
    except AuditFindings as exc:
        print(exc, file=sys.stderr)
        return 1
    except (OSError, RuntimeError, ValueError, KeyError, tarfile.TarError) as exc:
        print(
            f"Release rehearsal failed: {exc}\n"
            "Correct the reported issue and rerun the workflow before using the artifacts.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
