"""Scan a complete Git history with a pinned, verified Gitleaks release."""

import hashlib
import json
import os
import platform
import subprocess
import sys
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.request import urlopen

VERSION = "8.30.1"
ARCHIVE = f"gitleaks_{VERSION}_linux_x64.tar.gz"
URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{VERSION}/{ARCHIVE}"
SHA256 = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
FINDINGS = 42
SCANNER_ERROR = 2
REMEDIATION = (
    "Commit rejected because Gitleaks detected a possible secret. "
    "Revoke or rotate any real credential, remove it from the affected commits, "
    "and supply the replacement through an environment variable or your CI secret store. "
    "If the match is a test fixture, replace it with a descriptive placeholder "
    "or generate it at runtime."
)


def verified_archive() -> Path:
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise RuntimeError("The pinned Gitleaks binary requires Linux x86-64.")

    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    cache = cache / "vintar" / "gitleaks"
    cache.mkdir(parents=True, exist_ok=True)
    archive = cache / ARCHIVE
    if archive.exists():
        verify_checksum(archive)
        return archive

    with TemporaryDirectory(dir=cache) as directory:
        download = Path(directory) / ARCHIVE
        try:
            with urlopen(URL, timeout=30) as response, download.open("wb") as output:
                output.write(response.read(16 * 1024 * 1024))
        except (OSError, TimeoutError) as exc:
            raise RuntimeError(
                "Could not download the pinned Gitleaks archive."
            ) from exc

        verify_checksum(download)
        download.replace(archive)
    return archive


def verify_checksum(archive: Path) -> None:
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if digest != SHA256:
        raise RuntimeError(
            "Gitleaks archive SHA-256 mismatch. Remove the cached archive and download the pinned release again."
        )


def scan(directory: Path, *, release_contents: Path | None = None) -> int:
    if release_contents is None:
        history = subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            capture_output=True,
            text=True,
            check=False,
        )
        if history.returncode or history.stdout.strip() != "false":
            raise RuntimeError(
                "A shallow or invalid checkout cannot be scanned. Use a complete Git checkout."
            )
        mode = [
            "git",
            "--log-opts=--all --reflog --full-history -m --no-ext-diff --no-textconv",
        ]
        target = "."
        scope = "Git history"
    else:
        if not release_contents.is_dir():
            raise RuntimeError(
                "Release contents are missing. Unpack the verified distributions first."
            )
        mode = ["dir"]
        target = str(release_contents.resolve())
        scope = "release contents"

    binary = directory / "gitleaks"
    with tarfile.open(verified_archive(), "r:gz") as archive:
        member = archive.getmember("gitleaks")
        if not member.isfile() or (executable := archive.extractfile(member)) is None:
            raise RuntimeError("The verified archive has no Gitleaks executable.")
        with executable:
            binary.write_bytes(executable.read())
    binary.chmod(0o700)

    config = directory / "gitleaks.toml"
    config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    empty_ignore_file = directory / "empty.ignore"
    empty_ignore_file.touch()
    report = directory / "report.json"

    result = subprocess.run(
        [
            str(binary),
            *mode,
            "--redact=100",
            "--ignore-gitleaks-allow",
            "--gitleaks-ignore-path",
            str(empty_ignore_file),
            "--config",
            str(config),
            "--exit-code",
            str(FINDINGS),
            "--report-format",
            "json",
            "--report-path",
            str(report),
            target,
        ],
        capture_output=True,
        check=False,
    )

    if result.returncode == 0:
        print(f"Gitleaks {VERSION} found no secrets in {scope}.")
        return 0
    if result.returncode != FINDINGS:
        raise RuntimeError(
            f"Gitleaks exited unexpectedly with code {result.returncode}."
        )

    findings = json.loads(report.read_text(encoding="utf-8"))
    if not isinstance(findings, list) or not findings:
        raise RuntimeError("Gitleaks reported findings without a usable report.")
    message = (
        REMEDIATION
        if release_contents is None
        else REMEDIATION.replace("Commit rejected", "Release contents rejected")
    )
    print(message, file=sys.stderr)
    for finding in findings:
        location = {
            key: finding[key] for key in ("File", "Commit", "StartLine", "RuleID")
        }
        print(json.dumps(location), file=sys.stderr)
    return FINDINGS


def main(*, release_contents: Path | None = None) -> int:
    try:
        with TemporaryDirectory(prefix="vintar-gitleaks-") as directory:
            return scan(Path(directory), release_contents=release_contents)
    except RuntimeError as exc:
        print(f"Secret scan failed to run: {exc}", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        print(
            "Secret scan failed to run: could not prepare or read scanner files.",
            file=sys.stderr,
        )
    return SCANNER_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
