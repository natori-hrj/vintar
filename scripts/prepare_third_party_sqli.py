"""Fetch, verify, and locally build the pinned third-party SQLi target."""

import argparse
import hashlib
import json
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DECLARATIONS = ROOT / "third_party" / "sqli" / "targets.toml"
STATE_NAME = "prepared-target.json"


class PreparationError(RuntimeError):
    """An actionable target preparation failure."""


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_target() -> dict[str, object]:
    """Load the reviewed target declaration."""
    with DECLARATIONS.open("rb") as stream:
        document = tomllib.load(stream)
    target = document.get("target")
    if type(target) is not dict:
        raise PreparationError(
            "The third-party target declaration is invalid. Check targets.toml instead of preparing an unreviewed target."
        )
    return target


def load_records() -> list[dict[str, object]]:
    """Load the reviewed source-evidence records."""
    with DECLARATIONS.open("rb") as stream:
        document = tomllib.load(stream)
    records = document.get("records")
    if type(records) is not list:
        raise PreparationError(
            "The third-party source declarations are invalid. Check targets.toml instead of preparing unreviewed source."
        )
    result: list[dict[str, object]] = []
    for record in records:
        if type(record) is not dict:
            raise PreparationError(
                "A third-party source declaration is invalid. Supply reviewed record tables in targets.toml."
            )
        result.append(record)
    return result


def target_text(target: dict[str, object], key: str) -> str:
    """Read one required nonempty declaration string."""
    value = target.get(key)
    if type(value) is not str or not value:
        raise PreparationError(
            f"The reviewed target has an invalid {key}. Supply a nonempty value in targets.toml."
        )
    return value


def download_archive(url: str, destination: Path) -> None:
    """Download to a temporary file and publish only a complete archive."""
    try:
        with (
            urllib.request.urlopen(url, timeout=60) as response,
            tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as output,
        ):
            temporary = Path(output.name)
            while block := response.read(1024 * 1024):
                output.write(block)
    except (OSError, urllib.error.URLError) as exc:
        raise PreparationError(
            "The pinned DSVW archive could not be fetched. Check network access during preparation and rerun; measurement itself does not download dependencies."
        ) from exc
    temporary.replace(destination)


def extract_archive(archive: Path, destination: Path) -> Path:
    """Extract the verified archive and return its single source root."""
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            roots = {
                Path(member.name).parts[0]
                for member in bundle.getmembers()
                if Path(member.name).parts
            }
            if len(roots) != 1:
                raise PreparationError(
                    "The pinned DSVW archive has an unexpected layout. Check the reviewed archive digest instead of building it."
                )
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise PreparationError(
            "The pinned DSVW archive could not be extracted. Remove the preparation workspace and fetch the reviewed archive again."
        ) from exc
    root = destination / roots.pop()
    if not root.is_dir():
        raise PreparationError(
            "The pinned DSVW source root is missing. Remove the preparation workspace and fetch the reviewed archive again."
        )
    return root


def source_manifest_sha256(root: Path) -> str:
    """Hash the paths, kinds, links, and contents in one build context."""
    digest = hashlib.sha256()
    for path in sorted(
        root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
    ):
        relative = path.relative_to(root).as_posix().encode()
        if path.is_symlink():
            kind = b"link"
            content = path.readlink().as_posix().encode()
        elif path.is_file():
            kind = b"file"
            content = path.read_bytes()
        elif path.is_dir():
            kind = b"directory"
            content = b""
        else:
            raise PreparationError(
                "The verified DSVW archive contains an unsupported build-context entry. Review the pinned archive instead of building it."
            )
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(kind)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def source_fragment_evidence(
    root: Path, record: dict[str, object]
) -> tuple[str, dict[str, object]]:
    """Record one reviewed source reference and its observed fragment hash."""
    record_id = record.get("id")
    source_path = record.get("source_path")
    start = record.get("source_start_line")
    end = record.get("source_end_line")
    if (
        type(record_id) is not str
        or not record_id
        or type(source_path) is not str
        or not source_path
        or type(start) is not int
        or type(end) is not int
        or start < 1
        or end < start
    ):
        raise PreparationError(
            "A reviewed source range is invalid. Supply an ID, source path, and positive inclusive line range in targets.toml."
        )
    try:
        lines = (root / source_path).read_bytes().splitlines(keepends=True)
    except OSError as exc:
        raise PreparationError(
            "A reviewed DSVW source file is missing from the verified archive. Check the pinned commit and source declaration."
        ) from exc
    if end > len(lines):
        raise PreparationError(
            "A reviewed DSVW source range is outside the verified file. Check targets.toml against the pinned commit."
        )
    observed = hashlib.sha256(b"".join(lines[start - 1 : end])).hexdigest()
    return record_id, {
        "source_end_line": end,
        "source_fragment_sha256": observed,
        "source_path": source_path,
        "source_start_line": start,
    }


def run_docker(arguments: list[str]) -> str:
    """Run Docker with bounded output and an actionable fixed diagnostic."""
    try:
        completed = subprocess.run(
            ["docker", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreparationError(
            "Docker could not prepare DSVW. Check that Docker is installed, running, and allowed to build local images."
        ) from exc
    if completed.returncode != 0:
        raise PreparationError(
            "Docker could not prepare DSVW. Check the Docker daemon and ensure build dependencies can be fetched during preparation."
        )
    return completed.stdout.strip()


def write_state(path: Path, state: dict[str, object]) -> None:
    """Atomically write nonsensitive preparation metadata."""
    content = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(content)
        output.flush()
    temporary.replace(path)


def prepare(workspace: Path) -> Path:
    """Prepare the exact reviewed target and return its state path."""
    target = load_target()
    records = load_records()
    commit = target_text(target, "commit")
    expected_archive_digest = target_text(target, "archive_sha256")
    workspace.mkdir(parents=True, exist_ok=True)
    archive = workspace / f"dsvw-{commit}.tar.gz"
    if not archive.exists():
        download_archive(target_text(target, "archive_url"), archive)
    observed_archive_digest = sha256_file(archive)
    if observed_archive_digest != expected_archive_digest:
        raise PreparationError(
            "The DSVW archive SHA-256 does not match the reviewed declaration. Remove it and fetch the pinned archive again; do not build unverified source."
        )

    image_tag = f"vintar-third-party-dsvw:{commit[:12]}"
    with tempfile.TemporaryDirectory(
        prefix=".dsvw-verified-source-", dir=workspace
    ) as temporary_source:
        source_root = extract_archive(archive, Path(temporary_source))
        manifest_digest = source_manifest_sha256(source_root)
        source_evidence = dict(
            source_fragment_evidence(source_root, record) for record in records
        )
        run_docker(
            [
                "build",
                "--pull=false",
                "--tag",
                image_tag,
                str(source_root),
            ]
        )
    image_id = run_docker(["image", "inspect", "--format", "{{.Id}}", image_tag])
    if not image_id.startswith("sha256:"):
        raise PreparationError(
            "Docker did not return a content-addressed DSVW image ID. Check the local image store before measurement."
        )

    state_path = workspace / STATE_NAME
    write_state(
        state_path,
        {
            "archive_sha256": observed_archive_digest,
            "commit": commit,
            "image_id": image_id,
            "image_tag": image_tag,
            "schema_version": 1,
            "source_evidence": source_evidence,
            "source_manifest_sha256": manifest_digest,
        },
    )
    return state_path


def main() -> int:
    """Prepare DSVW without running a measurement."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        state_path = prepare(arguments.workspace.resolve())
    except PreparationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Prepared the pinned DSVW image. State: {state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
