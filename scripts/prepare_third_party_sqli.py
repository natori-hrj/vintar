"""Fetch, verify, and locally build the pinned third-party SQLi target."""

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

from third_party_sqli_contract import (
    is_image_digest,
    pinned_image_digest,
)

ROOT = Path(__file__).resolve().parents[1]
DECLARATIONS = ROOT / "third_party" / "sqli" / "targets.toml"
STATE_NAME = "prepared-targets.json"
_TARGET_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,31}")


class PreparationError(RuntimeError):
    """An actionable target preparation failure."""


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of one file."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def load_declarations() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Load reviewed multi-target declarations."""
    with DECLARATIONS.open("rb") as stream:
        document = tomllib.load(stream)
    targets = document.get("targets")
    records = document.get("records")
    if document.get("version") != 2 or type(targets) is not list:
        raise PreparationError(
            "The third-party target declaration is invalid. Use declaration version 2 with reviewed targets and records instead of preparing unreviewed input."
        )
    if type(records) is not list:
        raise PreparationError(
            "The third-party source declarations are invalid. Check targets.toml instead of preparing unreviewed source."
        )
    typed_targets: list[dict[str, object]] = []
    target_ids: set[str] = set()
    for target in targets:
        if type(target) is not dict:
            raise PreparationError(
                "A third-party target declaration is invalid. Supply a reviewed target table instead."
            )
        target_id = target.get("id")
        if (
            type(target_id) is not str
            or _TARGET_ID.fullmatch(target_id) is None
            or target_id in target_ids
        ):
            raise PreparationError(
                "A third-party target id is invalid or duplicated. Use a unique lowercase target id with letters, digits, or hyphens."
            )
        images = target.get("service_images")
        if type(images) is not list or any(
            pinned_image_digest(image) is None for image in images
        ):
            raise PreparationError(
                f"Target {target_id!r} has an unpinned service image. Use image@sha256:<64 lowercase hex characters> instead of a mutable tag."
            )
        volumes = target.get("fresh_volumes")
        if type(volumes) is not list or any(
            type(volume) is not str or _TARGET_ID.fullmatch(volume) is None
            for volume in volumes
        ):
            raise PreparationError(
                f"Target {target_id!r} has invalid fresh volume declarations. Use lowercase volume names with letters, digits, or hyphens."
            )
        target_ids.add(target_id)
        typed_targets.append(target)
    result: list[dict[str, object]] = []
    labels: dict[tuple[str, str], set[str]] = {}
    for record in records:
        if type(record) is not dict:
            raise PreparationError(
                "A third-party source declaration is invalid. Supply reviewed record tables in targets.toml."
            )
        target_id = record.get("target_id")
        check_type = record.get("check_type")
        label = record.get("label")
        if target_id not in target_ids:
            raise PreparationError(
                "A third-party record references an unknown target. Bind target_id to a reviewed target table."
            )
        if (
            type(target_id) is not str
            or type(check_type) is not str
            or not check_type
            or label not in {"positive", "negative"}
        ):
            raise PreparationError(
                "A third-party record has an invalid check type or label. Supply a supported check type and positive or negative ground truth."
            )
        labels.setdefault((target_id, check_type), set()).add(label)
        result.append(record)
    for (target_id, check_type), observed in labels.items():
        if observed != {"positive", "negative"}:
            raise PreparationError(
                f"Target {target_id!r} check type {check_type!r} lacks a positive or negative record. Supply both reviewed ground-truth labels before preparation."
            )
    unused_targets = target_ids - {target_id for target_id, _ in labels}
    if unused_targets:
        target_id = min(unused_targets)
        raise PreparationError(
            f"Target {target_id!r} has no measurement records. Supply a reviewed check type with both labels before preparation."
        )
    return typed_targets, result


def target_text(target: dict[str, object], key: str) -> str:
    """Read one required nonempty declaration string."""
    value = target.get(key)
    if type(value) is not str or not value:
        raise PreparationError(
            f"The reviewed target has an invalid {key}. Supply a nonempty value in targets.toml."
        )
    return value


def download_archive(url: str, destination: Path, target_id: str) -> None:
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
            f"The pinned {target_id} archive could not be fetched. Check network access during preparation and rerun; measurement itself does not download dependencies."
        ) from exc
    temporary.replace(destination)


def extract_archive(archive: Path, destination: Path, target_id: str) -> Path:
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
                    f"The pinned {target_id} archive has an unexpected layout. Check the reviewed archive digest instead of building it."
                )
            bundle.extractall(destination, filter="data")
    except (OSError, tarfile.TarError) as exc:
        raise PreparationError(
            f"The pinned {target_id} archive could not be extracted. Remove the preparation workspace and fetch the reviewed archive again."
        ) from exc
    root = destination / roots.pop()
    if not root.is_dir():
        raise PreparationError(
            f"The pinned {target_id} source root is missing. Remove the preparation workspace and fetch the reviewed archive again."
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
                "The verified target archive contains an unsupported build-context entry. Review the pinned archive instead of building it."
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
            "A reviewed target source file is missing from the verified archive. Check the pinned commit and source declaration."
        ) from exc
    if end > len(lines):
        raise PreparationError(
            "A reviewed target source range is outside the verified file. Check targets.toml against the pinned commit."
        )
    observed = hashlib.sha256(b"".join(lines[start - 1 : end])).hexdigest()
    return record_id, {
        "source_end_line": end,
        "source_fragment_sha256": observed,
        "source_path": source_path,
        "source_start_line": start,
    }


def run_docker(arguments: list[str], target_id: str) -> str:
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
            f"Docker could not prepare {target_id}. Check that Docker is installed, running, and allowed to build local images."
        ) from exc
    if completed.returncode != 0:
        raise PreparationError(
            f"Docker could not prepare {target_id}. Check the Docker daemon and ensure build dependencies can be fetched during preparation."
        )
    return completed.stdout.strip()


def validate_prepared_image_id(image_id: object, target_id: str) -> str:
    """Require a content-addressed local image before recording state."""
    if not is_image_digest(image_id):
        raise PreparationError(
            f"Docker did not return a valid SHA-256 image ID for {target_id}, so the measured image cannot be identified. Rerun prepare after checking the local image store."
        )
    return image_id


def write_state(path: Path, state: dict[str, object]) -> None:
    """Atomically write nonsensitive preparation metadata."""
    content = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode()
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(content)
        output.flush()
    temporary.replace(path)


def prepare_target(
    workspace: Path,
    target: dict[str, object],
    records: list[dict[str, object]],
) -> dict[str, object]:
    """Prepare one exact reviewed target."""
    target_id = target_text(target, "id")
    commit = target_text(target, "commit")
    expected_archive_digest = target_text(target, "archive_sha256")
    workspace.mkdir(parents=True, exist_ok=True)
    archive = workspace / f"{target_id}-{commit}.tar.gz"
    if not archive.exists():
        download_archive(target_text(target, "archive_url"), archive, target_id)
    observed_archive_digest = sha256_file(archive)
    if observed_archive_digest != expected_archive_digest:
        raise PreparationError(
            f"The {target_id} archive SHA-256 does not match the reviewed declaration. Remove it and fetch the pinned archive again; do not build unverified source."
        )

    image_tag = f"vintar-third-party-{target_id}:{commit[:12]}"
    with tempfile.TemporaryDirectory(
        prefix=f".{target_id}-verified-source-", dir=workspace
    ) as temporary_source:
        source_root = extract_archive(archive, Path(temporary_source), target_id)
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
            ],
            target_id,
        )
    image_id = run_docker(
        ["image", "inspect", "--format", "{{.Id}}", image_tag], target_id
    )
    image_id = validate_prepared_image_id(image_id, target_id)
    return {
        "archive_sha256": observed_archive_digest,
        "commit": commit,
        "image_id": image_id,
        "image_tag": image_tag,
        "source_evidence": source_evidence,
        "source_manifest_sha256": manifest_digest,
    }


def prepare(workspace: Path) -> Path:
    """Prepare every reviewed target and return the shared state path."""
    targets, records = load_declarations()
    workspace.mkdir(parents=True, exist_ok=True)
    prepared = {
        target_text(target, "id"): prepare_target(
            workspace,
            target,
            [record for record in records if record["target_id"] == target["id"]],
        )
        for target in targets
    }

    state_path = workspace / STATE_NAME
    write_state(
        state_path,
        {
            "schema_version": 2,
            "targets": prepared,
        },
    )
    return state_path


def main() -> int:
    """Prepare reviewed targets without running a measurement."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        state_path = prepare(arguments.workspace.resolve())
    except PreparationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Prepared the pinned third-party target images. State: {state_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
