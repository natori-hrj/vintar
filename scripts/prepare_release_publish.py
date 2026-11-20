"""Revalidate the release tag and stage verified files still absent from PyPI."""

import argparse
import json
import os
import re
import shutil
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class PublishPreflightError(ValueError):
    """Publishing cannot proceed safely."""


def read_json(url: str, *, token: str | None = None) -> object:
    headers = {"Accept": "application/json", "Cache-Control": "no-cache"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    with urlopen(Request(url, headers=headers), timeout=30) as response:
        return json.load(response)


def verify_remote_tag(
    api: str, repository: str, tag: str, commit: str, token: str
) -> None:
    base = f"{api}/repos/{repository}/git"
    url = f"{base}/ref/tags/{quote(tag, safe='')}"
    moved = (
        f"Publishing stopped because tag {tag} moved or was deleted after verification. "
        "Do not move the tag back. Cut a new patch version tag from the intended commit."
    )
    unavailable = "Publishing stopped because the remote tag could not be verified. Check GitHub API access and retry."
    for _ in range(16):
        try:
            response = read_json(url, token=token)
        except HTTPError as exc:
            raise PublishPreflightError(
                moved if exc.code == 404 else unavailable
            ) from exc
        except (URLError, OSError, ValueError) as exc:
            raise PublishPreflightError(unavailable) from exc
        target = response.get("object") if isinstance(response, dict) else None
        if not isinstance(target, dict):
            raise PublishPreflightError(unavailable)
        sha = target.get("sha")
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise PublishPreflightError(unavailable)
        if target.get("type") == "commit":
            if sha != commit:
                raise PublishPreflightError(moved)
            return
        if target.get("type") != "tag":
            raise PublishPreflightError(moved)
        url = f"{base}/tags/{sha}"
    raise PublishPreflightError(
        "Publishing stopped because the tag has too many annotation levels. "
        "Cut a new patch version tag directly from the intended commit."
    )


def verified_distributions(artifact: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in (artifact / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+(?:\.whl|\.tar\.gz))", line
        )
        if match is None or match[2] in entries:
            raise PublishPreflightError(
                "The verified checksum manifest is invalid. Rerun release verification."
            )
        entries[match[2]] = match[1]
    if (
        sum(name.endswith(".whl") for name in entries) != 1
        or sum(name.endswith(".tar.gz") for name in entries) != 1
    ):
        raise PublishPreflightError(
            "The checksum manifest must list one wheel and one sdist. Rerun release verification."
        )
    return entries


def published_distributions(version: str) -> dict[str, str]:
    unavailable = (
        f"Publishing stopped because PyPI metadata for vintar {version} could not be verified. "
        "Check PyPI availability and rerun the release."
    )
    try:
        response = read_json(
            f"https://pypi.org/pypi/vintar/{quote(version, safe='')}/json"
        )
    except HTTPError as exc:
        if exc.code == 404:
            return {}
        raise PublishPreflightError(unavailable) from exc
    except (URLError, OSError, ValueError) as exc:
        raise PublishPreflightError(unavailable) from exc
    files = response.get("urls") if isinstance(response, dict) else None
    if not isinstance(files, list):
        raise PublishPreflightError(unavailable)
    published: dict[str, str] = {}
    for file in files:
        digests = file.get("digests") if isinstance(file, dict) else None
        digest = digests.get("sha256") if isinstance(digests, dict) else None
        name = file.get("filename") if isinstance(file, dict) else None
        if (
            not isinstance(name, str)
            or name in published
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise PublishPreflightError(unavailable)
        published[name] = digest
    return published


def stage_pypi(artifact: Path, destination: Path, version: str) -> bool:
    verified = verified_distributions(artifact)
    published = published_distributions(version)
    missing = []
    for name, digest in verified.items():
        if name not in published:
            missing.append(name)
        elif published[name] != digest:
            raise PublishPreflightError(
                f"Publishing stopped because PyPI already has {name} with a different SHA-256. "
                "A new version is required. Cut a new patch version release."
            )
    if not missing:
        return False
    destination.mkdir()
    for name in missing:
        shutil.copyfile(artifact / name, destination / name)
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check-tag")
    stage = commands.add_parser("stage-pypi")
    stage.add_argument("artifact", type=Path)
    stage.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        tag = os.environ["GITHUB_REF_NAME"]
        if args.command == "check-tag":
            verify_remote_tag(
                os.environ["GITHUB_API_URL"],
                os.environ["GITHUB_REPOSITORY"],
                tag,
                os.environ["GITHUB_SHA"],
                os.environ["GH_TOKEN"],
            )
        else:
            pending = stage_pypi(args.artifact, args.destination, tag.removeprefix("v"))
            print(f"upload={str(pending).lower()}")
    except PublishPreflightError as exc:
        print(exc, file=sys.stderr)
        return 2
    except (OSError, KeyError, ValueError):
        print(
            "Publishing stopped during preflight. Check the verified artifact and workflow configuration, then rerun.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
