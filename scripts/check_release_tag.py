"""Check that a release tag matches the version at the tagged commit."""

import argparse
import re
import tomllib
from pathlib import Path


def project_version(root: Path) -> str:
    with (root / "pyproject.toml").open("rb") as pyproject:
        return tomllib.load(pyproject)["project"]["version"]


def validate_release_tag(tag: str, version: str) -> None:
    if tag != f"v{version}" or not re.fullmatch(
        r"v(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*)){2}", tag, re.ASCII
    ):
        raise ValueError(
            f"Release tag {tag!r} and package version {version!r} disagree. "
            "Tag the merged release commit instead."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tag")
    args = parser.parse_args()
    version = project_version(Path(__file__).resolve().parents[1])
    try:
        validate_release_tag(args.tag, version)
    except ValueError as error:
        raise SystemExit(str(error)) from None


if __name__ == "__main__":
    main()
