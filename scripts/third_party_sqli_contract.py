"""Shared image identity rules for the third-party SQLi harness."""

import re

_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def is_image_digest(value: object) -> bool:
    """Return whether a value is an exact Docker SHA-256 image digest."""
    return type(value) is str and _IMAGE_DIGEST.fullmatch(value) is not None


def pinned_image_digest(reference: object) -> str | None:
    """Return the digest from one exact name@sha256 reference."""
    if type(reference) is not str or reference.count("@") != 1:
        return None
    name, digest = reference.split("@")
    if not name or any(character.isspace() for character in name):
        return None
    return digest if is_image_digest(digest) else None
