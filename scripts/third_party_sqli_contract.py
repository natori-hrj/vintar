"""Shared image identity rules for the third-party SQLi harness."""

import re

_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


class ServiceImageMismatch(ValueError):
    """A resolved auxiliary image mapping contradicts its declaration."""


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


def validate_service_image_mapping(
    target_id: str,
    service_images: object,
    declared_images: object,
) -> dict[str, str]:
    """Validate per-service images against a declaration treated as a set."""
    if type(service_images) is not dict or type(declared_images) is not list:
        raise ServiceImageMismatch(
            f"Service image mismatch for target {target_id!r}, service '<invalid>': declared {declared_images!r}, resolved {service_images!r}. Update targets.toml or the Compose file so they agree."
        )
    declared_set = set(declared_images)
    validated: dict[str, str] = {}
    for service, image in service_images.items():
        if type(service) is not str or not service or type(image) is not str:
            raise ServiceImageMismatch(
                f"Service image mismatch for target {target_id!r}, service {service!r}: declared '<valid service and pinned image>', resolved {image!r}. Update targets.toml or the Compose file so they agree."
            )
        if image not in declared_set:
            same_name = next(
                (
                    reference
                    for reference in declared_images
                    if type(reference) is str
                    and reference.partition("@")[0] == image.partition("@")[0]
                ),
                "<not declared>",
            )
            raise ServiceImageMismatch(
                f"Service image mismatch for target {target_id!r}, service {service!r}: declared {same_name!r}, resolved {image!r}. Update targets.toml or the Compose file so they agree."
            )
        if pinned_image_digest(image) is None:
            raise ServiceImageMismatch(
                f"Service image mismatch for target {target_id!r}, service {service!r}: declared {image!r}, resolved image is not digest-pinned. Update targets.toml or the Compose file so they agree."
            )
        validated[service] = image
    unused = declared_set - set(validated.values())
    if unused:
        declared_image = min(unused, key=str)
        raise ServiceImageMismatch(
            f"Service image mismatch for target {target_id!r}, service '<unused>': declared {declared_image!r}, resolved '<not used>'. Update targets.toml or the Compose file so they agree."
        )
    return validated
