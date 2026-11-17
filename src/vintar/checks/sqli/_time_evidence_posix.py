"""Shared descriptor-relative POSIX acquisition boundary for local evidence.

The caller performs platform capability checks. This internal module
provides confinement and metadata consistency, not an atomic snapshot.
"""

import os
import stat
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from vintar.checks.sqli.time_evidence import MAX_EVIDENCE_BYTES

MAX_CHUNK_SIZE = 64 * 1024
_MAX_ROOT_DEPTH = 64
_MAX_ROOT_PATH_LENGTH = 4096
_MAX_DEPTH = 16
_MAX_RELATIVE_PATH_LENGTH = 1024
_SAFE_FILENAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
)


class EvidenceAcquisitionError(RuntimeError):
    """Evidence could not be acquired under the local safety policy."""


def require_posix() -> None:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if os.name != "posix" or any(not hasattr(os, name) for name in required):
        raise EvidenceAcquisitionError(
            "Secure local evidence acquisition is unsupported."
        )
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        raise EvidenceAcquisitionError(
            "Directory-relative file opening is unsupported."
        )


def root_components(root: str | Path) -> tuple[str, ...]:
    if isinstance(root, Path):
        value = str(root)
    elif type(root) is str:
        value = root
    else:
        raise TypeError("Invalid evidence root.")
    if (
        not value.startswith("/")
        or value == "/"
        or len(value) > _MAX_ROOT_PATH_LENGTH
        or "\x00" in value
        or value.endswith("/")
        or "//" in value
    ):
        raise ValueError("Invalid evidence root.")
    components = tuple(value[1:].split("/"))
    if not 1 <= len(components) <= _MAX_ROOT_DEPTH or any(
        component in ("", ".", "..") or len(component) > 255 for component in components
    ):
        raise ValueError("Invalid evidence root.")
    return components


def relative_components(relative_path: str) -> tuple[str, ...]:
    if type(relative_path) is not str:
        raise TypeError("Invalid relative evidence path.")
    if not 1 <= len(relative_path) <= _MAX_RELATIVE_PATH_LENGTH:
        raise ValueError("Invalid relative evidence path.")
    components = tuple(relative_path.split("/"))
    if not 1 <= len(components) <= _MAX_DEPTH:
        raise ValueError("Invalid relative evidence path.")
    if any(
        not component
        or component in (".", "..")
        or len(component) > 100
        or any(character not in _SAFE_FILENAME_CHARS for character in component)
        for component in components
    ):
        raise ValueError("Invalid relative evidence path.")
    return components


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _file_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | os.O_NONBLOCK
        | getattr(os, "O_NOCTTY", 0)
    )


def stable_file(before: os.stat_result, after: os.stat_result) -> bool:
    attributes = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(before, name) == getattr(after, name) for name in attributes)


def validate_file_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceAcquisitionError("Evidence is not a regular file.")
    if metadata.st_nlink != 1:
        raise EvidenceAcquisitionError("Evidence has an unsupported link count.")
    if not 1 <= metadata.st_size <= MAX_EVIDENCE_BYTES:
        raise EvidenceAcquisitionError(
            "Evidence file size is outside the allowed range."
        )


@contextmanager
def managed_fd(fd: int) -> Iterator[int]:
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def open_confined_evidence(
    *,
    root: str | Path,
    relative_path: str,
    checkpoint: Callable[[], None] | None = None,
    pre_open_check: Callable[[os.stat_result], None] | None = None,
) -> Iterator[tuple[int, os.stat_result]]:
    """Yield a validated regular-file FD and its pre-read metadata.

    The descriptor remains owned by this context manager. The caller must
    finish reading and call validate_after_read before leaving the scope.
    """
    roots = root_components(root)
    parts = relative_components(relative_path)

    def check() -> None:
        if checkpoint is not None:
            checkpoint()

    with ExitStack() as stack:
        check()
        directory_fd = stack.enter_context(managed_fd(os.open("/", _directory_flags())))
        for component in (*roots, *parts[:-1]):
            check()
            directory_fd = stack.enter_context(
                managed_fd(os.open(component, _directory_flags(), dir_fd=directory_fd))
            )
        check()
        path_metadata = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
        validate_file_metadata(path_metadata)
        if pre_open_check is not None:
            pre_open_check(path_metadata)
        check()
        file_fd = stack.enter_context(
            managed_fd(os.open(parts[-1], _file_flags(), dir_fd=directory_fd))
        )
        before = os.fstat(file_fd)
        validate_file_metadata(before)
        if not stable_file(path_metadata, before):
            raise EvidenceAcquisitionError("Evidence changed during acquisition.")
        if pre_open_check is not None:
            pre_open_check(before)
        yield file_fd, before


def validate_after_read(*, file_fd: int, before: os.stat_result, received: int) -> None:
    """Check metadata stability and exact byte count after a bounded read."""
    after = os.fstat(file_fd)
    if not stable_file(before, after):
        raise EvidenceAcquisitionError("Evidence changed during acquisition.")
    if received != before.st_size:
        raise EvidenceAcquisitionError("Evidence length changed during acquisition.")
