"""Acquire local timing evidence through a confined POSIX file boundary.

This adapter performs filesystem I/O. It does not authenticate the
evidence source or provide an atomic filesystem snapshot.
"""

import os
import stat
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from pathlib import Path

from vintar.checks.sqli.time_evidence import MAX_EVIDENCE_BYTES
from vintar.checks.sqli.time_evidence_session import (
    EvidenceCheckStatus,
    VerificationSession,
    check_evidence_in_session,
)

_CHUNK_SIZE = 64 * 1024
_MAX_ROOT_DEPTH = 64
_MAX_ROOT_PATH_LENGTH = 4096
_MAX_DEPTH = 16
_MAX_RELATIVE_PATH_LENGTH = 1024
_SAFE_FILENAME_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-"
)


class EvidenceAcquisitionError(RuntimeError):
    """Evidence could not be acquired under the local safety policy."""


def _require_posix() -> None:
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


def _root_components(root: str | Path) -> tuple[str, ...]:
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


def _relative_components(relative_path: str) -> tuple[str, ...]:
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


def _stable_file(before: os.stat_result, after: os.stat_result) -> bool:
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


def _validate_file_metadata(metadata: os.stat_result) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise EvidenceAcquisitionError("Evidence is not a regular file.")

    if metadata.st_nlink != 1:
        raise EvidenceAcquisitionError("Evidence has an unsupported link count.")

    if not 1 <= metadata.st_size <= MAX_EVIDENCE_BYTES:
        raise EvidenceAcquisitionError(
            "Evidence file size is outside the allowed range."
        )


def read_local_evidence(
    *,
    root: str | Path,
    relative_path: str,
) -> bytes:
    """Read a regular file below a symlink-free absolute root.

    Every path component is opened relative to a held directory FD.
    A bounded read and before/after fstat checks limit common races.
    These checks do not provide transactional filesystem isolation.
    """
    _require_posix()
    roots = _root_components(root)
    parts = _relative_components(relative_path)

    try:
        with ExitStack() as stack:
            directory_fd = stack.enter_context(
                _managed_fd(os.open("/", _directory_flags()))
            )

            for component in roots:
                directory_fd = stack.enter_context(
                    _managed_fd(
                        os.open(
                            component,
                            _directory_flags(),
                            dir_fd=directory_fd,
                        )
                    )
                )

            for component in parts[:-1]:
                directory_fd = stack.enter_context(
                    _managed_fd(
                        os.open(
                            component,
                            _directory_flags(),
                            dir_fd=directory_fd,
                        )
                    )
                )

            path_metadata = os.stat(
                parts[-1],
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            _validate_file_metadata(path_metadata)

            file_fd = stack.enter_context(
                _managed_fd(
                    os.open(
                        parts[-1],
                        _file_flags(),
                        dir_fd=directory_fd,
                    )
                )
            )

            before = os.fstat(file_fd)
            _validate_file_metadata(before)

            if not _stable_file(path_metadata, before):
                raise EvidenceAcquisitionError("Evidence changed during acquisition.")

            chunks: list[bytes] = []
            received = 0

            while True:
                remaining = MAX_EVIDENCE_BYTES + 1 - received
                if remaining <= 0:
                    raise EvidenceAcquisitionError("Evidence exceeds the maximum size.")

                chunk = os.read(file_fd, min(_CHUNK_SIZE, remaining))
                if not chunk:
                    break

                chunks.append(chunk)
                received += len(chunk)

            after = os.fstat(file_fd)

            if not _stable_file(before, after):
                raise EvidenceAcquisitionError("Evidence changed during acquisition.")

            if received != before.st_size:
                raise EvidenceAcquisitionError(
                    "Evidence length changed during acquisition."
                )

            return b"".join(chunks)

    except OSError:
        raise EvidenceAcquisitionError("Local evidence acquisition failed.") from None


@contextmanager
def _managed_fd(fd: int) -> Iterator[int]:
    """Yield an owned file descriptor and close it on every exit path."""
    try:
        yield fd
    finally:
        os.close(fd)


def check_local_evidence_in_session(
    *,
    session: VerificationSession,
    evidence_id: str,
    root: str | Path,
    relative_path: str,
) -> VerificationSession:
    """Acquire one bound artifact and register its byte-integrity check.

    Acquisition errors leave the caller's original session unchanged.
    A well-formed but digest-mismatching file yields MISMATCHED.
    """
    if type(session) is not VerificationSession:
        raise TypeError("Invalid verification session.")

    record = session.binding.index.get(evidence_id)

    if record is None:
        raise ValueError("Evidence identifier is not bound.")

    if session.evidence_status(evidence_id) is not EvidenceCheckStatus.UNCHECKED:
        raise ValueError("Evidence already checked in this session.")

    content = read_local_evidence(
        root=root,
        relative_path=relative_path,
    )

    return check_evidence_in_session(
        session=session,
        evidence_id=evidence_id,
        content=content,
    )
