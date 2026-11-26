"""Bounded descriptor-based reads for trusted local input files."""

import os
import stat
from pathlib import Path

_open = os.open
_fstat = os.fstat
_read = os.read
_close = os.close


class NoFollowUnavailableError(OSError):
    """The platform cannot safely open an operator-selected local file."""


def read_bounded_regular_file(path: str | Path, limit: int) -> bytes:
    """Read one regular file through the same bounded, no-follow descriptor."""
    if type(limit) is not int or limit < 0:
        raise ValueError("Invalid file size limit.")

    nofollow = getattr(os, "O_NOFOLLOW", None)
    if type(nofollow) is not int or nofollow == 0:
        raise NoFollowUnavailableError(
            "This platform cannot open files without following symlinks. "
            "Use a trusted non-file input or a platform with O_NOFOLLOW support."
        )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOINHERIT", 0)
    flags |= nofollow
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)

    descriptor = _open(os.fspath(path), flags)
    try:
        metadata = _fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("Input is not a regular file.")
        if metadata.st_size > limit:
            raise ValueError("Input exceeds its size limit.")

        chunks = bytearray()
        while len(chunks) <= limit:
            request_size = min(65_536, limit + 1 - len(chunks))
            chunk = _read(descriptor, request_size)
            if not chunk:
                break
            chunks.extend(chunk)

        if len(chunks) > limit:
            raise ValueError("Input exceeds its size limit.")
        return bytes(chunks)
    finally:
        _close(descriptor)
