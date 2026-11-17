"""Acquire local timing evidence through a confined POSIX file boundary.

This adapter performs filesystem I/O. It does not authenticate the
source or provide an atomic filesystem snapshot.
"""

import os
from pathlib import Path

from vintar.checks.sqli._time_evidence_posix import (
    MAX_CHUNK_SIZE,
    EvidenceAcquisitionError,
    open_confined_evidence,
    validate_after_read,
)
from vintar.checks.sqli._time_evidence_posix import (
    require_posix as _require_posix,
)
from vintar.checks.sqli.time_evidence import MAX_EVIDENCE_BYTES
from vintar.checks.sqli.time_evidence_session import (
    EvidenceCheckStatus,
    VerificationSession,
    check_evidence_in_session,
)


def read_local_evidence(*, root: str | Path, relative_path: str) -> bytes:
    """Read a confined regular file and check pre/post metadata consistency."""
    _require_posix()
    try:
        with open_confined_evidence(root=root, relative_path=relative_path) as (
            file_fd,
            before,
        ):
            chunks: list[bytes] = []
            received = 0
            while True:
                remaining = MAX_EVIDENCE_BYTES + 1 - received
                if remaining <= 0:
                    raise EvidenceAcquisitionError("Evidence exceeds the maximum size.")
                chunk = os.read(file_fd, min(MAX_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                received += len(chunk)
            validate_after_read(file_fd=file_fd, before=before, received=received)
            return b"".join(chunks)
    except OSError:
        raise EvidenceAcquisitionError("Local evidence acquisition failed.") from None


def check_local_evidence_in_session(
    *,
    session: VerificationSession,
    evidence_id: str,
    root: str | Path,
    relative_path: str,
) -> VerificationSession:
    """Acquire bound evidence and return a new verification session."""
    if type(session) is not VerificationSession:
        raise TypeError("Invalid verification session.")
    record = session.binding.index.get(evidence_id)
    if record is None:
        raise ValueError("Evidence identifier is not bound.")
    if session.evidence_status(evidence_id) is not EvidenceCheckStatus.UNCHECKED:
        raise ValueError("Evidence already checked in this session.")
    content = read_local_evidence(root=root, relative_path=relative_path)
    return check_evidence_in_session(
        session=session, evidence_id=evidence_id, content=content
    )
