"""Regression tests for the shared confined POSIX evidence boundary."""

import os
from pathlib import Path

import pytest

from vintar.checks.sqli._time_evidence_posix import (
    EvidenceAcquisitionError,
    open_confined_evidence,
    relative_components,
    require_posix,
    root_components,
    validate_after_read,
)
from vintar.checks.sqli.time_evidence_loader import read_local_evidence

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Requires POSIX")


def test_shared_boundary_opens_regular_file(tmp_path: Path):
    content = b"local evidence"
    (tmp_path / "evidence").write_bytes(content)
    require_posix()
    with open_confined_evidence(root=tmp_path, relative_path="evidence") as (
        fd,
        before,
    ):
        assert os.read(fd, len(content)) == content
        validate_after_read(file_fd=fd, before=before, received=len(content))
    with pytest.raises(OSError):
        os.fstat(fd)


def test_shared_boundary_supports_nested_paths(tmp_path: Path):
    directory = tmp_path / "subdir"
    directory.mkdir()
    (directory / "file.txt").write_bytes(b"data")
    with open_confined_evidence(root=tmp_path, relative_path="subdir/file.txt") as (
        fd,
        before,
    ):
        assert os.read(fd, 4) == b"data"
        validate_after_read(file_fd=fd, before=before, received=4)


@pytest.mark.parametrize(
    "relative_path",
    ("../escape", "subdir/../file", "./file", "/etc/passwd", "a//b", "a\\b"),
)
def test_shared_boundary_rejects_traversal(tmp_path: Path, relative_path: str):
    with (
        pytest.raises(ValueError, match="relative evidence path"),
        open_confined_evidence(root=tmp_path, relative_path=relative_path),
    ):
        pytest.fail("Invalid path was opened")


def test_shared_boundary_rejects_file_symlink(tmp_path: Path):
    (tmp_path / "real").write_bytes(b"data")
    (tmp_path / "alias").symlink_to(tmp_path / "real")
    with (
        pytest.raises((EvidenceAcquisitionError, OSError)),
        open_confined_evidence(root=tmp_path, relative_path="alias"),
    ):
        pytest.fail("Symlink was followed")


def test_shared_boundary_rejects_directory_symlink(tmp_path: Path):
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "file").write_bytes(b"data")
    (tmp_path / "alias").symlink_to(actual, target_is_directory=True)
    with (
        pytest.raises((EvidenceAcquisitionError, OSError)),
        open_confined_evidence(root=tmp_path, relative_path="alias/file"),
    ):
        pytest.fail("Directory symlink was followed")


def test_shared_boundary_rejects_fifo_without_open(tmp_path: Path, monkeypatch):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO unavailable")
    os.mkfifo(tmp_path / "pipe")
    original_open = os.open
    opened_fifo = False

    def tracked_open(path, *args, **kwargs):
        nonlocal opened_fifo
        if path == "pipe":
            opened_fifo = True
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", tracked_open)
    with (
        pytest.raises(EvidenceAcquisitionError, match="regular file"),
        open_confined_evidence(root=tmp_path, relative_path="pipe"),
    ):
        pytest.fail("FIFO was opened")
    assert not opened_fifo


def test_shared_boundary_rejects_hard_link(tmp_path: Path):
    original = tmp_path / "original"
    original.write_bytes(b"data")
    os.link(original, tmp_path / "linked")
    with (
        pytest.raises(EvidenceAcquisitionError, match="link count"),
        open_confined_evidence(root=tmp_path, relative_path="linked"),
    ):
        pytest.fail("Hard link was accepted")


def test_shared_boundary_detects_short_read(tmp_path: Path):
    (tmp_path / "file").write_bytes(b"evidence")
    with open_confined_evidence(root=tmp_path, relative_path="file") as (fd, before):
        assert os.read(fd, 3) == b"evi"
        with pytest.raises(EvidenceAcquisitionError, match="length changed"):
            validate_after_read(file_fd=fd, before=before, received=3)


def test_shared_boundary_detects_mutation(tmp_path: Path):
    file = tmp_path / "file"
    file.write_bytes(b"original")
    with open_confined_evidence(root=tmp_path, relative_path="file") as (fd, before):
        assert os.read(fd, 8) == b"original"
        file.write_bytes(b"changed and extended")
        with pytest.raises(EvidenceAcquisitionError, match="changed"):
            validate_after_read(file_fd=fd, before=before, received=8)


def test_pre_open_check_rejects_before_file_open(tmp_path: Path, monkeypatch):
    (tmp_path / "file").write_bytes(b"evidence")
    original_open = os.open
    opened_file = False

    def tracked_open(path, *args, **kwargs):
        nonlocal opened_file
        if path == "file":
            opened_file = True
        return original_open(path, *args, **kwargs)

    def reject(metadata):
        raise ValueError("Rejected before open")

    monkeypatch.setattr(os, "open", tracked_open)
    with (
        pytest.raises(ValueError, match="Rejected before open"),
        open_confined_evidence(
            root=tmp_path,
            relative_path="file",
            pre_open_check=reject,
        ),
    ):
        pytest.fail("File was opened")
    assert not opened_file


def test_second_pre_open_check_failure_closes_every_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    (tmp_path / "file").write_bytes(b"evidence")
    original_open = os.open
    opened: list[int] = []
    checks = 0

    def tracked_open(*args, **kwargs) -> int:
        descriptor = original_open(*args, **kwargs)
        opened.append(descriptor)
        return descriptor

    def reject_after_open(metadata: os.stat_result) -> None:
        nonlocal checks
        checks += 1
        if checks == 2:
            raise ValueError("Rejected after open")

    monkeypatch.setattr(os, "open", tracked_open)

    with (
        pytest.raises(ValueError, match="Rejected after open"),
        open_confined_evidence(
            root=tmp_path,
            relative_path="file",
            pre_open_check=reject_after_open,
        ),
    ):
        pytest.fail("Callback failure was ignored")

    assert checks == 2
    assert opened
    for descriptor in opened:
        with pytest.raises(OSError):
            os.fstat(descriptor)


def test_callbacks_run_around_final_open(tmp_path: Path):
    (tmp_path / "file").write_bytes(b"evidence")
    events: list[str] = []

    def checkpoint() -> None:
        events.append("checkpoint")

    def pre_open_check(metadata: os.stat_result) -> None:
        events.append("metadata")

    with open_confined_evidence(
        root=tmp_path,
        relative_path="file",
        checkpoint=checkpoint,
        pre_open_check=pre_open_check,
    ) as (fd, before):
        content = os.read(fd, before.st_size)
        validate_after_read(file_fd=fd, before=before, received=len(content))

    assert events[-3:] == ["metadata", "checkpoint", "metadata"]


def test_checkpoint_can_abort_before_first_open(tmp_path: Path, monkeypatch):
    def forbidden_open(*args, **kwargs):
        pytest.fail("No file descriptor should be opened")

    def abort():
        raise ValueError("Deadline reached")

    monkeypatch.setattr(os, "open", forbidden_open)
    with (
        pytest.raises(ValueError, match="Deadline reached"),
        open_confined_evidence(
            root=tmp_path,
            relative_path="file",
            checkpoint=abort,
        ),
    ):
        pytest.fail("Checkpoint was bypassed")


def test_path_validation_is_shared(tmp_path: Path):
    assert root_components(tmp_path)
    assert relative_components("subdir/file.txt") == ("subdir", "file.txt")
    with pytest.raises(ValueError, match="root"):
        root_components("../root")
    with pytest.raises(ValueError, match="relative evidence path"):
        relative_components("../escape")


def test_full_loader_uses_shared_boundary(tmp_path: Path, monkeypatch):
    from vintar.checks.sqli import _time_evidence_posix as primitive
    from vintar.checks.sqli import time_evidence_loader

    (tmp_path / "file").write_bytes(b"content")
    opened = False
    original_open = primitive.os.open

    def tracked_open(*args, **kwargs):
        nonlocal opened
        opened = True
        return original_open(*args, **kwargs)

    monkeypatch.setattr(time_evidence_loader, "_require_posix", lambda: None)
    monkeypatch.setattr(primitive.os, "open", tracked_open)
    assert read_local_evidence(root=tmp_path, relative_path="file") == b"content"
    assert opened
