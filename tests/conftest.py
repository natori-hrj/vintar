"""Shared test fixtures."""

import builtins
import io
import os
import subprocess
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def tracked_markdown() -> frozenset[Path]:
    try:
        listing = subprocess.run(
            ["git", "ls-files", "-z", "--", "*.md"],
            cwd=ROOT,
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        reason = (
            os.fsdecode(exc.stderr).strip() or str(exc)
            if isinstance(exc, subprocess.CalledProcessError)
            else str(exc)
        )
        pytest.exit(
            f"Could not list Git-tracked Markdown: {reason}. "
            "Run pytest from a Git checkout with Git installed.",
            returncode=pytest.ExitCode.TESTS_FAILED,
        )
    return frozenset(
        (ROOT / os.fsdecode(path)).resolve()
        for path in listing.stdout.split(b"\0")
        if path
    )


@pytest.fixture(autouse=True)
def enforce_doc_drift_marker(request, monkeypatch, tracked_markdown):
    """Check mark membership against actual reads of repository Markdown."""
    documents = set()

    def track(open_file):
        def tracked(file, mode="r", *args, **kwargs):
            stream = open_file(file, mode, *args, **kwargs)
            if (
                ("r" in mode or "+" in mode)
                and isinstance(file, (str, bytes, os.PathLike))
                and os.fsdecode(file).endswith(".md")
            ):
                path = Path(os.fsdecode(file)).resolve()
                if path in tracked_markdown:
                    documents.add(path.relative_to(ROOT, walk_up=True))
            return stream

        return tracked

    with monkeypatch.context() as patch:
        patch.setattr(io, "open", track(io.open))
        patch.setattr(builtins, "open", track(builtins.open))
        yield

    marked = request.node.get_closest_marker("doc_drift") is not None
    if documents and not marked:
        pytest.fail(
            f"{request.node.nodeid} reads {', '.join(map(str, sorted(documents)))} "
            "without the doc_drift marker. Add @pytest.mark.doc_drift so the "
            "documentation check runs under -m doc_drift."
        )
    if marked and not documents:
        pytest.fail(
            f"{request.node.nodeid} is marked doc_drift but read no Git-tracked "
            "Markdown. Read the document being checked or remove the marker."
        )


@pytest.fixture
def worker_pool() -> Iterator[ThreadPoolExecutor]:
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        yield pool
    finally:
        pool.shutdown(wait=False)
