"""Shared test fixtures."""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest


@pytest.fixture
def worker_pool() -> Iterator[ThreadPoolExecutor]:
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        yield pool
    finally:
        pool.shutdown(wait=False)
