import time
from dataclasses import FrozenInstanceError

import pytest

from vintar.core.rate_limit import RateLimiter, RateLimitInterruptedError


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.delays: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.delays.append(seconds)
        self.now += seconds


def test_first_request_has_no_delay():
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    limiter.acquire()

    assert clock.delays == []


def test_requests_are_spaced():
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    limiter.acquire()
    limiter.acquire()
    limiter.acquire()

    assert clock.delays == [0.5, 0.5]
    assert clock.now == 1.0


def test_no_wait_after_sufficient_time():
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    limiter.acquire()

    clock.now = 2.0
    limiter.acquire()

    assert clock.delays == []


def test_rate_limiter_uses_updated_clock():
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    limiter.acquire()
    clock.now = 0.25
    limiter.acquire()

    assert clock.delays == [0.25]
    assert clock.now == 0.5


def test_rate_limiter_is_immutable():
    clock = FakeClock()
    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    with pytest.raises(FrozenInstanceError):
        limiter.requests_per_second = 100

    with pytest.raises(FrozenInstanceError):
        limiter._clock = time.monotonic

    with pytest.raises(FrozenInstanceError):
        limiter._sleep = time.sleep

    with pytest.raises(FrozenInstanceError):
        limiter._next_allowed = None


@pytest.mark.parametrize(
    "rate",
    [
        0,
        -1,
        True,
        False,
        "2",
        None,
        101,
        float("nan"),
        float("inf"),
        float("-inf"),
        5e-324,
        0.01,
        1e-308,
        10**1000,
    ],
)
def test_invalid_rate(rate):
    with pytest.raises(ValueError):
        RateLimiter(requests_per_second=rate)


def test_failed_sleep_preserves_deadline():
    clock = FakeClock()
    attempts: list[float] = []

    def controlled_sleep(seconds: float) -> None:
        attempts.append(seconds)

        if len(attempts) == 1:
            raise RuntimeError("Sleep interrupted.")

        clock.sleep(seconds)

    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=controlled_sleep,
    )

    limiter.acquire()
    clock.now = 0.25

    with pytest.raises(RateLimitInterruptedError) as exc_info:
        limiter.acquire()

    assert isinstance(exc_info.value.__cause__, RuntimeError)
    assert str(exc_info.value.__cause__) == "Sleep interrupted."

    limiter.acquire()

    assert attempts == [0.25, 0.25]
    assert clock.now == 0.5


@pytest.mark.parametrize(
    ("rate", "expected_interval"),
    [
        (0.1, 10.0),
        (1.0, 1.0),
        (100.0, 0.01),
    ],
)
def test_valid_rate_boundaries(rate: float, expected_interval: float):
    limiter = RateLimiter(requests_per_second=rate)

    assert limiter.interval == pytest.approx(expected_interval)


def test_rate_limiter_hash_remains_stable():
    clock = FakeClock()

    limiter = RateLimiter(
        requests_per_second=2,
        _clock=clock.monotonic,
        _sleep=clock.sleep,
    )

    limiters = {limiter}
    hash_before = hash(limiter)

    limiter.acquire()

    assert hash(limiter) == hash_before
    assert limiter in limiters
    assert limiter != RateLimiter(requests_per_second=2)
