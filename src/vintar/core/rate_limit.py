import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(eq=False, slots=True, frozen=True)
class RateLimiter:
    """Limit request start rate for single-threaded execution.

    This class is not thread-safe

    Custom clock and sleep functions are trusted test dependencies only.
    They must not be exposed through untrusted configuration.
    """

    requests_per_second: float
    _clock: Callable[[], float] = field(
        default=time.monotonic,
        repr=False,
        compare=False,
    )
    _sleep: Callable[[float], None] = field(
        default=time.sleep,
        repr=False,
        compare=False,
    )
    _next_allowed: float | None = field(
        default=None,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        rate = self.requests_per_second
        if (
            isinstance(rate, bool)
            or not isinstance(rate, (int, float))
            or not 0.1 <= rate <= 100
            or not math.isfinite(rate)
        ):
            raise ValueError(
                "requests_per_second must be finite and between 0.1 and 100."
            )

    @property
    def interval(self) -> float:
        return 1.0 / self.requests_per_second

    def acquire(self) -> None:
        """wait until a request may begin."""

        now = self._clock()

        if self._next_allowed is not None:
            delay = self._next_allowed - now

            if delay > 0:
                self._sleep(delay)

        now = self._clock()
        object.__setattr__(
            self,
            "_next_allowed",
            now + self.interval,
        )
