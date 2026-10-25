from dataclasses import dataclass, field


class RequestBudgetExceededError(RuntimeError):
    """Raised when the request budget is exhausted."""


@dataclass(frozen=True, slots=True, eq=False)
class RequestBudget:
    """Track request usage for a single-threaded execution.

    This class is not thread-safe.
    """

    max_requests: int
    _used_requests: int = field(
        default=0,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if type(self.max_requests) is not int or self.max_requests <= 0:
            raise ValueError("max_requests must be a positive integer.")

    @property
    def used_requests(self) -> int:
        return self._used_requests

    @property
    def remaining(self) -> int:
        return self.max_requests - self._used_requests

    def consume(self) -> None:
        """Reserve one request before sending it."""
        if self._used_requests >= self.max_requests:
            raise RequestBudgetExceededError("Request budget exceeded.")

        object.__setattr__(
            self,
            "_used_requests",
            self._used_requests + 1,
        )
