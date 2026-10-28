import httpx

from vintar.core.budget import RequestBudget
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import ScopePolicy, validate_scope


class ScopedTransport(httpx.BaseTransport):
    """Enforce scope and budget immediately before transport dispatch.

    The underlying transport is closed only when close_underlying is True.
    This wrapper does not validate the actual DNS-resolved destination.
    """

    def __init__(
        self,
        transport: httpx.BaseTransport,
        scope: ScopePolicy,
        budget: RequestBudget,
        rate_limiter: RateLimiter,
        close_underlying: bool = False,
    ) -> None:
        if not isinstance(rate_limiter, RateLimiter):
            raise TypeError("rate_limiter must be a RateLimiter.")

        self._transport = transport
        self._scope = scope
        self._budget = budget
        self._rate_limiter = rate_limiter
        self._close_underlying = close_underlying

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        validate_scope(str(request.url), self._scope)
        self._budget.consume()
        self._rate_limiter.acquire()

        return self._transport.handle_request(request)

    def close(self) -> None:
        if self._close_underlying:
            self._transport.close()
