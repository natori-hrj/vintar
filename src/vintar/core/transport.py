"""Scoped HTTP transport with optional execution instrumentation."""

import math
import sys
import time
from collections.abc import Callable

import httpx

from vintar.core.budget import RequestBudget
from vintar.core.rate_limit import RateLimiter
from vintar.core.scope import ScopePolicy, validate_scope


class ExecutionDeadlineExceededError(RuntimeError):
    """Execution cannot dispatch another request within its deadline."""


class ScopedTransport(httpx.BaseTransport):
    """Enforce scope and budget immediately before transport dispatch.

    The underlying transport is closed only when close_underlying is True.
    This wrapper does not validate the actual DNS-resolved destination.

    Optional callbacks are trusted instrumentation, not authorization
    boundaries. The deadline prevents late dispatch but cannot forcibly
    interrupt an already blocking synchronous request or rate-limit sleep.
    """

    def __init__(
        self,
        transport: httpx.BaseTransport,
        scope: ScopePolicy,
        budget: RequestBudget,
        rate_limiter: RateLimiter,
        close_underlying: bool = False,
        *,
        deadline: float | None = None,
        on_rate_wait: Callable[[float], None] | None = None,
        on_dispatch: Callable[[], None] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(rate_limiter, RateLimiter):
            raise TypeError("rate_limiter must be a RateLimiter.")

        if deadline is not None and (
            type(deadline) not in (int, float)
            or not -sys.float_info.max <= deadline <= sys.float_info.max
            or not math.isfinite(deadline)
        ):
            raise ValueError("Invalid execution deadline.")

        if on_rate_wait is not None and not callable(on_rate_wait):
            raise TypeError("Invalid rate wait observer.")

        if on_dispatch is not None and not callable(on_dispatch):
            raise TypeError("Invalid dispatch observer.")

        if not callable(clock):
            raise TypeError("Invalid execution clock.")

        self._transport = transport
        self._scope = scope
        self._budget = budget
        self._rate_limiter = rate_limiter
        self._close_underlying = close_underlying
        self._deadline = deadline
        self._on_rate_wait = on_rate_wait
        self._on_dispatch = on_dispatch
        self._clock = clock

    def _check_deadline(self) -> None:
        if self._deadline is None:
            return

        now = self._clock()
        if (
            type(now) not in (int, float)
            or not -sys.float_info.max <= now <= sys.float_info.max
            or not math.isfinite(now)
        ):
            raise RuntimeError("Invalid execution clock.")

        if now >= self._deadline:
            raise ExecutionDeadlineExceededError("Execution deadline exceeded.")

    def _cap_request_timeout(self, request: httpx.Request) -> None:
        if self._deadline is None:
            return

        now = self._clock()
        if (
            type(now) not in (int, float)
            or not -sys.float_info.max <= now <= sys.float_info.max
            or not math.isfinite(now)
        ):
            raise RuntimeError("Invalid execution clock.")

        remaining = self._deadline - now
        if remaining <= 0:
            raise ExecutionDeadlineExceededError("Execution deadline exceeded.")

        configured = request.extensions.get("timeout")
        if not isinstance(configured, dict):
            return

        request.extensions["timeout"] = {
            name: remaining if value is None else min(float(value), remaining)
            for name, value in configured.items()
        }

    def _notify_rate_wait(self, started: float) -> None:
        if self._on_rate_wait is not None:
            self._on_rate_wait(max(0.0, time.perf_counter() - started))

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        validate_scope(str(request.url), self._scope)
        self._check_deadline()

        self._budget.consume()

        wait_started = time.perf_counter()
        try:
            self._rate_limiter.acquire()
        except Exception:
            self._notify_rate_wait(wait_started)
            raise

        self._notify_rate_wait(wait_started)

        self._check_deadline()
        self._cap_request_timeout(request)

        if self._on_dispatch is not None:
            self._on_dispatch()

        return self._transport.handle_request(request)

    def close(self) -> None:
        if self._close_underlying:
            self._transport.close()
