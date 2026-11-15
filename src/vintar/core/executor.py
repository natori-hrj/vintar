"""Execute validated HTTP requests within a scoped request budget."""

import math
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx

from vintar.core.budget import RequestBudget
from vintar.core.models import HttpResult
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import RequestTemplate
from vintar.core.scope import ScopePolicy, validate_scope
from vintar.core.template import send_template, validate_template
from vintar.core.transport import ScopedTransport


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Execute scoped HTTP requests within a fixed request budget.

    Single-threaded MVP.

    Scope validation checks URL origins, not DNS-resolved IP addresses.
    Network-level egress restrictions are required for untrusted targets.

    Custom transports and instrumentation callbacks are trusted test
    or internal dependencies only. They must not be exposed through
    untrusted configuration or LLM tools.

    The optional deadline controls dispatch, not absolute completion.
    """

    scope: ScopePolicy
    budget: RequestBudget
    timeout: float = 10.0
    max_response_size: int = 1_048_576
    rate_limiter: RateLimiter = field(
        default_factory=lambda: RateLimiter(requests_per_second=2.0)
    )

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not 0 < self.timeout <= 60
            or not math.isfinite(self.timeout)
        ):
            raise ValueError("Timeout must be between 0 and 60 seconds.")

        if type(self.max_response_size) is not int or self.max_response_size <= 0:
            raise ValueError("Maximum response size must be positive.")

        if not isinstance(self.rate_limiter, RateLimiter):
            raise TypeError("rate_limiter must be a RateLimiter.")

    def execute(
        self,
        template: RequestTemplate,
        *,
        transport: httpx.BaseTransport | None = None,
        request_timeout: float | None = None,
        deadline: float | None = None,
        on_rate_wait: Callable[[float], None] | None = None,
        on_dispatch: Callable[[], None] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> HttpResult:
        """Execute a scoped request with optional timing instrumentation.

        request_timeout may reduce, but never increase, the configured
        context timeout.

        The deadline is checked at the transport boundary before and
        after rate limiting. It does not interrupt active blocking I/O.

        Custom transports are trusted and are not closed by this method.
        """
        validate_template(template)
        validate_scope(template.url, self.scope)

        effective_timeout = self.timeout

        if request_timeout is not None:
            if (
                type(request_timeout) not in (int, float)
                or not 0 < request_timeout <= self.timeout
                or not math.isfinite(request_timeout)
            ):
                raise ValueError("Invalid per-request timeout.")

            effective_timeout = float(request_timeout)

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

        if clock is not None and not callable(clock):
            raise TypeError("Invalid execution clock.")

        owns_transport = transport is None

        if transport is None:
            transport = httpx.HTTPTransport(
                trust_env=False,
                proxy=None,
            )

        guarded = ScopedTransport(
            transport=transport,
            scope=self.scope,
            budget=self.budget,
            close_underlying=owns_transport,
            rate_limiter=self.rate_limiter,
            deadline=deadline,
            on_rate_wait=on_rate_wait,
            on_dispatch=on_dispatch,
            clock=clock if clock is not None else time.monotonic,
        )

        with httpx.Client(
            transport=guarded,
            trust_env=False,
            follow_redirects=False,
            timeout=effective_timeout,
        ) as client:
            return send_template(
                template=template,
                client=client,
                timeout=effective_timeout,
                max_response_size=self.max_response_size,
            )
