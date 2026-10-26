from dataclasses import dataclass

import httpx

from vintar.core.budget import RequestBudget
from vintar.core.models import HttpResult
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

    Custom transports are trusted test dependencies only.
    They must never be exposed through untrusted configuration or LLM tools.
    """

    scope: ScopePolicy
    budget: RequestBudget
    timeout: float = 10.0
    max_response_size: int = 1_048_576

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not 0 < self.timeout <= 60
        ):
            raise ValueError("Timeout must be between 0 and 60 seconds.")

        if type(self.max_response_size) is not int or self.max_response_size <= 0:
            raise ValueError("Maximum response size must be positive.")

    def execute(
        self,
        template: RequestTemplate,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> HttpResult:
        """Execute a scoped request within the configured budget.

        Custom transports must be trusted and are intended for tests only.
        They are not closed by this method and are not a security boundary.
        """

        validate_template(template)
        validate_scope(template.url, self.scope)

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
        )

        with httpx.Client(
            transport=guarded,
            trust_env=False,
            follow_redirects=False,
            timeout=self.timeout,
        ) as client:
            return send_template(
                template=template,
                client=client,
                timeout=self.timeout,
                max_response_size=self.max_response_size,
            )
