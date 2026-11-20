"""Evaluate Boolean SQLi with in-memory SQLite behind MockTransport.

This baseline executes real SQLite queries through Vintar's HTTPX boundary,
but it does not claim to exercise a socket-backed web application.
"""

import sqlite3
from collections.abc import Callable

import httpx
import pytest

from vintar.checks.sqli.models import Verdict, VerificationResult
from vintar.checks.sqli.orchestrator import verify_boolean_sqli
from vintar.core.budget import RequestBudget
from vintar.core.executor import ExecutionContext
from vintar.core.rate_limit import RateLimiter
from vintar.core.request import (
    InjectionLocation,
    InjectionMode,
    InjectionPoint,
    RequestTemplate,
)
from vintar.core.scope import AllowedOrigin, ScopePolicy

ORIGIN = "http://localhost:8000"

TRUE_PAYLOAD = "' AND '1'='1'-- "
FALSE_PAYLOAD = "' AND '1'='2'-- "


@pytest.fixture
def database():
    connection = sqlite3.connect(":memory:")

    connection.execute(
        "CREATE TABLE products (name TEXT NOT NULL, category TEXT NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO products (name, category) VALUES (?, ?)",
        [
            ("Cat toy", "Pets"),
            ("Dog toy", "Pets"),
            ("Notebook", "Office"),
        ],
    )

    try:
        yield connection
    finally:
        connection.close()


def execute_query(
    connection: sqlite3.Connection,
    category: str,
    *,
    vulnerable: bool,
) -> bytes:
    if vulnerable:
        # Intentionally vulnerable: this exists only in a test fixture.
        query = f"SELECT name FROM products WHERE category = '{category}'"
        rows = connection.execute(query).fetchall()
    else:
        query = "SELECT name FROM products WHERE category = ?"
        rows = connection.execute(
            query,
            (category,),
        ).fetchall()

    names = sorted(row[0] for row in rows)
    return "\n".join(names).encode("utf-8")


def make_context() -> ExecutionContext:
    return ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        budget=RequestBudget(6),
        rate_limiter=RateLimiter(
            requests_per_second=10,
        ),
        max_response_size=1_048_576,
    )


def run_fixture(handler: Callable[[str], bytes]) -> VerificationResult:
    received: list[str] = []

    def transport_handler(request: httpx.Request):
        assert request.method == "GET"
        assert request.url.scheme == "http"
        assert request.url.host == "localhost"
        assert request.url.port == 8000
        assert request.url.path == "/products"

        category = request.url.params["category"]
        received.append(category)

        return httpx.Response(
            status_code=200,
            content=handler(category),
        )

    context = make_context()

    result = verify_boolean_sqli(
        check_id="sqlite-boolean-sqli",
        template=RequestTemplate(
            method="GET",
            url=f"{ORIGIN}/products",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        true_payload=TRUE_PAYLOAD,
        false_payload=FALSE_PAYLOAD,
        context=context,
        transport=httpx.MockTransport(transport_handler),
    )

    assert len(received) == 6
    assert received == [
        "Pets",
        "Pets" + TRUE_PAYLOAD,
        "Pets" + FALSE_PAYLOAD,
        "Pets",
        "Pets" + FALSE_PAYLOAD,
        "Pets" + TRUE_PAYLOAD,
    ]
    assert result.request_count == 6
    assert context.budget.used_requests == 6

    return result


def test_vulnerable_sqlite_produces_boolean_candidate(
    database,
):
    baseline = execute_query(
        database,
        "Pets",
        vulnerable=True,
    )
    true = execute_query(
        database,
        "Pets" + TRUE_PAYLOAD,
        vulnerable=True,
    )
    false = execute_query(
        database,
        "Pets" + FALSE_PAYLOAD,
        vulnerable=True,
    )

    assert baseline == true
    assert baseline != false

    result = run_fixture(
        lambda category: execute_query(
            database,
            category,
            vulnerable=True,
        )
    )

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "boolean_candidate"
    assert result.evidence is not None
    assert result.evidence.baseline_true_similarity == 1.0
    assert result.evidence.baseline_false_similarity == 0.0
    assert result.evidence.true_false_similarity == 0.0


def test_parameterized_sqlite_rejects_boolean_interpretation(
    database,
):
    baseline = execute_query(
        database,
        "Pets",
        vulnerable=False,
    )
    true = execute_query(
        database,
        "Pets" + TRUE_PAYLOAD,
        vulnerable=False,
    )
    false = execute_query(
        database,
        "Pets" + FALSE_PAYLOAD,
        vulnerable=False,
    )

    assert baseline
    assert true == false == b""
    assert baseline != true

    result = run_fixture(
        lambda category: execute_query(
            database,
            category,
            vulnerable=False,
        )
    )

    assert result.verdict is Verdict.NOT_DETECTED
    assert result.reason_code == "no_boolean_difference_literal_input"
    assert result.evidence is not None
    assert result.evidence.baseline_true_similarity == 0.0
    assert result.evidence.baseline_false_similarity == 0.0
    assert result.evidence.true_false_similarity == 1.0


def test_business_logic_can_mimic_boolean_sqli():
    """Prove that a six-probe Boolean candidate is not SQLi proof."""

    def handler(category: str) -> bytes:
        if category == "Pets" + FALSE_PAYLOAD:
            return b"no-results"

        return b"products-found"

    result = run_fixture(handler)

    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.reason_code == "boolean_candidate"
    assert result.evidence is not None
    assert result.evidence.baseline_true_similarity == 1.0
    assert result.evidence.baseline_false_similarity == 0.0
    assert result.evidence.true_false_similarity == 0.0
