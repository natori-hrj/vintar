"""Experimental SQLi confirmation; not a production detector.

Uses a real in-memory SQLite database but no HTTP socket.
No changes to Vintar's verdict or CI security gate.
"""

import sqlite3
from collections import Counter
from collections.abc import Callable, Mapping

import pytest

TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
CONTROL = "__vintar_control_7f4a9c2e"

PLAN = (
    "B",
    "T1",
    "F1",
    "C",
    "T2",
    "F2",
    "B",
    "F2",
    "T2",
    "C",
    "F1",
    "T1",
)

type Response = tuple[int, bytes]
type Handler = Callable[[str], Response]


@pytest.fixture
def database():
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE products (name TEXT NOT NULL, category TEXT NOT NULL)"
    )
    connection.executemany(
        "INSERT INTO products VALUES (?, ?)",
        (
            ("Cat toy", "Pets"),
            ("Dog toy", "Pets"),
            ("Notebook", "Office"),
        ),
    )
    try:
        yield connection
    finally:
        connection.close()


def query_products(
    database: sqlite3.Connection,
    value: str,
    *,
    vulnerable: bool,
) -> Response:
    if vulnerable:
        # Deliberately unsafe; only used with in-memory test data.
        statement = f"SELECT name FROM products WHERE category = '{value}'"
        rows = database.execute(statement).fetchall()
    else:
        rows = database.execute(
            "SELECT name FROM products WHERE category = ?",
            (value,),
        ).fetchall()

    body = "\n".join(sorted(row[0] for row in rows))
    return 200, body.encode("utf-8")


def payloads(control: str = CONTROL) -> dict[str, str]:
    return {
        "B": "Pets",
        "T1": "Pets" + TRUE_1,
        "F1": "Pets" + FALSE_1,
        "C": "Pets" + control,
        "T2": "Pets" + TRUE_2,
        "F2": "Pets" + FALSE_2,
    }


def collect(
    handler: Handler,
    values: Mapping[str, str],
) -> dict[str, list[Response]]:
    """Execute exactly twelve local fixture calls."""
    responses: dict[str, list[Response]] = {key: [] for key in values}
    received = []

    for kind in PLAN:
        value = values[kind]
        received.append((kind, value))
        responses[kind].append(handler(value))

    assert len(received) == 12
    assert [kind for kind, _ in received] == list(PLAN)
    assert Counter(kind for kind, _ in received) == {key: 2 for key in values}

    return responses


def classify(responses: dict[str, list[Response]]) -> str:
    """Experimental relation, never a VULNERABLE or safety verdict.

    ``not_confirmed`` only means this exact relation was absent.
    """
    if set(responses) != {"B", "T1", "F1", "T2", "F2", "C"}:
        return "inconclusive"

    if any(len(items) != 2 for items in responses.values()):
        return "inconclusive"

    if any(
        not 200 <= status < 300 for items in responses.values() for status, _ in items
    ):
        return "inconclusive"

    if any(items[0] != items[1] for items in responses.values()):
        return "inconclusive"

    b, t1, f1, t2, f2, c = (
        responses[key][0] for key in ("B", "T1", "F1", "T2", "F2", "C")
    )

    if b == t1 == t2 and f1 == f2 == c and b != f1:
        return "candidate"

    return "not_confirmed"


def test_vulnerable_sqlite_produces_candidate(database):
    values = payloads()

    responses = collect(
        lambda value: query_products(database, value, vulnerable=True),
        values,
    )

    assert classify(responses) == "candidate"

    assert responses["B"][0] == responses["T1"][0]
    assert responses["B"][0] == responses["T2"][0]
    assert responses["F1"][0] == responses["F2"][0]
    assert responses["F1"][0] == responses["C"][0]
    assert responses["B"][0] != responses["F1"][0]


def test_parameterized_sqlite_is_not_confirmed(database):
    values = payloads()

    responses = collect(
        lambda value: query_products(database, value, vulnerable=False),
        values,
    )

    assert classify(responses) == "not_confirmed"
    assert responses["B"][0][1] != b""
    assert all(responses[kind][0][1] == b"" for kind in ("T1", "F1", "T2", "F2", "C"))


def test_simple_business_logic_false_positive_is_rejected():
    values = payloads()

    def business_logic(value: str) -> Response:
        if value == values["F1"]:
            return 200, b"no-results"
        return 200, b"products-found"

    responses = collect(business_logic, values)

    assert responses["B"][0] == responses["T1"][0]
    assert responses["B"][0] != responses["F1"][0]
    assert classify(responses) == "not_confirmed"


def test_http_200_filter_can_mimic_all_probes():
    """A non-SQL HTTP 200 filter page can reproduce the relation."""
    values = payloads()

    false_values = {values["F1"], values["F2"], values["C"]}

    def mimicking_logic(value: str) -> Response:
        if value in false_values:
            return 200, b"request-blocked"
        return 200, b"products-found"

    responses = collect(mimicking_logic, values)

    assert classify(responses) == "candidate"


def test_unstable_responses_are_inconclusive():
    values = payloads()
    calls = 0

    def dynamic_handler(value: str) -> Response:
        nonlocal calls
        calls += 1
        return 200, f"request-{calls}".encode()

    assert classify(collect(dynamic_handler, values)) == "inconclusive"


def test_http_200_authentication_expiry_is_inconclusive():
    values = payloads()
    calls = 0

    def expiring_session(value: str) -> Response:
        nonlocal calls
        calls += 1
        if calls > len(PLAN) // 2:
            return 200, b"login-page"
        return 200, b"authenticated-content"

    assert classify(collect(expiring_session, values)) == "inconclusive"


@pytest.mark.parametrize("status", [302, 401, 403, 429, 500])
def test_non_success_response_is_inconclusive(status):
    values = payloads()

    def handler(value: str) -> Response:
        if value == values["F2"]:
            return status, b"blocked"
        return 200, b"ok"

    assert classify(collect(handler, values)) == "inconclusive"


def test_missing_probe_is_inconclusive():
    values = payloads()

    responses = collect(
        lambda value: (200, b"ok"),
        values,
    )
    responses.pop("C")

    assert classify(responses) == "inconclusive"


def test_single_missing_repetition_is_inconclusive():
    responses = collect(
        lambda value: (200, b"ok"),
        payloads(),
    )
    responses["T2"].pop()

    assert classify(responses) == "inconclusive"


def test_plan_and_control_are_distinct_and_non_sql():
    assert len(PLAN) == 12
    assert Counter(PLAN) == {kind: 2 for kind in ("B", "T1", "F1", "C", "T2", "F2")}
    assert len({TRUE_1, FALSE_1, TRUE_2, FALSE_2}) == 4
    assert CONTROL.replace("_", "").isalnum()
