"""deterministic Boolean SQLi detection-quality corpus.

Six probes use the real Vintar orchestrator with MockTransport.
Twelve probes use an experimental relation classifier.

No network access, no production verdict changes, and no claim that
a candidate is a confirmed SQL injection vulnerability.
"""

import sqlite3
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass

import httpx
import pytest

from vintar.checks.sqli.models import ProbeError, Verdict
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

TRUE_1 = "' AND 1=1-- "
FALSE_1 = "' AND 1=2-- "
TRUE_2 = "' AND 2<3-- "
FALSE_2 = "' AND 2>3-- "
BASELINE_PRESERVING_CONTROL = "' AND 7=7-- "

PLAN_12 = (
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

PLAN_6 = ("B", "T1", "F1", "B", "F1", "T1")

ORIGIN = "http://localhost:8000"

type Response = tuple[int, bytes]


@dataclass(frozen=True)
class CorpusCase:
    name: str
    mode: str
    ground_truth: str


CORPUS = (
    CorpusCase("sqlite_vulnerable", "vulnerable", "vulnerable"),
    CorpusCase("sqlite_parameterized", "safe", "benign"),
    CorpusCase("simple_branch", "simple", "benign"),
    CorpusCase("full_mimic", "mimic", "benign"),
    CorpusCase("waf_200", "waf", "benign"),
    CorpusCase("auth_expiry", "auth", "benign"),
    CorpusCase("dynamic_content", "dynamic", "benign"),
    CorpusCase("cache_shift", "cache", "benign"),
    CorpusCase("http_429", "rate_limit", "unavailable"),
    CorpusCase("timeout", "timeout", "unavailable"),
)


def payloads() -> dict[str, str]:
    return {
        "B": "Pets",
        "T1": "Pets" + TRUE_1,
        "F1": "Pets" + FALSE_1,
        "T2": "Pets" + TRUE_2,
        "F2": "Pets" + FALSE_2,
        "C": "Pets" + BASELINE_PRESERVING_CONTROL,
    }


def sqlite_result(value: str, *, vulnerable: bool) -> bytes:
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE products (name TEXT NOT NULL, category TEXT NOT NULL)")
        db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            (
                ("Cat toy", "Pets"),
                ("Dog toy", "Pets"),
                ("Notebook", "Office"),
            ),
        )

        if vulnerable:
            # Intentionally vulnerable, isolated to in-memory data.
            rows = db.execute(
                f"SELECT name FROM products WHERE category = '{value}'"
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT name FROM products WHERE category = ?",
                (value,),
            ).fetchall()

    return "\n".join(sorted(row[0] for row in rows)).encode()


class CorpusHandler:
    """One independent deterministic scenario per probe run."""

    def __init__(self, case: CorpusCase):
        self.case = case
        self.received: list[str] = []
        self.values = payloads()

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.scheme == "http"
        assert request.url.host == "localhost"
        assert request.url.port == 8000
        assert request.url.path == "/products"

        value = request.url.params["category"]
        self.received.append(value)

        number = len(self.received)
        mode = self.case.mode

        if mode == "timeout":
            raise httpx.ReadTimeout(
                "Synthetic timeout",
                request=request,
            )

        if mode == "rate_limit":
            return httpx.Response(429, content=b"limited")

        if mode in ("vulnerable", "safe"):
            body = sqlite_result(
                value,
                vulnerable=(mode == "vulnerable"),
            )

        elif mode == "simple":
            body = b"no-results" if value == self.values["F1"] else b"products-found"

        elif mode in ("mimic", "waf"):
            blocked_values = {
                self.values["F1"],
                self.values["F2"],
            }
            blocked = value in blocked_values

            if mode == "waf":
                body = b"access-denied" if blocked else b"products-found"
            else:
                body = b"no-results" if blocked else b"products-found"

        elif mode == "auth":
            # Keep the target behavior identical for both detector plans.
            body = b"login-page" if number > 3 else b"authenticated-content"

        elif mode == "dynamic":
            body = f"response-{number}".encode()

        elif mode == "cache":
            # Simulate a cache becoming stale at a fixed request boundary.
            body = b"cached-old" if number <= 3 else b"cached-new"

        else:
            raise AssertionError("Unknown corpus mode")

        return httpx.Response(200, content=body)


def run_six(case: CorpusCase) -> tuple[str, int]:
    """Exercise the existing production six-probe orchestrator."""
    handler = CorpusHandler(case)
    values = payloads()

    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "localhost", 8000)})
        ),
        budget=RequestBudget(6),
        rate_limiter=RateLimiter(
            requests_per_second=10,
        ),
        max_response_size=1_048_576,
    )

    result = verify_boolean_sqli(
        check_id=case.name,
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
        true_payload=TRUE_1,
        false_payload=FALSE_1,
        context=context,
        transport=httpx.MockTransport(handler),
    )

    assert context.budget.used_requests == result.request_count
    assert len(handler.received) == result.request_count

    if case.mode in ("rate_limit", "timeout"):
        assert result.request_count == 1
        assert handler.received == [values["B"]]
    else:
        assert result.request_count == 6
        assert handler.received == [values[kind] for kind in PLAN_6]

    if case.mode == "rate_limit":
        assert result.reason_code == "rate_limited"
        assert result.failures == ()
    elif case.mode == "timeout":
        assert result.reason_code == "probe_failed"
        assert len(result.failures) == 1
        assert result.failures[0].error is ProbeError.TIMEOUT

    if (
        result.verdict is Verdict.INCONCLUSIVE
        and result.reason_code == "boolean_candidate"
    ):
        label = "candidate"
    elif result.verdict is Verdict.INCONCLUSIVE:
        label = "inconclusive"
    elif result.verdict is Verdict.NOT_DETECTED:
        label = "not_confirmed"
    else:
        raise AssertionError("Unexpected production verdict")

    return label, result.request_count


def classify_twelve(
    responses: dict[str, list[Response]],
) -> str:
    """Experimental classification, not a security verdict."""
    required = {"B", "T1", "F1", "T2", "F2", "C"}

    if set(responses) != required:
        return "inconclusive"

    if any(len(items) != 2 for items in responses.values()):
        return "inconclusive"

    if any(
        not 200 <= status < 300 for items in responses.values() for status, _ in items
    ):
        return "inconclusive"

    if any(items[0] != items[1] for items in responses.values()):
        return "inconclusive"

    b, t1, f1, t2, f2, control = (
        responses[kind][0] for kind in ("B", "T1", "F1", "T2", "F2", "C")
    )

    if b == t1 == t2 == control and f1 == f2 and b != f1:
        return "candidate"

    return "not_confirmed"


def run_twelve(case: CorpusCase) -> tuple[str, int]:
    """Run an experiment, not the production interruption policy.

    It stops at the first RequestError or HTTP 429, but does not implement
    the production budget, timeout, or result model.
    """
    handler = CorpusHandler(case)
    values = payloads()

    responses: dict[str, list[Response]] = {kind: [] for kind in values}

    with httpx.Client(
        transport=httpx.MockTransport(handler),
        trust_env=False,
        follow_redirects=False,
        timeout=5,
    ) as client:
        for kind in PLAN_12:
            try:
                response = client.get(
                    ORIGIN + "/products",
                    params={"category": values[kind]},
                )
            except httpx.RequestError:
                return "inconclusive", len(handler.received)

            responses[kind].append((response.status_code, response.content))

            if response.status_code == 429:
                return "inconclusive", len(handler.received)

    assert len(handler.received) == 12
    assert Counter(PLAN_12) == {kind: 2 for kind in values}
    assert handler.received == [values[kind] for kind in PLAN_12]

    return classify_twelve(responses), len(handler.received)


def evaluate(
    cases: tuple[CorpusCase, ...],
    runner: Callable[[CorpusCase], tuple[str, int]],
) -> dict[str, int | float]:
    """Calculate rates without treating abstention as a negative."""
    positive = 0
    benign = 0
    true_candidates = 0
    false_candidates = 0
    inconclusive = 0
    false_negatives = 0
    positive_inconclusive = 0
    classified_ground_truth = 0
    classified_benign = 0
    requests = 0

    for case in cases:
        classification, count = runner(case)
        requests += count

        if classification == "inconclusive":
            inconclusive += 1

        if case.ground_truth == "vulnerable":
            positive += 1
            if classification == "candidate":
                true_candidates += 1
                classified_ground_truth += 1
            elif classification == "not_confirmed":
                false_negatives += 1
                classified_ground_truth += 1
            else:
                positive_inconclusive += 1

        elif case.ground_truth == "benign":
            benign += 1
            if classification != "inconclusive":
                classified_ground_truth += 1
                classified_benign += 1
                if classification == "candidate":
                    false_candidates += 1

        else:
            assert case.ground_truth == "unavailable"
            assert classification == "inconclusive"

    return {
        "cases": len(cases),
        "positive_cases": positive,
        "benign_cases": benign,
        "true_candidates": true_candidates,
        "false_candidates": false_candidates,
        "false_negatives": false_negatives,
        "positive_inconclusive": positive_inconclusive,
        "inconclusive": inconclusive,
        "classified_ground_truth_cases": classified_ground_truth,
        "classified_benign_cases": classified_benign,
        "candidate_detection_rate": (true_candidates / positive if positive else 0.0),
        "candidate_false_positive_rate_all_benign": (
            false_candidates / benign if benign else 0.0
        ),
        "conditional_false_positive_rate": (
            false_candidates / classified_benign if classified_benign else 0.0
        ),
        "false_negative_rate": (false_negatives / positive if positive else 0.0),
        "inconclusive_rate_all_cases": (inconclusive / len(cases) if cases else 0.0),
        "classification_coverage": (
            classified_ground_truth / (positive + benign) if positive + benign else 0.0
        ),
        "requests_used": requests,
    }


@pytest.mark.parametrize(
    ("case", "six", "twelve"),
    [
        (CORPUS[0], "candidate", "candidate"),
        (CORPUS[1], "not_confirmed", "not_confirmed"),
        (CORPUS[2], "candidate", "not_confirmed"),
        (CORPUS[3], "candidate", "candidate"),
        (CORPUS[4], "candidate", "candidate"),
        (CORPUS[5], "inconclusive", "inconclusive"),
        (CORPUS[6], "inconclusive", "inconclusive"),
        (CORPUS[7], "inconclusive", "inconclusive"),
        (CORPUS[8], "inconclusive", "inconclusive"),
        (CORPUS[9], "inconclusive", "inconclusive"),
    ],
    ids=[item.name for item in CORPUS],
)
def test_corpus_classifications(case, six, twelve):
    assert run_six(case)[0] == six
    assert run_twelve(case)[0] == twelve


def test_corpus_metrics_are_reproducible():
    six = evaluate(CORPUS, run_six)
    twelve = evaluate(CORPUS, run_twelve)

    assert evaluate(CORPUS, run_six) == six
    assert evaluate(CORPUS, run_twelve) == twelve

    assert six["cases"] == 10
    assert twelve["cases"] == 10

    assert six["candidate_detection_rate"] == 1.0
    assert twelve["candidate_detection_rate"] == 1.0

    # Three benign fixtures mimic the first Boolean pair.
    assert six["false_candidates"] == 3
    # Additional checks reject the simple branch only.
    assert twelve["false_candidates"] == 2

    # Unconditional rates use every benign fixture as the denominator.
    assert six["candidate_false_positive_rate_all_benign"] == 3 / 7
    assert twelve["candidate_false_positive_rate_all_benign"] == 2 / 7

    # Conditional rates exclude abstentions from the denominator and are
    # separate so abstentions cannot improve apparent classifier quality.
    assert six["classified_benign_cases"] == 4
    assert twelve["classified_benign_cases"] == 4
    assert six["conditional_false_positive_rate"] == 0.75
    assert twelve["conditional_false_positive_rate"] == 0.5

    assert six["false_negatives"] == 0
    assert twelve["false_negatives"] == 0
    assert six["positive_inconclusive"] == 0
    assert twelve["positive_inconclusive"] == 0

    assert six["inconclusive"] == 5
    assert twelve["inconclusive"] == 5

    # Coverage excludes the two deliberately unavailable cases, but includes
    # vulnerable and benign fixtures that abstained.
    assert six["classified_ground_truth_cases"] == 5
    assert twelve["classified_ground_truth_cases"] == 5
    assert six["classification_coverage"] == 5 / 8
    assert twelve["classification_coverage"] == 5 / 8

    assert six["inconclusive_rate_all_cases"] == 5 / 10
    assert twelve["inconclusive_rate_all_cases"] == 5 / 10

    assert six["requests_used"] == 50
    assert twelve["requests_used"] == 98


def test_no_production_vulnerable_verdict_is_generated():
    for case in CORPUS:
        classification, _ = run_six(case)
        assert classification in {
            "candidate",
            "not_confirmed",
            "inconclusive",
        }
