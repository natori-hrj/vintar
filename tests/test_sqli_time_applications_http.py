"""Evaluate distinct local ASGI applications over loopback HTTP.

The deliberately unsafe SQL exists only in isolated SQLite fixtures.
Application independence is limited by shared runtime infrastructure.
"""

import socket
import sqlite3
import threading
import time
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import Response

from vintar.checks.sqli.time_analyzer import (
    TimeAnalysisStatus,
    TimeObservation,
    TimeProbeOutcome,
    analyze_time_probes,
)
from vintar.checks.sqli.time_application_quality import (
    ApplicationOutcome,
    ApplicationUnit,
    summarize_applications,
)
from vintar.checks.sqli.time_plan import (
    TIME_PROBE_ORDER,
    TimePayloads,
    prepare_time_plan,
)
from vintar.checks.sqli.time_quality import (
    GroundTruth,
    QualitySample,
)
from vintar.checks.sqli.time_runner import TimeRunReport, verify_time_based_sqli
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

DELAY_SECONDS = 0.4
EXPECTED_DELAY = 0.3

DELAY_PAYLOAD = "' AND vintar_delay(0.4)=1-- "
CONTROL_PAYLOAD = "' AND vintar_delay(0)=1-- "

CASES = (
    (
        "unsafe_sqlite",
        GroundTruth.VULNERABLE,
        "sqlite",
        "where",
        TimeAnalysisStatus.CANDIDATE,
    ),
    (
        "prepared_sqlite",
        GroundTruth.NON_VULNERABLE,
        "sqlite",
        "where",
        TimeAnalysisStatus.NOT_CONFIRMED,
    ),
    (
        "non_sql_mimic",
        GroundTruth.NON_VULNERABLE,
        "none",
        "none",
        TimeAnalysisStatus.CANDIDATE,
    ),
    (
        "non_sql_plain",
        GroundTruth.NON_VULNERABLE,
        "none",
        "none",
        TimeAnalysisStatus.NOT_CONFIRMED,
    ),
)

SAFE_LIVE_OUTCOMES = frozenset(
    {
        (TimeAnalysisStatus.NOT_CONFIRMED, "timing_pattern_not_matched"),
        (TimeAnalysisStatus.INCONCLUSIVE, "unstable_timing"),
    }
)
DELAY_SIGNAL_LIVE_OUTCOMES = frozenset(
    {
        (TimeAnalysisStatus.CANDIDATE, "timing_pattern_matched"),
        (TimeAnalysisStatus.INCONCLUSIVE, "unstable_timing"),
    }
)

# Recorded loopback sequences in TIME_PROBE_ORDER. Exact classification uses
# these fixed observations; live HTTP tests cover mechanics and bounded outcomes.
RECORDED_ELAPSED_SECONDS = {
    "unsafe_sqlite": (
        (
            0.015715,
            0.003466,
            0.403446,
            0.003033,
            0.403137,
            0.002695,
            0.404679,
            0.002409,
            0.001751,
        ),
        (
            0.005938,
            0.002817,
            0.403902,
            0.002461,
            0.402684,
            0.002193,
            0.404221,
            0.001986,
            0.002104,
        ),
    ),
    "prepared_sqlite": (
        (
            0.004221,
            0.002726,
            0.002584,
            0.001933,
            0.001789,
            0.001635,
            0.001891,
            0.001503,
            0.001778,
        ),
        (
            0.003744,
            0.002281,
            0.002366,
            0.001851,
            0.001962,
            0.001714,
            0.001803,
            0.001681,
            0.001824,
        ),
    ),
    "non_sql_mimic": (
        (
            0.003603,
            0.002308,
            0.402937,
            0.002518,
            0.402779,
            0.024741,
            0.403522,
            0.002458,
            0.001915,
        ),
        (
            0.004112,
            0.002105,
            0.403418,
            0.002264,
            0.403006,
            0.002731,
            0.404089,
            0.002019,
            0.001862,
        ),
    ),
    "non_sql_plain": (
        (
            0.004068,
            0.002188,
            0.002177,
            0.001874,
            0.001879,
            0.001813,
            0.001617,
            0.002148,
            0.002070,
        ),
        (
            0.003829,
            0.002013,
            0.002241,
            0.001722,
            0.001916,
            0.001764,
            0.001695,
            0.001987,
            0.001841,
        ),
    ),
}


@dataclass(repr=False)
class ApplicationState:
    received: list[str] = field(default_factory=list)
    sql_executions: int = 0
    delay_values: list[float] = field(default_factory=list)
    lock: threading.Lock = field(
        default_factory=threading.Lock,
        repr=False,
    )

    def record_request(self, category: str) -> None:
        with self.lock:
            self.received.append(category)

    def record_sql(self) -> None:
        with self.lock:
            self.sql_executions += 1

    def record_delay(self, seconds: float) -> None:
        with self.lock:
            self.delay_values.append(seconds)

    def snapshot(self):
        with self.lock:
            return (
                tuple(self.received),
                self.sql_executions,
                tuple(self.delay_values),
            )


def execute_sql(
    *,
    category: str,
    vulnerable: bool,
    state: ApplicationState,
) -> None:
    with closing(sqlite3.connect(":memory:")) as database:

        def sleep_function(seconds: float) -> int:
            state.record_delay(seconds)
            time.sleep(seconds)
            return 1

        database.create_function(
            "vintar_delay",
            1,
            sleep_function,
        )
        database.execute("CREATE TABLE products (category TEXT NOT NULL)")
        database.execute(
            "INSERT INTO products VALUES (?)",
            ("Pets",),
        )

        state.record_sql()

        if vulnerable:
            database.execute(
                f"SELECT category FROM products WHERE category = '{category}'"
            ).fetchall()
        else:
            database.execute(
                "SELECT category FROM products WHERE category = ?",
                (category,),
            ).fetchall()


def create_application(
    application_id: str,
    state: ApplicationState,
) -> FastAPI:
    app = FastAPI(
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/products")
    def products(request: Request) -> Response:
        values = request.query_params.getlist("category")

        if len(values) != 1:
            return Response(status_code=400)

        category = values[0]
        state.record_request(category)

        if application_id == "unsafe_sqlite":
            try:
                execute_sql(
                    category=category,
                    vulnerable=True,
                    state=state,
                )
            except sqlite3.Error:
                return Response(
                    b"query-error",
                    status_code=500,
                )

        elif application_id == "prepared_sqlite":
            try:
                execute_sql(
                    category=category,
                    vulnerable=False,
                    state=state,
                )
            except sqlite3.Error:
                return Response(
                    b"query-error",
                    status_code=500,
                )

        elif application_id == "non_sql_mimic":
            if category == "Pets" + DELAY_PAYLOAD:
                state.record_delay(DELAY_SECONDS)
                time.sleep(DELAY_SECONDS)

        elif application_id != "non_sql_plain":
            return Response(status_code=404)

        return Response(b"ok", media_type="text/plain")

    return app


@contextmanager
def running_application(application_id: str):
    state = ApplicationState()
    app = create_application(application_id, state)

    listener = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )

    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)

        port = listener.getsockname()[1]

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            lifespan="off",
            access_log=False,
            log_level="critical",
            server_header=False,
        )

        server = uvicorn.Server(config)

        worker = threading.Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            daemon=True,
        )
        worker.start()

        try:
            deadline = time.monotonic() + 5.0

            while (
                not server.started and worker.is_alive() and time.monotonic() < deadline
            ):
                time.sleep(0.01)

            assert server.started
            assert worker.is_alive()

            yield state, f"http://127.0.0.1:{port}"

        finally:
            server.should_exit = True
            worker.join(timeout=5)

            if worker.is_alive():
                server.force_exit = True
                worker.join(timeout=5)

            assert not worker.is_alive()

    finally:
        listener.close()


def run_application(origin: str):
    port = urlsplit(origin).port
    assert port is not None

    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset(
                {
                    AllowedOrigin(
                        "http",
                        "127.0.0.1",
                        port,
                    )
                }
            )
        ),
        budget=RequestBudget(9),
        timeout=3.0,
        rate_limiter=RateLimiter(
            requests_per_second=100.0,
        ),
    )

    report = verify_time_based_sqli(
        template=RequestTemplate(
            method="GET",
            url=origin + "/products",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=TimePayloads(
            delay=DELAY_PAYLOAD,
            control=CONTROL_PAYLOAD,
        ),
        expected_delay_seconds=EXPECTED_DELAY,
        context=context,
        max_total_seconds=15.0,
    )

    assert context.budget.used_requests == report.budget_used
    return report


def analyze_fixed_elapsed(elapsed_values: tuple[float, ...]):
    origin = "http://127.0.0.1:18083"
    context = ExecutionContext(
        scope=ScopePolicy(
            allowed_origins=frozenset({AllowedOrigin("http", "127.0.0.1", 18083)})
        ),
        budget=RequestBudget(9),
        timeout=3.0,
        rate_limiter=RateLimiter(requests_per_second=100.0),
    )
    plan = prepare_time_plan(
        template=RequestTemplate(
            method="GET",
            url=origin + "/products",
            params=(("category", "Pets"),),
        ),
        point=InjectionPoint(
            location=InjectionLocation.QUERY,
            name="category",
            mode=InjectionMode.APPEND,
        ),
        payloads=TimePayloads(delay=DELAY_PAYLOAD, control=CONTROL_PAYLOAD),
        expected_delay_seconds=EXPECTED_DELAY,
        context=context,
    )
    observations = tuple(
        TimeObservation(
            kind=kind,
            sequence=sequence,
            outcome=TimeProbeOutcome.COMPLETED,
            elapsed_seconds=elapsed,
            status_code=200,
        )
        for sequence, (kind, elapsed) in enumerate(
            zip(
                TIME_PROBE_ORDER,
                elapsed_values,
                strict=True,
            ),
            start=1,
        )
    )
    return analyze_time_probes(plan=plan, observations=observations)


def fixed_application_analysis(application_id: str, iteration: int):
    return analyze_fixed_elapsed(RECORDED_ELAPSED_SECONDS[application_id][iteration])


@dataclass(frozen=True, slots=True)
class LiveApplicationRun:
    application_id: str
    report: TimeRunReport
    received: tuple[str, ...]
    sql_count: int
    delay_values: tuple[float, ...]


@pytest.fixture(scope="module")
def live_application_runs():
    runs = []

    for (
        application_id,
        _truth,
        _dbms,
        _sql_context,
        _,
    ) in CASES:
        with running_application(application_id) as (state, origin):
            for _ in range(2):
                before_received, before_sql, before_delays = state.snapshot()

                report = run_application(origin)

                received, sql_count, delay_values = state.snapshot()

                new_requests = received[len(before_received) :]
                new_sql = sql_count - before_sql
                new_delays = delay_values[len(before_delays) :]

                runs.append(
                    LiveApplicationRun(
                        application_id=application_id,
                        report=report,
                        received=new_requests,
                        sql_count=new_sql,
                        delay_values=new_delays,
                    )
                )

    return tuple(runs)


def test_application_level_http_mechanics(live_application_runs):
    expected_requests = (
        "Pets",
        "Pets" + CONTROL_PAYLOAD,
        "Pets" + DELAY_PAYLOAD,
        "Pets" + CONTROL_PAYLOAD,
        "Pets" + DELAY_PAYLOAD,
        "Pets",
        "Pets" + DELAY_PAYLOAD,
        "Pets",
        "Pets" + CONTROL_PAYLOAD,
    )
    assert len(live_application_runs) == 8

    for run in live_application_runs:
        report = run.report
        analysis = report.analysis
        elapsed_values = tuple(
            observation.elapsed_seconds for observation in analysis.observations
        )
        diagnostic = (
            f"application_id={run.application_id!r}, status={analysis.status.value!r}, "
            f"reason_code={analysis.reason_code!r}, elapsed_seconds={elapsed_values!r}"
        )
        allowed = (
            DELAY_SIGNAL_LIVE_OUTCOMES
            if run.application_id in {"unsafe_sqlite", "non_sql_mimic"}
            else SAFE_LIVE_OUTCOMES
        )
        assert (analysis.status, analysis.reason_code) in allowed, diagnostic
        if run.application_id == "unsafe_sqlite":
            assert analysis.status is not TimeAnalysisStatus.NOT_CONFIRMED, diagnostic

        assert report.budget_used == 9, diagnostic
        assert report.transport_attempts == 9, diagnostic
        assert analysis.request_count == 9, diagnostic
        assert len(run.received) == 9, diagnostic
        assert not report.deadline_exceeded, diagnostic
        assert run.received == expected_requests, diagnostic

        if run.application_id == "unsafe_sqlite":
            assert run.sql_count == 9, diagnostic
            assert run.delay_values.count(0.4) == 3, diagnostic
            assert run.delay_values.count(0.0) == 3, diagnostic
        elif run.application_id == "prepared_sqlite":
            assert run.sql_count == 9, diagnostic
            assert not run.delay_values, diagnostic
        elif run.application_id == "non_sql_mimic":
            assert run.sql_count == 0, diagnostic
            assert run.delay_values == (0.4, 0.4, 0.4), diagnostic
        else:
            assert run.sql_count == 0, diagnostic
            assert not run.delay_values, diagnostic


@pytest.mark.parametrize(
    ("application_id", "iteration", "expected_status"),
    [(case[0], iteration, case[4]) for case in CASES for iteration in range(2)],
)
def test_recorded_application_observations_classify_exactly(
    application_id, iteration, expected_status
):
    analysis = fixed_application_analysis(application_id, iteration)
    expected_reason = (
        "timing_pattern_matched"
        if expected_status is TimeAnalysisStatus.CANDIDATE
        else "timing_pattern_not_matched"
    )
    elapsed_values = tuple(
        observation.elapsed_seconds for observation in analysis.observations
    )
    diagnostic = (
        f"application_id={application_id!r}, status={analysis.status.value!r}, "
        f"reason_code={analysis.reason_code!r}, elapsed_seconds={elapsed_values!r}"
    )

    assert analysis.status is expected_status, diagnostic
    assert analysis.reason_code == expected_reason, diagnostic
    assert analysis.request_count == 9, diagnostic


def test_recorded_application_runs_are_independent():
    for application_id, runs in RECORDED_ELAPSED_SECONDS.items():
        assert runs[0] != runs[1], (
            f"application_id={application_id!r} has identical recorded runs; identical "
            "runs cannot measure variation. Record a second independent run instead."
        )


def summarize_recorded_applications(cases, recorded_elapsed_seconds):
    units = []

    for application_id, truth, dbms, sql_context, _ in cases:
        samples = []
        for iteration, elapsed_values in enumerate(
            recorded_elapsed_seconds[application_id]
        ):
            analysis = analyze_fixed_elapsed(elapsed_values)
            samples.append(
                QualitySample(
                    case_id=application_id,
                    iteration=iteration,
                    ground_truth=truth,
                    status=analysis.status,
                    reason_code=analysis.reason_code,
                    budget_used=9,
                    transport_attempts=9,
                    server_received=9,
                    observation_count=9,
                    elapsed_seconds=sum(elapsed_values),
                )
            )

        units.append(
            ApplicationUnit(
                application_id=application_id,
                ground_truth=truth,
                framework="fastapi",
                dbms=dbms,
                sql_context=sql_context,
                samples=tuple(samples),
            )
        )

    return summarize_applications(tuple(units))


@pytest.fixture(scope="module")
def application_results():
    return summarize_recorded_applications(CASES, RECORDED_ELAPSED_SECONDS)


def test_application_aggregate_detects_mixed_fixed_observations():
    candidate_elapsed = RECORDED_ELAPSED_SECONDS["unsafe_sqlite"][0]
    not_confirmed_elapsed = (0.1,) * 9
    result = summarize_recorded_applications(
        (
            (
                "variation_guard",
                GroundTruth.VULNERABLE,
                "sqlite",
                "where",
                TimeAnalysisStatus.CANDIDATE,
            ),
        ),
        {"variation_guard": (candidate_elapsed, not_confirmed_elapsed)},
    )

    assert result.mixed_case_rate > 0
    assert result.reason_flaky_rate > 0


def test_application_level_http_quality(application_results):
    result = application_results

    assert result.application_count == 4
    assert result.run_count == 8
    assert result.vulnerable_count == 1
    assert result.non_vulnerable_count == 3
    assert result.true_candidates == 1
    assert result.false_candidates == 1

    assert result.candidate_sensitivity == 1
    assert result.false_candidate_rate == pytest.approx(1 / 3)
    assert result.classification_coverage == 1
    assert result.abstention_rate == 0
    assert result.mixed_case_rate == 0
    assert result.reason_flaky_rate == 0
    assert result.execution_error_run_count == 0

    assert result.request_count == 72
    assert result.dispatch_count == 72
    assert result.server_received == 72

    sensitivity = result.sensitivity_interval()
    false_candidates = result.false_candidate_interval()
    assert sensitivity is not None
    assert sensitivity.trials == 1
    assert false_candidates is not None
    assert false_candidates.trials == 3


def test_application_strata(application_results):
    groups = dict(application_results.strata("dbms"))

    assert groups["sqlite"].application_count == 2
    assert groups["none"].application_count == 2

    assert groups["sqlite"].candidate_sensitivity == 1
    assert groups["sqlite"].false_candidate_rate == 0

    assert groups["none"].candidate_sensitivity is None
    assert groups["none"].false_candidate_rate == 0.5


def test_application_outcomes_preserve_mimic(
    application_results,
):
    outcomes = {
        app.application_id: app.outcome for app in application_results.applications
    }

    assert outcomes == {
        "unsafe_sqlite": ApplicationOutcome.CANDIDATE,
        "prepared_sqlite": ApplicationOutcome.NOT_CONFIRMED,
        "non_sql_mimic": ApplicationOutcome.CANDIDATE,
        "non_sql_plain": ApplicationOutcome.NOT_CONFIRMED,
    }
