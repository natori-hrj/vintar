
# Time-based SQL Injection HTTP Evaluation

## Purpose

This document defines the experimental HTTP evaluation corpus
for Vintar's time-based SQL injection component.

The corpus uses loopback HTTP requests and isolated SQL or non-SQL
application fixtures.

A timing CANDIDATE is not proof of SQL injection.

## Ground Truth

Every evaluated application case must have ground truth established
independently of the Timing Analyzer.

Ground-truth categories:

- VULNERABLE
- NON_VULNERABLE

These categories describe the test fixture, not Vintar's
production Verdict enum.

A SQL-backed application with deliberately unsafe query construction
and a working conditional SQL delay is labeled VULNERABLE.

An application using parameterized SQL, or one that does not
execute SQL, is labeled NON_VULNERABLE.

## Test Environment

The default corpus uses:

- A FastAPI application
- A Uvicorn HTTP server
- The 127.0.0.1 loopback interface
- An ephemeral TCP port
- SQLite in-memory databases
- Deterministic application behavior where practical

The optional database corpus uses:

- Dedicated PostgreSQL test database
- Dedicated MySQL test database
- Explicit environment-based opt-in
- Known database identity
- A dedicated test table

Database credentials must not appear in output or reports.

The test application must not listen on an externally
reachable interface.

## Probe Configuration

The experimental settings are:

- Nine probes
- Three BASELINE observations
- Three CONTROL observations
- Three DELAY observations
- Expected delay: 0.30 seconds
- Configured fixture delay: 0.40 seconds
- Request timeout: 3 seconds
- Total cooperative deadline: 15 seconds
- Request rate limit: 100 requests per second

The configured delay is intentionally larger than the
expected delay to allow some local timing variation.

These values are experimental settings, not validated
production detection thresholds.

The total deadline is cooperative, not a hard wall-clock
execution guarantee.

## Default Corpus

| Case | Ground truth | Expected classification |
| --- | --- | --- |
| sqlite_vulnerable | VULNERABLE | CANDIDATE |
| sqlite_safe | NON_VULNERABLE | NOT_CONFIRMED |
| non_sql_mimic | NON_VULNERABLE | CANDIDATE |
| non_sql_slow | NON_VULNERABLE | NOT_CONFIRMED |
| non_sql_jitter | NON_VULNERABLE | INCONCLUSIVE |

The expected classifications are test hypotheses.

They must be confirmed by executing the corpus.

The non-SQL mimic case intentionally demonstrates that a
repeatable delay pattern can exist without SQL execution.

A false candidate in this fixture must remain a known limitation.

The dedicated HTTP 429 fixture is an execution-safety case rather
than a classification-quality denominator. It must stop after one
request with an INCONCLUSIVE `rate_limited` result.

## Optional Database Corpus

| DBMS | Case | Ground truth | Expected classification |
| --- | --- | --- | --- |
| PostgreSQL | vulnerable | VULNERABLE | CANDIDATE |
| PostgreSQL | safe | NON_VULNERABLE | NOT_CONFIRMED |
| MySQL | vulnerable | VULNERABLE | CANDIDATE |
| MySQL | safe | NON_VULNERABLE | NOT_CONFIRMED |

The optional cases must be evaluated separately from the
default corpus unless a combined denominator is explicitly stated.

SQL query planning and database load can influence timing behavior.

The PostgreSQL delay expression is an uncorrelated scalar subquery
over `pg_sleep()`. With the one-row fixture it is expected to execute
once for each DELAY request. The MySQL `SLEEP()` predicate is evaluated
against a table containing exactly one qualifying row and is likewise
expected once per DELAY request. The corpus verifies three bounded
DELAY measurements rather than claiming that every optimizer and SQL
shape preserves this evaluation count.

A passing fixture does not prove compatibility with every
SQL context or DBMS version.

## Expected Metrics

For the five default classification cases, if every
expected result is reproduced:

- Vulnerable cases: 1
- Non-vulnerable cases: 4
- CANDIDATE: 2
- NOT_CONFIRMED: 2
- INCONCLUSIVE: 1
- SKIPPED: 0
- Execution errors: 0

The corresponding illustrative metrics are:

| Metric | Formula | Expected |
| --- | --- | --- |
| Candidate sensitivity | TP / P | 1 / 1 = 100% |
| False-candidate rate | FC / N | 1 / 4 = 25% |
| Classification coverage | (C + NC) / T | 4 / 5 = 80% |
| Abstention rate | (IC + SK) / T | 1 / 5 = 20% |
| Execution error rate | ER / T | 0 / 5 = 0% |
| Conditional false-candidate proportion | FC / (FC + NC_N) | 1 / 3 |

These are expected values, not measured results.

The sample size is too small for general-world
performance claims.

The rate of 25% is not an estimate of the production
false-positive rate.

## Reference Measurement

A local Linux and Python 3.13.16 run on 2026-11-16 produced the
following five-case default-corpus result:

- CANDIDATE: 2
- NOT_CONFIRMED: 2
- INCONCLUSIVE: 1
- Candidate sensitivity: 1 / 1 = 100%
- False-candidate rate: 1 / 4 = 25%
- Classification coverage: 4 / 5 = 80%
- Abstention rate: 1 / 5 = 20%
- Execution error rate: 0 / 5 = 0%
- Conditional false-candidate proportion: 1 / 3 = 33.3%
- Budget consumption: 45
- Transport dispatches: 45
- Server-received requests: 45
- Sum of runner elapsed times: 7.2575 seconds

The dedicated HTTP 429 safety case stopped after one request with
equal budget, dispatch, and server-receive counts.

The optional PostgreSQL and MySQL run produced CANDIDATE for both
unsafe fixtures and NOT_CONFIRMED for both parameterized fixtures.
Across those four cases, budget consumption, dispatches, and received
requests were all 36, and runner elapsed time totaled 2.9465 seconds.

This is a reproducibility record for one controlled environment. It
does not replace repeated evaluation or establish production rates.

## Request Accounting

Each completed default classification case is expected to
use nine HTTP requests.

If all five cases complete their nine requests:

- Total budget consumption: 45
- Total transport dispatches: 45
- Total recorded observations: 45

The corpus must report these three quantities separately.

A transport dispatch does not prove that the server
received the request.

The server-side request count is separately observable
inside the fixture.

The SQLite fixture additionally counts calls to its registered SQL
delay function. A vulnerable nine-probe run must invoke the 0.40-second
function three times and the zero-second control function three times.
The parameterized fixture must invoke neither function.

Timeout or deadline cases may legitimately have
different counts.

## Timing Evidence

For completed classifications, inspect:

- Baseline median
- Control median
- Delay median
- Median excess
- Minimum delay margin
- Within-category span
- Baseline and Control drift

Do not store:

- Raw response bodies
- Authorization headers
- Cookies
- Database credentials
- Raw injected requests in published summaries

Timing evidence is not proof of SQL execution.

## Reliability

Socket-backed integration tests are influenced by:

- Process scheduling
- Operating system load
- Python interpreter scheduling
- Database load
- Network stack behavior
- Application startup and shutdown
- Request timeout behavior

A single successful run is not sufficient to quantify
repeatability.

Timing-sensitive tests should be repeated and evaluated
for flaky classifications.

When timing instability prevents an expected classification,
report the observed status and evidence instead of silently
weakening the assertion.

## Database Safety

Only use an explicitly authorized, disposable database environment.

The PostgreSQL and MySQL tests must not run automatically
against arbitrary database hosts.

The tests use known loopback endpoints and dedicated
database identities.

Database data setup is destructive to its dedicated
test table.

Do not reuse the configured database credentials against
production systems.

The database container, network, and disposable volumes
should be removed after the integration run.

## Reproduction

Run default HTTP corpus tests:

```bash
uv run pytest tests/test_sqli_time_http_corpus.py -v
```

Optional PostgreSQL and MySQL integration tests require
the existing dedicated Docker test environment.

Enable them only after verifying database identity and
connection configuration.

For the standard test suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

A skipped database integration test must never be
reported as passed.

## Release Interpretation

Passing this corpus demonstrates that the experimental
runner can classify the specific local scenarios under
the observed timing conditions.

It does not establish:

- Real-world candidate sensitivity
- Real-world false-positive rate
- Production stability
- Strict wall-clock deadline enforcement
- Universal SQL dialect compatibility
- Reliability against WAF and CDN interference
- SQL injection exploitation proof

A CANDIDATE must not automatically become
Verdict.VULNERABLE.

The component remains experimental and must not be
connected to a production AppSec security gate based
solely on these fixture results.

## Future Evaluation

Further work should include:

- Repeated runs with measured classification variance
- Independent vulnerable applications
- Independent safe applications
- Non-SQL application delay mimics
- Timeout fixtures
- Authentication changes
- Cache interference
- Concurrent server load
- Network jitter
- Strict total-execution deadline controls
- Broader SQL contexts and injection locations

Independent evaluation is necessary before proposing
production detection thresholds.
