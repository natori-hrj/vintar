
# Time-based SQLi Reliability Evaluation

## Purpose

This document defines repeatability metrics for Vintar's
experimental time-based SQL injection component.

The purpose is to measure classification behavior across
repeated executions, including known false candidates.

The evaluation does not prove SQL execution or establish
production detection accuracy.

## Scope

The evaluation includes:

- Independent fixture ground truth
- Repeated timing classifications
- Candidate sensitivity
- False-candidate rate
- Classification coverage
- Abstention rate
- Execution error rate
- Case-level classification changes
- Request and elapsed-time accounting

The Time Plan, Analyzer thresholds, and HTTP Runner
classification contract remain unchanged.

## Ground Truth

Fixtures must be labeled independently of the Analyzer.

Supported ground-truth labels:

- VULNERABLE
- NON_VULNERABLE

The label describes the fixture's implementation.

CANDIDATE is an experimental classification, not a
production vulnerability verdict.

A non-SQL conditional delay can be labeled
NON_VULNERABLE and still produce CANDIDATE.

## Repeated Measurements

A quality evaluation contains one or more named cases.

Every case has:

- A stable case identifier
- One independently established ground truth
- The same number of repetitions
- Unique iteration indices starting from zero

Repetitions are separate Runner invocations.

The loopback baseline runs the first repetition in declared case
order and the second in reverse order. This varies each case's
position in the schedule without claiming statistical randomization.

Each invocation must use a fresh ExecutionContext
and an unused nine-request budget.

The evaluator rejects missing, duplicated, or
unbalanced repetition indices.

An execution error must not be silently removed from
the evaluation denominator.

## Classification Quality Metrics

Let:

- T = total execution attempts
- P = attempts against vulnerable fixtures
- N = attempts against non-vulnerable fixtures
- TP = vulnerable attempts classified CANDIDATE
- FC = non-vulnerable attempts classified CANDIDATE
- C = all CANDIDATE attempts
- NC = all NOT_CONFIRMED attempts
- IC = all INCONCLUSIVE attempts
- ER = internal execution errors
- NC_N = non-vulnerable attempts classified NOT_CONFIRMED

The metrics are:

```text
Candidate sensitivity = TP / P

False-candidate rate = FC / N

Classification coverage = (C + NC) / T

Abstention rate = IC / T

Execution error rate = ER / T

Conditional false-candidate proportion = FC / (FC + NC_N)
```

Undefined rates must be represented as None.

An execution error is distinct from INCONCLUSIVE.

Neither execution errors nor INCONCLUSIVE results
may be removed from the total execution denominator.

## Classification Repeatability

A case is classification-flaky when at least two
repetitions produce different classifications.

Execution error is treated as a distinct outcome
for classification repeatability.

The case-level flaky rate is:

```text
Number of cases with multiple observed outcomes
/
Total number of evaluated cases
```

Reason-code variation within the same classification
is recorded, but does not by itself change the
classification-flaky rate.

A separate reason-code instability metric may be
added in future work.

A zero flaky rate after two repetitions does not
establish statistical reliability.

## HTTP Test Scenarios

The additional loopback evaluation includes:

| Case | Ground truth | Expected status |
| --- | --- | --- |
| vulnerable | VULNERABLE | CANDIDATE |
| safe | NON_VULNERABLE | NOT_CONFIRMED |
| mimic | NON_VULNERABLE | CANDIDATE |
| auth | NON_VULNERABLE | INCONCLUSIVE |
| waf | NON_VULNERABLE | INCONCLUSIVE |
| cache | NON_VULNERABLE | INCONCLUSIVE |
| load | NON_VULNERABLE | INCONCLUSIVE |

The vulnerable endpoint executes intentionally unsafe
SQL against an in-memory SQLite database.

The safe endpoint uses a parameterized SQLite query.

The mimic endpoint does not execute SQL. It produces
the same conditional delay pattern at the application layer.

The authentication fixture returns HTTP 401 during
the request sequence.

The WAF-like fixture returns HTTP 403 for the
control payload.

The cache fixture delays only the first DELAY request.

The load fixture delays a BASELINE response without
regard to injected SQL.

These are controlled application behaviors, not
complete simulations of real authentication, WAF,
cache, or production workload systems.

## Expected Evaluation Accounting

The baseline reliability experiment uses:

- Seven cases
- Two repetitions per case
- Fourteen total Runner invocations

Expected results, if every classification is reproduced:

| Classification | Runs |
| --- | ---: |
| CANDIDATE | 4 |
| NOT_CONFIRMED | 2 |
| INCONCLUSIVE | 8 |
| Execution error | 0 |

Expected quality metrics:

| Metric | Expected |
| --- | --- |
| Candidate sensitivity | 2 / 2 |
| False-candidate rate | 2 / 12 |
| Classification coverage | 6 / 14 |
| Abstention rate | 8 / 14 |
| Execution error rate | 0 / 14 |
| Conditional false-candidate proportion | 2 / 4 |
| Classification-flaky case rate | 0 / 7 |

These values are test expectations, not recorded measurements.

They must be replaced or supplemented with actual results
after executing the corpus.

The fixture-specific rates must not be generalized to
real applications.

## Reference Measurement

A local Linux and Python 3.13.16 run on 2026-11-16 reproduced the
expected classifications in both scheduling orders:

- CANDIDATE: 4 runs
- NOT_CONFIRMED: 2 runs
- INCONCLUSIVE: 8 runs
- Execution errors: 0 runs
- Candidate sensitivity: 2 / 2 = 100%
- False-candidate rate: 2 / 12 = 16.7%
- Classification coverage: 6 / 14 = 42.9%
- Abstention rate: 8 / 14 = 57.1%
- Execution error rate: 0 / 14 = 0%
- Conditional false-candidate proportion: 2 / 4 = 50%
- Classification-flaky case rate: 0 / 7 = 0%
- Budget consumption: 102
- Transport dispatches: 102
- Server-received requests: 102
- Recorded observations: 102
- Sum of Runner elapsed times: 6.6292 seconds

Two repetitions cannot establish a statistically reliable flaky
rate. These values are a controlled-fixture reproducibility record,
not estimates for production applications.

## Timing Interpretation

The timing Analyzer evaluates:

- Median response latency
- Median DELAY versus CONTROL excess
- Minimum DELAY versus maximum CONTROL margin
- Within-category variation
- BASELINE versus CONTROL stability
- Endpoint drift

A timeout alone is not SQL injection evidence.

The Analyzer's current thresholds remain experimental.

The quality evaluator does not modify those thresholds
and does not change classification results.

## Fundamental Identification Limit

A non-SQL application can imitate a conditional SQL delay.

When two systems produce observationally equivalent
timing distributions, timing measurements alone cannot
establish which system executed SQL.

Additional evidence or an independent verification
mechanism is required.

Additional probes may reduce certain accidental
timing confounders but cannot eliminate this fundamental
identification limitation.

The evaluator must not claim that a timing CANDIDATE
is a confirmed vulnerability.

## Execution Accounting

For every evaluation attempt, record:

- Budget consumption
- Transport dispatch attempts
- Server-received requests
- Observation count
- Runner elapsed time

These quantities have different meanings.

Transport dispatch does not prove server receipt.

Server-received counts are available only from
instrumented test fixtures.

A separate Runner invocation must have its own
fresh RequestBudget.

The quality evaluator does not enforce a strict
total wall-clock deadline.

The underlying Runner retains its cooperative
deadline limitation.

## Safety

All intentionally vulnerable SQL runs only against
a local in-memory SQLite fixture.

The HTTP server binds to 127.0.0.1 using an
ephemeral local port.

The evaluation must not contact external targets.

SQL exceptions return a fixed HTTP response
without disclosing the SQL statement.

Raw response bodies, SQL payloads, credentials,
and request headers are not part of QualitySample.

Real database fixtures require separate isolation
and explicit authorization.

## Reproduction

Run pure evaluation unit tests:

```bash
uv run pytest tests/test_sqli_time_quality.py -v
```

Run loopback HTTP reliability tests:

```bash
uv run pytest tests/test_sqli_time_reliability_http.py -v
```

Run the existing HTTP corpus:

```bash
uv run pytest tests/test_sqli_time_http_corpus.py -v
```

Run the complete regression suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The new tests do not require Docker.

The existing PostgreSQL and MySQL integration
tests remain explicitly opt-in.

## Limitations

The evaluation still lacks:

- Sufficient repetitions for confidence intervals
- Randomized test execution order
- Independent applications and infrastructure
- Network perturbation and independent jitter
- Real WAF products
- Real cache layers
- Authentication session rotation
- Concurrent workload generators
- Strict total wall-clock enforcement
- Independent confirmation of SQL execution
- Broad database and injection-context coverage

The initial reliability corpus is an experimental
baseline and not a release-quality accuracy benchmark.

## Future Work

Recommended next investigations:

- Repeatability experiments with multiple seeds
- Randomized case scheduling
- Reason-code stability
- Confidence intervals for candidate sensitivity
- Confidence intervals for false-candidate rate
- Separately controlled network and application jitter
- Independent control experiments
- More realistic authentication and cache scenarios
- Hard execution deadline enforcement
- Independent vulnerability confirmation

The shipped CI gate uses the
[product result contract](sqli-time-contract.md#product-result-contract),
which reports timing candidates as `INCONCLUSIVE` and never as `VULNERABLE`.
