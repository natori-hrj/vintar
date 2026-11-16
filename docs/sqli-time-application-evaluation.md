
# Time-based SQLi Application-Level Evaluation

## Purpose

This document defines application-level quality evaluation
for Vintar's experimental time-based SQLi component.

The objective is to prevent repeated executions of one
application from being counted as independent applications.

This evaluation does not produce vulnerability verdicts.

## Evaluation Hierarchy

The hierarchy is:

```text
Application
  |
  +-- Execution 0
  +-- Execution 1
  +-- ...
```

Each application has:

- A stable application identifier
- Independently established ground truth
- Framework classification
- DBMS classification
- SQL-context classification
- One or more execution samples

The application identifier is a grouping key.

Distinct identifiers do not prove that application
implementations are statistically independent.

## Ground Truth

Ground truth is assigned from the fixture implementation.

Supported labels:

- VULNERABLE
- NON_VULNERABLE

The Timing Analyzer does not assign ground truth.

An application can be NON_VULNERABLE and still produce
a timing CANDIDATE.

## Application Outcome

An application outcome is determined from its
repeated execution classifications.

| Execution outcomes | Application outcome |
| --- | --- |
| All CANDIDATE | CANDIDATE |
| All NOT_CONFIRMED | NOT_CONFIRMED |
| All INCONCLUSIVE | INCONCLUSIVE |
| All execution errors | EXECUTION_ERROR |
| Any mixture | MIXED |

MIXED represents observed classification instability.

A majority of CANDIDATE executions does not promote
a MIXED application to CANDIDATE.

Reason-code variation is recorded separately from
classification variation.

## Application-Level Rates

Let:

- A = evaluated applications
- P = vulnerable applications
- N = non-vulnerable applications
- TP = vulnerable applications classified CANDIDATE
- FC = non-vulnerable applications classified CANDIDATE
- C = applications classified CANDIDATE
- NC = applications classified NOT_CONFIRMED
- IC = applications classified INCONCLUSIVE
- M = applications classified MIXED
- ER = applications classified EXECUTION_ERROR

The rates are:

```text
Candidate sensitivity = TP / P
False-candidate rate = FC / N
Classification coverage = (C + NC) / A
Abstention rate = (IC + M) / A
Execution error rate = ER / A
Mixed-case rate = M / A
```

Undefined rates are represented as None.

All application outcomes remain in the relevant
ground-truth denominator.

A MIXED application does not count as a true candidate
or a false candidate.

## Execution Error Limitation

EXECUTION_ERROR is reserved for applications where
every repetition fails with an internal execution error.

If some executions fail and others return ordinary
classifications, the application outcome is MIXED.

Consequently, application-level execution error rate
does not capture every partially failed application.

`execution_error_run_count` preserves the number of failed runs,
including failures inside MIXED applications. It is not an
application-level rate. Run-level error metrics remain necessary.

## Statistical Intervals

Wilson score intervals use the number of applications
as the denominator.

Repeated runs of one application do not increase
the number of application trials.

For example:

```text
One vulnerable application
Ten CANDIDATE repetitions

Application-level trials: 1
Application-level successes: 1
```

This differs from a run-weighted evaluation.

Wilson intervals still rely on sampling assumptions.

Applications sharing code, runtime infrastructure,
developers, datasets, or other characteristics
may be statistically dependent.

Application-level grouping alone does not establish
independent or representative sampling.

## Stratification

Supported dimensions:

- framework
- dbms
- sql_context

Each stratum contains a subset of complete applications.

No application is duplicated within a stratum
of one dimension.

Strata are descriptive and do not establish causal
relationships between framework, DBMS, SQL context,
and detection results.

Small or empty denominators must not be hidden.

## Local HTTP Corpus

The initial real HTTP test evaluates four distinct
ASGI application instances.

| Application | Ground truth | DBMS | Expected outcome |
| --- | --- | --- | --- |
| unsafe_sqlite | VULNERABLE | sqlite | CANDIDATE |
| prepared_sqlite | NON_VULNERABLE | sqlite | NOT_CONFIRMED |
| non_sql_mimic | NON_VULNERABLE | none | CANDIDATE |
| non_sql_plain | NON_VULNERABLE | none | NOT_CONFIRMED |

Each application receives two complete Runner
executions with a fresh ExecutionContext and
RequestBudget for each execution.

Expected accounting:

```text
Applications: 4
Executions: 8
Requests per execution: 9

Budget: 72
Dispatch: 72
Server received: 72
```

These are test expectations, not measurements
recorded before running the test suite.

## Reference Measurement

A local loopback run on Linux with Python 3.13.16 produced:

- Applications: 4
- Executions: 8
- CANDIDATE applications: 2
- NOT_CONFIRMED applications: 2
- INCONCLUSIVE, MIXED, and EXECUTION_ERROR applications: 0
- Candidate sensitivity: 1 / 1 = 100%
- False-candidate rate: 1 / 3 = 33.3%
- Classification coverage: 4 / 4 = 100%
- Abstention, execution-error, mixed-case, and reason-instability rates: 0%
- Budget, dispatch, and server-received requests: 72 each

The application-level 95% Wilson intervals were:

- Candidate sensitivity, 1 / 1: [20.7%, 100%]
- False-candidate rate, 1 / 3: [6.1%, 79.2%]

The corresponding run-weighted rates happen to have the same point
estimates because both executions of every fixture agreed. Their
denominators would incorrectly be 2 vulnerable runs and 6
non-vulnerable runs if presented as independent applications. This
would narrow the Wilson intervals to [34.2%, 100%] and [9.7%, 70.0%]
without adding independently developed applications.

The DBMS strata were:

| DBMS tag | Applications | Sensitivity | False-candidate rate |
| --- | ---: | ---: | ---: |
| sqlite | 2 | 1 / 1 | 0 / 1 |
| none | 2 | None | 1 / 2 |

Framework, DBMS, and SQL-context tags are descriptive grouping labels.
They neither establish ground truth nor prove that applications in a
stratum are statistically independent.

The services bind only to 127.0.0.1 using
ephemeral ports.

The SQL fixtures use SQLite in-memory databases.

## Interpretation

The test demonstrates that the evaluator can:

- Group repeated executions into an application
- Preserve independently assigned fixture labels
- Avoid counting repeated runs as new applications
- Keep known non-SQL false candidates visible
- Produce application-level Wilson intervals
- Partition applications by DBMS and SQL context
- Verify separate execution accounting

It does not demonstrate that four independently
developed applications were evaluated.

All test applications share the same framework,
runtime, host environment, and test harness.

The evaluation should not be extrapolated to
real-world AppSec performance.

## Provenance and Safety

Application identifiers and grouping tags are
validated using a restricted ASCII character set.

The evaluation records do not retain:

- HTTP URLs
- Request bodies
- Response bodies
- Authentication secrets
- Cookies
- Raw payloads

The evaluator relies on trusted fixtures to provide
ground truth and server-receive counts.

It cannot independently verify that those claims
are accurate.

No additional requests are generated by the
aggregation module.

The separate HTTP test uses explicitly scoped
loopback applications only.

## Reproduction

Run pure aggregation tests:

```bash
uv run pytest tests/test_sqli_time_application_quality.py -v
```

Run the local HTTP application tests:

```bash
uv run pytest tests/test_sqli_time_applications_http.py -v
```

Run regression and static checks:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The tests do not require Docker or an external database.

## Remaining Limitations

The evaluation does not yet provide:

- Independently developed applications
- Representative application sampling
- Multiple framework implementations
- Multiple independent SQL contexts
- Application-cluster bootstrap intervals
- Hierarchical uncertainty estimates
- Cross-DBMS application samples
- Strong provenance of application independence
- Strict total wall-clock execution guarantees
- Proof that arbitrary timing candidates are SQLi

The application-level corpus is a structural
evaluation baseline, not a production benchmark.

## Release Boundary

The following remain unchanged:

- SQLi Analyzer thresholds
- HTTP Runner classification contract
- Production Verdict
- Schema
- CLI
- CI security gates

A timing CANDIDATE must not automatically become
Verdict.VULNERABLE.
