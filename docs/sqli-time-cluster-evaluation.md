
# Time-based SQLi Cluster-Level Evaluation

## Purpose

This document defines descriptive cluster-level quality metrics
for Vintar's experimental time-based SQLi evaluation.

The evaluation hierarchy is:

```text
Cluster
  |
  +-- Application
        |
        +-- Execution
        +-- Execution
        +-- ...
```

This framework does not prove statistical independence
or produce vulnerability verdicts.

## Cluster Definition

A cluster is an explicitly declared group of applications
that share a relevant dependency boundary.

Possible dependency boundaries include:

- Common source code or derived implementations
- Shared framework components
- Shared infrastructure and runtime configuration
- Common deployment artifacts
- Shared test harnesses
- Common data-generation processes

Cluster assignment must be justified independently
of the observed detection results.

An application must belong to exactly one cluster
within a benchmark.

The implementation rejects duplicate application
identifiers across clusters.

Cluster identifiers are grouping metadata and
must not contain raw secrets or URLs.

## Evaluation Units

Three observation levels must remain distinct.

### Execution

An execution is one Time-based Runner invocation.

Each execution has its own request accounting,
observations, status, and reason code.

### Application

An application aggregates one or more executions.

Its outcome follows the existing application contract:

- CANDIDATE
- NOT_CONFIRMED
- INCONCLUSIVE
- MIXED
- EXECUTION_ERROR

A mixed result must not be promoted to CANDIDATE
by majority vote.

### Cluster

A cluster contains one or more applications.

A cluster does not receive a vulnerability verdict.

Its quality measurements are calculated from its
application-level benchmark.

## Application-weighted Evaluation

The application-weighted false-candidate rate is:

```text
Number of non-vulnerable CANDIDATE applications
/
Number of non-vulnerable applications
```

Every eligible application has equal weight,
regardless of the number of repeated executions.

This is the existing application-level calculation.

## Cluster-balanced Evaluation

For each cluster with a defined denominator,
calculate its application-level rate.

The cluster-balanced estimate is:

```text
Sum of eligible cluster-level rates
/
Number of eligible clusters
```

Every contributing cluster has equal weight.

A cluster without vulnerable applications does not
contribute to candidate sensitivity.

A cluster without non-vulnerable applications does not
contribute to false-candidate rate.

Undefined denominators are not replaced with zero.

The number of contributing clusters must always
be reported alongside the estimate.

`ClusterRate` retains the validated source clusters and recomputes the
expected per-cluster values during construction. Direct construction or
`dataclasses.replace()` cannot attach arbitrary numeric observations
without matching application-level provenance.

## Example

Consider two clusters:

| Cluster | Applications | False candidates | Rate |
| --- | ---: | ---: | ---: |
| Family A | 9 | 9 | 100% |
| Family B | 1 | 0 | 0% |

Application-weighted false-candidate rate:

```text
9 / 10 = 90%
```

Cluster-balanced false-candidate rate:

```text
(100% + 0%) / 2 = 50%
```

Neither number is universally preferable.

The application-weighted result describes the
observed application collection.

The cluster-balanced result gives each declared
cluster equal influence.

Neither necessarily estimates the false-candidate
rate of a target population.

## Leave-one-cluster-out Diagnostics

For a metric with at least two eligible clusters,
recalculate the cluster-balanced estimate after
removing one eligible cluster at a time.

Report the minimum and maximum of those estimates.

This describes sensitivity to individual clusters.

It is not a confidence interval.

When fewer than two clusters contribute,
the range is undefined and represented as None.

A wide range means that the observed estimate
depends strongly on which clusters are included.

The implementation recomputes each omitted-cluster mean directly rather
than subtracting one value from a precomputed total, avoiding unnecessary
floating-point cancellation.

## Repetition Policy

Each ApplicationUnit supports between one and
one hundred executions.

The cluster benchmark has a configurable minimum
repetition policy.

The default minimum is two executions per application.

Applications below the minimum are reported in
under_replicated_applications.

The meets_repetition_policy flag is false when
any application falls below the configured minimum.

Insufficiently repeated applications are not
silently removed from descriptive metrics.

A benchmark that fails its repetition policy
must be marked as insufficient for the intended
reliability comparison.

Different applications may have different numbers
of repetitions.

The cluster-balanced estimate remains
application-weighted within each cluster.

## Execution Errors

The existing ApplicationUnit preserves the count of
execution errors, including partial errors inside
MIXED application outcomes.

The cluster benchmark reports the sum of execution
errors across all applications and executions.

This count must not be confused with the rate of
applications classified EXECUTION_ERROR.

An application whose executions include both
successful results and errors is MIXED.

## Statistical Limitations

Applications may be correlated within clusters.

Clusters may also remain correlated with each other.

Equal weighting of clusters does not guarantee
independent observations.

The module does not currently implement:

- Cluster bootstrap confidence intervals
- Hierarchical Bayesian inference
- Mixed-effects models
- Intraclass correlation estimation
- Population-representative weighting
- Effective sample-size estimation

Wilson intervals from application-level evaluation
remain descriptive and may underestimate uncertainty
when applications are correlated.

Leave-one-cluster-out ranges are sensitivity
diagnostics, not confidence intervals.

No reported rate is a verified real-world
detection accuracy estimate.

## Ground Truth

Ground Truth remains an application property.

Valid values are:

- VULNERABLE
- NON_VULNERABLE

Ground Truth is supplied by independently reviewed
test fixtures.

Neither a cluster label nor a Timing Analyzer
classification establishes SQL execution.

A non-SQL delay mimic may still be CANDIDATE.

The evaluation must preserve this known limitation.

## Provenance

The cluster assignment should be recorded before
the evaluation takes place.

The accompanying research record should state:

- Why the applications share a cluster
- Which codebase or infrastructure is shared
- Which dependencies remain shared across clusters
- How ground truth was independently established
- Whether the corpus was selected before evaluating
  candidate outcomes

The model validates identifiers, uniqueness,
ordering, and application membership.

It cannot independently verify these provenance
claims.

## Stratification

The original application benchmark supports
stratification by:

- framework
- dbms
- sql_context

Cluster evaluation preserves access to these
descriptive application strata.

A stratum may contain applications from several
dependency clusters.

A framework tag does not automatically define
a dependency cluster.

Likewise, using different DBMS products does
not automatically establish statistical independence.

## Test Scope

The initial unit corpus includes:

- Vulnerable applications
- Parameterized safe applications
- Non-SQL timing mimics
- Mixed classification outcomes
- Partial execution failures
- Unequal cluster sizes
- Unequal repetition counts
- Undefined ground-truth denominators

The unit tests do not send HTTP requests.

Previously implemented loopback HTTP and DBMS
corpora remain separate.

This addition does not claim to introduce new
independently developed applications.

## Reference Calculation

The deterministic unit corpus contains:

- 3 declared clusters
- 5 applications
- 10 executions
- 2 vulnerable and 3 non-vulnerable applications

Its application-weighted results are:

- Candidate sensitivity: 1 / 2 = 50%
- False-candidate rate: 1 / 3 = 33.3%
- Classification coverage: 5 / 5 = 100%

Its cluster-balanced results are:

| Metric | Eligible clusters | Estimate | Leave-one-cluster-out range |
| --- | ---: | ---: | ---: |
| Candidate sensitivity | 2 | 50% | 0%–100% |
| False-candidate rate | 3 | 33.3% | 0%–50% |
| Classification coverage | 3 | 100% | 100%–100% |

The equality of the application- and cluster-weighted point estimates in
this small corpus is incidental. A separate unequal-size test produces a
90% application-weighted false-candidate rate and a 50% cluster-balanced
rate.

## Reproduction

Run the cluster-level evaluation tests:

```bash
uv run pytest tests/test_sqli_time_cluster_quality.py -v
```

Run existing application and research tests:

```bash
uv run pytest tests/test_sqli_time_application_quality.py -v
uv run pytest tests/test_sqli_time_applications_http.py -v
uv run pytest tests/test_sqli_time_research.py -v
```

Run the complete regression suite:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The new cluster unit tests do not require Docker.

Existing database integration tests remain opt-in.

## Release Boundary

The following are unchanged:

- Timing Analyzer thresholds
- Time-based HTTP Runner behavior
- Production vulnerability verdicts
- CLI
- Schema
- CI security gates

The research evaluator must not promote
CANDIDATE to Verdict.VULNERABLE.

## Future Work

Recommended follow-up work includes:

- Independently developed application corpora
- Explicit cluster provenance records
- Cluster-resampling experiments
- Multiple independent application families
- Multiple frameworks and SQL contexts
- Independent SQL execution instrumentation
- Statistical analysis of between-cluster variance
- Repeatability under diverse operating systems
- Strict total wall-clock deadline enforcement

The present implementation is a descriptive
hierarchical evaluation baseline, not a
production performance benchmark.
