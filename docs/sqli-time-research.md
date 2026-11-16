
# Time-based SQLi Independent Control and Statistical Research

## Purpose

This document describes research-only extensions for Vintar's
experimental time-based SQL injection evaluation.

The extensions provide:

- Wilson score intervals for observed binary rates
- Separate status and reason-code variability metrics
- Comparisons with independently executed control conditions
- Explicit limits on causal interpretation

They do not change the Time Plan, Timing Analyzer, HTTP Runner,
production Verdict, CLI, Schema, or CI gates.

## Statistical Intervals

Candidate sensitivity uses:

```text
CANDIDATE on vulnerable fixtures
/
All executions of vulnerable fixtures
```

False-candidate rate uses:

```text
CANDIDATE on non-vulnerable fixtures
/
All executions of non-vulnerable fixtures
```

INCONCLUSIVE and execution errors remain in these denominators.

For each defined proportion, a Wilson score interval is calculated.

The default confidence level is 95%.

The implementation derives the two-sided normal quantile from the
requested confidence level and applies the Wilson score formula without
a continuity correction. Floating-point endpoints are clamped so that
the observed proportion remains inside the returned interval.

A rate with zero denominator has no interval and is represented
as None.

A measured 100% success rate with a small sample must not be
presented as proof of perfect performance.

## Independence Limitation

Wilson score intervals are derived from a binomial sampling model.

Repeated measurements of the same application fixture may be
correlated because they share:

- Application implementation
- Runtime environment
- Network conditions
- Database configuration
- Operating system scheduler
- Timing Analyzer thresholds

Consequently, treating repeated fixture runs as independent trials
can produce misleadingly narrow intervals.

The intervals are descriptive for the collected observations.

They do not guarantee population coverage for real-world
applications.

Independent application-level sampling and hierarchical analysis
would be needed for stronger generalization claims.

## Status and Reason-code Variability

Status variability is present when repeated executions of a case
produce more than one classification status.

Reason-code variability is present when repeated executions produce
more than one reason code.

These are separate metrics.

For example, a case may remain INCONCLUSIVE in every run while
alternating between:

```text
unstable_timing
ambiguous_timing
```

Such a case has:

```text
Status variability: false
Reason-code variability: true
```

Execution errors are treated as distinct outcomes.

An execution error can therefore make both the status and reason-code
variability flags true. An INCONCLUSIVE result and an execution error
are not the same outcome.

The metrics describe observed variation, not the probability of
future classification changes.

## Independent Control Experiment

An independent control is an additional, explicitly authorized
experiment using a different, justified test condition.

It is not an extra automatic request inside the existing
nine-probe Runner.

Each experiment requires:

- Its own validated plan
- Its own fresh ExecutionContext
- A new nine-request budget
- The same authorized target boundary
- Independently collected observations

Comparisons must not imply that the two executions share an
identical network or application state.

## Control Assessment

If the primary execution produces CANDIDATE:

| Control result | Assessment |
| --- | --- |
| CANDIDATE | CONTROL_REACTIVE |
| NOT_CONFIRMED | CONTROL_NOT_REACTIVE |
| INCONCLUSIVE | UNDETERMINED |

If the primary execution is not CANDIDATE, the control
assessment is UNDETERMINED.

CONTROL_REACTIVE indicates that the independent condition
also produces a candidate timing pattern.

CONTROL_NOT_REACTIVE indicates that the independent condition
did not reproduce that candidate pattern.

Neither assessment proves or disproves SQL injection.

No control assessment is converted into Verdict.VULNERABLE.

## Fundamental Identification Limit

A non-SQL application may reproduce precisely the same timing
behavior as a vulnerable SQL-backed application.

If the systems are observationally equivalent under the tested
requests, timing measurements alone cannot identify which one
executed SQL.

A non-reactive independent control does not resolve this
limitation.

A reactive independent control may indicate broader application
behavior, filtering, caching, or another confounding factor,
but does not establish its cause.

The intended semantics of a control must be justified before
its observed response can be interpreted.

## Controlled Test Fixtures

The unit research corpus includes:

- A SQLite-backed SQL expression with a registered delay function
- A non-SQL application that imitates the primary delay condition
- A non-SQL application that responds to a broader set of conditions

The tests execute through HTTPX MockTransport and a controlled clock.

In the SQLite experiment, the primary delay and control values terminate
the string literal and invoke the registered `vintar_delay` SQL function.
The shadow values are opaque application strings: when appended to the
fixture input they remain inside the SQL string literal and do not invoke
that function. They are controls for broader application-level timing
reactions, not a second SQL injection syntax.

The controlled results are:

| Fixture | Primary | Shadow control | Assessment |
| --- | --- | --- | --- |
| Vulnerable SQLite expression | CANDIDATE | NOT_CONFIRMED | CONTROL_NOT_REACTIVE |
| Exact non-SQL timing mimic | CANDIDATE | NOT_CONFIRMED | CONTROL_NOT_REACTIVE |
| Broad non-SQL timing mimic | CANDIDATE | CANDIDATE | CONTROL_REACTIVE |

The identical first two rows demonstrate that a non-reactive control does
not distinguish the vulnerable SQL expression from a sufficiently exact
non-SQL mimic.

They do not constitute socket-backed HTTP verification.

The separately maintained real HTTP corpus remains the source
for loopback socket observations.

The SQL fixture is deliberately vulnerable and must remain confined
to controlled test code.

## Evaluation Policy

Before changing the Analyzer:

1. Establish ground truth independently of classification.
2. Preserve the existing detection thresholds.
3. Collect repeated classifications and reasons.
4. Record budget, transport dispatch, and elapsed time.
5. Calculate rates using explicit denominators.
6. Report interval estimates and sample sizes.
7. Identify correlated or non-independent observations.
8. Evaluate independent controls without promoting findings.
9. Separate execution errors from diagnostic abstentions.
10. Compare results using independently held-out applications.

## Safety Boundaries

The new modules perform no autonomous scanning.

Custom payloads and transports remain trusted test inputs.

The research models do not retain:

- Raw response bodies
- Cookies
- Authorization headers
- Database credentials
- HTTP request templates

All database and transport fixtures must remain isolated.

The existing cooperative Deadline is not a strict total
wall-clock execution guarantee.

## Test Commands

```bash
uv run pytest tests/test_sqli_time_research.py -v
uv run pytest tests/test_sqli_time_control_experiment.py -v

uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

## Remaining Work

The research basis remains limited by:

- Small per-fixture repetition counts
- Correlated observations
- Limited independent applications
- Controlled rather than production-like network conditions
- Lack of independent SQL execution confirmation for arbitrary targets
- Incomplete DBMS and SQL-context coverage
- Cooperative rather than strict execution deadline
- Potentially indistinguishable non-SQL timing mimics

These limitations prevent production detection accuracy claims
and automatic vulnerability-verdict promotion.
