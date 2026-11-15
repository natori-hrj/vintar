# Time-based SQL Injection Verification Contract

## Purpose

This document defines the experimental design and safety
requirements for Vintar's time-based SQL injection verification.

The implementation includes:

- A bounded, immutable request plan
- A pure timing analyzer
- An experimental HTTP runner

The component does not establish SQL execution or prove SQL injection.

It is not approved for production vulnerability findings or CI gates.

## Separation From Boolean Verification

Time-based verification is independent of Boolean-based verification.

It reuses the shared HTTP execution foundation:

- RequestTemplate
- InjectionPoint
- ScopePolicy
- ExecutionContext
- RequestBudget
- RateLimiter
- HTTP timeouts
- Response size limits
- Request validation and preflight

Boolean response equality, Boolean Evidence, and Boolean confirmation
reason codes are not timing detection rules.

## Probe Categories

### BASELINE

An unchanged request used to measure ordinary response latency.

### CONTROL

A request containing a condition intended not to trigger an
artificial delay.

### DELAY

A request containing a condition intended to trigger a bounded delay.

Payloads are trusted caller-supplied inputs.

The request plan validates payload structure, not SQL semantics.

It cannot prove that a payload executes SQL or causes a database sleep.

## Probe Order

The experimental sequence contains nine probes:

```text
BASELINE
CONTROL
DELAY
CONTROL
DELAY
BASELINE
DELAY
BASELINE
CONTROL
```

Each category appears exactly three times.

The order reduces simple timing-position bias but does not eliminate
network jitter, application load changes, caching, or conditional
non-SQL delays.

Three samples per category are not sufficient to establish
general-world detection accuracy.

## Request Plan

The plan requires:

- Nine planned requests
- An unused RequestBudget with a maximum of nine
- Expected delay between 0.25 and 2.0 seconds
- Context request timeout no greater than 8.0 seconds
- Timeout at least 0.5 seconds longer than expected delay
- Three distinct logical request templates
- Full preflight template validation
- Full preflight origin-scope validation
- No HTTP I/O during preparation

The plan accepts only an exact InjectionPoint whose fields have
the expected types.

The current injection location is QUERY.

APPEND and REPLACE preserve the selected occurrence when duplicate
query parameter names exist.

Payloads must be bounded, distinct strings without Unicode
category C characters.

A plan is a structural description of requests, not an authorization
token or a proof of execution provenance.

## Timing Observation

Each TimeObservation records:

- Probe category
- Sequence number
- Probe outcome
- Completed response latency, if available
- HTTP status, if available
- Response truncation
- RateLimiter acquisition duration

Completed latency and rate-limit waiting must remain separate.

Transport elapsed time is calculated by the shared HTTP layer and
includes response processing.

The runner subtracts measured RateLimiter acquisition duration
before producing a completed timing observation.

The result is an approximation of response execution time rather
than a hardware-calibrated network measurement.

No observation contains raw HTTP response bodies, injected payloads,
cookies, or authorization headers.

A failed or interrupted attempt does not contribute a completed
latency sample.

## Timing Analysis

The pure analyzer validates:

1. Observation order and sequence numbers
2. Terminal failure conditions
3. HTTP 429
4. Truncated responses
5. Other non-2xx statuses
6. Completeness of nine observations
7. Timing evidence
8. Stability
9. Candidate delay conditions
10. Absence of the expected delay

The analysis uses:

- Baseline median
- Control median
- Delay median
- Median delay excess
- Baseline and Control median difference
- Within-category spans
- Baseline and Control endpoint drift
- Minimum Delay versus maximum Control margin

The experimental stability threshold is:

```text
max(0.12, expected_delay_seconds * 0.25)
```

The CANDIDATE rule requires both:

```text
median_excess >= expected_delay_seconds * 0.75
minimum_delay_margin >= expected_delay_seconds * 0.50
```

The NOT_CONFIRMED rule requires:

```text
median_excess <= expected_delay_seconds * 0.25
```

Stability failures take precedence over candidate classification.

Intermediate or otherwise ambiguous measurements are INCONCLUSIVE.

These thresholds are laboratory heuristics, not validated
statistical confidence bounds or production thresholds.

A non-SQL delay mimic may still become CANDIDATE.

## Analysis Result Semantics

### CANDIDATE

A reproducible experimental timing pattern was observed.

This is not a VULNERABLE verdict.

### NOT_CONFIRMED

The specified experimental delay pattern was not reproduced.

This is not proof that the target is secure.

### INCONCLUSIVE

The measurement was incomplete, unstable, ambiguous, or interrupted
by a terminal HTTP or transport condition.

Timeouts are never treated as standalone evidence of SQL injection.

### Execution error

An internal contract violation or unexpected execution failure is
an execution error rather than a normal target classification.

Unexpected analyzer failures must not be transformed into a candidate.

## HTTP Runner

The runner constructs the plan and observations inside one trusted
function invocation.

It performs up to nine scoped HTTP requests using a single
ExecutionContext.

The runner stops after:

- HTTP 429
- Any other non-2xx status
- Response truncation
- Transport timeout
- Transport request failure
- RateLimiter interruption
- Execution deadline expiry

For a completed nine-probe sequence, it invokes the pure timing
analyzer.

The runner is not connected to Schema v1, the public CLI, or the
production CI security gate.

## Request Accounting

Three counts must remain distinguishable:

- RequestBudget consumption
- Actual underlying transport dispatches
- Recorded observations

The request budget is consumed before RateLimiter acquisition.

Therefore, a canceled or interrupted rate-limit wait can consume
budget without dispatching an HTTP request.

The report exposes budget consumption and dispatch count.

An observation records a logical attempt, not necessarily a
completed HTTP response.

## Total Execution Deadline

The experimental runner accepts a total time limit in seconds.

The default is 45 seconds, with a maximum of 120 seconds.

The runner uses a monotonic clock.

Before each request, the runner checks the remaining time and
reduces the per-request HTTP timeout accordingly.

The transport checks the deadline before and after RateLimiter
acquisition.

Immediately before dispatch, it caps HTTPX connect, read, write,
and pool timeouts to the remaining cooperative deadline.

These are per-operation timeouts and do not convert synchronous
HTTPX execution into a hard total-time boundary.

A request must not be deliberately dispatched after a deadline
check has established that the deadline has expired.

If a completed response arrives after the deadline, it is not
included as a usable completed timing measurement.

### Important limitation

The current deadline is cooperative.

RateLimiter sleep and synchronous HTTP I/O are not guaranteed
to be forcibly interrupted at the deadline.

An HTTP timeout may bound individual socket operations rather
than guarantee a strict end-to-end wall-clock limit.

Consequently, total observed execution time can exceed the
configured limit.

A strict execution deadline remains an open requirement.

The current runner must not be advertised as providing a hard
wall-clock execution ceiling.

## Scope and Network Safety

Every request is subject to scope validation at the actual
HTTP transport boundary.

The standard HTTP path disables environment proxy inheritance
and does not follow redirects.

ScopePolicy validates permitted URL origins, not destination IP
addresses obtained after DNS resolution.

Untrusted environments require network-level egress controls.

Custom transports and instrumentation callbacks are trusted
internal or test dependencies.

Time-based probes can increase application and database resource
usage. Targets must be explicitly authorized and suitable for
controlled testing.

## Evidence and Data Retention

The runner's analysis evidence does not retain:

- Raw HTTP response bodies
- Request templates
- Injection payloads
- Authorization headers
- Cookies

Timing observations may nevertheless reveal information about
application behavior and should be handled appropriately.

The runner creates plan and observation data inside one invocation.

Direct construction of arbitrary observations is not proof that
those observations originated from the represented target.

## Evaluation Requirements

The component must be evaluated against independently established
ground truth.

The evaluation corpus must include:

- Vulnerable SQL application with controlled delay
- Safe parameterized SQL application
- Non-SQL conditional delay mimic
- Stable high-latency application
- Variable-latency application
- Background load
- Request timeout
- HTTP 429
- Authentication changes
- Cache interference

Measurements must distinguish:

- Candidate sensitivity
- False-candidate rate
- Classification coverage
- Abstention rate
- Execution errors
- Budget usage
- Actual dispatches
- Total execution time

Synthetic test results must not be presented as real-world
false-positive rates.

## Outstanding Requirements

Before production use:

- Enforce a hard end-to-end execution deadline
- Validate total execution time under blocking transports
- Add controlled SQL-backed HTTP fixtures
- Evaluate safe and non-SQL delay-mimic fixtures
- Measure timing stability under network and application jitter
- Establish acceptable detection and coverage thresholds
- Validate cancellation and rate-limit interruption
- Document supported DBMS and SQL contexts
- Review response evidence disclosure
- Define machine-readable reporting and CLI integration
- Define CI gate behavior
- Perform independent evaluation

## Current Completion Assessment

The request plan and pure analyzer are implemented.

An experimental HTTP runner is implemented, subject to successful
review and regression tests.

The runner provides bounded request counts and cooperative deadline
checks, not a strict total-time guarantee.

The component is suitable for controlled research after validation.

It is not yet a production SQL injection detector and must not
emit a production VULNERABLE finding.
