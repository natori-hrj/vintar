# Time-based SQL Injection Verification Contract

## Purpose

This document defines the experimental design and safety
requirements for Vintar's time-based SQL injection verification.

The current implementation only prepares and validates a
bounded request plan.

It does not execute time-based probes or classify targets.

## Separation From Boolean Verification

Time-based verification is a separate detection technique.

It may reuse:

- RequestTemplate
- InjectionPoint
- ScopePolicy
- ExecutionContext
- RequestBudget
- RateLimiter
- HTTP timeouts
- Response size limits
- Request validation and preflight

It must not reuse Boolean response equality as its timing
decision rule.

Boolean evidence and time-based evidence are different types
of observations.

## Probe Categories

Three probe categories are defined.

### BASELINE

An unchanged request used to measure ordinary response latency.

### CONTROL

A request containing a condition designed not to trigger
an artificial delay.

### DELAY

A request containing a condition designed to trigger a
bounded artificial delay.

The meaning of CONTROL and DELAY must be established by
the trusted payload provider.

The plan validator cannot prove that a payload executes SQL,
that a condition is true, or that a database will sleep.

## Probe Order

The initial design uses nine requests.

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

Each category appears three times.

The order is distributed to reduce simple position and
time-trend bias.

This ordering does not eliminate network jitter, server
load variation, caching, or other timing confounders.

Three samples per category are an experimental starting
point, not a demonstrated minimum for reliable detection.

## Current Plan Constraints

The initial plan imposes:

- Exactly nine planned requests
- Exactly nine available budget slots
- An unused RequestBudget
- Expected delay from 0.25 to 2.0 seconds
- Request timeout not exceeding 8.0 seconds
- Timeout at least 0.5 seconds longer than expected delay
- Three distinct logical request templates
- Full template and scope validation
- No HTTP I/O during plan preparation

The current injection boundary accepts only an exact
`InjectionPoint` using `InjectionLocation.QUERY`, a non-empty string
name, a non-negative integer occurrence, and an `InjectionMode` enum.
String lookalikes and Boolean or floating-point occurrences are rejected.
Both APPEND and REPLACE retain the selected occurrence when duplicate
query-parameter names are present.

Payload text is caller-supplied trusted input. The plan enforces bounded,
distinct strings and rejects Unicode control, formatting, surrogate, and
other Unicode `C` category code points. It does not validate SQL dialect
or delay semantics and does not generate payloads.

These constraints apply to the plan, not to a completed
verification execution.

The timeout margin does not guarantee that an intentionally
delayed response will complete successfully.

## Total Execution Deadline

A request budget does not enforce a wall-clock deadline.

A future runner must provide an independent monotonic
deadline that accounts for:

- HTTP request execution
- Rate-limit waits
- Transport failures
- Application delays
- Response processing
- Cancellation

Per-request timeouts must not be presented as a strict
end-to-end elapsed-time bound.

Before each wait or request, that runner must calculate the remaining
deadline. Rate-limiter sleep, transport setup and I/O, response reading,
and local processing must all fit within it. A per-request timeout must
be capped to the remaining deadline, and exhausted time must stop the
run without another send.

The initial plan does not implement such a deadline.

A runner must not be approved for execution until the
deadline and interruption behavior have been validated.

## Timing Measurement

The future runner must use a monotonic clock.

Timing observations should distinguish:

- Transport-observed response elapsed time
- Time spent waiting for the rate limiter
- Overall execution elapsed time

Evidence should also identify the probe category and sequence position,
whether a send was attempted and completed, timeout or failure category,
HTTP status and truncation/comparability state.

Timing values must be finite and non-negative.

A future evidence model must not retain raw response bodies,
authorization headers, cookies, or injected payloads.

Elapsed time alone does not prove SQL execution.

## Planned Timing Analysis

Timing analysis must evaluate both:

- Delayed-versus-control differences
- Baseline-versus-control stability

Future research should include:

- Median differences
- Variability and jitter estimates
- Drift between early and late samples
- Repeated trials
- Non-SQL delay mimics
- Slow but non-vulnerable applications
- Cache and authentication interference

No fixed threshold is currently approved as evidence
of a vulnerability.

Statistical methods must be selected and validated against
independent evaluation data before detector use.

## Timeout Handling

An HTTP timeout is not evidence that a time-based SQL
injection occurred.

Timeouts may result from:

- Network congestion
- Server load
- Connection failures
- Deliberate application delays
- Rate-limit interactions
- A genuine SQL-induced delay

The future runner must keep timeout observations separate
from completed response-time measurements.

It must not automatically turn a timeout into CANDIDATE
or VULNERABLE.

## Planned Result Semantics

The future time-based component should distinguish:

- CANDIDATE
- NOT_CONFIRMED
- INCONCLUSIVE
- SKIPPED
- Internal execution errors

The status meanings must be documented before implementation.

A timing-based CANDIDATE must not be promoted to
Verdict.VULNERABLE without stronger independent evidence.

The component must remain disconnected from production
CI security gates until its detection contract is reviewed.

## Safety Requirements

Time-based testing can increase server resource usage.

A future execution layer must enforce:

- Explicit target authorization
- Scope validation for every request
- Strict request budget
- Strict execution deadline
- Bounded expected delays
- Rate limiting
- Cancellation or interruption handling
- Early termination for HTTP 429
- Early termination for unsafe response conditions
- Explicit handling of timeouts
- Non-destructive test targets
- Secret redaction

Origin-based scope checks do not prove that the
DNS-resolved destination IP remains inside the intended
network boundary.

Network isolation remains necessary for untrusted targets.

The initial implementation supports QUERY injection points.
Other injection locations require separate implementation
and testing.

Scope validation is origin-based and is performed for the baseline,
control, and delay templates during preparation. It does not consume the
request budget. A future runner must repeat validation at the actual send
boundary; a prepared plan alone grants no authority to communicate.

## Required Evaluation Corpus

Before timing detection is enabled, the evaluation suite
must include:

- Vulnerable SQL-backed application with controlled delay
- Safe parameterized SQL implementation
- Non-SQL application performing a similar delay
- Stable high-latency server
- Variable-latency server
- Background server-load interference
- HTTP timeout
- HTTP 429
- Authentication state changes
- Cache interference

Ground truth must be established independently of the
detector's timing classification.

Evaluation should report:

- Candidate sensitivity
- False-candidate rate
- Classification coverage
- Abstention rate
- Execution error rate
- Requests per run
- Total elapsed time

The baseline corpus should be separated from independent
validation targets.

## Integration Boundary

The current time-based plan is not connected to:

- A live time-based HTTP runner
- A timing analyzer
- A time-based evidence model
- Schema v1
- The public CLI
- CI security gates
- A VULNERABLE verdict

The plan is not an authorization token.

It is a validated structural description of requests.

A future runner must construct and execute the plan within
one trusted invocation using a single scoped ExecutionContext.

## Completion Criteria

The design phase is complete when:

- The probe ordering is explicit
- Request budget constraints are tested
- Delay and timeout constraints are validated
- Injection templates are independently validated
- Scope failures do not consume request budget
- Plan construction performs no HTTP I/O
- Raw payloads and credentials are excluded from repr
- Known limitations are documented

Completing these criteria does not establish that a
time-based SQL injection detector has been implemented.
