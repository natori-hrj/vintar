# Time-based SQL Injection Verification Contract

## Purpose

This document defines the shipped case contract, research design, and safety
requirements for Vintar's time-based SQL injection verification.

The implementation includes:

- A bounded, immutable request plan
- A pure timing analyzer
- An HTTP runner used by Schema v1 cases through `vintar verify`

The component does not establish SQL execution or prove SQL injection.

CI can block for review when a timing candidate is returned.

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

## Schema v1 Time Case

Schema v1 accepts an explicit time-based case without inferring a DBMS, SQL
context, or payload preset:

```toml
version = 1
id = "product-search-time-sqli"
type = "sqli.time"
expected_verdict = "not_detected"

[target]
url = "http://127.0.0.1:8000/products"
allowed_origin = "http://127.0.0.1:8000"
params = [{ name = "category", value = "Pets" }]

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
delay_payload = "reviewed-delay-expression"
control_payload = "reviewed-control-expression"
expected_delay_seconds = 0.5

[limits]
max_requests = 9
requests_per_second = 2.0
timeout_seconds = 2.0
```

The loader requires:

- Exactly the three time probe fields; Boolean, mixed, and unknown probe keys
  are rejected
- Explicit, distinct payloads of 1–512 characters without Unicode category C
  characters
- `expected_delay_seconds` from 0.25 through 2.0
- Exactly nine requests
- `requests_per_second` from 0.1 through 10.0
- `timeout_seconds` at least 0.5 seconds above the expected delay and no more
  than 8.0 seconds
- Exact built-in numeric values; booleans are not numbers
- Query injection with a non-negative occurrence and `append` or `replace`
- Distinct baseline, control, and delay request URLs, all inside the declared
  allowed origin

All case and trusted-policy checks finish before the first HTTP request.
Diagnostics explain which setting is invalid and what bound or field to use,
without echoing URLs, payloads, or baseline values.

### OpenAPI materialization config

The offline `materialize-case` pipeline uses the existing reviewed OpenAPI
draft and answers. To request a Time case, the target config explicitly adds
`type = "sqli.time"` and supplies:

```toml
config_version = 1
type = "sqli.time"
input_id = "input-reviewed-id"

[probes]
selection = "explicit"
delay_payload = "reviewed-delay-expression"
control_payload = "reviewed-control-expression"
expected_delay_seconds = 0.5

[limits]
max_requests = 9
requests_per_second = 2.0
timeout_seconds = 2.0
```

The config also requires the same explicit `[target]` and query `[injection]`
tables as Boolean materialization. `selection = "preset"` is not supported for
Time cases; reviewers must write both reviewed payloads explicitly. OpenAPI
scalar types do not select a DBMS, SQL context, payload, or check type. The
generated TOML expands only the Schema v1 probe fields and is validated by the
unchanged case loader before any destination file is written.

Boolean cases retain the reviewed material's existing deterministic case ID.
Time cases append `-time` to the same base ID. This makes Boolean and Time cases
from one reviewed draft distinct in a mixed batch. The suffix is never silently
truncated; materialization rejects a base ID longer than 59 characters because
the resulting ID would exceed the Schema v1 64-character limit.

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
- Baseline and Control within-category spans
- Delay span, used only after the candidate conditions are not met
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

Classification uses this precedence:

1. Baseline or Control stability failures produce
   `INCONCLUSIVE / unstable_timing`.
2. If both candidate conditions are met, the result is CANDIDATE. Delay span does
   not affect this path because CPU-bound Delay work can vary with scheduling and
   host load while every Delay response remains separated from the Control band.
3. If the candidate conditions are not met, a Delay span above the stability
   limit produces `INCONCLUSIVE / unstable_timing`.
4. Only after those checks can the no-delay relation produce `NOT_DETECTED` or an
   intermediate relation produce `INCONCLUSIVE / ambiguous_timing`.

This asymmetry keeps a clearly separated candidate despite Delay variance while
preventing incomplete negative evidence from passing the CI gate.

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

## Product Result Contract

The offline product contract maps a validated timing analysis to a product
verdict without changing its reason code. Schema v1, the CLI, and CI reports
use this mapping.

A timing candidate maps to `INCONCLUSIVE`, never `VULNERABLE`. A
`NOT_DETECTED` result means only that the configured timing pattern was not
reproduced by this bounded check; it does not prove the absence of SQL
injection.

| Reason code | Analysis status | Product verdict | Requests | Complete nine | Evidence |
| --- | --- | --- | ---: | --- | --- |
| `timing_pattern_matched` | CANDIDATE | INCONCLUSIVE | 9 | required | required |
| `timing_pattern_not_matched` | NOT_CONFIRMED | NOT_DETECTED | 9 | required | required |
| `incomplete_probes` | INCONCLUSIVE | INCONCLUSIVE | 0–8 | no | forbidden |
| `probe_timeout` | INCONCLUSIVE | INCONCLUSIVE | 1–9 | no | forbidden |
| `probe_failed` | INCONCLUSIVE | INCONCLUSIVE | 1–9 | no | forbidden |
| `probe_interrupted` | INCONCLUSIVE | INCONCLUSIVE | 1–9 | no | forbidden |
| `rate_limited` | INCONCLUSIVE | INCONCLUSIVE | 1–9 | no | forbidden |
| `non_success_status` | INCONCLUSIVE | INCONCLUSIVE | 1–9 | no | forbidden |
| `truncated_response` | INCONCLUSIVE | INCONCLUSIVE | 1–9 | no | forbidden |
| `unstable_timing` | INCONCLUSIVE | INCONCLUSIVE | 9 | required | required |
| `ambiguous_timing` | INCONCLUSIVE | INCONCLUSIVE | 9 | required | required |

`TIME_RESULT_RULES` is the machine-readable source for these invariants. The
analyzer validates status, reason, request count, completeness, and evidence
against that table before a result can be mapped.

### Structured decision facts

New CI reports include bounded `decision_facts` for every Time non-decision
listed below. Legacy schema-v1 reports may omit this additive sibling.

- Operational reasons identify stage `time`, the one-based sequence and fixed
  probe kind, a condition enum, and an HTTP status only when a response exists.
  Deadline expiry before dispatch points to the next request in the fixed plan.
- `unstable_timing` lists one or more causes in deterministic order:
  `baseline_span`, `control_span`, `baseline_control_difference`, `drift`, and
  `delay_span`.
- `ambiguous_timing` records only whether the candidate median condition, the
  candidate minimum-margin condition, and the no-delay condition were met.

These facts deliberately exclude elapsed values, medians, thresholds, margins,
payloads, URLs, and response content. They are constructed by the analyzer or
runner from the same predicates that select the reason; the report layer only
serializes them. Constructors, JSON Schema, and the Python report validator
reject a fact category or shape that contradicts the reason.

The CI report has no per-probe Time observation array. Its validator can bind
an operational fact to the fixed plan and `request_count`, but cannot compare
the reported HTTP status against a second per-probe field.

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

The runner accepts validated Schema v1 `sqli.time` cases through both the
single-case regression API and `vintar verify`. Time cases can share a batch
with Boolean cases while retaining their independent nine-request execution
budget.

## CI report contract

A time outcome uses the common `actual_verdict`, `actual_reason_code`, and
`request_count` fields and adds:

```json
{
  "check_type": "sqli.time",
  "timing": {
    "status": "candidate",
    "reason_code": "timing_pattern_matched",
    "request_count": 9
  }
}
```

Time outcomes never contain the Boolean `verification` or `confirmation`
objects. Boolean outcomes never contain `check_type` or `timing`. Time outcomes
do not expose elapsed observations, medians, thresholds, payloads, or target
URLs. Boolean outcomes in the same report retain their per-observation `elapsed`
values. The Schema v1 extension is additive; legacy v1 reports remain valid.

The existing process exit contract is unchanged: a matched timing pattern is
INCONCLUSIVE with exit code 3, a matching NOT_DETECTED result can pass with exit
code 0, expectation failures use exit code 1, and invalid execution or report
inputs use exit code 2.

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

The regression API takes the total time limit from
`TrustedExecutionPolicy.max_time_execution_seconds`, independently of the
case. A case cannot increase this operator-owned limit.

The CLI exposes this trusted policy as `--time-deadline`. The default is 45
seconds, with a maximum of 120 seconds. Invalid or impossible combinations fail
preflight with guidance to increase the deadline or rate, or shorten the valid
per-request timeout.

Before HTTP, preflight applies the stricter case and trusted request rates and
per-request timeouts. The deadline must accommodate one full per-request
timeout plus the eight required rate-limit intervals:

```text
9 * effective_timeout + 8 / effective_requests_per_second
```

This budgets every request at its full per-request timeout plus the eight
rate-limit intervals between nine requests. The runner receives that same
trusted deadline, checks remaining time before every request, and caps each
request timeout to the remaining duration. The trusted timeout must also
remain at least 0.5 seconds above the expected delay. Impossible combinations
are rejected before dispatch with guidance to increase the trusted deadline or
rate, or shorten the valid timeout.

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

The content-addressed evidence, acquisition, signature, checkpoint, audit,
freshness, lifecycle, streaming, and governor modules remain research
infrastructure. They are not imported into or required by the product result
mapping path.

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

Before making broader production reliability claims:

- Enforce a hard end-to-end execution deadline
- Validate total execution time under blocking transports
- Add controlled SQL-backed HTTP fixtures
- Evaluate safe and non-SQL delay-mimic fixtures
- Measure timing stability under network and application jitter
- Establish acceptable detection and coverage thresholds
- Validate cancellation and rate-limit interruption
- Document supported DBMS and SQL contexts
- Review response evidence disclosure
- Perform independent evaluation

## Current Completion Assessment

The request plan, pure analyzer, and HTTP runner are available through
Schema v1 Time cases.

The runner provides bounded request counts and cooperative deadline
checks, not a strict total-time guarantee.

The component is suitable for controlled research after validation.

It is not yet a production SQL injection detector and must not
emit a production VULNERABLE finding.
