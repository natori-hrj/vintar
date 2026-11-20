# Boolean-based SQL Injection Verification Contract

## Purpose

This document defines the supported behavior, boundaries, and
interpretation of Vintar's Boolean-based SQL injection verification.

The current implementation is an experimental verification component
for explicitly authorized targets.

It is not a general-purpose SQL injection scanner and does not claim
to prove that a vulnerability exists.

## Architecture

The Boolean verification workflow consists of:

1. Initial Boolean verification
2. Eligibility assessment
3. Additional confirmation
4. Cross-phase consistency assessment
5. Final confirmation classification

The initial stage performs up to six HTTP requests.

An eligible candidate may receive twelve additional requests.

The maximum request budget for a complete confirmation run is
eighteen requests.

The confirmation runner uses a single ExecutionContext for both
stages.

## Initial Verification

The initial verification uses three logical probe categories:

- BASELINE
- TRUE
- FALSE

Each category is sampled twice when the full initial verification
completes.

The request order is:

```text
BASELINE, TRUE, FALSE, BASELINE, FALSE, TRUE
```

The analyzer compares each response pair and each cross-category
relation using:

- HTTP status code
- The full captured response body

It records the HTTP status, body size, and SHA-256 body digest in
each `Observation`. Body size and digest are therefore retained as
non-body evidence, but the initial equality decision is made from
status and the captured body rather than by directly comparing the
stored size and digest fields.

A Boolean-like response relation may produce:

- Verdict.INCONCLUSIVE
- reason_code: boolean_candidate

This is an observation of response behavior, not proof that an
injected SQL expression was executed.

The initial verifier uses the following result reasons:

| Verdict | reason_code | Meaning |
| --- | --- | --- |
| INCONCLUSIVE | `budget_unavailable` | Six requests were not available before execution. |
| INCONCLUSIVE | `rate_limited` | HTTP 429 stopped the initial sequence early. |
| INCONCLUSIVE | `probe_failed` | A budget, local rate limit, timeout, connection, or response-read failure stopped the sequence. |
| INCONCLUSIVE | `truncated_response` | At least one completed response was truncated. |
| INCONCLUSIVE | `non_success_status` | At least one completed response was not 2xx. |
| INCONCLUSIVE | `possible_dynamic_response` | Unstable pairs contained small localized differences. |
| INCONCLUSIVE | `unstable_response` | At least one repeated pair was not stable. |
| INCONCLUSIVE | `boolean_candidate` | BASELINE matched TRUE and differed from FALSE. |
| INCONCLUSIVE | `unexpected_difference` | Stable responses differed without the expected relation. |
| NOT_DETECTED | `no_boolean_difference` | BASELINE, TRUE, and FALSE all matched. |
| NOT_DETECTED | `no_boolean_difference_literal_input` | Stable TRUE and FALSE responses matched each other while both differed from BASELINE. |

`probe_failed` records the structured probe error separately; its
reason code does not distinguish the individual transport failure.

A NOT_DETECTED result is not proof that the target is free
from SQL injection.

The literal-input result means that the two Boolean probes produced no response
difference. It does not prove that the target is not vulnerable: an unsupported SQL
context can also make both payloads ineffective. Check whether the target treated the
payloads as literal input and whether the probe syntax applies to the tested context.

## Confirmation Eligibility

Additional confirmation is only available when the initial
verification satisfies the complete eligibility contract.

Requirements include:

- Initial verdict is INCONCLUSIVE
- Initial reason code is boolean_candidate
- Six completed initial observations
- Two observations per logical category
- Internally stable response pairs
- Only 2xx HTTP response statuses
- No truncated responses
- No initial probe failures
- Required Boolean comparison evidence
- `baseline_true_similarity == 1.0`
- `baseline_false_similarity == 0.0`
- `true_false_similarity == 0.0`

Eligibility rechecks the two samples for each initial category using
status code, body size, and SHA-256 digest. This is stricter than
checking the reason code alone and is separate from the initial
analyzer's full-body equality comparison.

An ineligible initial result does not enter the additional
confirmation stage.

## Additional Confirmation

The confirmation phase performs twelve additional requests.

It uses six logical probe categories:

- BASELINE
- TRUE_1
- FALSE_1
- TRUE_2
- FALSE_2
- CONTROL

Each logical category is sampled twice.

The request order is:

```text
BASELINE, TRUE_1, FALSE_1, CONTROL, TRUE_2, FALSE_2,
BASELINE, FALSE_2, TRUE_2, CONTROL, FALSE_1, TRUE_1
```

The runner generates a fresh random control value for each
complete execution and reuses it within that execution.

All possible confirmation requests are validated before the
initial HTTP request is sent.

The confirmation phase requires every response to be 2xx and not
truncated. It compares status code, body size, and SHA-256 digest,
requires both samples of every logical category to match, and then
evaluates the expected relation.

The expected candidate relation is:

- BASELINE matches TRUE_1 and TRUE_2
- FALSE_1 matches FALSE_2 and CONTROL
- BASELINE differs from FALSE_1

A matching pattern is not evidence of actual SQL execution.

## Cross-Phase Consistency

Cross-phase assessment compares the initial and confirmation
response signatures for:

- BASELINE
- TRUE / TRUE_1
- FALSE / FALSE_1

Each signature contains:

- HTTP status code
- Response body size
- SHA-256 digest

The assessment performs no additional HTTP requests.

Only completed CANDIDATE results enter the cross-phase guard.

A mismatch changes the result to:

- status: INCONCLUSIVE
- reason_code: confirmation_cross_phase_mismatch
- evidence: None

A matching assessment preserves CANDIDATE.

NOT_CONFIRMED, SKIPPED, and existing INCONCLUSIVE results do not
enter the guard.

The guard's MATCH result does not establish that SQL executed.

## Confirmation Status Semantics

The runner emits these normal status and reason-code combinations:

| Status | reason_code |
| --- | --- |
| SKIPPED | `initial_not_eligible` |
| CANDIDATE | `confirmation_pattern_matched` |
| NOT_CONFIRMED | `confirmation_pattern_not_matched` |
| INCONCLUSIVE | `confirmation_budget_unavailable` |
| INCONCLUSIVE | `confirmation_preflight_failed` |
| INCONCLUSIVE | `confirmation_budget_exceeded` |
| INCONCLUSIVE | `confirmation_rate_limit_interrupted` |
| INCONCLUSIVE | `confirmation_timeout` |
| INCONCLUSIVE | `confirmation_request_failed` |
| INCONCLUSIVE | `confirmation_rate_limited` |
| INCONCLUSIVE | `confirmation_truncated` |
| INCONCLUSIVE | `confirmation_non_success_status` |
| INCONCLUSIVE | `confirmation_unstable` |
| INCONCLUSIVE | `confirmation_cross_phase_mismatch` |

An internal cross-phase guard failure has no status/reason-code
combination because no normal `ConfirmationOutcome` is returned.

### CANDIDATE

The initial Boolean relation, confirmation relation, and
cross-phase consistency requirements were satisfied.

Interpretation:

A reproducible SQLi-like HTTP response pattern was observed.

CANDIDATE is not equivalent to VULNERABLE.

A non-SQL implementation or middleware can reproduce the same
pattern.

### NOT_CONFIRMED

The additional confirmation completed with stable observations,
but the required candidate relation was not satisfied.

Interpretation:

The specific experimental hypothesis was not reproduced.

This does not establish that the target is secure.

### INCONCLUSIVE

The verification could not establish a reliable confirmation
classification.

Possible causes include:

- Budget interruption
- Preflight failure
- Rate limit interruption
- Timeout
- Request failure
- Non-success HTTP status
- Truncated response
- Unstable confirmation observations
- Cross-phase response mismatch

An INCONCLUSIVE result must not be interpreted as NOT_DETECTED
or as evidence of safety.

An internal guard failure is reported as an execution error,
not converted into CANDIDATE or a normal target classification.
The runner raises a sanitized `RuntimeError` in this case. It does
not return a `ConfirmationOutcome` for that execution.

### SKIPPED

The initial verification did not satisfy confirmation eligibility.

No additional confirmation requests are sent.

SKIPPED does not imply that the target is secure.

## Vulnerability Verdict

The confirmation runner does not produce Verdict.VULNERABLE.

CANDIDATE must not be converted into VULNERABLE solely because
a Boolean response pattern matches.

Enabling a vulnerability verdict requires independent evidence
that supports a vulnerability claim and an explicit review of
the detection contract.

## Request and Safety Boundaries

The confirmation runner requires:

- An explicitly authorized target
- A valid request template
- A valid injection point
- A fresh request budget
- An ExecutionContext
- Scope validation
- Request template validation
- Rate limiting
- Timeouts
- Response size limits

The supplied `ExecutionContext` must contain a fresh
`RequestBudget` whose maximum and remaining request count are both
exactly eighteen. Initial and confirmation requests share that
budget and the same `RateLimiter` state.

Before the first HTTP request, the runner builds and validates the
initial templates and every distinct template that can be used by
the confirmation phase. Each actual request is still enforced by
`ExecutionContext` at the transport boundary. A locally interrupted
rate-limit wait consumes the request budget according to the current
transport ordering but does not reach the HTTP transport.

The runner owns the initial verification result and the
confirmation evidence generated during that invocation.

Callers cannot supply a previously created initial result or
confirmation plan to the runner.

An injected custom HTTP transport is supported only as a trusted test
dependency. It is not an untrusted configuration surface.

Scope validation alone is not a complete network isolation
boundary.

DNS resolution, proxies, redirects, and environment-specific
network behavior require independent security consideration.

The standard execution path disables environment proxy use and does
not follow redirects. Scope validation is origin-based and does not
validate the IP address obtained after DNS resolution.

Untrusted CI execution requires network-level egress controls.

Application-level side effects must also be evaluated before
running probes against an authorized environment.

## Sensitive Information

Confirmation result objects do not retain raw HTTP response bodies.

Request templates, injected payloads, authorization headers,
cookies, and random control values must not be included in
logs or serialized findings.

A cross-phase mismatch must not expose confirmation evidence.

SHA-256 response digests may reveal low-entropy response bodies
through offline guessing.

Digests therefore must not be treated as inherently anonymous
or safe to publish.

## Supported Verification Characteristics

The current implementation has been evaluated using:

- SQLite-backed HTTP applications
- PostgreSQL-backed HTTP applications
- MySQL-backed HTTP applications
- Non-SQL response mimics
- Simulated WAF interference
- Authentication interference
- Cache interference
- Dynamic response behavior

These tests demonstrate behavior for the tested fixtures.

They do not establish universal DBMS compatibility or
general-world detection accuracy.

## Known Limitations

The current implementation does not guarantee detection of:

- All SQL injection vulnerabilities
- Every SQL dialect or SQL context
- Every parameter encoding
- Second-order SQL injection
- Time-based blind SQL injection
- Error-based SQL injection
- UNION-based SQL injection
- Out-of-band SQL injection
- SQL injection requiring multi-step application workflows

Additional limitations include:

- WAF behavior may mimic a Boolean response pattern
- Non-SQL application logic may mimic SQL execution
- Authentication changes may alter observations
- Cache generation changes may invalidate comparisons
- Dynamic response bodies may reduce classification coverage
- Stable incorrect responses may still appear consistent
- SHA-256 equality does not prove why a response occurred

These limitations must remain visible to maintainers and users.

## Integration Boundary

The confirmation runner and `ConfirmationStatus` are not exposed as
a production SQLi finding through the existing Schema v1, CLI, or
CI security gate. Existing CLI and regression paths still invoke the
six-probe `verify_boolean_sqli()` workflow, not
`verify_boolean_sqli_with_confirmation()`.

No confirmation status automatically becomes a production
vulnerability finding.

Future integration must define:

- A stable result schema
- Appropriate user-facing terminology
- Evidence disclosure policy
- Finding deduplication
- Handling of execution errors
- CI gate behavior
- Backward compatibility requirements

## Contract Change Policy

Changes to the following require explicit review:

- Probe ordering
- Request budgets
- Eligibility rules
- Confirmation response relations
- Cross-phase signature comparison
- ConfirmationStatus meanings
- Reason codes
- Evidence retention
- Guard failure behavior
- Vulnerability verdict semantics

A change that improves candidate suppression but increases
INCONCLUSIVE results must report both effects.

A change must not be described as increasing accuracy solely
because fewer candidates are returned.
