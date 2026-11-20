# Boolean-based SQL Injection Evaluation

## Objective

This document defines the evaluation methodology for Vintar's
Boolean-based SQL injection verification.

The objective is to measure:

- Detection behavior
- False-candidate behavior
- Classification coverage
- Execution stability
- HTTP request cost
- Safety invariants
- Regression risk

Passing unit tests is necessary but not sufficient to establish
real-world detection accuracy.

## Evaluation Principles

1. Keep ground truth separate from detector output.
2. Evaluate vulnerable and non-vulnerable targets.
3. Record all outcomes, including inconclusive and skipped.
4. Do not count CANDIDATE as confirmed exploitation.
5. Preserve denominators when reporting rates.
6. Distinguish synthetic fixtures from independent targets.
7. Measure changes in both error rates and coverage.
8. Do not use production systems without explicit authorization.
9. Do not publish sensitive response contents or credentials.
10. Reproduce results before making release claims.

## Outcome Categories

Every evaluation attempt must have exactly one terminal outcome:

- One confirmation classification, or
- One execution error

The confirmation classifications are:

- CANDIDATE
- NOT_CONFIRMED
- INCONCLUSIVE
- SKIPPED

An internal execution error is recorded separately instead of a
confirmation classification.

Execution errors must not be silently counted as NOT_CONFIRMED
or SKIPPED.

## Ground Truth

Each fixture must have a ground-truth label:

- VULNERABLE
- NON_VULNERABLE

Ground truth must be established independently of Vintar's
candidate classification.

These evaluation labels are not instances of the production
`Verdict` enum. In particular, a VULNERABLE ground-truth label does
not mean that Vintar emitted `Verdict.VULNERABLE`.

For SQL-backed fixtures, ground truth should be established
from application implementation and query behavior.

For non-SQL fixtures, ground truth should be established by
the absence of SQL execution in the tested behavior.

If ground truth cannot be established, the fixture must not
be included in binary classification metrics.

## Evaluation Record

Each case should record:

- Case identifier
- Application or fixture identifier
- Ground-truth label
- DBMS, if applicable
- Injection location
- SQL context, if known
- Middleware characteristics
- Expected classification
- Observed classification
- Reason code
- Total HTTP requests
- Execution error, if any
- Test environment
- Relevant source revision

Do not store authentication secrets, raw injected requests,
or sensitive response bodies in evaluation summaries.

## Metrics

Use one fixed ground-truth label per evaluated attempt. Let:

- P = number of vulnerable ground-truth cases
- N = number of non-vulnerable ground-truth cases
- C = cases classified CANDIDATE
- TP = vulnerable cases classified CANDIDATE
- FC = non-vulnerable cases classified CANDIDATE
- NC = cases classified NOT_CONFIRMED
- NC_N = non-vulnerable cases classified NOT_CONFIRMED
- IC = cases classified INCONCLUSIVE
- SK = cases classified SKIPPED
- ER = cases with execution errors
- T = total evaluated attempts

For a corpus in which every attempt has binary ground truth:

```text
T = P + N
T = C + NC + IC + SK + ER
```

There is no production `FALSE_NEGATIVE` status. Vulnerable cases
that are NOT_CONFIRMED, INCONCLUSIVE, SKIPPED, or execution errors
must be reported by their actual outcome rather than collapsed into
one detector status.

When a metric denominator is zero, report the metric as undefined
or not applicable rather than substituting zero. Repeated executions
of the same fixture should be reported both as repeatability attempts
and as one unique ground-truth case; they must not silently inflate
the apparent corpus size.

### Candidate sensitivity

For vulnerable ground-truth cases:

candidate_sensitivity = TP / P

This measures how often a vulnerable fixture produces a
CANDIDATE result.

It does not mean that a CANDIDATE is proof of exploitation.

Report the vulnerable cases that are NOT_CONFIRMED,
INCONCLUSIVE, SKIPPED, or execution errors separately.

### False-candidate rate

For non-vulnerable ground-truth cases:

false_candidate_rate = FC / N

This is the fraction of non-vulnerable fixtures that still
produce CANDIDATE.

It is not directly comparable to a conventional false-positive
rate from a binary classifier because the detector has
abstention and skip states.

### Classification coverage

classification_coverage = (C + NC) / T

This measures the fraction of evaluated cases receiving a
completed confirmation classification.

INCONCLUSIVE, SKIPPED, and execution errors are not
considered classified.

Classification coverage is not the same as endpoint coverage
or injection-point discovery coverage.

### Abstention rate

abstention_rate = (IC + SK) / T

Report IC and SK separately as well.

### Execution error rate

execution_error_rate = ER / T

Execution errors are operational failures and must remain
distinct from normal classification results.

For a binary-ground-truth corpus with one terminal outcome per
attempt, classification coverage, abstention rate, and execution
error rate sum to 1.

### Conditional false-candidate proportion

For a non-vulnerable-only corpus:

conditional_false_candidate_proportion =
    FC / (FC + NC_N)

This metric measures the fraction of completed classifications
that are false candidates in that corpus.

It must not be labeled a population-wide false discovery rate.
The same formula applies to the non-vulnerable subset of a mixed
corpus. Vulnerable CANDIDATE and NOT_CONFIRMED outcomes must not enter
this denominator.

### Request cost

Measure:

- Requests per case
- Requests per classification
- Total requests per corpus
- Number of early terminations
- Budget consumption
- Additional requests introduced by new validation logic
- Request-budget consumption, HTTP transport attempts, and server
  receipts separately when failures can make those counts differ

The confirmation runner must not exceed eighteen requests
per complete invocation.

## Existing Non-SQL Middleware Corpus

The existing middleware corpus contains ten scenarios.

All ten have non-vulnerable ground truth.

| Scenario | Expected status | Requests |
| --- | --- | ---: |
| waf200_mimic | CANDIDATE | 18 |
| waf403 | SKIPPED | 6 |
| waf429 | SKIPPED | 3 |
| waf200_blanket | SKIPPED | 6 |
| auth401 | INCONCLUSIVE | 7 |
| auth302 | INCONCLUSIVE | 7 |
| auth200_login | NOT_CONFIRMED | 18 |
| cache_ignore_query | SKIPPED | 6 |
| cache_dynamic | INCONCLUSIVE | 18 |
| cache_rollover | INCONCLUSIVE | 18 |

Expected totals:

- CANDIDATE: 1
- NOT_CONFIRMED: 1
- INCONCLUSIVE: 4
- SKIPPED: 4
- Total requests: 107
- Initial verification requests: 57
- Additional confirmation requests: 50
- Guard-specific HTTP requests: 0

Derived metrics:

- False-candidate rate: 1 / 10 = 10%
- Classification coverage: 2 / 10 = 20%
- INCONCLUSIVE rate: 4 / 10 = 40%
- SKIPPED rate: 4 / 10 = 40%
- Abstention rate: 8 / 10 = 80%
- Conditional false-candidate proportion: 1 / 2 = 50%

These numbers describe this specific synthetic corpus.

They are not estimates of real-world detection accuracy.
In particular, the 10% false-candidate rate must not be described
as a production false-positive rate, an expected deployment rate,
or evidence that 90% of benign targets will be classified safely.

## Database Integration Evaluation

The evaluated database families are:

- SQLite
- PostgreSQL
- MySQL

The existing scenarios include:

- Vulnerable SQL execution
- Parameterized SQL execution
- Non-SQL simple branching
- Non-SQL full response mimicry

For every database family, verify:

1. Vulnerable SQL reaches the expected candidate classification.
2. Safe parameterized SQL is not promoted to CANDIDATE.
3. A simple non-SQL branch is not treated as a proven vulnerability.
4. A full non-SQL mimic is recorded as a known false candidate.
5. SQL errors do not leak credentials or query details.
6. Request budgets and response limits remain enforced.

Passing these fixtures does not establish support for all SQL
dialects, database versions, or injection contexts.

## Regression Baseline

The most recently reported validation results were:

- Standard test suite: 855 passed, 14 skipped
- Enabled PostgreSQL/MySQL integration suite: 14 passed
- Runner cross-phase tests: 15 passed
- Middleware tests: 20 passed
- Ruff checks: passed
- Formatting checks: passed
- Diff whitespace checks: passed

These values are historical checkpoints, not perpetual
acceptance thresholds.

Test counts may change as coverage improves.

The acceptance criterion is that all applicable tests pass,
with skips understood and documented.

## Reproduction

Run the standard test suite:

```bash
uv run pytest -v
```

Run static checks:

```bash
uv run ruff check .
uv run ruff format --check .
git diff --check
```

Run the isolated database integration suite using the
repository's documented test configuration.

Do not assume that a skipped integration test has passed.

Capture the commands, environment, and results in the
review report.

## Release Readiness Criteria

### Required for an experimental Boolean verifier

- [x] Initial Boolean request workflow implemented
- [x] Eligibility assessment implemented
- [x] Additional confirmation workflow implemented
- [x] Cross-phase consistency assessment implemented
- [x] Bounded request execution implemented
- [x] Deterministic synthetic response fixtures evaluated
- [x] SQLite HTTP fixtures evaluated
- [x] PostgreSQL integration fixtures evaluated
- [x] MySQL integration fixtures evaluated
- [x] Middleware interference fixtures evaluated
- [x] CANDIDATE distinguished from VULNERABLE

These boxes describe implemented and reported capabilities.
They do not imply production approval.

### Required before production AppSec use

- [ ] Independent evaluation targets beyond development fixtures
- [ ] Explicit supported DBMS and SQL context matrix
- [ ] Defined minimum candidate sensitivity and coverage targets
- [ ] Defined acceptable false-candidate threshold
- [ ] Repeated stability measurements across environments
- [ ] Authenticated workflow and side-effect assessment
- [ ] Threat model for target discovery and network egress
- [ ] Evidence disclosure and retention policy
- [ ] User-facing result schema and terminology review
- [ ] Confirmation-result integration and failure-gate contract
- [ ] Operational documentation and safe-use guidance

These criteria are intentionally not marked complete.

## Decision

The existing Boolean verification component is suitable as an
experimental Boolean response-pattern verifier and as a test bed for
candidate-suppression research.

It is not complete as an initial production SQLi detector and is not
approved as an AppSec production security gate.

A CANDIDATE must remain a candidate.

No VULNERABLE verdict should be enabled on the basis of the
existing response-pattern evidence alone.

Design and isolated prototyping may proceed for a separate time-based
verification component. The shared scope, budget, rate-limit,
timeout, response-size, immutable-template, and preflight mechanisms
provide a usable execution foundation. Boolean response relations,
payload plans, evidence, and thresholds must not be reused as though
they were valid time-based detection rules.

Before a time-based component can be treated as a detector, it needs
its own bounded request plan, timing model, jitter controls, timeout
distinction, cancellation behavior, side-effect assessment, result
model, and vulnerable/non-vulnerable evaluation corpus.

## Current Completion Assessment

| Question | Assessment |
| --- | --- |
| Sufficient as an experimental Boolean verifier? | Yes, for the documented authorized fixtures and research use. |
| Complete as an initial practical SQLi detector? | No. Supported contexts, independent evaluation, and quantitative release thresholds are missing. |
| Suitable for an AppSec production security gate? | No. Confirmation results are not connected to the production schema or gate, and detection reliability is not established. |
| Is the common foundation ready for time-based design work? | Partly. The bounded execution and safety foundation is reusable; timing-specific detection and evaluation contracts are not implemented. |

## Future Evaluation Work

Priorities include:

1. Independent vulnerable and non-vulnerable applications
2. Broader SQL contexts and parameter locations
3. Real WAF and authentication middleware behavior
4. Cache and CDN behavior across repeated executions
5. Dynamic response normalization experiments
6. Sensitivity and coverage measurement on held-out cases
7. Quantitative release thresholds
8. Evidence and report schema design

Any new evaluation must distinguish a genuine improvement
in classification quality from a reduction in classification
coverage.

## Candidate-signal measurement

The v0.1.0 evidence covers the matched SQLite loopback fixtures described below.
The separate `waf200_mimic` result demonstrates that non-SQL middleware can
produce candidates. PostgreSQL and MySQL integration tests remain opt-in and
are outside the default CI measurement.

The always-on pytest suite measures the Boolean candidate signal on labeled synthetic
observations. A positive is `INCONCLUSIVE / boolean_candidate`. A negative is
`NOT_DETECTED`. All other results are non-decisions. Replay reports true positives,
false negatives, false positives, true negatives, and non-decisions. Any false
negative, false positive, or non-decision fails the test with remediation.

The schema-version 2 JSON report separates `replay`, `live_loopback`,
`known_limitations`, and `fixed_app_loopback`. The live mode runs the production
six-probe check through `ExecutionContext` against fresh socket-backed SQLite
servers. It measures a string-quoted pair (`/vulnerable` and `/safe`) and an unquoted
numeric pair (`/numeric-vulnerable` and `/numeric-safe`). Labels and preset names are
declared next to each endpoint. The report marks the live positive measurement as
covered.

The string twins use the declared initial category `Pets`; the numeric twins use the
declared product ID `1`. Both values come from the seeded fixture data. With the
matching append-mode preset, each vulnerable endpoint returns its baseline row or
rows for the baseline and TRUE probes and no rows for the FALSE probes, producing
`INCONCLUSIVE / boolean_candidate`. Each parameterized endpoint treats the appended
payload as a literal value, producing identical empty TRUE and FALSE responses and
`NOT_DETECTED / no_boolean_difference_literal_input`.

The first Phase 8-2 run exposed that relation as a detector limitation: it was
reported as `INCONCLUSIVE / unexpected_difference`. The analyzer now classifies the
stable, identical TRUE and FALSE responses as
`NOT_DETECTED / no_boolean_difference_literal_input`. No input or fixture label was
changed to obtain that result. The expanded live confusion matrix records two true
positives and two true negatives, with no false positives, false negatives, or
non-decisions.

The confirmation measurement uses a reviewed second predicate pair and a
baseline-preserving third predicate. The third predicate checks reproducibility of
the response relation, not SQL semantics. Real string and numeric SQLite vulnerable
twins retain `boolean_candidate` after 18 total requests. Exact-string branches such
as `simple_branch` and `pagination-branch` become INCONCLUSIVE with
`candidate_confirmation_mismatch`; they do not become NOT_DETECTED. Synthetic
positive response-relation cases are reported separately from real SQLite fixtures,
and their confirmation mismatch is not counted as a real vulnerable false negative.

The deterministic precision measurements are:

| Six-probe response-relation corpus | TP | TN | FP | FN | non-decision |
| --- | ---: | ---: | ---: | ---: | ---: |
| Before confirmation | 3 | 2 | 2 | 0 | 4 |

The three TPs in that table are synthetic positive response relations, not SQL-backed
vulnerabilities. After confirmation, the eight negative fixtures record two TNs, one
remaining FP (`waf-200`), and five non-decisions. The three synthetic positives all
produce `candidate_confirmation_mismatch` and are reported as three synthetic
demotions, not as real vulnerable FNs. Separately, both real SQLite vulnerable twins
retain `boolean_candidate`; both parameterized twins retain their initial
NOT_DETECTED results and do not enter confirmation.

Two no-SQL structural false candidates reproduce the complete confirmation relation
and are registered from actual loopback runs outside the matched-twin confusion
matrix: `structural-full-mimic` and `structural-waf-200`. Their records must remain
present exactly once with `confirmation_pattern_matched` and 18 requests. A missing,
duplicate, newly introduced, or unexpectedly resolved record fails after the JSON
report is saved. Registration documents a known limitation; it does not suppress the
candidate or turn it into a pass.

Results still depend on the initial value and must not be generalized to other benign
values. A NOT_DETECTED result means only that these probes found no Boolean
differential; an unsupported SQL context can make both probes ineffective on a
vulnerable target. The existing fixed-app loopback check separately verifies the
benign `Pets` response and contributes no entries to the confusion matrix. Confirmed
vulnerability detection requires separate evidence.

The mismatch safety tests remain outside that matched-preset confusion matrix. The
`numeric` preset on the string-quoted vulnerable endpoint is treated as literal input
and produces `NOT_DETECTED / no_boolean_difference_literal_input`. The
`string-quoted` preset on the numeric vulnerable endpoint causes four SQLite syntax
errors and produces `INCONCLUSIVE / non_success_status`. In particular, the first
result does not clear the known vulnerable fixture: a NOT_DETECTED result from an
incompatible preset does not prove absence of SQL injection.

Run `uv run --locked pytest tests/test_sqli_candidate_reliability.py` to reproduce
the report. Pytest writes `sqli-candidate-reliability.json` under its temporary test
directory. To retain it at a known location, pass `--basetemp` with a dedicated
temporary directory. A future release gate should validate the schema, require the
expected endpoint IDs by measurement mode, and interpret the explicit coverage marker.

Expected loopback failures are recorded as `socket_bind`, `startup`, `shutdown`,
`transport`, or `unexpected_response`. The test writes the JSON before failing on a
loopback failure or a false negative, false positive, or non-decision. Diagnostics
name the endpoint and observed verdict and reason, then direct investigation to the
fixture label, response stability, or transport setup.

The filename `sqli-candidate-reliability.json` is reserved for the real
measurement. Failure simulations use `sqli-candidate-reliability.simulated-*.json`
and run without sockets. Collect the exact real filename for CI artifacts.
