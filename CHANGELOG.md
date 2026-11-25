# Changelog

## [Unreleased]

**Added**

- Add bounded, machine-readable Boolean `decision_facts` to new CI batch
  reports for operational, response-dynamics, and confirmation-relation
  non-decisions while legacy schema-v1 reports may omit the additive field.
- Add bounded Time SQLi `decision_facts` to new CI batch reports for
  operational stops, timing-instability causes, and ambiguous timing
  predicates without exposing elapsed values, thresholds, or margins.
- Add a trusted Python-only SQLi attempt sink for completed, failed, and
  undispatched plan positions, pure Boolean/confirmation/Time decision
  classifiers, and bounded Error operational `decision_facts` in CI reports.

- Extend the pinned-source third-party SQLi evaluation with the independent
  MySQL 8-backed sqli-dojo-docker target, including reviewed positive and
  non-SQL negative records for Boolean, Time, and Error checks.
- Add the PostgreSQL 16-backed OWASP Training Lab to the pinned-source
  third-party SQLi corpus, with reviewed GET-only positive and non-SQL negative
  records for Boolean, Time, and Error checks.

**Changed**

- Report `confirmation_unstable` when independently reviewed Boolean TRUE or FALSE
  predicate pairs do not reproduce each other; reserve
  `candidate_confirmation_mismatch` for stable pairs whose remaining relation
  differs. Manual third-party measurement reports now use schema version 9 so
  reports written under the previous v8 confirmation precedence must be
  remeasured rather than reinterpreted. Replace the reviewed fixture with the
  real v9 measurement and remove the temporary docs-bound v8 compatibility path.
- Normalize only context-bound echoes of complete Boolean SQLi probe values
  before response comparison, preserving status codes and unrelated response
  differences while reducing reflection-only non-decisions. Manual third-party
  measurement reports require per-probe Boolean
  normalization status and echo counts.
- Replace the reviewed third-party SQLi evaluation fixture with a real schema
  version 9 measurement containing request-ordered wire and analyzer evidence,
  including the observed Boolean echo-normalization and confirmation results.
- Retain request-ordered wire provenance separately from exact analyzer
  observations, truncation, and reviewed Error signature-match evidence in
  version 7 of the manual third-party SQLi measurement report.
- Use sqli-dojo confirmation payloads that avoid characters filtered by the fixture target.
- Render a cross-target DBMS and technique matrix with observed non-decisions
  from the validated report. Select documentation drift tests with `-m doc_drift`.

- Generalize the manual third-party SQLi evaluation harness to declaration
  version 2 and report version 4, with target-bound provenance and both overall
  and per-target aggregates. DSVW remains the only target in this phase.
- Classify `sqli.time` candidates by their relation to stable Baseline and Control
  responses. Delayed-sample variance no longer blocks a clearly separated
  candidate, but it still prevents a `NOT_DETECTED` verdict when the candidate
  relation is absent.

## [0.4.0] - 2026-11-21

**Added**

- Verify explicit Schema v1 cases with check type `sqli.error` using a fixed
  four-request plan and a reviewed DBMS diagnostic signature registry. A repeated
  new diagnostic produces `INCONCLUSIVE / dbms_error_disclosed` and blocks CI
  with exit code 3 unless a batch failure takes precedence. The Error check
  never emits `VULNERABLE`.
- Include an additive, redacted `error` object in Schema v1 CI report outcomes
  for Error cases.
- Materialize reviewed OpenAPI decisions into explicit Schema v1 `sqli.error`
  cases with fixed four-request limits and deterministic `<id>-error` case IDs.
  Error payloads remain explicit reviewer input; no DBMS, SQL context, or
  payload is inferred from OpenAPI metadata.

**Internal**

- Extend the pinned-source manual DSVW evaluation with schema v3 reports and
  separate four-request Error SQLi candidate and reflected-only negative
  measurements. Error candidates remain `INCONCLUSIVE`.

## [0.3.0] - 2026-11-21

**Internal**

- Audit locked runtime and development dependencies in CI and enable weekly
  Dependabot updates for uv and GitHub Actions.
- Extend the manual pinned-source DSVW evaluation to cover explicit nine-request
  `sqli.time` cases, reported separately from Boolean results.

**Added**

- Map a Time SQLi candidate from the analyzer to the product result
  `INCONCLUSIVE / timing_pattern_matched`. It never produces `VULNERABLE`.
- Materialize reviewed OpenAPI decisions into explicit Schema v1 `sqli.time`
  cases with query-only injection, fixed nine-request limits, and no inferred
  DBMS, SQL context, or probe preset. Time materialization appends a deterministic
  `-time` case-ID suffix so Boolean and Time cases from one draft can share a batch.
- Run explicit Schema v1 `sqli.time` cases through the Python API and the
  `vintar verify` CLI with a fixed nine-request plan and an operator-owned execution
  deadline. Schema v1 CI reports now carry redacted time status, reason, and
  request counts, including mixed Boolean/time batches, while existing Boolean
  and legacy reports remain compatible.

**Dependencies**

- Update Typer to 0.29.1, FastAPI to 0.163.2, pytest to 9.2.0, and Ruff to 0.17.5.

## [0.2.1] - 2026-11-21

**Fixed**

- SQLi checks could miss candidate signals on servers that decode percent escapes
  but leave `+` unchanged, because those servers received plus signs where the
  probes expected spaces. Query values now encode spaces as `%20` and literal plus
  signs as `%2B` per RFC 3986, so probes reach both percent-only and form-style
  query decoders intact.

**Internal**

- Add a third-party DSVW evaluation harness for maintainers.

## [0.2.0] - 2026-11-20

- Add a local loopback Boolean SQLi precision corpus with separate true-positive,
  true-negative, false-candidate, and non-decision measurements.
- Add a reviewed second predicate pair and baseline-preserving third predicate
  confirmation, including `candidate_confirmation_mismatch`, while retaining
  `boolean_candidate` as the final reason when confirmation matches.
- Register structural full-mimic and WAF-200 candidate signals as tested known
  limitations.
- Allow Schema v1 Boolean SQLi cases to opt into bounded 18-request confirmation;
  named probe presets expand confirmation automatically, while explicit probes are
  never completed by inference.
- Report whether confirmation was not configured, not eligible, matched,
  mismatched, or stopped for an operational reason. CI exit codes are unchanged,
  and existing v1 reports without confirmation fields remain valid.
- Test time-based reliability with separate deterministic analysis and live
  loopback checks for request order, response status, database calls, and budgets.

## [0.1.1] - 2026-11-20

- Describe Vintar in CLI help as a tool for security regression tests in CI pipelines.
- Clarify the supported scope in the README and CI integration guide.

## [0.1.0] - 2026-11-20

- Run authorized Boolean SQL injection regression checks on GET query parameters with Schema v1 TOML cases, JSON reports, and CI exit codes.
- Discover inputs offline from OpenAPI 3.0 and 3.1, review the decisions, and materialize reviewed cases with explicit `string-quoted` or `numeric` preset selection.
- Report candidate signals as inconclusive and block CI on inconclusive or failed batches.
- Enforce target origin, request budgets, rate limits, and response size limits during verification.
- Inspect HTTP responses and run individual Boolean checks from the CLI.
- Measure candidate-signal reliability with matched SQLite loopback fixtures.
- Validate batch reports and verify exit contracts against local fixtures in GitHub Actions.
- Check CLI output and README examples with deterministic golden tests. CI also checks formatting, architecture, strict types, and Git history for committed secrets.

[Unreleased]: https://github.com/natori-hrj/vintar/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/natori-hrj/vintar/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/natori-hrj/vintar/compare/v0.2.1...v0.3.0
