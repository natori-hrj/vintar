# Changelog

## [Unreleased]

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
