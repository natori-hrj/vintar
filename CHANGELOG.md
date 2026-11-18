# Changelog

## Unreleased

### 0.1.0

- Run authorized Boolean SQL injection regression batches from versioned TOML cases, with JSON reports and CI exit codes.
- Enforce target origin, request budgets, rate limits, and response size limits during verification.
- Inspect HTTP responses and run individual Boolean checks from the CLI.
- Validate batch reports and verify exit contracts against local fixtures in GitHub Actions.
- Check CLI output and README examples with deterministic golden tests. CI also checks formatting, architecture, strict types, and Git history for committed secrets.
