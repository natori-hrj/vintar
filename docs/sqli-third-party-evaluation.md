# Third-party Boolean SQLi evaluation

This manual measurement exercises the complete Vintar pipeline against DSVW, an
independent deliberately vulnerable project. It demonstrates end-to-end behavior
for two reviewed inputs (`n=2`); it is not a statistical precision claim and is not
combined with Vintar's synthetic or repository-owned SQLite measurements.

## Ground truth and scope

Both labels come from the pinned upstream source at commit
`9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908`, not from Vintar output. The reviewed
line ranges and SHA-256 digests are recorded in `third_party/sqli/targets.toml`.

- `dsvw-blind-boolean-id` is positive because DSVW concatenates the `id` query
  parameter into a SQLite statement.
- `dsvw-version-query` is negative because `v` only changes displayed version text
  and never reaches a SQL sink. This is weaker negative evidence than a
  parameterized twin. A third-party parameterized comparison is deferred until
  Vintar can address VAmPI's path parameter without an adapter.

The run is local-only. Preparation verifies the pinned archive before building and
records the local image digest. Measurement uses `--pull=never`, an internal Docker
network, and an ephemeral loopback-only published port. It runs a fresh DSVW
container for every record and mode.

## Reviewed measurement

The following block is generated from the actual report format and checked by
`scripts/run_third_party_sqli_measurement.py`. A run fails after saving its JSON
artifact if this reviewed summary drifts.

<!-- third-party-measurement:start -->
| Record | Mode | Expected label | Actual verdict | Reason | Confirmation | Requests | Classification |
| --- | --- | --- | --- | --- | --- | ---: | --- |
| dsvw-blind-boolean-id | confirmation | positive | inconclusive | boolean_candidate | matched | 18 | tp |
| dsvw-blind-boolean-id | six_probe | positive | inconclusive | boolean_candidate | not_configured | 6 | tp |
| dsvw-version-query | confirmation | negative | inconclusive | unexpected_difference | not_eligible | 6 | non_decision |
| dsvw-version-query | six_probe | negative | inconclusive | unexpected_difference | not_configured | 6 | non_decision |

| Mode | TP | TN | FP | FN | Non-decision |
| --- | ---: | ---: | ---: | ---: | ---: |
| six_probe | 1 | 0 | 0 | 0 | 1 |
| confirmation | 1 | 0 | 0 | 0 | 1 |
<!-- third-party-measurement:end -->

The first Phase 12-1 run exposed a query-encoding integration defect. DSVW applies
RFC 3986 percent decoding but does not convert `+` to a space. Vintar previously
serialized the reviewed preset's spaces as `+`, causing malformed SQLite expressions
and `INCONCLUSIVE / non_success_status`. Vintar now serializes spaces as `%20` and
literal plus signs as `%2B`. With the same label, initial value, payloads, and
expectation, the real SQL-backed positive produces `boolean_candidate` in both modes
and its confirmation relation matches after eighteen requests.

The reflected safe value produces stable responses, but each appended predicate is
also reflected and therefore the TRUE and FALSE responses differ. Under the existing
contract this is a non-decision, not a true negative and not evidence of SQLi. The
measurement command consequently returns non-zero after preserving the report. This
weak reflected-parameter negative remains a non-decision and must not be relabeled or
suppressed to make the measurement pass.

The classification contract matches `docs/sqli-boolean-evaluation.md`: only
`INCONCLUSIVE / boolean_candidate` is a positive decision, only `NOT_DETECTED` is a
negative decision, and every other result is a non-decision. Confirmation cannot
turn a result into `NOT_DETECTED` or `VULNERABLE`.
