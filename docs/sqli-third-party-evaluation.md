# Third-party SQLi evaluation

This manual measurement exercises the complete Vintar pipeline against DSVW, an
independent deliberately vulnerable project. It demonstrates end-to-end behavior
for two reviewed inputs per check type (`n=2` Boolean and `n=2` Time); it is not a
statistical precision claim and is not combined with Vintar's synthetic or
repository-owned SQLite measurements.

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
- `dsvw-time-id` uses the same positive SQL sink with the explicit conditional
  `RANDOMBLOB(300000000)` expression derived from DSVW's documented time attack at
  `dsvw.py:10`.
- `dsvw-time-version-query` uses the same reflected-only `v` negative. It remains a
  weaker negative than a parameterized-safe endpoint.

The Time threshold was fixed before measurement at `expected_delay_seconds = 0.5`
with a five-second per-request timeout. DSVW's delay is CPU-bound, so this choice
and its ground-truth labels were not adjusted after observing the host result.

The run is local-only. Preparation verifies the pinned archive before building and
records the local image digest. Measurement uses `--pull=never`, an internal Docker
network, and an ephemeral loopback-only published port. It runs a fresh DSVW
container for every record and mode.

## Reviewed measurement

The following block is generated from the actual report format and checked by
`scripts/run_third_party_sqli_measurement.py`. A run fails after saving its JSON
artifact if this reviewed summary drifts.

The manual maintainer report uses schema version 2. Compared with version 1:

- `schema_version` changes from `1` to `2`.
- `counts["six_probe"]` moves to
  `counts["sqli.boolean"]["six_probe"]`.
- `counts["confirmation"]` moves to
  `counts["sqli.boolean"]["confirmation"]`.
- Time results are separate under `counts["sqli.time"]["nine_probe"]`; they are
  never combined with Boolean counts.
- Every record adds `check_type`.
- A Boolean record's `confirmation` object moves to the common sibling key
  `detail`. Time records also use `detail` for their timing status, reason, and
  request count.

Readers accept only version 2 and reject a report whose version or shape differs.
Version 1 artifacts must be regenerated with the current measurement script; there
is no silent fallback or dual-shape parsing.

<!-- third-party-measurement:start -->
| Check type | Record | Mode | Expected label | Actual verdict | Reason | Detail status | Requests | Classification |
| --- | --- | --- | --- | --- | --- | --- | ---: | --- |
| sqli.boolean | dsvw-blind-boolean-id | confirmation | positive | inconclusive | boolean_candidate | matched | 18 | tp |
| sqli.boolean | dsvw-blind-boolean-id | six_probe | positive | inconclusive | boolean_candidate | not_configured | 6 | tp |
| sqli.time | dsvw-time-id | nine_probe | positive | inconclusive | unstable_timing | inconclusive | 9 | non_decision |
| sqli.time | dsvw-time-version-query | nine_probe | negative | not_detected | timing_pattern_not_matched | not_confirmed | 9 | tn |
| sqli.boolean | dsvw-version-query | confirmation | negative | inconclusive | unexpected_difference | not_eligible | 6 | non_decision |
| sqli.boolean | dsvw-version-query | six_probe | negative | inconclusive | unexpected_difference | not_configured | 6 | non_decision |

| Check type | Mode | TP | TN | FP | FN | Non-decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| sqli.boolean | six_probe | 1 | 0 | 0 | 0 | 1 |
| sqli.boolean | confirmation | 1 | 0 | 0 | 0 | 1 |
| sqli.time | nine_probe | 0 | 1 | 0 | 0 | 1 |
<!-- third-party-measurement:end -->

This Time run was measured on an AMD Ryzen AI 5 PRO 340 (12 logical CPUs) with
Docker Engine 29.9.2 and Docker Compose 5.6.1. The positive completed all nine
requests but was `INCONCLUSIVE / unstable_timing`; this is a recorded non-decision,
not a reason to tune the fixed inputs and not an acceptance failure. The reflected
negative was `NOT_DETECTED / timing_pattern_not_matched`. Results can differ on
hosts with different CPU performance or scheduling.

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

The Boolean classification contract matches `docs/sqli-boolean-evaluation.md`: only
`INCONCLUSIVE / boolean_candidate` is a positive decision, only `NOT_DETECTED` is a
negative decision, and every other result is a non-decision. Confirmation cannot
turn a result into `NOT_DETECTED` or `VULNERABLE`.

For Time, `INCONCLUSIVE / timing_pattern_matched` is the positive decision and
`NOT_DETECTED / timing_pattern_not_matched` is the negative decision. Other Time
results are non-decisions. Boolean and Time counts are never combined.
