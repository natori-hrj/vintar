# Third-party SQLi evaluation

This manual measurement exercises the complete Vintar pipeline against DSVW
(SQLite), sqli-dojo-docker (MySQL 8), and OWASP Training Lab (PostgreSQL 16),
three independent deliberately vulnerable projects. Each target contributes two
reviewed inputs per check type. The combined sample is `n=6` Boolean, `n=6` Time,
and `n=6` Error; it is not a
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
- `dsvw-error-id` is positive because the handler concatenates `id` into SQLite
  and returns the caught `sqlite3.OperationalError` traceback in the response.
  The reviewed source reference spans both the sink and exception response.
- `dsvw-error-version-query` uses the same reflected-only `v` negative. It does
  not reach SQL and is weaker evidence than a parameterized-safe endpoint.

Both Error records use the same explicit single-quote payload fixed before
measurement. It was not changed after observing either result.

The sqli-dojo-docker labels come from commit
`81f20037de323376d8a7651377e3a3971efdbae8`, whose archive SHA-256 is
`6c0218fef749fddec28560af883865eb4178ed998d5cc927a5e3592add50b88f`.
For each technique, `id` is positive because `src/lookup_person.php:4-18`
concatenates it into a MySQL query. The independent `source` negative is handled
by `src/common/view_source.php:1-31`, which renders the page source and terminates
before the vulnerable page reaches SQL. The Boolean numeric predicates, MySQL
`SLEEP(0.5)` Time relation, Error quote, and 0.5-second Time expectation were all
fixed before measurement.

The OWASP Training Lab labels come from MIT-licensed commit
`9cb62dd2e30b08a0ddc753247c62b54b90e933ed`, whose archive SHA-256 is
`5d0c805d86cd6a3ec8d95afdb2fdae99cab5dc765842dac4e6d122c171737db4`.
The Boolean and Error positive records use the raw PostgreSQL interpolation in
`app/categories/a03_injection/routes.py:104-112`; the Time positive uses the
documented blind `pg_sleep` sink at lines 123-136. All three negative records use
the GET-only greeting at lines 115-120. That route reflects `name` into HTML but
never reaches SQL: it is an independent Boolean negative because predicates
cannot affect a query, a Time negative because it has no delay sink, and an Error
negative because it cannot disclose a DBMS diagnostic. Reflection can still make
the Boolean detector abstain, which is recorded rather than suppressed.

The Boolean LIKE-context predicates, PostgreSQL `pg_sleep(0.5)` relation, Error
quote, and 0.5-second Time expectation were fixed before the first measurement.
The Error-positive route does not render PostgreSQL exceptions; its generic 500
is therefore recorded as a non-decision rather than being relabeled. The POST
error-disclosure route is outside this GET-only phase.

The Time threshold was fixed before measurement at `expected_delay_seconds = 0.5`
with a five-second per-request timeout. DSVW's delay is CPU-bound, so this choice
and its ground-truth labels were not adjusted after observing the host result.

The run is local-only. Preparation verifies the pinned archive before building and
records the local image digest. Measurement uses `--pull=never`, an internal Docker
network, and an ephemeral loopback-only published port. It runs a fresh target
and fresh declared database volume for every record and mode.

## Reviewed measurement

The following block is generated from the actual report format and checked by
`scripts/run_third_party_sqli_measurement.py`. A run fails after saving its JSON
artifact if this reviewed summary drifts.

The manual maintainer report uses schema version 4. Versions 2 and 3 introduced
per-technique records and Error evidence. Version 4 generalizes that contract to
multiple independently prepared targets:

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

Version 3 added `counts["sqli.error"]["error_probe"]`, Error records whose `detail`
contains the redacted Error result evidence, and the Error-only `candidate`
classification. A candidate means the positive ground-truth record produced
`INCONCLUSIVE / dbms_error_disclosed` with the reviewed DBMS evidence. It is not a
TP or a `VULNERABLE` verdict. Error negatives retain TN/FP/FN/non-decision under
the existing decision contract.

Version 4 moves the former `target` object to target-id-keyed `targets`, adds
`target_id` to every record, moves the former counts tree to `counts.overall`, and
adds the same complete tree for each target under `counts.by_target`. Readers
accept only version 4 and reject a report whose version or shape differs. Version
1, 2, and 3 artifacts must be regenerated with the current measurement script;
there is no silent fallback or dual-shape parsing.

Each v4 target metadata object records the prepared app image ID and the resolved
digest-pinned auxiliary `service_images` map. The runner compares that map with
the declaration before starting Compose, so the report identifies every image
that participated in the measurement.

<!-- third-party-measurement:start -->
| Target | Check type | Record | Mode | Expected label | Actual verdict | Reason | Detail status | Requests | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- | ---: | --- |
| dsvw | sqli.boolean | dsvw-blind-boolean-id | confirmation | positive | inconclusive | boolean_candidate | matched | 18 | tp |
| dsvw | sqli.boolean | dsvw-blind-boolean-id | six_probe | positive | inconclusive | boolean_candidate | not_configured | 6 | tp |
| dsvw | sqli.error | dsvw-error-id | error_probe | positive | inconclusive | dbms_error_disclosed | matched | 4 | candidate |
| dsvw | sqli.error | dsvw-error-version-query | error_probe | negative | not_detected | dbms_error_not_observed | not_matched | 4 | tn |
| dsvw | sqli.time | dsvw-time-id | nine_probe | positive | inconclusive | timing_pattern_matched | candidate | 9 | tp |
| dsvw | sqli.time | dsvw-time-version-query | nine_probe | negative | not_detected | timing_pattern_not_matched | not_confirmed | 9 | tn |
| dsvw | sqli.boolean | dsvw-version-query | confirmation | negative | inconclusive | unexpected_difference | not_eligible | 6 | non_decision |
| dsvw | sqli.boolean | dsvw-version-query | six_probe | negative | inconclusive | unexpected_difference | not_configured | 6 | non_decision |
| owasp-lab | sqli.boolean | owasp-lab-boolean-greet | confirmation | negative | inconclusive | unexpected_difference | not_eligible | 6 | non_decision |
| owasp-lab | sqli.boolean | owasp-lab-boolean-greet | six_probe | negative | inconclusive | unexpected_difference | not_configured | 6 | non_decision |
| owasp-lab | sqli.boolean | owasp-lab-boolean-search | confirmation | positive | inconclusive | unexpected_difference | not_eligible | 6 | non_decision |
| owasp-lab | sqli.boolean | owasp-lab-boolean-search | six_probe | positive | inconclusive | unexpected_difference | not_configured | 6 | non_decision |
| owasp-lab | sqli.error | owasp-lab-error-greet | error_probe | negative | not_detected | dbms_error_not_observed | not_matched | 4 | tn |
| owasp-lab | sqli.error | owasp-lab-error-search | error_probe | positive | inconclusive | non_success_status | inconclusive | 4 | non_decision |
| owasp-lab | sqli.time | owasp-lab-time-check-username | nine_probe | positive | inconclusive | timing_pattern_matched | candidate | 9 | tp |
| owasp-lab | sqli.time | owasp-lab-time-greet | nine_probe | negative | not_detected | timing_pattern_not_matched | not_confirmed | 9 | tn |
| sqli-dojo | sqli.boolean | sqli-dojo-boolean-id | confirmation | positive | inconclusive | candidate_confirmation_mismatch | mismatch | 18 | non_decision |
| sqli-dojo | sqli.boolean | sqli-dojo-boolean-id | six_probe | positive | inconclusive | boolean_candidate | not_configured | 6 | tp |
| sqli-dojo | sqli.boolean | sqli-dojo-boolean-source | confirmation | negative | not_detected | no_boolean_difference | not_eligible | 6 | tn |
| sqli-dojo | sqli.boolean | sqli-dojo-boolean-source | six_probe | negative | not_detected | no_boolean_difference | not_configured | 6 | tn |
| sqli-dojo | sqli.error | sqli-dojo-error-id | error_probe | positive | inconclusive | dbms_error_disclosed | matched | 4 | candidate |
| sqli-dojo | sqli.error | sqli-dojo-error-source | error_probe | negative | not_detected | dbms_error_not_observed | not_matched | 4 | tn |
| sqli-dojo | sqli.time | sqli-dojo-time-id | nine_probe | positive | inconclusive | timing_pattern_matched | candidate | 9 | tp |
| sqli-dojo | sqli.time | sqli-dojo-time-source | nine_probe | negative | not_detected | timing_pattern_not_matched | not_confirmed | 9 | tn |

| Check type | Mode | Candidate | TP | TN | FP | FN | Non-decision |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| sqli.boolean | six_probe | - | 2 | 1 | 0 | 0 | 3 |
| sqli.boolean | confirmation | - | 1 | 1 | 0 | 0 | 4 |
| sqli.time | nine_probe | - | 3 | 3 | 0 | 0 | 0 |
| sqli.error | error_probe | 2 | - | 3 | 0 | 0 | 1 |

### Cross-target results

Cells list TP/TN/FP/FN/non-decision. Error cells append candidate. A dash means the technique does not use TP.

| Target (DBMS) | Boolean six_probe | Boolean confirmation | Time nine_probe | Error error_probe |
| --- | --- | --- | --- | --- |
| dsvw (sqlite) | 1/0/0/0/1 | 1/0/0/0/1 | 1/1/0/0/0 | —/1/0/0/0/1 |
| owasp-lab (postgresql) | 0/0/0/0/2 | 0/0/0/0/2 | 1/1/0/0/0 | —/1/0/0/1/0 |
| sqli-dojo (mysql) | 1/1/0/0/0 | 0/1/0/0/1 | 1/1/0/0/0 | —/1/0/0/0/1 |

### Known non-decisions

- `dsvw` / `dsvw-version-query` / `sqli.boolean` / `confirmation`: `unexpected_difference`.
- `dsvw` / `dsvw-version-query` / `sqli.boolean` / `six_probe`: `unexpected_difference`.
- `owasp-lab` / `owasp-lab-boolean-greet` / `sqli.boolean` / `confirmation`: `unexpected_difference`.
- `owasp-lab` / `owasp-lab-boolean-greet` / `sqli.boolean` / `six_probe`: `unexpected_difference`.
- `owasp-lab` / `owasp-lab-boolean-search` / `sqli.boolean` / `confirmation`: `unexpected_difference`.
- `owasp-lab` / `owasp-lab-boolean-search` / `sqli.boolean` / `six_probe`: `unexpected_difference`.
- `owasp-lab` / `owasp-lab-error-search` / `sqli.error` / `error_probe`: `non_success_status`.
- `sqli-dojo` / `sqli-dojo-boolean-id` / `sqli.boolean` / `confirmation`: `candidate_confirmation_mismatch`.
<!-- third-party-measurement:end -->

This Time run was measured on an AMD Ryzen AI 5 PRO 340 (12 logical CPUs) with
Docker Engine 29.9.2 and Docker Compose 5.6.1. The positive completed all nine
requests and was `INCONCLUSIVE / timing_pattern_matched`; the reflected negative
was `NOT_DETECTED / timing_pattern_not_matched`. An earlier run on the same model,
under the pre-Phase 15-2 analyzer, produced `unstable_timing` solely because the
CPU-bound Delay samples varied with host performance or scheduling. Phase 15-2 no
longer treats Delay variance alone as instability; it requires the Delay samples
to remain separated from the Control band. Neither historical outcome is a reason
to tune the fixed inputs or threshold.

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

On sqli-dojo-docker, the six-probe Boolean positive produced
`boolean_candidate`, while the second-pair confirmation produced
`candidate_confirmation_mismatch`; it is preserved as a positive non-decision,
not tuned into a match. The MySQL Time positive produced
`timing_pattern_matched`, and the Error positive disclosed the reviewed
`mysql_syntax_error_1064` signature. All three `source` negatives were true
negatives. The run used Docker Engine 29.9.2 and Docker Compose 5.6.1; no input,
threshold, label, or expectation was changed after observing these results.

On OWASP Training Lab, the PostgreSQL Time positive produced
`timing_pattern_matched` and the `greet` Time negative was a true negative. The
Error positive returned a generic non-success page without a PostgreSQL signature,
so it remains `INCONCLUSIVE / non_success_status`; the Error negative was a true
negative. Both Boolean records produced `unexpected_difference`: the vulnerable
search and the non-SQL greeting reflect their inputs, so exact response relations
do not isolate the SQL-driven difference. These are recorded as non-decisions in
both six-probe and confirmation modes. No payload, threshold, label, or expected
verdict was changed after observing the run.

The Boolean classification contract matches `docs/sqli-boolean-evaluation.md`: only
`INCONCLUSIVE / boolean_candidate` is a positive decision, only `NOT_DETECTED` is a
negative decision, and every other result is a non-decision. Confirmation cannot
turn a result into `NOT_DETECTED` or `VULNERABLE`.

For Time, `INCONCLUSIVE / timing_pattern_matched` is the positive decision and
`NOT_DETECTED / timing_pattern_not_matched` is the negative decision. Other Time
results are non-decisions. For Error, a reproducible signature is reported as a
candidate rather than TP because its product verdict remains `INCONCLUSIVE`;
`NOT_DETECTED / dbms_error_not_observed` is the negative decision. Counts for all
three check types are never combined, and this small sample makes no precision
claim.
