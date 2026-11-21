# Error SQLi contract

Schema v1 `sqli.error` cases run a fixed four-request plan in this order:
baseline, error probe, baseline, error probe. The payload is explicit, the
request budget is exactly four, and query injection is the only supported
location. Error signatures come from the reviewed, immutable registry in
`vintar.checks.sqli.error_signatures`; the case payload itself must not contain
a registered signature.

The analyzer scans bounded response bytes for strong SQLite, PostgreSQL, MySQL,
MSSQL, and Oracle diagnostics. A disclosed diagnostic is a stable signal only
when both baselines have the same status and no signature, and both probes have
the same status and the same single `(dbms, signature_id)` match. Response body
bytes do not need to be identical: timestamps, CSRF tokens, and request IDs may
legitimately change while the status and signature relation stays stable.
Status drift produces `unstable_response`; differing repeated signature matches
produce `unstable_error_signal`.

A repeated new diagnostic maps to `INCONCLUSIVE / dbms_error_disclosed`, never
`VULNERABLE`. Displaying a diagnostic proves disclosure, but it does not prove
that the supplied input changed SQL execution. Independent confirmation would
be required for that stronger claim. `dbms_error_not_observed` is the only
`NOT_DETECTED` result. Operational stops and ambiguous, baseline-present,
unstable, or non-success results remain `INCONCLUSIVE`.

## CI report

An Error outcome uses `check_type = "sqli.error"` and carries a sibling object:

```json
{
  "check_type": "sqli.error",
  "actual_verdict": "inconclusive",
  "actual_reason_code": "dbms_error_disclosed",
  "request_count": 4,
  "error": {
    "status": "matched",
    "reason_code": "dbms_error_disclosed",
    "request_count": 4,
    "dbms": "sqlite",
    "signature_id": "sqlite_operational_syntax"
  }
}
```

The `error` object and check type are all-or-nothing. `dbms` and `signature_id`
are both present only for a rule that requires evidence. The report never
contains response bodies, matched text, payloads, target URLs, or raw baseline
values. The schema and validator enforce the status, verdict, request range,
and evidence requirements from `ERROR_RESULT_RULES`.

The existing CI exit contract is unchanged: a matching `NOT_DETECTED` result
passes with exit 0, expectation mismatch uses exit 1, invalid execution or input
uses exit 2, and every Error candidate or other inconclusive result blocks with
exit 3.
