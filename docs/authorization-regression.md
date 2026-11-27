# Authorization regression contracts

Authorization Case v1 records only explicit, operator-reviewed allow and deny
expectations. Vintar does not infer policy, roles, ownership, tenants, resource
identifiers, or operations from OpenAPI documents or observed responses.

Case aliases are limited to lowercase ASCII letters, digits, `_`, and `-`, with
a maximum length of 64 characters. Reviewers must still choose non-identifying
aliases: the schema cannot determine whether an otherwise valid alias contains
PII or sensitive business data.

Case v1 is read-only and accepts only literal GET targets. It rejects path
templates, runtime object-ID substitution, enumeration, and denial represented
as a 2xx empty result. Every identity and exact origin requires its own positive
control. This includes an explicitly unauthenticated identity, whose control can
be a reviewed public endpoint.

The separate `authorization_execution` policy is trusted operator input. It
binds case digests, identities, exact origins, literal GET operations, expected
allow or deny outcomes, environment classes, and aggregate limits. It never
contains credential values. Authorization Case v1 remains offline-only until a
dedicated command is introduced; the existing verification CLI rejects it with
`authorization_execution_unavailable`.

Policy v1 authenticated identities may declare an optional `expires_at` RFC
3339 UTC timestamp ending in `Z`. When present, it must cover the conservative
duration of the complete multi-identity run plus the authentication safety
margin. Omitting it means that the policy declares no expiry metadata; it does
not cause Vintar to infer an expiry from credential material.

The internal execution composition builds a separate HTTP client, cookie jar,
transport, and connection pool for every identity, including unauthenticated
identities. Request budget, rate limiting, and the run deadline are shared
across identities. Provider-owned header names form one run-wide reserved set
and are checked against both client defaults and the final request for every
identity. Credential environment values are resolved only after complete
secret-free preflight and are never included in diagnostics or representations.
This composition is intentionally unreachable from the CLI and regression
batch in this release. The internal authorization runner is its sole consumer:
it executes approved GET operations sequentially, runs every identity's
positive controls before its other cells, and retains only aliases, verdicts,
and closed reason codes. A failed positive control prevents that identity's
deny cells from being sent. Its allow cells still run, but only a response that
satisfies every assertion can conform; rejection or assertion mismatch remains
inconclusive because the credential state was not established. The existing
CLI continues to reject authorization cases with
`authorization_execution_unavailable` until the dedicated command and report
are introduced.

Response bodies are read only up to the trusted policy limit and discarded
after assertion evaluation. Headers and URLs are not copied into results.
Empty denial bodies conform only when explicitly allowed, and HTML, malformed,
truncated, or oversized bodies cannot prove that a protected JSON pointer is
absent. An explicitly allowed empty body may omit Content-Type because there is
no representation to label; when Content-Type is present, it must match the
declared media type.

Future credential-bearing authorization jobs must run only in a protected
environment. They must not run for forks or other untrusted pull requests. No
credential-bearing workflow is provided by the initial contracts work.

Future reports must not contain response bodies, response headers, response
values, or response-body digests. Assertions expose only bounded assertion IDs
and decision facts; validators must reject fields that could carry the omitted
material.
