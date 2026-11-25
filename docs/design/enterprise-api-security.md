# Enterprise API Security Regression Design

Status: proposed design; no runtime behavior is implemented by this document.

## 1. Current state of latest `main`

This design is based on `main` commit `d4c65f7` (also the branch point of
`enterprise-security-design`) and Vintar 0.5.2.

### Offline discovery and materialization

- `vintar.regression.discovery._Discovery` parses bounded OpenAPI 3.0/3.1 JSON
  or YAML, resolves bundled local references, and inventories GET query inputs.
  `discovery_drafts.draft_files`, `discovery_review.resolve_review`, and
  `case_materialization.materialize_case` implement the existing offline
  discover -> review -> materialize chain. Review retains raw baseline values
  only at the offline boundary and records digests in its report.
- `vintar.regression.post_json_inventory.analyze_post_json` is a separate,
  offline-only capability inventory. It finds POST `application/json` request
  bodies, walks nested properties and arrays, emits RFC 6901-style property
  pointers plus `/*` array placeholders, preserves declared JSON types, records
  schema-definition provenance, and resolves effective OpenAPI security
  declarations. Every field is deliberately `injectable = false`, and every
  operation has `case_generation = unsupported` with
  `post_method_unsupported` and
  `request_body_case_generation_unsupported`. The v1 report and
  `scripts/validate_post_json_inventory.py` are strict, bounded, deterministic,
  and privacy-preserving.
- OpenAPI security data in `post_json_inventory._resolve_auth` is only an
  inventory of declaration alternatives. It does not authenticate, acquire a
  credential, or prove authorization.

### Request and execution model

- `core.request.RequestTemplate` is a frozen value containing method, URL,
  headers, cookies, query pairs, and opaque body bytes. `InjectionPoint` only
  supports `InjectionLocation.QUERY`; `core.injector.inject` returns a copied
  template and preserves the original.
- `core.template.validate_template` rejects malformed methods, headers,
  duplicate headers, `Host`, query-in-URL, and ambiguous cookie input.
  `send_template` is the shared serializer/sender.
- `core.executor.ExecutionContext.execute` validates the template and origin,
  then sends through `ScopedTransport`. The transport owns request-budget
  consumption, rate limiting, redirect refusal, and dispatch/deadline hooks.
  `ScopePolicy` is exact-origin based; it is not a DNS/IP or path firewall.
- `regression.runner.TrustedExecutionPolicy` is supplied independently of a
  case and caps origin scope, total requests, rate, timeout, response size, and
  Time-check duration. `regression.binding.bind_runtime_target` can replace a
  case's placeholder origin while preserving its raw path and rechecking the
  trusted scope. `regression.batch.run_regression_batch` preflights every case,
  uses one aggregate budget/rate limiter, runs sequentially, and fails closed
  on decisive or unsafe conditions.

### Verification, decisions, and reports

- Schema v1 TOML cases in `regression.cases` support only `sqli.boolean`,
  `sqli.time`, and `sqli.error` against GET query parameters. They are immutable,
  strictly parsed, bounded, and contain no runtime credential abstraction.
- Boolean execution is in `checks.sqli.orchestrator` and
  `confirmation_runner`; Time and Error execution are in `time_runner` and
  `error_runner`. All send through `ExecutionContext`. `decision_facts.py`
  contains bounded SQLi non-decision facts. Boolean confirmation, Time, and
  Error candidate signals remain `INCONCLUSIVE`; this work must preserve the
  current rule that it does not turn them into `VULNERABLE`.
- `regression.report.regression_batch_report_dict` emits an allowlisted,
  redacted Schema v1 CI report. It excludes URLs, headers, cookies, payloads,
  bodies, and free-form runtime diagnostics. The JSON Schema and
  `scripts/validate_ci_report.py` enforce structural and semantic invariants;
  the legacy fixture verifies additive compatibility. Exit codes are stable:
  pass 0, fail 1, error 2, inconclusive 3.
- The maintainer measurement harness in
  `scripts/run_third_party_sqli_measurement.py` separates classifier quality
  into TP/TN/FP/FN/non-decision or candidate categories, captures redacted
  request-ordered evidence, and validates report provenance. Local loopback and
  optional pinned third-party targets complement ordinary unit tests.

### Enforced architecture and release gates

- `pyproject.toml` import-linter contracts keep `core` independent of checks,
  regression, and CLI; checks independent of regression and CLI; and regression
  independent of CLI. Checks may not call `core.http` directly.
- `scripts/check_architecture.py` mechanically prevents network imports in the
  offline discovery/review/materialization boundary and prevents checks from
  bypassing `ExecutionContext`.
- `.github/workflows/vintar-pr.yml` runs Ruff lint/format, import-linter, the
  architecture guard, strict mypy, branch coverage with fail-under 89%, secret
  history scanning, dependency audit, E2E, report validation, and distribution
  checks. Release workflows repeat quality checks and bind tags, builds,
  hashes, SBOMs, and publication to the verified commit.

## 2. Reuse plan for existing components

Reuse rather than replace these boundaries:

| Existing component | Enterprise extension |
| --- | --- |
| `_Discovery` and `analyze_post_json` | Share pure OpenAPI resolution and evolve the POST inventory into reviewable operation/field drafts. Keep discovery unable to import HTTP, auth providers, or runners. |
| `draft_files` / `resolve_review` / `materialize_case` | Add POST-body review decisions: concrete immutable request body, one explicit JSON Pointer, selected array indexes, side-effect classification, operation approval, and isolated-environment attestation. Never materialize every POST automatically. |
| `RequestTemplate` / `inject` | Add canonical JSON body support and a JSON Pointer injection location. Injection must parse once, copy the complete JSON tree, replace only the selected value, preserve every other value and JSON type, and deterministically serialize bytes. |
| `ScopePolicy`, `ExecutionContext`, `ScopedTransport` | Keep the single network path and aggregate limits. Add credential binding before dispatch, with the final origin checked both before and after credential application. |
| `TrustedExecutionPolicy` | Generalize into a trusted runtime policy that also selects approved case IDs/operations, approved identity/provider bindings, permitted credential destinations, mutation permission, and CI trust level. It must never be derived from OpenAPI, a case, or PR-controlled files. |
| SQLi check runners and analyzers | Accept the generalized injection point and an already prepared authenticated execution context. Do not change SQLi verdict rules or decision facts. Auth acquisition occurs outside timed probe windows. |
| Batch preflight and report allowlists | Preflight complete request/auth plans before the first dispatch, retain shared budgets, and add separately typed SQLi and authorization outcomes. Keep legacy Schema v1 reports valid. |
| CI/report validators and measurement patterns | Extend schema plus semantic validation, golden fixtures, local E2E, and quality matrices rather than relying on test counts. |

The new package boundaries should be `core` for secret-free request primitives,
`auth` for providers and credential application, `checks.sqli` for SQLi,
`checks.authorization` for authorization assertions and decisions,
`regression` for cases/policy/batching/reporting, and CLI modules as adapters.
Import contracts should forbid `auth` and both check families from importing
regression or CLI, forbid offline modules from importing `auth`, and keep every
check on `ExecutionContext`.

## 3. POST JSON dynamic verification design

### Reviewed lifecycle

1. **Discover offline.** Extend the existing inventory model, retaining
   operation pointer, request-body pointer, schema definition pointer, JSON
   Pointer, declared types, diagnostics, and security declarations. Array
   inventory pointers such as `/orders/*/sku` are patterns, not executable
   pointers.
2. **Review.** A reviewer selects exactly one operation and field per draft,
   supplies a complete concrete baseline JSON document or an explicitly chosen
   bundled example, replaces every `*` with a non-negative array index, confirms
   the baseline digest, selects the SQLi check and explicit probes/preset under
   existing rules, and records side-effect assessment. The review must state
   `no_side_effect`, `idempotent_test_mutation`, or `mutating`; POST is never
   inferred to have no side effect. It also names an isolated test environment
   class and cleanup owner when mutation is possible.
3. **Materialize.** Produce one explicit case for the reviewed operation and
   concrete RFC 6901 JSON Pointer. The case stores request data and approval
   metadata, but no credential, provider configuration, token source, or secret.
   Materialization rejects wildcard pointers, absent targets, ambiguous array
   choices, incompatible target values, unreviewed schema diagnostics, and
   operation/body drift.
4. **Verify.** Trusted runtime configuration independently approves the case ID,
   exact operation (`POST` plus path), destination origin, environment class,
   allowed side-effect class, budget, and rate. A POST case without this
   per-operation intersection fails before authentication or network access.

### Request and injection invariants

- Introduce a JSON value model with exact JSON distinctions: `null`, boolean,
  integer, finite number, string, array, and object. Reject duplicate object
  keys, non-finite numbers, excessive nesting/size, invalid UTF-8, and trailing
  data using the existing strict-JSON approach.
- `RequestTemplate` remains immutable. Prefer adding a mutually exclusive
  `json_body` canonical value to treating arbitrary bytes as JSON. Construction
  emits `Content-Type: application/json` centrally and rejects a conflicting
  user header. Existing `body: bytes` remains for v1 compatibility.
- A body injection point is `{location = "json_body", pointer = "/a/0/b",
  mode = "replace"}`. RFC 6901 escape processing is strict. Arrays require a
  concrete decimal index; `-`, negative indexes, leading-zero aliases, wildcards,
  and append are rejected. The root pointer `""` may replace a scalar root.
- Replacement payload conversion is check-owned and explicit. SQLi payloads are
  strings; therefore a selected body value must be a reviewed string unless a
  future check defines a typed transformation. No implicit stringify/coercion.
- Injection returns a new template, verifies the target exists, and proves via
  structural comparison that only the target leaf changed. Non-target values,
  object keys, array ordering/length, and types are unchanged. Deterministic
  serialization makes equality and golden tests stable.
- Boolean, Time, and Error runners reuse their request plans, analyzers,
  `decision_facts`, budgets, and stop rules. Only the injection adapter changes.
  No POST support may alter candidate-to-verdict mapping.

### Safety

Preflight builds every baseline and injected template and validates content
type, origin, approval, budget, and distinctness before acquiring credentials.
The batch retains a shared request budget and slowest approved rate. Mutating
POST cases are excluded unless trusted policy explicitly enables their exact
case and side-effect class; the first implementation should support only
reviewed `no_side_effect` POSTs in disposable/local environments. HTTP retries remain
disabled because replaying POST can duplicate effects.

## 4. Authentication layer design

### Interfaces and ownership

`AuthenticationProvider` is a runtime-only protocol that returns a short-lived
`AuthContext` for one configured identity and approved origin. Initial providers
consume externally obtained credentials; Vintar does not implement browser
login, password grant, refresh-token storage, service-account key minting, or a
general OAuth client.

Suggested types:

- `CredentialBinding(identity_id, provider_id, allowed_origins, expires_at,
  placement)` is built only from trusted runtime configuration.
- `AuthMaterial` is a secret-bearing, non-serializable, `repr=False` runtime
  object with a narrow apply operation. It supports Bearer, API key header or
  query placement, Basic, a static externally supplied Cookie/session value,
  Google Cloud IAP token, WIF-produced token, and externally acquired OAuth
  2.0/OIDC access token. Vendor adapters implement the same protocol later.
- `AuthenticatedExecutionContext(identity_id, auth_context,
  ExecutionContext)` owns an identity-isolated client/transport lifecycle.
  SQLi uses one identity; authorization checks use multiple separate contexts.

Credential acquisition and application are separate phases. Acquisition occurs
after all non-secret preflight and before a Time runner starts its measurement
clock. Token acquisition latency, provider subprocess latency, and refresh time
are never part of Time SQLi elapsed evidence. A credential that expires too soon
for the worst-case plan fails preflight; no mid-plan refresh or retry is allowed
initially.

### Mechanical protections

- Bind credentials to normalized exact origins. After runtime target binding and
  again immediately before dispatch, require the request origin to be in both
  trusted scope and credential scope. Redirects remain disabled. Credential
  material is never forwarded across origins.
- Reserve provider-owned header, cookie, and query names. A case or OpenAPI
  template containing `Authorization`, the selected API-key name, `Cookie`, or a
  provider-owned collision is rejected with guidance to remove it and configure
  the provider. Provider application must not silently overwrite values.
- Keep probe payloads and credentials in different types and functions. JSON
  injection runs before auth application; auth application cannot alter URL
  path/body/injection data, and injection cannot access auth material.
- Central redaction accepts registered secret byte/string values and derived
  encodings (for example Basic) and is applied to exception chains, logs, CLI
  diagnostics, evidence, and test failures. Public exceptions expose stable
  enums and actionable generic text only. No `repr`, equality failure, report,
  or callback may reveal material.
- Classify failures as `auth_material_unavailable`, `auth_material_expired`,
  `auth_configuration_invalid`, `auth_collision`, `auth_origin_mismatch`,
  `authentication_rejected`, or `authorization_rejected_or_unknown`. HTTP 401 is
  authentication rejection. HTTP 403 alone cannot distinguish invalid auth from
  insufficient authorization and must not infer policy.
- OpenAPI security requirements remain offline declarations. Provider selection
  and identity binding are trusted runtime inputs; a successful response proves
  neither that the declared scheme was used nor that authorization is correct.

### Trusted CI configuration

Runtime policy and provider bindings initially come only from environment
variables or a local config file, with an explicit precedence rule. In CI these
sources must be protected runner configuration, never the checked-out PR,
generated case, OpenAPI file, CLI argument assembled from PR data, or report.
Prefer OIDC/WIF or environment-injected short-lived tokens. Use least-privilege test identities,
an isolated non-production tenant, protected main/manual or post-merge execution,
environment reviewers, log masking as defense in depth, and network egress
allowlists. Fork and untrusted PR jobs must run without credentials and must not
be able to select a privileged environment. Secret presence alone must never
enable authenticated execution.

## 5. Authorization regression testing design

Authorization is a new check family, independent of SQLi types, verdicts,
decision facts, payloads, and analyzers.

### Case model

An authorization case declares:

- a stable case/check ID and category: IDOR, BOLA, BFLA, horizontal escalation,
  vertical escalation, broken access control, tenant isolation, or
  unauthenticated access;
- two or more explicit identity references, each with reviewed role/permission
  labels that are descriptive inputs, not discovered truth;
- explicit resource IDs and reviewed ownership/tenant declarations;
- an expected authorization matrix for each identity x operation x resource;
- one positive control request for every authenticated identity, using that
  identity's own credentials against a pre-approved resource it is expected to
  access, plus negative controls using pre-approved identities and resources;
- immutable request templates and response assertions; and
- side-effect classification, with reviewed `no_side_effect` operations
  initially required.

Cases never contain credentials. They never enumerate, guess, mutate, or follow
links to arbitrary users/resources. OpenAPI and observed responses may help a
human find candidates but cannot generate expected policy, ownership, roles, or
permissions.

Materialization rejects a case unless every authenticated identity has exactly
the required explicit positive control and its expected success assertions.
A case-wide positive control cannot satisfy this rule. An unauthenticated
identity is exempt from the positive-control requirement only when the case
declares it explicitly as unauthenticated; absence of an identity or provider
binding is not an implicit unauthenticated identity.

### Isolation and execution

Each identity receives a separate provider acquisition, cookie jar, HTTP client,
transport/connection pool, and `AuthenticatedExecutionContext`. The
unauthenticated identity has an explicit no-auth provider and a fresh context.
No headers, cookies, session state, TLS state intended to identify a principal,
or pooled connection state crosses identity boundaries. Execution order should
be deterministic but alternated in evaluation fixtures to detect order-dependent
leakage.

The runner preflights the complete matrix and aggregate request budget before
acquisition. It verifies only declared cells. Read-only operations ship first.
Mutation requires a separate case version or capability flag, operation-specific
approval, disposable resources, cleanup verification, idempotency analysis, and
a smaller trusted budget; it is not part of the initial implementation.

### Assertions and decisions

Status codes are necessary but insufficient. Each matrix cell defines bounded,
typed assertions such as allowed status set, response media type, selected JSON
Pointer equality/absence/type, stable body digest for fixtures, required/forbidden
header presence, and bounded schema/shape checks. Assertions cannot contain
secrets or production PII. A denial must also assert that protected resource
markers are absent; an allow must assert identity/resource-specific declared
fields or markers. Initial assertions are limited to status code plus presence
or absence of declared response fields or markers. Each authenticated identity's
own positive control must succeed with that identity's credentials before any
denial cell for that identity can conform. If the control fails because of an
expired credential, authentication failure, unexpected status, or any other
control assertion failure, every denial result for that identity is
`inconclusive`, never `conforms`. A different identity's successful control
cannot substitute for it. Negative controls prove the denial assertion can
distinguish principals.

Field-presence and field-absence assertions are evaluated only after the body is
fully read within the configured read limit and parsed successfully in the
case's declared expected format, initially JSON. A content-type mismatch, parse
failure, truncated body, or read-limit overflow makes the matrix cell
`inconclusive`, never `conforms`. In particular, failure to evaluate a JSON
Pointer because the body is unparseable is not evidence that the field is
absent. A denial cell may explicitly declare that an empty body is acceptable;
without that declaration, an empty body is `inconclusive` whenever the cell has
a field-presence or field-absence assertion.

Use a distinct `AuthorizationVerdict` such as `conforms`, `violation`, and
`inconclusive`, with explicit reasons for assertion mismatch, unexpected allow,
unexpected deny, auth failure, control failure, rate limit, and transport failure.
An authorization `violation` fails the CI gate directly. Never map it through
SQLi `Verdict`, `_classify`, or `decision_facts`. Evidence is an allowlisted set
of identity aliases, operation/resource aliases, observed status, assertion IDs,
and digests/sizes where safe; never bodies, resource values, credentials, URLs,
PII, or free text.

## 6. Threat model

| Threat | Required control |
| --- | --- |
| Malicious OpenAPI with external/cyclic refs, huge/deep values, path tricks, security declarations, or examples containing secrets | Keep parsing bounded and offline; local refs only; strict path/pointer validation; size/depth limits; never fetch refs or acquire auth; treat examples as untrusted review candidates; redact diagnostics. |
| Malicious case changes target, method, auth header, resource, budget, or POST effects | Strict closed schema; immutable models; trusted policy intersection; exact operation and case approval; full-plan preflight; auth-field collision rejection; protected CODEOWNERS/review. |
| Credential leakage through reports, logs, exceptions, repr, callbacks, crash output, or response evidence | Secret-bearing types with `repr=False`; central redaction; stable error enums; report allowlists; no request/body/header dumps; hostile-secret tests; restricted artifacts. |
| Credential forwarded to another origin through case URL, redirect, provider endpoint, or target rebinding | Exact origin-bound credentials; target and credential scope intersection; redirects off; final pre-dispatch check; network egress policy; no URL credentials. |
| Injection changes or captures credential material | Inject before auth; disjoint types; provider-owned fields reserved; structural proof that JSON injection changes one leaf only. |
| Identity/session contamination creates false authorization results | Separate client, transport, cookies, headers, auth context, and connection pool per identity; no shared mutable session; isolation tests with identity canaries. |
| An expired or rejected credential makes a denial look correct | Require a successful positive control for each authenticated identity using its own credentials; classify every denial for that identity as inconclusive when its control fails. Only explicitly declared unauthenticated identities are exempt. |
| A proxy or read failure turns an unreadable denial body into apparent field absence | Require complete bounded reads, matching declared content type, successful format parsing, and evaluable pointers before field assertions. Treat HTML proxy responses, truncation, overflow, parse failure, and undeclared empty bodies as inconclusive. |
| Untrusted PR exfiltrates CI credentials or changes policy | No credentials or protected environment for PR/fork jobs; trusted post-merge workflow; pin actions/dependencies; environment approval; do not use `pull_request_target`; protected runtime policy outside checkout. |
| SSRF, DNS rebinding, or access to metadata/internal services | Existing exact-origin scope plus runner/network egress allowlists, DNS/IP controls, metadata blocking, and isolated runners. Document that application origin checks alone are insufficient. |
| POST causes unintended effects or replay | No automatic POST execution; reviewed per-operation approval; isolated environment; only `no_side_effect` initially; fixed budget/rate; no retries; mutation-specific assessment and cleanup. |
| Response contains secrets or PII | Do not serialize bodies; assertions operate in memory; report aliases/digests and bounded facts only; use synthetic test data. |
| OpenAPI security declaration is mistaken for successful authentication or real policy | Type and UI separation: declaration inventory, runtime auth result, and authorization expectation are distinct artifacts and report fields. |

## 7. Impact on case schema and report schema

### Case schema

Keep Schema v1 parsing byte-for-byte compatible. Introduce Case Schema v2 first
for POST JSON SQLi; do not add ambiguous optional tables to v1. V2 is a
discriminated SQLi union:

- SQLi cases retain the existing check-specific probe models and verdict
  semantics, while `request.method` and `request.json_body` plus a
  `json_body` injection point are permitted.
- All cases use symbolic `identity_id` only. Provider IDs, environment variable
  names, credential locations/values, token endpoints, and secrets are forbidden.
- Approval metadata records exact method/path, operation pointer/digest,
  side-effect class, environment class, and review provenance. Runtime policy
  must independently approve them; case metadata is not authority.

The loader should retain explicit v1 model types and add a v2 union rather than
silently converting v1. Golden v1 TOML and parser-error tests remain unchanged.
Authorization case versioning will be decided when its independent case model is
implemented; it must not be folded into POST SQLi Case Schema v2 merely to reuse
a version number.

### Report schema

Keep SQLi Report Schema v1 and its current writer output stable while POST SQLi
is introduced. Decide whether SQLi Report Schema v2 is necessary only after
demonstrating that Report v1 cannot represent POST results without changing the
meaning of existing fields. Authorization uses a separate gate and a separate
report with its own schema, verdicts, reasons, controls, matrix cells, and
assertion evidence; it is never added as an outcome family to the SQLi report.

Compatibility verification must include:

- current v1 writer output against the current and compatibility validator;
- `tests/fixtures/regression-batch-report-v1-legacy.json` and all CLI goldens;
- rejection of authorization fields in SQLi reports and SQLi fields in
  authorization reports;
- deterministic serialization and bounded report size;
- validator re-derivation of counts, request totals, outcome status, controls,
  matrix coverage, and CI exit code; and
- hostile values proving that credentials, headers, URLs, bodies, PII, and
  unbounded strings cannot enter reports.

The two report validators and CI jobs remain independently executable. CI may
compose their job statuses at the workflow level, but there is no mixed batch,
shared aggregate exit code, or shared report artifact contract.

## 8. PR-by-PR roadmap

All PRs retain Ruff, format, strict mypy, import-linter, architecture guard,
branch coverage >= 89%, secret scan, existing E2E, report validation, golden
tests, and distribution checks. No skip/xfail/noqa/per-file-ignore/type-ignore/
coverage pragma, retry, or sleep-based synchronization is permitted.

| PR | Scope and likely files | Tests and gates | Estimate | Depends on |
| --- | --- | --- | --- | --- |
| 1. JSON request primitives | Add strict immutable JSON value/body and concrete RFC 6901 pointer replacement in `core/request.py`, `core/injector.py`, `core/template.py`, possibly a focused `core/json_body.py`; no case or network behavior. | Unit/property-style tables for escapes, root, nested objects, explicit arrays, duplicate keys, type preservation, one-leaf mutation, deterministic bytes, content-type collision; all existing template/injector tests unchanged. | 250-400 LOC product, 400-600 tests | none |
| 2. POST discovery review | Extend `post_json_inventory.py` and offline draft/review models to turn supported fields into review candidates with explicit array selection, baseline digest, operation approval, side-effect/environment declarations; update inventory schema/validator without network imports. | OpenAPI 3.0/3.1 fixtures; nested/array/ref/diagnostic drift; malicious pointers/examples; deterministic goldens; architecture tests prove offline boundary. | 350-550 product, 500-750 tests/docs | PR 1 pointer model only; no execution |
| 3. POST SQLi case v2 materialization | Add v2 SQLi JSON-body case models/parser/materializer while retaining v1; require one reviewed operation/pointer and immutable baseline; prohibit credentials. | v1 compatibility/goldens; v2 closed-union negative tests; Boolean/Time/Error preflight templates differ only at target; schema drift and size limits. | 400-600 product, 600-850 tests | PRs 1-2 |
| 4. Trusted POST execution | Generalize runner preflight for POST v2, exact per-operation approval, isolated-environment policy, reviewed `no_side_effect` enforcement, shared budget/rate, and existing SQLi runners through generalized injection. | Isolated loopback E2E for Boolean/Time/Error JSON bodies; request capture proves type/value preservation and exact counts; reject every side-effect class except `no_side_effect`; 429/budget/rate/timeout; no retries; SQLi never promoted to vulnerable; confirm SQLi Report v1 represents POST results before proposing a Report v2. | 350-500 product, 500-800 tests | PR 3 |
| 5. Authentication contracts | Add `vintar.auth` protocol, secret-bearing types, origin binding, collision rules, failure taxonomy, redaction, no-auth and externally supplied Bearer/API-key/Basic/static-Cookie providers; consume externally obtained IAP/WIF/OAuth/OIDC tokens without login or token acquisition automation; extend import contracts/guard. | Unit tests with canary secrets in every error/report/log path; origin/collision/expiry tests; provider conformance; static Cookie isolation; no network acquisition or login flow; architecture tests. | 450-650 product, 650-900 tests | PR 1; policy decisions |
| 6. Authenticated execution | Compose provider with isolated execution contexts; acquire material after preflight and outside Time clocks; accept trusted runtime configuration only from environment variables or a local config file with an explicit precedence rule; treat IAP/WIF/OAuth/OIDC as externally supplied token profiles. | Local authenticated server E2E for success/401/403/expiry/cross-origin; environment/file precedence and rejection tests; Time clock proof; no forwarding; CI fixture has synthetic tokens only. | 400-600 product, 650-900 tests/docs | PRs 4-5 |
| 7. Authorization case model | Add `checks.authorization` pure models, assertions, verdict/reason types, an independently versioned authorization case parser, reviewed ownership/matrix/controls, and only status plus declared field/marker presence/absence assertions; require one successful-control definition per authenticated identity and explicit unauthenticated identities; model bounded body readability, expected format, and opt-in empty denial bodies; no HTTP runner yet. | Closed schemas, matrix completeness, aliases, explicit resources, per-identity positive-control presence, unauthenticated exemption, readable-body assertion prerequisites, empty-body declaration, assertion allowlist, no inferred policy, PII/secret rejection, cross-family type/import tests. | 450-700 product, 700-1,000 tests | PR 5 |
| 8. Authorization runner | Execute each authenticated identity's positive control and the declared read-only matrix with one isolated context per identity and a distinct decision model; make that identity's denial cells inconclusive when its control fails; require complete bounded parsing before field assertions; integrate aggregate policy/budget/rate and fail-closed controls. | Multi-identity local server E2E for IDOR/BOLA/BFLA/horizontal/vertical/tenant/unauthenticated cases; expired-credential control failure proves all denial cells for that identity are inconclusive; HTML `403` proxy, content-type mismatch, malformed JSON, truncation, read-limit overflow, and undeclared empty-body fixtures never satisfy absence; declared acceptable empty denial body; canary isolation; order independence without sleeps; transport failures. | 500-750 product, 800-1,200 tests | PRs 6-7 |
| 9. Separate authorization report and CI gate | Add authorization-only serialization, schema, semantic validator, CLI/report artifact, and CI gate without changing the SQLi Report v1 or SQLi gate; update goldens and CI guide. | Existing SQLi v1 legacy fixture and goldens remain unchanged; authorization semantic mutation suite, independent exit-code matrix, redaction/size/determinism, isolated E2E artifact validation. | 450-700 product, 700-1,000 tests/docs | PR 8 |
| 10. Local authorization measurement and release hardening | Build a local synthetic authorization app and derive the corpus size, diversity, and release thresholds at this stage; add the POST/auth quality harness and document CI deployment, threat model, limitations, and migration. | Measure expected matrix-cell classification, false violation, missed violation, inconclusive/auth-failure rates, identity leakage, and budget adherence; record and review thresholds before release; release rehearsal/distributions. | 250-450 product/scripts, 500-800 fixtures/docs | PR 9 |

PR sizes are rough changed-line ranges and should be split again if a PR cannot
be reviewed independently or temporarily weakens a gate.

## 9. Test and real-measurement evaluation plan

Use three layers:

1. **Pure invariants.** Table-driven tests cover strict parsing, pointer
   resolution, immutable copying, type preservation, auth collisions/redaction,
   policy intersection, matrix completeness, mandatory per-authenticated-identity
   positive controls, explicit unauthenticated identities, bounded response
   readability and empty-body declarations, serializers, and semantic validators.
   Mechanical architecture tests forbid forbidden imports and send paths.
2. **Isolated local E2E.** Deterministic loopback servers capture requests and
   implement synthetic authenticated tenants/roles/resources. Tests verify exact
   request order/count, no credential forwarding, no identity state sharing,
   auth acquisition outside timing, per-identity positive/negative controls,
   expired credentials, HTML `403` proxy responses, content-type/parse/truncation/
   read-limit failures, explicit empty-body behavior, response assertions,
   rate/budget stops, and stable exit/report contracts. Synchronize with explicit
   events/queues/server readiness, never sleeps or retries.
3. **Maintainer real measurement.** Extend the existing measurement discipline
   to a local synthetic authorization app when the roadmap reaches authorization
   checks, and later to reviewed pinned disposable API fixtures if needed. Corpus
   size, diversity, and numeric authorization release thresholds are deliberately
   deferred until that local app produces evidence. Run only in isolated networks
   with synthetic data and least-privilege test identities. Record provenance and
   redacted wire metadata, never credentials or bodies.

Quality metrics, reported per check/category and target, are:

- SQLi: retain TP/TN/FP/FN/non-decision or candidate metrics and verify POST
  results do not regress GET query baselines;
- authorization: true violation detection, conforming-cell false violation,
  missed violation, inconclusive/control-failure, and auth-failure rates over
  reviewed matrix cells;
- isolation: credential cross-origin attempts blocked / attempted, cross-identity
  canary leakage (must be zero), and provider-field collisions rejected;
- safety: requests dispatched versus planned/budgeted, mutation attempts (zero
  in initial release), redirects followed (zero), retries (zero), and secret
  canary appearances in outputs/artifacts (zero); and
- stability: deterministic result/report across repeated fixture seeds and
  execution-order permutations. Repetition is measurement, not hidden retry.

Test count is not a release metric. Coverage remains a floor; each supported
claim requires a corresponding invariant or measured fixture.

## 10. Release criteria

The first enterprise release is eligible only when:

- POST JSON supports reviewed nested objects and concrete array elements for
  Boolean, Time, and Error SQLi through one-leaf immutable injection;
- no SQLi candidate path introduced here can emit `VULNERABLE`;
- every POST requires exact case/operation approval, trusted isolated-environment
  policy, bounded requests/rate, and a reviewed `no_side_effect` declaration;
  automatic execution of discovered POST operations is impossible;
- externally supplied short-lived Bearer, API key, Basic, Cookie/session, IAP,
  WIF, and OAuth/OIDC token forms fit the provider contract, with documented
  support levels and conformance tests;
- origin binding, collision prevention, redaction, identity isolation, and Time
  acquisition exclusion pass hostile local E2E tests;
- authorization read-only cases cover all named categories through explicit
  users/resources/matrices, a successful positive control for every authenticated
  identity, explicit unauthenticated identities, and negative controls; a failed
  identity control makes all denial cells for that identity inconclusive;
- field assertions conform only after a complete within-limit read and successful
  parse in the declared format; content-type mismatch, parse failure, truncation,
  read-limit overflow, an unevaluable pointer, and an undeclared empty body are
  inconclusive, including the HTML `403` proxy scenario;
- untrusted PR execution cannot access trusted credentials or select the
  privileged environment in the supplied CI example;
- legacy case/report fixtures, JSON Schemas, CLI goldens, and exit codes remain
  compatible or have a documented major-version migration;
- SQLi real-measurement safety requirements continue to be met. Authorization
  corpus size, diversity, and numeric release thresholds are defined from the
  local synthetic app when the roadmap reaches authorization checks, then agreed
  and met before authorization release;
- all repository and release gates pass without suppression, and distribution
  smoke tests exercise both v1 compatibility and v2 parsing; and
- limitations explicitly state origin-only application scope, network controls,
  candidate semantics, supported auth acquisition model, read-only authorization
  scope, and isolated-environment requirement.

Authorization corpus size, diversity, and numeric thresholds are deliberately
deferred to the local synthetic-app measurement work in PR 10; do not encode
aspirational numbers as evidence before then.

## 11. Alignment with a future GUI

Keep the GUI a client of the same typed, deterministic APIs and artifacts:

- discovery returns operation/field/auth-declaration data without network side
  effects;
- review presents schema provenance, concrete pointer selection, baseline digest,
  side-effect assessment, identity/resource aliases, matrix cells, and unresolved
  diagnostics;
- materialization produces portable, reviewable cases with no secrets;
- runtime credential/provider selection is a separate trusted screen or external
  integration, never prefilled from OpenAPI or case content;
- execution streams bounded state transitions and redacted evidence, not raw
  requests/responses; and
- SQLi and authorization use visibly different verdict vocabularies and evidence
  panels. OpenAPI declaration, authentication result, and authorization result
  must never be collapsed into one green/red auth indicator.

Stable IDs, reason enums, JSON Pointers, assertion IDs, and versioned reports
allow a GUI without importing CLI code. The CLI remains an adapter over the same
application services. GUI-specific storage, credential vaults, remote execution,
and multi-user collaboration are deferred.

## 12. Explicit non-goals

- Crawling, fuzzing, automatic POST execution, arbitrary user/resource
  enumeration, or inference of real authorization policy.
- Confirming SQLi candidates as vulnerabilities, changing existing SQLi
  decision logic, UNION/exfiltration payloads, or exploit generation.
- Production testing by default, destructive/mutating authorization tests in the
  first release, cleanup orchestration, or compensating transactions.
- A general OAuth/OIDC client, browser automation, MFA handling, long-lived
  secret storage, refresh-token vault, cloud IAM provisioning, or vendor SDK
  ecosystem. Initial providers consume externally acquired short-lived material.
- Trusting OpenAPI security declarations, examples, case files, generated files,
  PR inputs, HTTP status alone, or observed behavior as authorization truth.
- Redirect credential forwarding, cross-origin sessions, shared identity
  connection state, automatic retries, or retry-on-auth-failure.
- Full JSON Schema validation/coercion, arbitrary JSONPath, wildcard runtime
  injection, array append, multiple simultaneous injection points, multipart,
  form bodies, GraphQL, WebSocket, gRPC, or asynchronous/concurrent execution in
  the initial increment.
- DNS rebinding prevention inside the Python origin model. CI/network controls
  remain required.
- A GUI implementation, plugin system, policy language, remote control plane,
  database, or enterprise RBAC for Vintar itself.

## Decisions

1. Introduce Case Schema v2 for POST SQLi first. Keep SQLi Report Schema v1 and
   decide on Report Schema v2 only after confirming that v1 cannot represent
   POST results without changing existing field semantics.
2. SQLi and authorization use separate gates and separate reports. There is no
   mixed batch or shared aggregate exit-code contract.
3. Initial trusted runtime configuration sources are environment variables and
   a local config file only. Their precedence must be explicit and tested.
4. Cookie/session credentials are static externally supplied input only. Login
   flow automation is out of scope.
5. IAP, WIF, OAuth 2.0, and OIDC support means consuming externally obtained
   tokens; Vintar does not acquire them in process.
6. Initial authorization assertions are status code plus presence or absence of
   declared response fields or markers.
7. The only initially allowed POST side-effect class is reviewed
   `no_side_effect`. HTTP method or OpenAPI metadata never establishes it.
8. Authorization measurement corpus design and release thresholds are deferred
   until the roadmap reaches authorization checks. They will be derived using a
   local synthetic application before authorization release.
