# Vintar

Vintar is a Python tool for running authorized web security regression checks in CI. It runs reviewed cases against a configured target and reports the batch result as JSON and a process exit code.

## Supported Scope

Vintar supports Boolean-, time-, and error-based SQL injection regression
checks for `GET` query parameters. OpenAPI 3.0 and 3.1 `discover`,
`review-draft`, and `materialize-case` support Boolean, Time, and Error cases
and run offline; `verify` runs all three check types against an authorized,
configured target. Reviewers explicitly select the `string-quoted` or `numeric`
probe preset for Boolean cases that use presets. Time and Error cases require
explicit reviewed payloads; Vintar never infers a DBMS, SQL context, or payload
from an OpenAPI type.

Time cases require explicit reviewed delay and control payloads and a fixed
nine-request budget. The operator controls the execution deadline with
`verify --time-deadline`. Time presets are unavailable.

Deferred are confirmed Error `VULNERABLE` verdicts and UNION-based SQL
injection checks, POST form and JSON body injection, cookie and header injection,
and authenticated workflows.

Minimal Error case:

```toml
version = 1
id = "reviewed-error-case"
type = "sqli.error"
expected_verdict = "inconclusive"

[target]
url = "http://placeholder.invalid:8000/items"
allowed_origin = "http://placeholder.invalid:8000"
params = [{ name = "id", value = "1" }]

[injection]
location = "query"
name = "id"
occurrence = 0
mode = "append"

[probes]
error_payload = "'"

[limits]
max_requests = 4
requests_per_second = 10.0
timeout_seconds = 5.0
```

## Install from PyPI

Use Python 3.13 or later. With uv, install Vintar as a CLI tool.

```bash
uv tool install vintar
```

Alternatively, install it in an active virtual environment with pip.

```bash
pip install vintar
```

### Install from Source

For development, clone the repository and install from the lockfile.

```bash
git clone https://github.com/natori-hrj/vintar.git
cd vintar
uv sync --locked
```

The examples below use `uv run --locked vintar` from a source checkout. With an
installed CLI, use `vintar` in its place.

## Run Your First Regression Batch

### Create a TOML Case

Save this example as `security/cases/a-case.toml`. It expects a test fixture with an `/ok` endpoint and a `category` query parameter. Adapt the path, parameter, and reviewed probe values to your authorized fixture. `--cases` accepts one TOML file or a directory of TOML files. Directory discovery is nonrecursive.

<!-- cli-example: verify-pass/case -->
```toml
version = 1
id = "a-case"
type = "sqli.boolean"
expected_verdict = "not_detected"

[target]
url = "http://placeholder.invalid:8000/ok"
allowed_origin = "http://placeholder.invalid:8000"

[[target.params]]
name = "category"
value = "Pets"

[injection]
location = "query"
name = "category"
occurrence = 0
mode = "append"

[probes]
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 5.0
```

### Configure the Authorized Target

Run verification only against systems you own or have explicit permission to test. `--authorized` is your attestation. Set both `VINTAR_TARGET_ORIGIN` and `VINTAR_ALLOWED_ORIGIN` to the authorized service's exact origin in the trusted CI environment for Schema v1 cases. Vintar replaces the case's placeholder origin with the runtime target and preserves the case path. Keep credentials and secrets out of origins and case files.

Reviewed identity-bearing Schema v2 GET query and POST JSON cases additionally require a strict trusted runtime
policy supplied through `VINTAR_RUNTIME_POLICY_JSON` or
`VINTAR_RUNTIME_POLICY_FILE`. Inline JSON takes complete precedence and an
invalid selected source never falls back to the file. The policy must approve
the exact case, identity, method, path, origin, and environment class. POST
approvals also bind operation and baseline digests plus the `no_side_effect`
classification. Case files and specifications grant
no execution permission. In CI, inject inline policy from protected runner
configuration or point at a protected file outside the PR-controlled checkout.
A policy committed to the repository grants nothing by itself; it is used only
when an operator independently selects it. Policy files must be regular,
non-symlink, bounded UTF-8 strict JSON files.

The policy selects an externally supplied Bearer, dedicated API-key header, or
Basic credential by environment-variable name. Cases and reports never contain
that name or value. For example, protected CI configuration can contain this
synthetic identity entry:

```json
{"identity_id":"example-reader","credential_kind":"bearer","env_var":"VINTAR_EXAMPLE_CREDENTIAL","header_name":"Authorization"}
```

```bash
VINTAR_EXAMPLE_CREDENTIAL=example-token-value \
VINTAR_TARGET_ORIGIN=https://staging.example.com \
VINTAR_RUNTIME_POLICY_FILE=/run/vintar/runtime-policy.json \
uv run --locked vintar verify --cases security/cases/v2 --authorized
```

Use a short-lived, least-privilege test credential in an isolated environment.
Keep policy and credentials in protected CI configuration outside an untrusted
checkout, and never expose them to fork or untrusted PR jobs. Vintar does not
perform login, token fetch, refresh, retry, or POST replay. Cookie auth, query
API keys, and path-template binding are unsupported. Redirects are not followed.
Exact-origin checks do not replace DNS/IP and network egress controls. HTTP 401,
403, or 407 during probes is inconclusive and stops the batch; the same response
to the initial baseline is an error with no report.

### Run `vintar verify`

Replace `https://staging.example.com` with your authorized fixture origin.

<!-- cli-example: verify-pass/command -->
```bash
VINTAR_TARGET_ORIGIN=https://staging.example.com \
VINTAR_ALLOWED_ORIGIN=https://staging.example.com \
uv run --locked vintar verify \
  --cases security/cases/a-case.toml --max-requests 6 --authorized
```

## Exit Codes and JSON Reports

| Case outcome or batch condition | `verify` exit code | CI meaning |
| --- | --- | --- |
| `NOT_DETECTED` matches the reviewed expectation for every case in a complete batch | `0` | **PASS.** The tested probes did not reproduce a Boolean differential or the configured timing pattern for their respective checks. This does not prove SQL injection is absent. |
| `INCONCLUSIVE` with reason `boolean_candidate` | `3` | **BLOCK / Review required.** A SQLi-like Boolean response differential was observed. This is a candidate signal and requires independent evidence before anyone can call it a confirmed vulnerability. |
| `INCONCLUSIVE` with reason `timing_pattern_matched` | `3` | **BLOCK / Review required.** The configured timing pattern was reproduced. This is a candidate signal and never produces a `VULNERABLE` verdict. |
| Other `INCONCLUSIVE` reasons or an incomplete batch | `3` | **BLOCK / Investigation required.** Verification was insufficient. Check the budget, rate limits, transport or HTTP status, and response stability. |
| `FAIL` | `1` | **FAIL.** A `NOT_DETECTED` result did not match the reviewed expectation. |
| `ERROR` | `2` | **ERROR.** Invalid input, configuration, execution, or output prevented a usable result. |
| Interrupted | `130` | **Interrupted.** A usable report may be absent. |

These are batch exit codes. A failed case takes precedence over inconclusive
outcomes and an incomplete batch. An inconclusive case never passes, even when
its verdict matches the expectation.

`verify` emits one [schema v1 JSON report](schemas/regression-batch-report-v1.schema.json) on stdout for results `0`, `1`, and `3`. Diagnostics go to stderr. Use `--pretty` for indentation. An error or interruption can leave stdout empty or incomplete.

This excerpt shows the summary fields of a passing report.

<!-- cli-example: verify-pass/report -->
```json
{
  "schema_version": 1,
  "report_type": "regression_batch",
  "status": "pass",
  "exit_code": 0,
  "complete": true,
  "requests_used": 6
}
```

## Integrate with GitHub Actions

- **PR loopback checks.** The PR workflow runs lint, architecture checks, and pytest before loopback E2E. The E2E uses a local fixture and verifies the batch exit and report contracts.
- **Authorized staging verification.** The staging workflow is manually dispatched from `main` using the `security-testing` environment. Configure the trusted origins and add reviewed cases under `security/cases/`.
- **Report validation and artifacts.** The staging workflow captures the CLI exit code, validates the report against it, and uploads the report only after validation. An absent or invalid report becomes workflow error `2`, including when the CLI was interrupted. Restrict artifact access because case IDs and response metadata can be sensitive.

See the [CI integration guide](docs/ci-integration.md) for setup and operational details.

## Scope, Request Budgets, and Rate Limits

Verification scope is the origin, which consists of scheme, host, and port. Redirects are disabled. The batch preflights its cases against `--max-requests` before sending traffic and shares one request budget and rate limiter across the batch. `--rps`, `--timeout`, and `--max-response-size` set trusted caps. Case settings can tighten the applicable limits.

Apply network egress controls in sensitive environments. Origin validation leaves DNS-resolved IPs and individual URL paths outside its enforcement.

## Discover Inputs for Review

Use `vintar discover` to inventory a single local OpenAPI 3.0 or 3.1 spec in JSON or YAML. The report lists operations, declared inputs, held and ignored items, and source pointers. Discovery performs no HTTP requests. It produces review data that is separate from regression case files.

### OpenAPI discovery skeletons

```bash
uv run --locked vintar discover --spec ./openapi.yaml --skeleton-output ./skeleton.json
```

The skeleton lists operations under `paths` and declared query, path, header,
cookie, and `application/json` body fields. It preserves path templates and
includes JSON Pointers into the spec. The operation ID is `null` when the spec
omits it. Every operation requires side-effect review and is non-executable.
Baseline presence is unverified because discovery reads only the spec.

### Inventory POST JSON Bodies

Use `vintar inventory-post-json` for an offline, versioned inventory of every
POST operation whose request body declares `application/json`:

```bash
uv run --locked vintar inventory-post-json \
  --spec openapi.json --output post-json-inventory.json
```

The report lists body-field JSON pointers, schema types, required status,
unsupported schema diagnostics, and resolved authentication requirements. It
records only security scheme component names and types. It never includes
example, default, enum, or const values; server and OAuth/OIDC URLs; scope
names; API-key parameter names; descriptions; extension values; credentials;
or the spec file path.

All POST bodies retain `case_generation: "unsupported"` and no inventory field
is injectable. Inventory v2 adds only unapproved candidates for fields whose
declared type is exactly `string`; it does not infer safety from the method,
path, or operation ID. The inventory is not an executable case or authorization
configuration.

Review one candidate offline with a complete baseline body, a concrete JSON
Pointer (including an explicit index for every array), the canonical body
SHA-256, and explicit operation, `no_side_effect`, and isolated-environment
confirmations:

```bash
uv run --locked vintar review-post-json \
  --spec openapi.json \
  --inventory post-json-inventory.json \
  --answers post-json-review-answers.json \
  --output post-json-review.json
```

The separate review artifact records only digests, schema provenance, the
concrete pointer, and confirmations. It never records the baseline body and
cannot execute HTTP or materialize a regression case.
In a pointer pattern, `*` denotes an array index unless its zero-based token
position is listed in `literal_star_positions`. Those positions select object
properties named `*` and stay literal in the concrete pointer.
Candidate IDs identify stable operation/field locations. A separate operation
definition digest binds side-effect approval to the complete resolved operation,
including referenced request/response schemas and path-level parameters and
servers. Changing that definition requires side-effect review again. Baseline
pointers are limited to the selected JSON media type's direct `example` or its
named `examples[*].value`, including locally referenced component examples.

Validate a report before consuming or archiving it:

```bash
uv run --locked python scripts/validate_post_json_inventory.py \
  post-json-inventory.json
```

The validator accepts historical schema v1 and current schema v2 while checking
ordering, counts, pointers, uniqueness, authentication consistency, candidate
coverage, and injectability invariants. It exits `0` for a valid report and `2`
for invalid input without echoing report content.

Run discovery with your local `openapi.json` to find stable input IDs. To reproduce this example, copy `tests/fixtures/discovery/openapi30.json` to `openapi.json`. Commit `review.toml` with the IDs a reviewer approved. Omit `--selection` to inventory inputs before review.

<!-- cli-example: discover-review/selection -->
```toml
version = 1
approved = ["input-24a9c3cf0c3d01709121ac0d09079903"]
```

<!-- cli-example: discover-review/command -->
```bash
uv run --locked vintar discover \
  --spec openapi.json --selection review.toml --output inventory.json
```

`inventory.json` contains the versioned report. Stdout contains one JSON summary and stderr carries diagnostics. Exit codes are `0` for success, `2` for invalid input or output, and `130` for interruption. Choose an output path separate from the spec and selection.

<!-- cli-example: discover-review/report -->
```json
{
  "schema_version": 1,
  "report_type": "discovery_summary",
  "operations": 3,
  "selected": 1
}
```

### Export Review Drafts

After reviewing `review.toml`, export one draft per approved input. Run from a directory that contains the spec so the draft can record a relative source path.

<!-- cli-example: discover-drafts/command -->
```bash
uv run --locked vintar discover \
  --spec openapi.json --selection review.toml --drafts-dir drafts
```

<!-- cli-example: discover-drafts/report -->
```json
{
  "report_type": "discovery_draft_summary",
  "schema_version": 1,
  "drafts": ["case-24a9c3cf0c3d01709121ac0d09079903.draft.toml"]
}
```

Drafts record declared inputs and decisions still needed. Keep them outside your verification case directory. `vintar verify` rejects them and requires reviewed Schema v1 cases. Reruns leave identical drafts in place. If a file conflicts, review it or select a new destination.

Draft export requires a filesystem that supports hard links, such as ext4, APFS, or NTFS. Choose another `--drafts-dir` if your current destination is on exFAT or FAT32.

### Record Draft Review Decisions

Save the reviewer’s decisions in `answers.json`. Each declared query parameter needs an explicit `value`, a local `pointer` to a declared example, default, or single-value enum, or `{"omit": true}` for an optional parameter. Null and compound values are rejected. Explicit pointers may include `value_sha256` to detect changed values during re-review. The digest uses compact ASCII-escaped JSON with sorted keys. Choose the expected verdict explicitly.

<!-- cli-example: draft-review/answers -->
```json
{
  "version": 1,
  "expected_verdict": "not_detected",
  "parameters": {"q": {"value": "fixture-baseline"}}
}
```

<!-- cli-example: draft-review/command -->
```bash
uv run --locked vintar review-draft \
  --spec openapi.json --draft drafts/case-24a9c3cf0c3d01709121ac0d09079903.draft.toml \
  --answers answers.json --output review.json
```

<!-- cli-example: draft-review/report -->
```json
{
  "schema_version": 1,
  "report_type": "discovery_draft_review_summary"
}
```

The offline report records evidence, omission decisions, and value digests. It contains no raw baseline values. `vintar verify` requires a separately reviewed Schema v1 TOML case. Reruns preserve identical output and refuse to replace conflicting files. The output filesystem must support hard links.

### Materialize a Reviewed Case

Create an explicit target config for the reviewed input. The target URL is the route that verification will call; it may include a proxy prefix or fixture route and is not inferred from the OpenAPI path. Origins, injection behavior, limits, security expectations, and probe selection are never guessed. Headers, cookies, and credentials are not accepted in this config.

<!-- cli-example: materialize-case/config -->
```toml
config_version = 1
input_id = "input-24a9c3cf0c3d01709121ac0d09079903"

[target]
url = "http://cli-fixture.invalid/fixture-route"
allowed_origin = "http://cli-fixture.invalid"

[injection]
location = "query"
name = "q"
occurrence = 0
mode = "append"

[probes]
selection = "explicit"
true_payload = "true-probe"
false_payload = "false-probe"

[limits]
max_requests = 6
requests_per_second = 10.0
timeout_seconds = 5.0
```

<!-- cli-example: materialize-case/command -->
```bash
uv run --locked vintar materialize-case \
  --spec openapi.json --draft drafts/case-24a9c3cf0c3d01709121ac0d09079903.draft.toml \
  --answers answers.json --review review.json --config case-config.toml \
  --output security/cases/case-24a9c3cf0c3d01709121ac0d09079903.toml
```

<!-- cli-example: materialize-case/report -->
```json
{
  "case_id": "case-24a9c3cf0c3d01709121ac0d09079903",
  "confirmation": "not configured",
  "max_requests": 6,
  "report_type": "regression_case_materialization_summary",
  "schema_version": 1
}
```

Materialization is offline. It regenerates the draft and review decisions from the current spec and answers, verifies the supplied review report including value SHA-256 digests, and validates the generated TOML with the Schema v1 loader. The case ID comes from the regenerated draft. Optional parameters answered with `{"omit": true}` are absent from `target.params`; an explicit empty string remains `value = ""`. Strings are preserved exactly, while booleans, integers, and finite floats use compact canonical JSON scalar text (`true`, `17`, or `1.25`).

The generated case contains the reviewed raw parameter values and explicit probe payloads, so treat it as sensitive review material. Rerunning with byte-identical content is a no-op. Existing conflicting output is preserved, and publishing requires a hard-link-capable filesystem.

Instead of supplying explicit payloads, a reviewer may select one reviewed Boolean probe preset:

```toml
[probes]
selection = "preset"
preset = "string-quoted"
```

The supported presets are `string-quoted` and `numeric`. Materialization expands
the selected initial pair and its reviewed second pair plus baseline-preserving
third predicate into the Schema v1 case; preset cases therefore use
`max_requests = 18`. The reviewer must explicitly choose a
preset for the downstream SQL context. An OpenAPI integer type alone cannot
establish that context.

With `selection = "explicit"`, the reviewer may either omit confirmation and use
`max_requests = 6`, or explicitly supply all three confirmation fields and use
`max_requests = 18`. Explicit payloads are never matched to or completed from a
preset.

To materialize an explicit time-based case, add `type = "sqli.time"` beside
`config_version` and use the Time probe shape:

```toml
config_version = 1
type = "sqli.time"
input_id = "input-24a9c3cf0c3d01709121ac0d09079903"

[probes]
selection = "explicit"
delay_payload = "reviewed-delay-expression"
control_payload = "reviewed-control-expression"
expected_delay_seconds = 0.5

[limits]
max_requests = 9
requests_per_second = 2.0
timeout_seconds = 2.0
```

To materialize an Error case, select the check type and supply one explicit
reviewed payload. Error presets are unavailable. The generated case ID adds the
`-error` suffix; the reviewed base ID must therefore be at most 58 characters.

```toml
config_version = 1
type = "sqli.error"
input_id = "input-24a9c3cf0c3d01709121ac0d09079903"

[probes]
selection = "explicit"
error_payload = "'"

[limits]
max_requests = 4
requests_per_second = 2.0
timeout_seconds = 5.0
```

The `[target]` and `[injection]` tables are the same explicit tables shown
above, and Time injection is query-only. Time presets are not available:
reviewers must provide both payloads explicitly. Materialization never infers a
DBMS, SQL context, or Time payload from an OpenAPI parameter type. Time limits
use the Schema v1 bounds documented in the
[Time SQLi contract](docs/sqli-time-contract.md#schema-v1-time-case).

Boolean materialization keeps the discovery draft's existing deterministic case
ID. Time materialization appends `-time` to that ID, so both check types from the
same reviewed draft can run in one batch. Materialization fails instead of
truncating if the suffixed ID would exceed the Schema v1 64-character limit.

## Other CLI Commands

- `vintar --help` lists commands, and `vintar version` prints the current project version.
- `vintar http send` inspects a GET or POST response and prints text. It accepts `--body`, `--header`, `--cookie`, repeatable `--param`, and `--timeout`. The response body limit for this command is 1 MiB.
- `vintar sqli verify` runs a single bounded Boolean check and exits `0` whenever it emits a report, including an `inconclusive` verdict. Use `verify` for a batch gate that distinguishes PASS, FAIL, and INCONCLUSIVE.

For the same authorized test fixture, a single-check invocation looks like this.

<!-- cli-example: sqli-normal/command -->
```bash
uv run --locked vintar sqli verify \
  --url https://staging.example.com/ok --allow-origin https://staging.example.com \
  --param category=Pets --inject-param category --append \
  --true-payload true-probe --false-payload false-probe \
  --authorized
```

<!-- cli-example: sqli-normal/report -->
```json
{
  "schema_version": 1,
  "check_type": "sqli_boolean",
  "verdict": "not_detected",
  "reason_code": "no_boolean_difference",
  "request_count": 6
}
```

## Current Limitations

- Non-SQL middleware can mimic a Boolean response differential. The
  `waf200_mimic` fixture demonstrates a false candidate. Vintar does not claim
  zero false candidates across environments.
- Matched live loopback evaluation covers ephemeral SQLite twins using the
  corresponding `string-quoted` and `numeric` presets. The observed candidate
  counts were **TP=2, TN=2, FP=0, FN=0** for those fixtures. PostgreSQL and MySQL
  integration tests are opt-in and do not run in default CI.
- Schema v1 uses placeholder origins. Verification binds the case to the trusted runtime origin.
- The [DSVW evaluation](docs/sqli-third-party-evaluation.md) covers two reviewed
  inputs per check type. Timing results depend on the host, and this small
  evaluation does not establish detection precision.
- The batch engine has per-request timeouts. The staging workflow supplies the job-level timeout.
- Schema validation checks the report. Case definitions still require trusted review.

## Development and Golden Tests

```bash
uv run pytest
uv run ruff check
uv run ruff format --check
uv run lint-imports
uv run python scripts/check_architecture.py
```

The CLI golden tests use deterministic fixtures. After an intentional output change, run `uv run python scripts/update_cli_goldens.py --write` and review the resulting diff. The README examples are checked against the same goldens by pytest.

On Linux x86-64, run `uv run python scripts/scan_git_history.py` from a full Git checkout to scan committed secrets. The first run downloads the pinned Gitleaks archive from GitHub. Later scans and pytest reuse the cached archive and verify its SHA-256 before each use. CI warms the same cache in the scan step before pytest. A download or verification failure fails the scan and its tests.

See the [security policy](https://github.com/natori-hrj/vintar/blob/main/SECURITY.md) to report a vulnerability privately.

## License

Vintar is licensed under the [Apache License, Version 2.0](LICENSE).
