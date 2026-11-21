
# Vintar GitHub Actions Integration

This document describes the initial, manually triggered Vintar
security verification workflow.

## Supported Scope

Vintar supports Boolean- and time-based SQL injection regression checks for
`GET` query parameters. OpenAPI 3.0 and 3.1 discovery, draft review, and case
materialization run offline. The workflow is
`discover → review-draft → materialize-case → verify`. Reviewers explicitly
select the `string-quoted` or `numeric` probe preset for Boolean cases that use presets.
Verification runs against an authorized, configured target.

Deferred are confirmed `VULNERABLE` verdicts, error-based and UNION-based SQL
injection checks, POST form and JSON body injection, cookie and header injection,
and authenticated workflows.

## Requirements

- Python 3.13
- uv and a committed uv.lock
- At least one valid regression case under `security/cases/`
- Explicit authorization to test the target
- A trusted staging or test environment

Do not test targets you do not own or have permission to assess.

## GitHub Environment

Create an environment named `security-testing` under:

Settings → Environments → New environment

Configure:

- Deployment branches and tags: selected branches, exactly `main`
- Required reviewers where supported
- Prevent self-review where supported
- Disable administrator bypass where supported
- Restrict who can modify workflow and environment settings

Review protection availability for your repository visibility
and GitHub plan. On GitHub Free, Pro, and Team, required reviewers
are only available for public repositories. Environment protection
is not automatic, and "protected branches only" permits every
protected branch (or every branch if none is protected), so select
`main` explicitly.

Add the following Environment variables:

| Name | Example |
| --- | --- |
| VINTAR_TARGET_ORIGIN | https://staging.example.com |
| VINTAR_ALLOWED_ORIGIN | https://staging.example.com |

Both variables are required.

These values must be controlled by trusted maintainers.
Do not place API tokens, credentials, or secrets inside origins.

## Prepare reviewed cases

Use offline OpenAPI discovery to identify candidate inputs, record reviewer
decisions with `review-draft`, and produce reviewed Schema v1 TOML files with
`materialize-case`. Store the reviewed cases under `security/cases/` and run
`verify` with explicit authorization and trusted runtime origins. Restrict
access to materialized cases because they contain raw reviewed values.
See the [README workflow](../README.md#discover-inputs-for-review).

Schema v1 cases without `[probes.confirmation]` retain the six-request behavior.
Cases with the optional confirmation block reserve eighteen requests, although a
non-candidate initial result stops after six. The JSON report always states whether
confirmation was `not_configured`, `not_eligible`, `matched`, `mismatch`, or ended
for an operational reason. A matched confirmation retains the established final
reason code `boolean_candidate`; mismatch and operational reasons remain
INCONCLUSIVE and block the gate with exit code 3.

Schema v1 `sqli.time` cases use a fixed nine-request plan and require explicit
reviewed delay and control payloads. Time presets are unavailable. The operator-owned
`--time-deadline` option defaults to 45 seconds and cannot be increased by a
case. Preflight rejects a case whose per-request timeout and rate cannot fit
within that deadline before any HTTP request is sent.

## Execution

Go to:

Actions → Vintar Security Verification → Run workflow

Select the protected main branch.

GitHub allows a manual workflow to be dispatched against another
branch after the workflow exists on the default branch. Vintar rejects
such runs, but the Environment's selected-branch restriction is the
security boundary because a branch can contain a modified workflow.

The initial workflow only supports manual execution.
It does not run automatically on pull requests.

## CI status

| Case outcome or batch condition | `verify` exit code | CI meaning |
| --- | --- | --- |
| `NOT_DETECTED` matches the reviewed expectation for every case in a complete batch | `0` | **PASS.** No Boolean differential was detected under the tested probes and conditions. This does not prove SQL injection is absent. |
| `INCONCLUSIVE` with reason `boolean_candidate` | `3` | **BLOCK / Review required.** A SQLi-like Boolean response differential was observed. This is a candidate signal and requires independent evidence before anyone can call it a confirmed vulnerability. |
| `INCONCLUSIVE` with reason `timing_pattern_matched` | `3` | **BLOCK / Review required.** A bounded timing pattern was reproduced. This is a candidate signal, never a confirmed vulnerability. |
| Other `INCONCLUSIVE` reasons or an incomplete batch | `3` | **BLOCK / Investigation required.** Verification was insufficient. Check the budget, rate limits, transport or HTTP status, and response stability. |
| `FAIL` | `1` | **FAIL.** A `NOT_DETECTED` result did not match the reviewed expectation. |
| `ERROR` | `2` | **ERROR.** Invalid input, configuration, execution, or output prevented a usable result. |
| Interrupted | `130` | **Interrupted.** A usable report may be absent. |

These are batch exit codes. A failed case takes precedence over inconclusive
outcomes and an incomplete batch. An inconclusive case never passes, even when
its verdict matches the expectation.

Any nonzero code fails the verification job.

The report is checked against the versioned JSON Schema
and additional semantic invariants before publication.

## Artifacts

When a valid batch report exists, the workflow uploads:

`vintar-security-report`

Containing:

`vintar-report.json`

The artifact retention period is seven days.

The report does not contain raw HTTP request payloads, URLs, or credentials.
`sqli.time` outcomes contain no elapsed timing durations or medians: they contain
only the final verdict, reason, request count, and a sibling `timing` object with
analysis status, reason, and request count. Boolean outcomes retain their
per-observation `elapsed` values, response digests, and sizes. Case IDs and this
Boolean response metadata may still disclose information.

Access to artifacts must be restricted appropriately.
Anyone with read access to the repository can normally download its
Actions artifacts. Public-repository artifacts should be treated as
public metadata.

## Security boundaries

- VINTAR_ALLOWED_ORIGIN must not be controlled by untrusted PRs.
- Treat the checked-out `main` commit, workflow, lockfile, cases,
  schema, and validation script as one trusted release unit.
- Running untrusted code with privileged CI configuration is unsafe.
- Do not use pull_request_target to execute untrusted PR code.
- Apply branch protection and environment deployment restrictions.
- Require review for changes to `.github/workflows/`, `security/cases/`,
  `uv.lock`, `scripts/`, and the report schema, for example with CODEOWNERS.
- Apply network egress controls to prevent access to internal
  services and unapproved IP addresses.
- Current scope enforcement is origin-based, not path-based.
- The authorization flag is an attestation, not proof of consent.
- Avoid storing secrets in case files or CI logs.
- Do not run the workflow against production without an
  explicit operational security review.

GitHub-hosted runners must be able to reach the target.
Private staging services may require a separately secured,
network-isolated runner.

## First safe execution

1. Create a disposable test service that contains no production data.
2. Add one reviewed case under `security/cases/`. If that directory is
   absent or empty, the workflow intentionally exits with ERROR=2 and
   publishes no report.
3. Configure both Environment variables to the disposable service's
   exact origin.
4. Restrict the Environment to `main`, configure reviewers where the
   repository plan supports them, and protect `main`.
5. Dispatch the workflow from `main` and approve the Environment job.
6. Confirm the process result and downloaded JSON agree, then delete
   the artifact when it is no longer needed.

Before production use, exercise four fixtures against the same local or
isolated test target: a patched fixture (PASS=0), an expected mismatch
(FAIL=1), a deterministic 429 or connection failure (INCONCLUSIVE=3),
and an invalid/missing configuration (ERROR=2 with no artifact). Never
use an external target merely to test these paths.

## Current limitations

- Regression cases still use schema v1 with placeholder origins.
- Non-SQL middleware can mimic a Boolean response differential. The
  `waf200_mimic` fixture demonstrates a false candidate. Vintar does not claim
  zero false candidates across environments.
- Matched live loopback evaluation covers ephemeral SQLite twins using the
  corresponding `string-quoted` and `numeric` presets. The observed candidate
  counts were **TP=2, TN=2, FP=0, FN=0** for those fixtures. PostgreSQL and MySQL
  integration tests are opt-in and do not run in default CI.
- Time checks use a cooperative operator-owned execution deadline. Synchronous
  HTTP I/O can still overrun that deadline; retain a job-level timeout.
- An interrupted or failed execution may produce no report.
- Report validation does not make untrusted case definitions safe.
