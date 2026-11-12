
# Vintar GitHub Actions Integration

This document describes the initial, manually triggered Vintar
security verification workflow.

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

| Exit code | Meaning |
| --- | --- |
| 0 | PASS |
| 1 | FAIL |
| 2 | ERROR |
| 3 | INCONCLUSIVE |
| 130 | Interrupted |

Any nonzero code fails the verification job.

The report is checked against the versioned JSON Schema
and additional semantic invariants before publication.

## Artifacts

When a valid batch report exists, the workflow uploads:

`vintar-security-report`

Containing:

`vintar-report.json`

The artifact retention period is seven days.

The report does not contain raw HTTP request payloads, URLs,
or credentials. However, case IDs, response digests, sizes,
and related metadata may still disclose information.

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
- Automatic OpenAPI discovery is not implemented.
- Current SQLi analysis does not yet produce confirmed
  VULNERABLE verdicts.
- Global execution deadlines are not enforced by the engine;
  the workflow uses a job-level timeout.
- An interrupted or failed execution may produce no report.
- Report validation does not make untrusted case definitions safe.
