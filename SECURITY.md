# Security Policy

## Supported Versions

Before 1.0, only the latest minor release series receives security fixes.
Only Vintar 0.6.x receives security fixes.

## Reporting a Vulnerability

Report vulnerabilities privately through GitHub Private Vulnerability Reporting.
Open the repository's **Security** tab and select
[**Report a vulnerability**](https://github.com/natori-hrj/vintar/security/advisories/new).
Do not open a public issue for a vulnerability.

Vintar has a single maintainer. Expect an acknowledgement within seven days on
a best-effort basis.

## Scope

Report vulnerabilities in Vintar itself, such as unsafe handling of specs or
configuration, credential leakage in reports, or requests to unintended
network targets.

Findings about your own target application are outside this policy. Follow your
application's disclosure process for those findings. False `boolean_candidate`
signals are a [documented limitation](README.md#current-limitations). Open a
regular issue for those signals and remove any sensitive target details before
sharing it.

Only use Vintar to test systems you own or have explicit permission to test.

## Dependency Maintenance

The dependency audit checks locked runtime and development dependencies for
Linux and Python 3.13 on pull requests, pushes to `main`, and weekly. Dependabot
proposes weekly updates for uv dependencies and pinned GitHub Actions, grouping
minor and patch updates by ecosystem.
