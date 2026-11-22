# Third-party SQLi measurement

This directory uses declaration version 2 for manual, local-only measurements of
independent targets. DSVW is currently the only declared target. DSVW is
independent of Vintar and deliberately vulnerable. Never publish it on a public or
shared interface.

The declaration pins upstream commit
`9ca3c9acf3defa0a6148d40e5f5cebeb5dcbb908`, the commit archive SHA-256, and the
reviewed source fragments that supply the labels. The source is not vendored.
Preparation is the only step that downloads or builds dependencies; measurement
uses the recorded local image with `--pull=never` on an internal Docker network and
publishes only to an ephemeral `127.0.0.1` port.

Run from the repository root with a workspace outside the repository:

```console
uv run --locked python scripts/prepare_third_party_sqli.py --workspace /tmp/vintar-dsvw
uv run --locked python scripts/run_third_party_sqli_measurement.py \
  --workspace /tmp/vintar-dsvw \
  --output /tmp/vintar-dsvw-report.json
```

The runner performs `discover -> review-draft -> materialize-case -> verify` for
the two reviewed Boolean inputs in six-probe and confirmation modes, and for the
two reviewed Time inputs with the fixed nine-request plan, and the two reviewed
Error inputs with the fixed four-request plan. Boolean, Time, and Error
classifications are aggregated separately. It saves the JSON report before
reporting a false negative, false positive, or non-decision. Reports are local
artifacts and must not be added to the repository.

Each `[[targets]]` table owns provenance, DBMS, Compose/spec/config paths, runtime
service identity, reviewed parameter names, pinned auxiliary service images, and
fresh volume declarations. Each `[[records]]` table binds to it with `target_id`.
For every check type declared by a target, both positive and negative ground truth
are required. Auxiliary images must use `image@sha256:<digest>`; mutable tags are
rejected before preparation or measurement.

The saved manual measurement artifact uses schema version 4. `targets` is keyed
by target id, records carry `target_id`, and counts contain both `overall` and
`by_target` trees. The runner and documentation drift check reject older or
mixed-shape reports. Regenerate version 1, 2, or 3 artifacts rather than attempting
an in-place conversion. Error candidates remain `candidate`, never `tp` or
`vulnerable`.

Docker absence, an unavailable loopback binding, a changed archive, a changed local
image, source-evidence drift, startup failure, or documentation drift produces an
actionable error. The runner does not skip, retry, pull an image, or contact a remote
target.
