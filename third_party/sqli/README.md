# Third-party SQLi measurement

This directory uses declaration version 2 for manual, local-only measurements of
independent targets. DSVW exercises SQLite and sqli-dojo-docker exercises MySQL 8.
Both are independent of Vintar and deliberately vulnerable. Never publish either
target on a public or shared interface.

The declaration pins each upstream commit, commit archive SHA-256, and reviewed
source fragments that supply the labels. The source is not vendored.
Preparation is the only step that downloads or builds dependencies; measurement
uses the recorded local image with `--pull=never` on an internal Docker network and
publishes only to an ephemeral `127.0.0.1` port.

Run from the repository root with a workspace outside the repository:

```console
uv run --locked python scripts/prepare_third_party_sqli.py --workspace /tmp/vintar-third-party-sqli
uv run --locked python scripts/run_third_party_sqli_measurement.py \
  --workspace /tmp/vintar-third-party-sqli \
  --output /tmp/vintar-third-party-sqli-report.json
```

For each target, the runner performs
`discover -> review-draft -> materialize-case -> verify` for two reviewed Boolean
inputs in six-probe and confirmation modes, two Time inputs with the fixed
nine-request plan, and two Error inputs with the fixed four-request plan. Boolean, Time, and Error
classifications are aggregated separately. It saves the JSON report before
reporting a false negative, false positive, or non-decision. Reports are local
artifacts and must not be added to the repository.

Each `[[targets]]` table owns provenance, DBMS, Compose/spec/config paths, runtime
service identity, reviewed parameter names, pinned auxiliary service images, and
fresh volume declarations. Each `[[records]]` table binds to it with `target_id`.
For every check type declared by a target, both positive and negative ground truth
are required. Auxiliary images must use `image@sha256:<digest>`; mutable tags are
rejected before preparation or measurement. Before every `compose up`, the runner
resolves `docker compose config --format json`: the app service must use the
prepared local image reference, and the exact set of all other resolved images
must match `service_images`. The resolved auxiliary service-to-image map and the
prepared app image ID are recorded in report target metadata.

sqli-dojo-docker is pinned at commit
`81f20037de323376d8a7651377e3a3971efdbae8` with archive SHA-256
`6c0218fef749fddec28560af883865eb4178ed998d5cc927a5e3592add50b88f`.
Its repository-owned build recipe pins the PHP/Apache base image, and its Compose
file pins MySQL 8 by digest. Every case gets a fresh project-scoped MySQL volume;
the readiness healthcheck uses `/index.php`, never the measured
`/lookup_person.php` endpoint.
Preparation records the repository-relative build-recipe path and SHA-256 in the
prepared state. Measurement recomputes that digest before any container starts
and refuses a stale image when the recipe has changed or its evidence is missing.

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
