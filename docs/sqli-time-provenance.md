
# Time-based SQLi Evaluation Provenance

## Purpose

This document defines a research-only provenance manifest
for Vintar's experimental time-based SQLi evaluation.

The manifest records declared relationships between:

- Evaluation clusters
- Application implementations
- Source-code families
- Runtime families
- Shared dependencies
- Ground Truth evidence
- Evaluation registration records

It does not perform network access, file access,
or automatic vulnerability assessment.

## Evaluation Hierarchy

```text
Evaluation Manifest
  |
  +-- Cluster Benchmark
  |     |
  |     +-- Cluster
  |           |
  |           +-- Application
  |                 |
  |                 +-- Run
  |
  +-- Cluster Provenance
  |
  +-- Application Provenance
  |
  +-- Registration Declaration
```

The existing ClusterBenchmark remains the source
of evaluation results.

Provenance records must agree with the benchmark's
cluster membership and application Ground Truth.

## Cluster Provenance

Each cluster record contains:

- cluster_id
- basis
- rationale_evidence_id
- dependency_ids

The basis must be one of:

- SHARED_SOURCE
- SHARED_RUNTIME
- SHARED_HARNESS
- MULTIPLE_DEPENDENCIES

These are declared grouping rationales.

The model does not infer the correct grouping.

For the two bases that can be checked structurally, the manifest requires:

- SHARED_SOURCE: every application in the cluster declares the same
  source_family_id
- SHARED_RUNTIME: every application in the cluster declares the same
  runtime_family_id
- MULTIPLE_DEPENDENCIES: at least two dependency_ids

SHARED_HARNESS cannot be verified semantically from opaque identifiers.
Its rationale remains an external claim referenced by
rationale_evidence_id.

A rationale evidence ID identifies an external
research record but does not verify its contents.

Dependency IDs must be unique, ordered,
and validated using a restricted ASCII allowlist.

## Application Provenance

Each application record contains:

- application_id
- cluster_id
- source_family_id
- runtime_family_id
- ground_truth
- ground_truth_method
- ground_truth_evidence_id
- evaluation_plan_id

The application must exist in the supplied
ClusterBenchmark and must belong to the declared
cluster.

The Ground Truth label must match the
ApplicationUnit in that benchmark.

## Ground Truth Methods

Supported evidence categories:

### SQL_EXECUTION_TRACE

The research record claims that SQL execution
was independently instrumented.

The referenced trace must be inspected outside
this model.

### SOURCE_REVIEW

The research record claims that application
source code was reviewed.

The review must establish the relevant
SQL execution or non-execution property.

### NON_SQL_IMPLEMENTATION

The fixture is declared to contain no SQL
execution path relevant to the test.

This method is incompatible with declaring
Ground Truth as VULNERABLE.

These method names describe evidence categories.
They are not verification results.

## Evaluation Registration

A corpus can be declared:

- PRE_REGISTERED
- RETROSPECTIVE

PRE_REGISTERED means the researcher claims that
the evaluation definition existed before results
were inspected.

RETROSPECTIVE means the definition was recorded
afterward or without adequate pre-registration.

Each manifest includes a registration_evidence_id.

The current model cannot verify timestamps,
signed commits, or immutable publication records.

Consequently, is_pre_registered is a statement
about the declared status, not verified proof.

## Cross-cluster Dependency Overlap

The manifest detects declared identifiers shared
by multiple clusters.

Supported overlap categories:

- source_family
- runtime_family
- declared_dependency

Example:

```text
Cluster A:
    runtime_family_id = shared_python_runtime

Cluster B:
    runtime_family_id = shared_python_runtime
```

The result reports a runtime_family overlap
between Cluster A and Cluster B.

Overlaps are grouped by category and identifier.

Source-family and runtime-family identifiers use separate namespaces.
The same text appearing once as a source family and once as a runtime
family is not treated as an overlap unless it is shared by multiple
clusters within the same category.

The absence of reported overlaps does not prove
that the clusters are independent.

Unreported common dependencies remain unknown.

Different source-family identifiers also do not
prove that source code is unrelated.

## Validation Contract

The manifest requires:

1. Exact cluster coverage of the benchmark
2. Exact application coverage of the benchmark
3. No duplicate cluster provenance
4. No duplicate application provenance
5. Correct application-to-cluster membership
6. Matching Ground Truth
7. Valid enum values
8. Bounded identifiers
9. Canonical record ordering
10. Unique, ordered dependency identifiers

Direct construction and dataclasses.replace()
run the same structural validation.

The factory sorts input records into the
canonical order.

## Data Minimization

Provenance models store opaque identifiers,
not raw evidence contents.

Do not put sensitive information in identifiers.

The models must not store:

- URL or host credentials
- Authorization tokens
- Cookie values
- HTTP request or response bodies
- SQL injection payloads
- Database credentials
- Personal information
- Raw source-code extracts

An external, access-controlled research repository
may store detailed evidence separately.

## Fixture Guidance

Existing local SQLite and FastAPI fixtures
should be treated as sharing the relevant test
harness and operating environment.

Separate ports or separate ASGI application
instances do not make them independent products.

Record these shared characteristics explicitly
when constructing a provenance manifest.

Ground Truth must be established from the
fixture implementation or independent tracing.

Do not use the Timing Analyzer's CANDIDATE
classification as Ground Truth evidence.

## Provenance Limitations

The manifest validates structural consistency.

It does not verify:

- External evidence availability
- Authenticity of evidence files
- Git commit signatures
- Source-code equivalence
- Actual runtime dependencies
- Statistical independence
- Population representativeness
- Whether registration preceded evaluation
- Causal relationships between SQL execution
  and observed timing behavior

A researcher must investigate these separately.

## Relationship to Statistical Evaluation

Cluster-balanced estimates and
leave-one-cluster-out diagnostics remain unchanged.

Provenance metadata helps identify dependencies
that may invalidate naive independence assumptions.

It does not automatically adjust confidence
intervals or calculate effective sample sizes.

The manifest does not introduce:

- Cluster bootstrap intervals
- Hierarchical posterior distributions
- Random-effects estimation
- Statistical hypothesis testing

Those require separate research designs and
additional independent application families.

## Reproduction

Run provenance tests:

```bash
uv run pytest tests/test_sqli_time_provenance.py -v
```

Run relevant existing tests:

```bash
uv run pytest tests/test_sqli_time_cluster_quality.py -v
uv run pytest tests/test_sqli_time_application_quality.py -v
uv run pytest tests/test_sqli_time_applications_http.py -v
```

Run full regression and static validation:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The provenance module requires no Docker,
network communication, or external databases.

## Release Boundary

No changes are made to:

- Time-based Probe Plan
- Timing Analyzer
- HTTP Runner
- Application or Cluster quality metrics
- SQLi vulnerability Verdict
- CLI
- Schema
- CI security gates

A declared provenance record must never promote
CANDIDATE to Verdict.VULNERABLE.

## Future Research

Recommended improvements:

1. Content-addressed evidence references
2. Verification of immutable evidence records
3. External corpus manifests with explicit schema
4. Independent application-family acquisition
5. Source-code lineage analysis
6. Verified runtime dependency discovery
7. Pre-registered evaluation protocols
8. Cluster resampling after collecting enough
   independent application families

This is an evidence-traceability baseline,
not proof of independent application sampling.
