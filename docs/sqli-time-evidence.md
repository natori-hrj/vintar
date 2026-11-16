
# Time-based SQLi Content-addressed Evidence

## Purpose

This document specifies a research-only evidence index for
Vintar's time-based SQLi evaluation provenance.

The index records expected SHA-256 digests and lengths of
externally maintained evidence artifacts.

It supports structural binding to ProvenanceManifest.

It does not implement a trusted evidence store, digital
signatures, filesystem access, or network retrieval.

## Evidence Layers

The evidence process has three different assurance levels.

### Reference integrity

A provenance reference has exactly one matching
EvidenceRecord with the expected evidence kind.

This is checked by EvidenceBinding.

### Content integrity

An explicitly supplied byte string has the same
size and SHA-256 digest as its EvidenceRecord.

This is checked by verify_evidence_bytes.

### Authenticity and evidentiary validity

The evidence was created by an authorized source,
has not been substituted by an attacker,
and actually supports the research claim.

This is not verified by the current implementation.

## Evidence Record

Each EvidenceRecord contains:

- evidence_id
- kind
- sha256
- size_bytes

Evidence IDs are opaque strings.

They must contain only ASCII letters, digits,
underscores, and hyphens.

The maximum ID length is 100 characters.

The digest must contain exactly 64 lowercase
hexadecimal characters.

Artifacts must contain between one byte and
16 MiB of data.

Only immutable bytes are accepted by the
content verification API.

Raw evidence content is not retained.

## Evidence Kinds

The four evidence kinds are:

- REGISTRATION
- CLUSTER_RATIONALE
- GROUND_TRUTH
- EVALUATION_PLAN

Each kind corresponds to a specific reference
field in ProvenanceManifest.

An evidence identifier must not refer to
different evidence kinds simultaneously.

Multiple references of the same kind may point
to one evidence record.

That sharing does not establish evidence quality.

The same identifier cannot be reused across different kinds. For
example, a registration record cannot also serve as Ground Truth
evidence under the same ID.

## Evidence Index

EvidenceIndex contains unique records sorted
by evidence ID.

The index holds at most 301 records, matching
the current research maximum of:

- 100 applications
- 100 clusters
- Two evidence references per application
- One registration evidence reference

The practical required record count may be
smaller when references are shared.

Unexpected extra evidence records are rejected
when binding the index to a manifest.

## Provenance Binding

EvidenceBinding validates:

1. A valid ProvenanceManifest.
2. A valid EvidenceIndex.
3. All registration evidence references.
4. All cluster rationale references.
5. All application Ground Truth references.
6. All evaluation plan references.
7. Matching evidence kinds.
8. No missing or unexpected evidence records.
9. No conflicting evidence roles.

Binding does not read evidence content.

An EvidenceBinding is therefore not a claim
that the referenced content has been verified.

The current model also does not retain which artifacts were supplied to
`verify_evidence_bytes`. A separate verification-session result would be
needed to track the exact set of successfully checked records without
conflating that state with authenticity.

## SHA-256 Verification

SHA-256 is calculated over the exact bytes
supplied by the caller.

The expected digest is compared with the
computed digest after the size is checked.

A successful comparison means that the supplied
bytes correspond to the declared digest.

It does not prove that the declared digest
is authoritative.

For example, if an attacker can replace both
an evidence file and its expected digest,
the resulting comparison may still succeed.

This guarantee relies on the expected digest being obtained through an
independently trusted channel and on SHA-256 collision and second-preimage
resistance. The implementation does not establish either condition.

SHA-256 is not encryption. A digest of predictable or low-entropy
evidence can support offline guessing of its contents. Sensitive evidence
and its digest still require an appropriate disclosure policy.

## Canonicalization

The index factory sorts evidence records.

Direct EvidenceIndex construction requires
canonical ordering.

The binding factory does not silently alter
ProvenanceManifest or its application grouping.

Evidence identifiers are treated as opaque,
not as filesystem paths or HTTP URLs.

## Threat Model

The current implementation protects against
accidental mismatch between:

- Evidence references
- Evidence kinds
- Evidence records
- Evidence bytes and expected digests

It does not protect against:

- Malicious replacement of the whole index
- Forged research claims
- Incorrect Ground Truth
- False pre-registration claims
- Collusion among evidence publishers
- Untrusted evidence repositories
- Missing external source authentication
- Unreported shared application dependencies

A hash is an integrity mechanism, not a
complete trust or provenance mechanism.

## Registration Records

PRE_REGISTERED remains a declaration within
the existing ProvenanceManifest.

An evidence record with kind REGISTRATION
may identify bytes representing that claim.

SHA-256 verification does not establish when
those bytes were originally created.

Cryptographically verifiable pre-registration
requires an independently trusted timestamp
or publication process.

Those functions are outside the present scope.

## Ground Truth

The Ground Truth label is supplied by the
existing ApplicationProvenance record.

An EvidenceRecord can bind to its external
Ground Truth evidence.

This does not make the evidence automatically
accurate or independently reviewed.

A vulnerable application may still produce
NOT_CONFIRMED.

A non-SQL application may still produce
CANDIDATE.

The evidence index does not change these
classification contracts.

## Data Minimization

The evidence model does not retain:

- Raw HTTP requests
- Raw response bodies
- SQLi payloads
- Cookies
- Authorization headers
- Database credentials
- Evidence byte arrays

Evidence IDs must not contain secrets.

Exception messages must not include invalid
identifier contents.

SHA-256 digests and byte counts are metadata.
Sensitive evidence should still be stored in
a separately access-controlled repository.

## Filesystem Boundary

File reading and writing are not implemented.

The caller must explicitly supply bytes for
hash creation and verification.

A future evidence loader should independently
enforce:

- Allowed local file roots
- File size limits before allocation
- No arbitrary path traversal
- No unintended symlink following
- Regular-file checks
- No network fetching
- Clear error behavior for changed files

A future signature verifier should also be
separate from the pure evidence model.

## Tests

Run evidence tests:

```bash
uv run pytest tests/test_sqli_time_evidence.py -v
```

Run existing provenance tests:

```bash
uv run pytest tests/test_sqli_time_provenance.py -v
uv run pytest tests/test_sqli_time_cluster_quality.py -v
uv run pytest tests/test_sqli_time_application_quality.py -v
```

Run full regression and static checks:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

The evidence model does not require Docker.

## Limitations

The current implementation does not provide:

- Persistent evidence storage
- Content-addressed filesystem objects
- Digitally signed manifests
- Trusted public-key management
- Trusted timestamps
- Immutable registration records
- Source repository verification
- Automatic evidence authenticity checks
- Proof of application independence
- Production SQLi detection guarantees

The index is an evidence metadata and byte
integrity baseline, not a trusted evidence
repository.

## Release Boundary

No changes are made to:

- Time Plan
- Timing Analyzer
- HTTP Runner
- Boolean SQLi
- Confirmation and Cross-Phase Guard
- Cluster quality metrics
- CLI
- Schema
- CI security gates
- Production vulnerability Verdict

Content integrity must not promote
CANDIDATE to Verdict.VULNERABLE.

## Future Research

The next implementation may introduce a
separately reviewed local evidence loader.

After that, a signed manifest and trusted
timestamp verification design can be evaluated.

Neither feature should be added to the
pure research aggregation models.
