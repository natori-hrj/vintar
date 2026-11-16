
# Time-based SQLi Evidence Verification Sessions

## Purpose

This document defines immutable verification-session records
for Vintar's experimental time-based SQLi evidence system.

The model distinguishes reference integrity from actual
byte-integrity checks performed with explicitly supplied
content.

It does not verify evidence authenticity, trusted timestamps,
source identity, or Ground Truth correctness.

## Existing Layers

The evidence architecture has three stages:

```text
ProvenanceManifest
        |
        v
EvidenceBinding
        |
        v
VerificationSession
```

ProvenanceManifest declares evidence references.

EvidenceBinding validates the correspondence between
those references and EvidenceRecords.

VerificationSession records the outcome of supplied
content checks against those records.

A valid EvidenceBinding does not mean content has
been checked.

## Per-evidence States

Every bound evidence identifier has one of three
states in a verification session.

### UNCHECKED

No observation is recorded for the identifier.

Unchecked evidence must not count as matched.

### MATCHED

An observation exists with the same size and
SHA-256 digest as the bound EvidenceRecord.

This establishes consistency of the declared
observation with the expected metadata.

It does not establish authenticity.

### MISMATCHED

An observation exists, but either its byte count
or SHA-256 digest differs from the expected record.

Mismatched evidence must not count as verified.

## Session States

Sessions have one of three states.

| State | Condition |
| --- | --- |
| COMPLETE | Every bound record is MATCHED |
| INCOMPLETE | Some records are UNCHECKED and none are MISMATCHED |
| FAILED | At least one record is MISMATCHED |

FAILED takes precedence over INCOMPLETE.

A session containing both unchecked and mismatched
evidence is FAILED.

A session that has checked all records but contains
a mismatch is also FAILED.

Only COMPLETE sets is_complete to True.

## Verification Flow

Create a session from a validated EvidenceBinding.

The initial session has no observations.

For each evidence artifact:

1. Obtain its bytes through an externally controlled process.
2. Call check_evidence_in_session.
3. Supply the bound evidence ID and artifact bytes.
4. Retain the returned new VerificationSession.

The previous session remains unchanged.

A check creates an EvidenceObservation containing:

- The exact in-memory EvidenceBinding and evidence ID
- The observed SHA-256 digest
- The observed byte count

Raw evidence bytes are not retained.

## Immutable Observations

EvidenceObservation is frozen and uses slots.

Its status is derived from the recorded byte count
and digest, rather than stored as a mutable flag.

Direct construction validates the digest format, byte-count range,
exact EvidenceBinding type, and evidence-ID membership.

VerificationSession validates that every observation
uses the same in-memory EvidenceBinding instance and corresponds
to a record in its bound index.

A mismatched expected EvidenceRecord cannot be
silently attached to another binding.

The binding-instance check prevents accidental or `dataclasses.replace()`
reattachment during one Python process. It is not a durable identity,
signature, or authenticated serialization format.

## Repeated Checks

A session permits one observation per evidence ID.

Attempts to check the same ID twice are rejected.

To conduct another independent verification pass,
create another VerificationSession.

Repeated checks are not counted as independent
evidence artifacts.

## Canonicalization

Observations are stored in ascending evidence-ID order.

The add function performs canonical ordering.

Direct session construction requires canonical order
and rejects duplicates.

The number of observations cannot exceed the
maximum EvidenceIndex record count.

Unchecked evidence is derived by comparing the
index IDs against recorded observations.

The checked, matched, mismatched, and unchecked counts are derived from
the canonical observations. They satisfy:

```text
checked = matched + mismatched
evidence_count = checked + unchecked
```

## Byte-size Contract

Content verification accepts immutable bytes only.

The accepted range is:

```text
1 byte <= content size <= 16 MiB
```

Empty or oversized content raises ValueError.

Non-bytes content raises TypeError.

Invalid content cannot be converted into a
MATCHED observation.

The caller remains responsible for safe acquisition
and resource usage before passing the bytes.

## Important Trust Limitation

EvidenceObservation is a data model, not a trusted
execution attestation.

A caller could directly construct an observation
using the expected digest and size without reading
the underlying artifact.

Such an observation would appear MATCHED because
its metadata is internally consistent.

The ordinary check_evidence_in_session workflow
calculates the digest from supplied bytes.

However, a Python dataclass cannot prove that
all observations originated through that workflow.

Therefore COMPLETE means:

All bound evidence has matching recorded observations.

It does not mean:

- A trusted verifier executed the checks
- Every external artifact was actually read
- A trusted timestamp exists
- A recognized author signed the evidence
- Ground Truth has been independently established
- The evidence is factually correct

These guarantees require additional controls
outside the pure model.

## Provenance and Ground Truth

Verification does not modify:

- Cluster membership
- Application ground_truth
- Ground_truth_method
- Registration status
- Application outcomes
- Candidate sensitivity
- False-candidate rate
- Cluster-balanced metrics

A vulnerable application may produce NOT_CONFIRMED.

A non-SQL timing mimic may produce CANDIDATE.

An evidence session must not convert either
classification into a vulnerability verdict.

## Data Minimization

Session models do not store:

- Raw evidence content
- Request or response bodies
- SQLi payloads
- Authentication headers
- Cookie values
- Database credentials
- URLs

Evidence IDs and SHA-256 digests remain metadata
and must not contain secrets.

Low-entropy evidence can sometimes be guessed
from publicly available digests.

Avoid publicly distributing sensitive evidence
metadata without considering this risk.

## Security Boundaries

This module performs no:

- Filesystem access
- Network retrieval
- Signature verification
- Trusted timestamp verification
- Certificate-chain validation
- Artifact acquisition
- Execution attestation

The model trusts the explicitly supplied data
up to the validation guarantees described above.

## Error Handling

Invalid model objects and unknown evidence IDs
raise exceptions.

A valid but nonmatching byte string produces
MISMATCHED.

A missing artifact is not represented by a
fabricated empty byte string.

If an artifact cannot be obtained, leave it
UNCHECKED and record the acquisition failure
outside the session model.

## Testing

Run the session tests:

```bash
uv run pytest tests/test_sqli_time_evidence_session.py -v
```

Run existing evidence and provenance tests:

```bash
uv run pytest tests/test_sqli_time_evidence.py -v
uv run pytest tests/test_sqli_time_provenance.py -v
```

Run full regression and static checks:

```bash
uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

No Docker or external service is required for
the session unit tests.

## Release Boundary

The following remain unchanged:

- Timing Analyzer
- Time Probe Plan
- HTTP Runner
- Boolean SQLi
- Confirmation and Cross-Phase Guard
- Application evaluation
- Cluster evaluation
- Provenance declarations
- EvidenceIndex
- CLI
- Schema
- CI
- Production vulnerability Verdict

VerificationSession must never promote
CANDIDATE to Verdict.VULNERABLE.

## Future Work

Potential follow-up development includes:

- Trusted artifact acquisition boundaries
- Safe local evidence loader
- Read-only verification adapters
- Independently signed evidence manifests
- Trusted signing-key management
- Verifiable registration timestamps
- Tamper-evident verification logs
- Explicit provenance of verification execution

A trusted verification system must distinguish
internally consistent records from authenticated
verification events.
