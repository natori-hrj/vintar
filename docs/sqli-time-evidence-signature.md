
# Signed Evidence Audit Checkpoints

## Purpose

This module adds Ed25519 digital signatures to the existing
evidence audit checkpoint model.

It supports:

- Signing an AuditCheckpoint
- Versioned signed envelopes
- Deterministic envelope serialization
- Strict bounded JSON decoding
- Verification with an independently trusted public key
- Combined signature and full audit-chain verification

The module does not manage persistent keys, publish public
keys, store checkpoints, or establish checkpoint freshness.

## Dependency

The implementation uses the Python cryptography library.

The project declares:

```text
cryptography>=46.0.5,<51.0.0
```

Ed25519 cryptography is delegated to that library.

Vintar does not implement Ed25519 arithmetic itself.

## Signing model

A SignedAuditCheckpoint contains:

- version
- algorithm
- key_id
- checkpoint
- signature_hex

The supported version is integer 1.

The only supported algorithm is Ed25519.

The signature is represented as 128 lowercase hexadecimal
characters encoding a 64-byte Ed25519 signature.

The checkpoint field uses the existing AuditCheckpoint model.

## Signing payload

The signed message is:

```text
domain_separator || canonical_json(signed_fields)
```

The domain separator is the ASCII representation of:

```text
vintar.audit.checkpoint.ed25519.v1
```

followed by one NUL byte.

The signed fields are:

```json
{
  "version": 1,
  "algorithm": "Ed25519",
  "key_id": "research-key-1",
  "checkpoint": {
    "version": 1,
    "journal_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "record_count": 0,
    "head_digest": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

Canonical JSON uses:

- Sorted keys
- Compact separators
- ASCII encoding
- No NaN or Infinity
- Explicit fixed fields

The signature itself is excluded from the signed message.

This prevents circular serialization.

The algorithm and Key ID are included in the message,
so changing them invalidates the signature.

## Key identifier

Key IDs are limited to 1–64 ASCII characters.

Allowed characters are:

- ASCII letters
- Digits
- Underscore
- Hyphen

A Key ID is metadata for selecting a trusted public key.

It is not itself an authentication mechanism.

Verification must use an independently trusted public key.

Verification additionally requires the expected Key ID.

The expected Key ID and public key must be associated
through the caller's external trust configuration.

## Signing

The caller supplies an Ed25519PrivateKey instance.

Example:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

private_key = Ed25519PrivateKey.generate()

envelope = sign_audit_checkpoint(
    checkpoint=checkpoint,
    private_key=private_key,
    key_id="research-key-1",
)
```

This example generates an ephemeral key in process memory.

Production key provisioning, storage, rotation and secure
deletion are outside this module.

The signing API does not serialize or export private keys.

The caller is responsible for protecting key material.

## Signed JSON

SignedAuditCheckpoint.to_json() produces deterministic JSON.

The decoder is:

```python
envelope = signed_checkpoint_from_json(
    payload=payload,
)
```

It rejects:

- Non-string inputs
- Empty inputs
- Non-ASCII input
- Inputs exceeding 1024 ASCII bytes
- Invalid JSON
- Duplicate JSON keys, including nested objects
- Unknown envelope fields
- Missing envelope fields
- Unsupported versions
- Unsupported signature algorithms
- Invalid Key IDs
- Invalid nested checkpoints
- Incorrect signature encoding

The nested checkpoint is validated using the existing
checkpoint decoder and model invariants.

JSON validation does not verify a digital signature.

The caller must invoke the signature verification API.

## Signature verification

The caller supplies an independently trusted public key.

```python
verified_checkpoint = verify_signed_checkpoint(
    envelope=envelope,
    public_key=trusted_public_key,
    expected_key_id="research-key-1",
)
```

The verifier:

1. Validates the envelope type.
2. Validates the public-key type.
3. Validates the expected Key ID.
4. Compares the expected Key ID with the envelope.
5. Reconstructs the canonical signed message.
6. Verifies the Ed25519 signature.
7. Returns the authenticated checkpoint value.

An invalid signature raises SignedCheckpointError.

The verifier does not look up keys from a network service.

It does not trust a public key supplied inside an envelope.

The envelope does not include a public key.

## Combined signature and audit-chain verification

The combined API verifies both the signature and the chain.

```python
result = verify_signed_audit_chain(
    records=records,
    envelope=envelope,
    public_key=trusted_public_key,
    expected_key_id="research-key-1",
    expected_journal_id=trusted_journal_id,
)
```

The signature is verified first.

The existing verify_audit_checkpoint() API then verifies:

- Journal identity against the expected identifier
- Full audit-chain hash integrity
- Checkpoint position
- Head digest
- Record count

The caller can allow legitimate later records:

```python
result = verify_signed_audit_chain(
    records=current_records,
    envelope=envelope,
    public_key=trusted_public_key,
    expected_key_id="research-key-1",
    expected_journal_id=trusted_journal_id,
    allow_extensions=True,
)
```

All supplied extension records are still checked.

## Rollback detection

A valid signed checkpoint authenticates one historical
chain position under the trusted signing key.

If a checkpoint authenticates record 100:

- A 90-record chain is rejected.
- A divergent 100-record chain is rejected.
- A valid 120-record extension may be accepted.
- Corrupted extension records are rejected.

This provides rollback detection relative to the
authenticated checkpoint.

It does not prove that record 100 is the newest checkpoint.

An older, validly signed checkpoint can still be replayed.

To prevent replay of stale checkpoints, the verifier needs
an independently maintained freshness or monotonic-state
policy.

Such a policy is not implemented here.

## Trust boundaries

Ed25519 signature verification establishes that the
signed message corresponds to the supplied public key.

It does not establish:

- The real-world identity of the signer
- Whether the signer was authorized
- Whether the signing key was compromised
- Whether the checkpoint is the latest checkpoint
- Whether the event declarations are truthful
- Whether all acquisition events were recorded
- Whether the journal was durably preserved
- Whether the originating host or process is trusted
- Whether the evidence or Ground Truth is authentic

An attacker with control of the verification key selection
can substitute their own key and checkpoint.

An attacker with the private key can issue new signatures.

These are external trust-management concerns.

## Key management

The module does not provide:

- Private-key file storage
- Hardware security module integration
- Key rotation
- Revocation
- Certificate validation
- Trusted issuer registries
- Public-key distribution
- Key deletion guarantees

The caller must establish a trusted mapping between
Key ID and Ed25519 public key.

For example, the mapping may be provisioned through a
separate trusted configuration mechanism.

That mechanism is not implemented by Vintar here.

## Compatibility

No changes are made to:

- AuditCheckpoint
- AcquisitionAuditJournal
- AcquisitionResourceGovernor
- AcquisitionSupervisor
- AcquisitionRun
- VerificationSession
- Process-isolated acquisition
- SQLi Analyzer
- HTTP Runner
- Ground Truth
- CLI
- Schema
- CI
- Vulnerability Verdict

The only existing project-level change is the addition
of the cryptography runtime dependency.

The signature mechanism does not promote research
CANDIDATE findings to Verdict.VULNERABLE.

## Validation

```bash
uv lock
uv sync

uv run pytest tests/test_sqli_time_evidence_signature.py -v
uv run pytest tests/test_sqli_time_evidence_checkpoint.py -v
uv run pytest tests/test_sqli_time_evidence_audit.py -v

uv run pytest -v
uv run ruff check .
uv run ruff format --check .
git diff --check
```

## Future work

Potential extensions include:

- Independently trusted public-key registries
- Key rotation and revocation
- Signed-checkpoint publication
- Replay protection and freshness tracking
- Durable checkpoint storage
- External anchoring
- Signed checkpoint history
- Trusted timestamps
- Hardware-backed signing keys
- Incident recovery and audit continuity

The current implementation provides cryptographic
checkpoint verification, not a complete audit trust system.
