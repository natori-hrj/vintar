"""Content-addressed evidence metadata for timing research.

This module performs no filesystem or network I/O. Digest matching
does not establish evidence authenticity or factual correctness.
"""

import hashlib
import hmac
from dataclasses import dataclass, field
from enum import Enum

from vintar.checks.sqli.time_provenance import ProvenanceManifest

MAX_EVIDENCE_BYTES = 16 * 1024 * 1024
MAX_EVIDENCE_RECORDS = 301
MAX_EVIDENCE_ID_LENGTH = 100


def _validate_id(value: object) -> None:
    if (
        type(value) is not str
        or not 1 <= len(value) <= MAX_EVIDENCE_ID_LENGTH
        or not all(
            char.isascii() and (char.isalnum() or char in "_-") for char in value
        )
    ):
        raise ValueError("Invalid evidence identifier.")


class EvidenceKind(str, Enum):
    REGISTRATION = "registration"
    CLUSTER_RATIONALE = "cluster_rationale"
    GROUND_TRUTH = "ground_truth"
    EVALUATION_PLAN = "evaluation_plan"


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceRecord:
    """Expected digest and metadata of an external evidence artifact."""

    evidence_id: str
    kind: EvidenceKind
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _validate_id(self.evidence_id)

        if type(self.kind) is not EvidenceKind:
            raise TypeError("Invalid evidence kind.")

        if (
            type(self.sha256) is not str
            or len(self.sha256) != 64
            or any(char not in "0123456789abcdef" for char in self.sha256)
        ):
            raise ValueError("Invalid SHA-256 digest.")

        if type(self.size_bytes) is not int:
            raise TypeError("Invalid evidence size.")

        if not 1 <= self.size_bytes <= MAX_EVIDENCE_BYTES:
            raise ValueError("Invalid evidence size.")


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceIndex:
    """An immutable, canonical collection of evidence descriptors."""

    records: tuple[EvidenceRecord, ...] = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.records) is not tuple:
            raise TypeError("Invalid evidence index records.")

        if not 1 <= len(self.records) <= MAX_EVIDENCE_RECORDS:
            raise ValueError("Invalid evidence index size.")

        if any(type(record) is not EvidenceRecord for record in self.records):
            raise TypeError("Invalid evidence index record.")

        ids = tuple(record.evidence_id for record in self.records)

        if ids != tuple(sorted(set(ids))):
            raise ValueError("Invalid evidence index ordering.")

    def get(self, evidence_id: str) -> EvidenceRecord | None:
        _validate_id(evidence_id)

        for record in self.records:
            if record.evidence_id == evidence_id:
                return record

        return None


def create_evidence_record(
    *,
    evidence_id: str,
    kind: EvidenceKind,
    content: bytes,
) -> EvidenceRecord:
    """Create expected metadata from explicitly supplied artifact bytes."""
    if type(content) is not bytes:
        raise TypeError("Evidence content must be bytes.")

    if not 1 <= len(content) <= MAX_EVIDENCE_BYTES:
        raise ValueError("Invalid evidence content size.")

    return EvidenceRecord(
        evidence_id=evidence_id,
        kind=kind,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )


def create_evidence_index(
    records: tuple[EvidenceRecord, ...],
) -> EvidenceIndex:
    """Canonicalize descriptors while rejecting duplicate identifiers."""
    if type(records) is not tuple:
        raise TypeError("Invalid evidence collection.")

    if any(type(record) is not EvidenceRecord for record in records):
        raise TypeError("Invalid evidence record.")

    return EvidenceIndex(
        records=tuple(sorted(records, key=lambda record: record.evidence_id))
    )


def verify_evidence_bytes(
    *,
    record: EvidenceRecord,
    content: bytes,
) -> bool:
    """Check bytes against the recorded size and SHA-256.

    True means byte-for-byte correspondence to the expected digest,
    not that the evidence is trusted, authentic, or factually correct.
    """
    if type(record) is not EvidenceRecord:
        raise TypeError("Invalid evidence record.")

    if type(content) is not bytes:
        raise TypeError("Evidence content must be bytes.")

    if not 1 <= len(content) <= MAX_EVIDENCE_BYTES:
        raise ValueError("Invalid evidence content size.")

    if len(content) != record.size_bytes:
        return False

    observed = hashlib.sha256(content).hexdigest()

    return hmac.compare_digest(observed, record.sha256)


def _required_references(
    manifest: ProvenanceManifest,
) -> dict[str, EvidenceKind]:
    required: dict[str, EvidenceKind] = {}

    def add(evidence_id: str, kind: EvidenceKind) -> None:
        previous = required.get(evidence_id)

        if previous is not None and previous is not kind:
            raise ValueError("Evidence identifier has conflicting roles.")

        required[evidence_id] = kind

    add(
        manifest.registration_evidence_id,
        EvidenceKind.REGISTRATION,
    )

    for cluster in manifest.clusters:
        add(
            cluster.rationale_evidence_id,
            EvidenceKind.CLUSTER_RATIONALE,
        )

    for application in manifest.applications:
        add(
            application.ground_truth_evidence_id,
            EvidenceKind.GROUND_TRUTH,
        )
        add(
            application.evaluation_plan_id,
            EvidenceKind.EVALUATION_PLAN,
        )

    return required


@dataclass(frozen=True, slots=True, repr=False)
class EvidenceBinding:
    """Exact correspondence between provenance references and evidence."""

    manifest: ProvenanceManifest = field(repr=False)
    index: EvidenceIndex = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.manifest) is not ProvenanceManifest:
            raise TypeError("Invalid provenance manifest.")

        if type(self.index) is not EvidenceIndex:
            raise TypeError("Invalid evidence index.")

        required = _required_references(self.manifest)
        actual = {record.evidence_id: record.kind for record in self.index.records}

        if required != actual:
            raise ValueError("Evidence does not match provenance references.")

    @property
    def evidence_count(self) -> int:
        return len(self.index.records)

    @property
    def application_count(self) -> int:
        return self.manifest.application_count

    @property
    def cluster_count(self) -> int:
        return self.manifest.cluster_count


def bind_evidence(
    *,
    manifest: ProvenanceManifest,
    index: EvidenceIndex,
) -> EvidenceBinding:
    """Validate complete reference coverage without reading artifacts."""
    return EvidenceBinding(manifest=manifest, index=index)
