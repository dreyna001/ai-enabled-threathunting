"""Application services for evidence-grounded hunt outputs.

The services in this package keep deterministic evidence handling separate
from model prompts, report rendering, and transport adapters.
"""

from .evidence import (
    EvidenceRepository,
    EvidenceSource,
    NormalizedEvidence,
    TruncationMetadata,
    build_evidence,
    canonical_evidence_envelope,
    evidence_sha256,
    verify_evidence_integrity,
)
from .findings import (
    ContextReference,
    ExtractedEntity,
    FindingDraft,
    FindingsRepository,
    IncompleteSynthesis,
    NoEvidenceSynthesis,
    Pivot,
    SynthesisContract,
)
from .citations import (
    Citation,
    CitationValidationError,
    CitationValidationResult,
    CitationValidator,
    QueryCitationRecord,
    validate_finding_citations,
)

__all__ = [
    "EvidenceRepository",
    "EvidenceSource",
    "Citation",
    "CitationValidationError",
    "CitationValidationResult",
    "CitationValidator",
    "ContextReference",
    "ExtractedEntity",
    "FindingDraft",
    "FindingsRepository",
    "IncompleteSynthesis",
    "NoEvidenceSynthesis",
    "NormalizedEvidence",
    "Pivot",
    "QueryCitationRecord",
    "SynthesisContract",
    "TruncationMetadata",
    "build_evidence",
    "canonical_evidence_envelope",
    "evidence_sha256",
    "validate_finding_citations",
    "verify_evidence_integrity",
]
