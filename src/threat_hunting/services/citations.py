"""Deterministic, owner-scoped citation validation.

Evidence citations prove observed activity and must resolve to an intact,
retained evidence snapshot.  Query citations prove only the completed scope
that was searched; they are not interchangeable with positive evidence.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, StrictBool, StrictStr, field_validator, model_validator

from threat_hunting.domain.common import DomainModel
from threat_hunting.domain.contracts import FindingClassification, ReportContent, StopDecision

from .evidence import NormalizedEvidence, verify_evidence_integrity
from .findings import FindingDraft, SynthesisContract


class CitationValidationError(ValueError):
    """Raised by callers that require a valid citation set."""


class QueryCitationRecord(DomainModel):
    """Minimal query ledger view needed for citation validation."""

    query_id: UUID
    owner_id: UUID
    hunt_id: UUID
    status: StrictStr
    outcome: StrictStr | None = None
    truncated: StrictBool = False
    partial_fetch: StrictBool = False

    @property
    def completed(self) -> bool:
        """Whether the query produced a completed ledger entry."""

        successful = self.outcome is None or self.outcome.lower() in {"success", "succeeded"}
        return successful and self.status.lower() in {"completed", "succeeded", "success"}


class Citation(DomainModel):
    """One explicit citation target attached to a material claim."""

    target_id: UUID
    kind: Literal["evidence", "query"]
    claim_kind: Literal["positive", "negative", "coverage"] = "positive"


class CitationValidationResult(DomainModel):
    """Stable validation result suitable for UI and audit output."""

    valid: StrictBool
    issues: list[StrictStr] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    query_ids: list[UUID] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_result(self) -> "CitationValidationResult":
        if self.valid and self.issues:
            raise ValueError("a valid citation result cannot contain issues")
        if not self.valid and not self.issues:
            raise ValueError("an invalid citation result requires issues")
        return self


QueryLookup = Mapping[UUID | str, Any] | Callable[[UUID], Any | None] | Any
EvidenceLookup = Mapping[UUID | str, Any] | Callable[[UUID], Any | None] | Any


def _lookup(source: Any, identifier: UUID) -> Any | None:
    if source is None:
        return None
    if callable(source):
        return source(identifier)
    getter = getattr(source, "get", None)
    if getter is not None:
        result = getter(identifier)
        return result if result is not None else getter(str(identifier))
    return None


def _attr(record: Any, name: str) -> Any:
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def _uuid(value: Any) -> UUID | None:
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value)) if value is not None else None
    except (TypeError, ValueError, AttributeError):
        return None


def _dedupe(values: Iterable[UUID]) -> tuple[list[UUID], list[str]]:
    seen: set[UUID] = set()
    unique: list[UUID] = []
    issues: list[str] = []
    for value in values:
        if value in seen:
            issues.append(f"duplicate_citation:{value}")
        else:
            seen.add(value)
            unique.append(value)
    return unique, issues


def _base_checks(
    *,
    evidence_ids: Sequence[UUID],
    query_ids: Sequence[UUID],
    owner_id: UUID,
    hunt_id: UUID,
    evidence_lookup: EvidenceLookup,
    query_lookup: QueryLookup,
    require_evidence: bool = False,
    require_query: bool = False,
    reject_evidence: bool = False,
    limitations: Sequence[str] = (),
) -> CitationValidationResult:
    """Validate target existence, ownership, hunt, state, and integrity."""

    issues: list[str] = []
    unique_evidence, duplicate_evidence = _dedupe(evidence_ids)
    unique_queries, duplicate_queries = _dedupe(query_ids)
    issues.extend(duplicate_evidence)
    issues.extend(duplicate_queries)
    if require_evidence and not unique_evidence:
        issues.append("evidence_required")
    if require_query and not unique_queries:
        issues.append("completed_query_required")
    if reject_evidence and unique_evidence:
        issues.append("evidence_not_allowed_for_query_grounded_claim")

    truncated_citation = False
    for evidence_id in unique_evidence:
        evidence = _lookup(evidence_lookup, evidence_id)
        if evidence is None:
            issues.append(f"evidence_not_found:{evidence_id}")
            continue
        record_owner = _uuid(_attr(evidence, "owner_id"))
        record_hunt = _uuid(_attr(evidence, "hunt_id"))
        if record_owner != owner_id:
            issues.append(f"evidence_owner_mismatch:{evidence_id}")
        if record_hunt != hunt_id:
            issues.append(f"evidence_hunt_mismatch:{evidence_id}")
        if not verify_evidence_integrity(evidence):
            issues.append(f"evidence_integrity_mismatch:{evidence_id}")
        lineage_query_id = _uuid(_attr(evidence, "query_id"))
        if lineage_query_id is None:
            issues.append(f"evidence_query_missing:{evidence_id}")
        elif lineage_query_id not in unique_queries:
            unique_queries.append(lineage_query_id)
        truncation = _attr(evidence, "truncation")
        if bool(_attr(truncation, "truncated") if truncation is not None else False):
            truncated_citation = True
    if truncated_citation and not any("trunc" in value.lower() for value in limitations):
        issues.append("truncation_not_disclosed")

    for query_id in unique_queries:
        query = _lookup(query_lookup, query_id)
        if query is None:
            issues.append(f"query_not_found:{query_id}")
            continue
        record_owner = _uuid(_attr(query, "owner_id"))
        record_hunt = _uuid(_attr(query, "hunt_id"))
        if record_owner != owner_id:
            issues.append(f"query_owner_mismatch:{query_id}")
        if record_hunt != hunt_id:
            issues.append(f"query_hunt_mismatch:{query_id}")
        status = _attr(query, "status")
        outcome = _attr(query, "outcome")
        successful = outcome is None or str(outcome).lower() in {"success", "succeeded"}
        completed = str(status).lower() in {
            "completed",
            "succeeded",
            "success",
        }
        if not completed or not successful:
            issues.append(f"query_not_completed:{query_id}")
        if require_query and (bool(_attr(query, "truncated")) or bool(_attr(query, "partial_fetch"))):
            issues.append(f"query_coverage_incomplete:{query_id}")

    # Keep issue ordering deterministic while preserving the first useful
    # diagnostic for each condition.
    issues = list(dict.fromkeys(issues))
    return CitationValidationResult(
        valid=not issues,
        issues=issues,
        evidence_ids=unique_evidence,
        query_ids=unique_queries,
    )


class CitationValidator:
    """Validate finding, stop-decision, and report citation semantics."""

    def __init__(self, evidence_lookup: EvidenceLookup, query_lookup: QueryLookup) -> None:
        self.evidence_lookup = evidence_lookup
        self.query_lookup = query_lookup

    def validate_finding(
        self,
        finding: FindingDraft | Any,
        *,
        owner_id: UUID | None = None,
        hunt_id: UUID | None = None,
    ) -> CitationValidationResult:
        """Validate positive findings against evidence and negative claims against queries."""

        owner = owner_id or _uuid(_attr(finding, "owner_id"))
        hunt = hunt_id or _uuid(_attr(finding, "hunt_id"))
        if owner is None or hunt is None:
            return CitationValidationResult(valid=False, issues=["owner_and_hunt_required"])
        classification = _attr(finding, "classification")
        classification_value = getattr(classification, "value", classification)
        result = _base_checks(
            evidence_ids=list(_attr(finding, "evidence_ids") or []),
            query_ids=list(_attr(finding, "query_ids") or []),
            owner_id=owner,
            hunt_id=hunt,
            evidence_lookup=self.evidence_lookup,
            query_lookup=self.query_lookup,
            require_evidence=classification_value in {
                FindingClassification.HUNT_LEAD.value,
                FindingClassification.SUPPORTED_OBSERVATION.value,
            },
            require_query=classification_value == FindingClassification.NOT_SUPPORTED_WITHIN_SCOPE.value,
            reject_evidence=classification_value == FindingClassification.NOT_SUPPORTED_WITHIN_SCOPE.value,
            limitations=list(_attr(finding, "limitations") or []),
        )
        context_refs = _attr(finding, "context_refs") or []
        context_ids = {_uuid(_attr(value, "context_id")) for value in context_refs}
        if None in context_ids or context_ids.intersection(set(result.evidence_ids) | set(result.query_ids)):
            result.issues.append("evidence_context_inseparable")
        if result.issues:
            return CitationValidationResult(
                valid=False,
                issues=list(dict.fromkeys(result.issues)),
                evidence_ids=result.evidence_ids,
                query_ids=result.query_ids,
            )
        return result

    def validate_stop_decision(
        self,
        decision: StopDecision | Any,
        *,
        owner_id: UUID,
        hunt_id: UUID,
    ) -> CitationValidationResult:
        """Validate the grounding rules for an agent stop decision."""

        disposition = _attr(decision, "disposition")
        disposition_value = getattr(disposition, "value", disposition)
        return _base_checks(
            evidence_ids=list(_attr(decision, "evidence_ids") or []),
            query_ids=list(_attr(decision, "query_ids") or []),
            owner_id=owner_id,
            hunt_id=hunt_id,
            evidence_lookup=self.evidence_lookup,
            query_lookup=self.query_lookup,
            require_evidence=disposition_value == "supported",
            require_query=disposition_value == "not_supported_within_scope",
            reject_evidence=disposition_value == "not_supported_within_scope",
            limitations=list(_attr(decision, "limitations") or []),
        )

    def validate_synthesis(
        self,
        synthesis: SynthesisContract,
    ) -> CitationValidationResult:
        """Validate a no-evidence or incomplete synthesis before report creation."""

        result = _base_checks(
            evidence_ids=synthesis.evidence_ids,
            query_ids=synthesis.query_ids,
            owner_id=synthesis.owner_id,
            hunt_id=synthesis.hunt_id,
            evidence_lookup=self.evidence_lookup,
            query_lookup=self.query_lookup,
            require_evidence=synthesis.disposition.value == "supported",
            require_query=synthesis.disposition.value == "not_supported_within_scope",
            reject_evidence=synthesis.status == "no_evidence",
            limitations=synthesis.limitations,
        )
        if synthesis.status == "no_evidence" and synthesis.finding_ids:
            result.issues.append("no_evidence_findings_not_allowed")
        if result.issues:
            return CitationValidationResult(
                valid=False,
                issues=list(dict.fromkeys(result.issues)),
                evidence_ids=result.evidence_ids,
                query_ids=result.query_ids,
            )
        return result

    def validate_report(
        self,
        report: ReportContent | Any,
        *,
        owner_id: UUID,
        hunt_id: UUID,
    ) -> CitationValidationResult:
        """Validate every top-level, entity, timeline, and conclusion citation."""

        evidence_ids = list(_attr(report, "evidence_ids") or [])
        query_ids = list(_attr(report, "query_ids") or [])
        conclusion = _attr(report, "conclusion")
        evidence_ids.extend(list(_attr(conclusion, "evidence_ids") or []))
        query_ids.extend(list(_attr(conclusion, "query_ids") or []))
        for entity in _attr(report, "entities") or []:
            evidence_ids.extend(list(_attr(entity, "evidence_ids") or []))
        for timeline in _attr(report, "timeline") or []:
            evidence_ids.extend(list(_attr(timeline, "evidence_ids") or []))
        disposition = _attr(report, "disposition")
        disposition_value = getattr(disposition, "value", disposition)
        return _base_checks(
            evidence_ids=evidence_ids,
            query_ids=query_ids,
            owner_id=owner_id,
            hunt_id=hunt_id,
            evidence_lookup=self.evidence_lookup,
            query_lookup=self.query_lookup,
            require_evidence=disposition_value == "supported",
            require_query=disposition_value == "not_supported_within_scope",
            reject_evidence=disposition_value == "not_supported_within_scope",
            limitations=list(_attr(report, "limitations") or []),
        )


def validate_finding_citations(
    finding: FindingDraft | Any,
    *,
    evidence_lookup: EvidenceLookup,
    query_lookup: QueryLookup,
    owner_id: UUID | None = None,
    hunt_id: UUID | None = None,
) -> CitationValidationResult:
    """Functional wrapper for deterministic finding citation validation."""

    return CitationValidator(evidence_lookup, query_lookup).validate_finding(
        finding, owner_id=owner_id, hunt_id=hunt_id
    )


__all__ = [
    "Citation",
    "CitationValidationError",
    "CitationValidationResult",
    "CitationValidator",
    "QueryCitationRecord",
    "validate_finding_citations",
]
