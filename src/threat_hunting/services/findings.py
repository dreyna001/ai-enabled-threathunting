"""Persistence and contracts for entities, pivots, and finding drafts."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import ConfigDict, Field, StrictStr, field_validator, model_validator
from sqlalchemy import Engine, insert, select
from sqlalchemy.exc import IntegrityError

from threat_hunting.domain.common import DomainModel, UTCDateTime, ensure_utc, utc_now
from threat_hunting.domain.contracts import Confidence, Disposition, EntityType, FindingClassification

from .schema import entities, entity_evidence, findings, metadata, pivots


Identifier = StrictStr
SchemaVersion = Literal["1.0"]


def _unique_ids(values: list[UUID], field_name: str) -> list[UUID]:
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} cannot contain duplicate IDs")
    return values


class ContextReference(DomainModel):
    """Reference to advisory or analyst context, never direct telemetry."""

    context_id: UUID
    context_kind: Literal["advisory", "analyst_note", "discovery"]
    provenance: Identifier


class ExtractedEntity(DomainModel):
    """Entity extracted from a query result and linked to retained evidence."""

    model_config = ConfigDict(extra="forbid")

    schema_version: SchemaVersion = "1.0"
    entity_id: UUID = Field(default_factory=uuid4)
    owner_id: UUID
    hunt_id: UUID
    entity_type: EntityType
    value: Identifier = Field(min_length=1, max_length=500)
    evidence_ids: list[UUID] = Field(default_factory=list)
    result_row_refs: list[Identifier] = Field(default_factory=list)
    created_at_utc: UTCDateTime = Field(default_factory=utc_now)

    _unique_evidence = field_validator("evidence_ids")(
        lambda values: _unique_ids(values, "evidence_ids")
    )


class Pivot(DomainModel):
    """A bounded follow-up pivot grounded in evidence or a completed query."""

    model_config = ConfigDict(extra="forbid")

    schema_version: SchemaVersion = "1.0"
    pivot_id: UUID = Field(default_factory=uuid4)
    owner_id: UUID
    hunt_id: UUID
    entity_id: UUID | None = None
    pivot_type: Identifier = Field(min_length=1, max_length=64)
    value: Identifier = Field(min_length=1, max_length=500)
    rationale: Identifier = Field(min_length=1, max_length=2000)
    evidence_ids: list[UUID] = Field(default_factory=list)
    query_ids: list[UUID] = Field(default_factory=list)
    created_at_utc: UTCDateTime = Field(default_factory=utc_now)

    _unique_evidence = field_validator("evidence_ids")(
        lambda values: _unique_ids(values, "evidence_ids")
    )
    _unique_queries = field_validator("query_ids")(
        lambda values: _unique_ids(values, "query_ids")
    )

    @model_validator(mode="after")
    def validate_grounding(self) -> "Pivot":
        if not self.evidence_ids and not self.query_ids:
            raise ValueError("a pivot requires evidence_ids or query_ids")
        return self


class FindingDraft(DomainModel):
    """Structured finding draft with separate evidence, context, and inference."""

    model_config = ConfigDict(extra="forbid")

    schema_version: SchemaVersion = "1.0"
    finding_id: UUID = Field(default_factory=uuid4)
    owner_id: UUID
    hunt_id: UUID
    title: Identifier = Field(min_length=1, max_length=500)
    classification: FindingClassification
    statement: Identifier = Field(min_length=1, max_length=4000)
    confidence: Confidence
    evidence_ids: list[UUID] = Field(default_factory=list)
    query_ids: list[UUID] = Field(default_factory=list)
    context_refs: list[ContextReference] = Field(default_factory=list)
    inference: StrictStr | Literal["unknown"] = "unknown"
    limitations: list[Identifier] = Field(default_factory=list)
    created_at_utc: UTCDateTime = Field(default_factory=utc_now)
    idempotency_key: StrictStr | None = None

    _unique_evidence = field_validator("evidence_ids")(
        lambda values: _unique_ids(values, "evidence_ids")
    )
    _unique_queries = field_validator("query_ids")(
        lambda values: _unique_ids(values, "query_ids")
    )

    @model_validator(mode="after")
    def validate_grounding_and_separation(self) -> "FindingDraft":
        """Require semantic grounding and prevent context/evidence overlap."""

        if self.classification in {
            FindingClassification.HUNT_LEAD,
            FindingClassification.SUPPORTED_OBSERVATION,
        } and not self.evidence_ids:
            raise ValueError("positive findings require retained evidence_ids")
        if self.classification == FindingClassification.NOT_SUPPORTED_WITHIN_SCOPE and not self.query_ids:
            raise ValueError("not_supported_within_scope findings require query_ids")
        context_ids = {reference.context_id for reference in self.context_refs}
        if context_ids.intersection(self.evidence_ids):
            raise ValueError("direct evidence IDs cannot also be context references")
        if context_ids.intersection(self.query_ids):
            raise ValueError("query IDs cannot also be context references")
        return self

    def computed_idempotency_key(self) -> str:
        """Return a stable key for replaying the same finding draft."""

        if self.idempotency_key:
            return self.idempotency_key
        envelope = {
            "owner_id": str(self.owner_id),
            "hunt_id": str(self.hunt_id),
            "title": self.title,
            "classification": self.classification.value,
            "statement": self.statement,
            "confidence": self.confidence.value,
            "evidence_ids": sorted(str(value) for value in self.evidence_ids),
            "query_ids": sorted(str(value) for value in self.query_ids),
            "context_refs": sorted(str(value.context_id) for value in self.context_refs),
            "inference": self.inference,
            "limitations": self.limitations,
        }
        payload = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()


class SynthesisContract(DomainModel):
    """Honest synthesis result for complete, no-evidence, or incomplete hunts."""

    model_config = ConfigDict(extra="forbid")

    schema_version: SchemaVersion = "1.0"
    owner_id: UUID
    hunt_id: UUID
    status: Literal["complete", "no_evidence", "incomplete"]
    disposition: Disposition
    summary: Identifier = Field(min_length=1, max_length=4000)
    finding_ids: list[UUID] = Field(default_factory=list)
    evidence_ids: list[UUID] = Field(default_factory=list)
    query_ids: list[UUID] = Field(default_factory=list)
    coverage: list[Identifier] = Field(default_factory=list)
    limitations: list[Identifier] = Field(default_factory=list)
    context_refs: list[ContextReference] = Field(default_factory=list)
    inference: StrictStr | Literal["unknown"] = "unknown"

    _unique_evidence = field_validator("evidence_ids")(
        lambda values: _unique_ids(values, "evidence_ids")
    )
    _unique_queries = field_validator("query_ids")(
        lambda values: _unique_ids(values, "query_ids")
    )

    @model_validator(mode="after")
    def validate_honest_status(self) -> "SynthesisContract":
        if self.status == "no_evidence":
            if self.evidence_ids or self.finding_ids:
                raise ValueError("no_evidence synthesis cannot cite evidence or findings")
            if not self.query_ids:
                raise ValueError("no_evidence synthesis requires completed query_ids")
            if self.disposition != Disposition.NOT_SUPPORTED_WITHIN_SCOPE:
                raise ValueError("no_evidence synthesis must be not_supported_within_scope")
            if not self.limitations:
                raise ValueError("no_evidence synthesis requires limitations")
        if self.status == "incomplete" and not self.limitations:
            raise ValueError("incomplete synthesis requires limitations")
        if self.disposition == Disposition.SUPPORTED and not self.evidence_ids:
            raise ValueError("supported synthesis requires evidence_ids")
        if self.disposition == Disposition.NOT_SUPPORTED_WITHIN_SCOPE and not self.query_ids:
            raise ValueError("not_supported_within_scope synthesis requires query_ids")
        context_ids = {reference.context_id for reference in self.context_refs}
        if context_ids.intersection(set(self.evidence_ids) | set(self.query_ids)):
            raise ValueError("context references cannot be direct evidence or query IDs")
        return self


NoEvidenceSynthesis = SynthesisContract
IncompleteSynthesis = SynthesisContract


def _as_json_ids(values: list[UUID]) -> list[str]:
    return [str(value) for value in values]


def _as_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return ensure_utc(value)


class FindingsRepository:
    """Engine-backed persistence for entities, pivots, and finding drafts."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def initialize(self) -> None:
        """Create all evidence-grounding tables for isolated tests."""

        metadata.create_all(self.engine)

    def save_entity(self, entity: ExtractedEntity) -> ExtractedEntity:
        values = {
            "entity_id": str(entity.entity_id),
            "owner_id": str(entity.owner_id),
            "hunt_id": str(entity.hunt_id),
            "entity_type": entity.entity_type.value,
            "value": entity.value,
            "result_row_refs": list(entity.result_row_refs),
            "created_at_utc": ensure_utc(entity.created_at_utc),
        }
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(entities).where(
                    entities.c.owner_id == values["owner_id"],
                    entities.c.hunt_id == values["hunt_id"],
                    entities.c.entity_type == values["entity_type"],
                    entities.c.value == values["value"],
                )
            ).mappings().first()
            if existing is None:
                try:
                    connection.execute(insert(entities).values(values))
                except IntegrityError:
                    existing = connection.execute(
                        select(entities).where(entities.c.entity_id == values["entity_id"])
                    ).mappings().first()
                    if existing is None:
                        raise
            result = self._entity_from_row(existing) if existing is not None else entity
            for evidence_id in entity.evidence_ids:
                link = {
                    "entity_id": str(result.entity_id),
                    "evidence_id": str(evidence_id),
                    "owner_id": str(entity.owner_id),
                    "hunt_id": str(entity.hunt_id),
                }
                try:
                    connection.execute(insert(entity_evidence).values(link))
                except IntegrityError:
                    # Idempotent replay of the same entity/evidence link.
                    pass
            return result

    def save_pivot(self, pivot: Pivot) -> Pivot:
        values = {
            "pivot_id": str(pivot.pivot_id),
            "owner_id": str(pivot.owner_id),
            "hunt_id": str(pivot.hunt_id),
            "entity_id": str(pivot.entity_id) if pivot.entity_id else None,
            "pivot_type": pivot.pivot_type,
            "value": pivot.value,
            "rationale": pivot.rationale,
            "evidence_ids": _as_json_ids(pivot.evidence_ids),
            "query_ids": _as_json_ids(pivot.query_ids),
            "created_at_utc": ensure_utc(pivot.created_at_utc),
        }
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(pivots).where(
                    pivots.c.owner_id == values["owner_id"],
                    pivots.c.hunt_id == values["hunt_id"],
                    pivots.c.pivot_type == values["pivot_type"],
                    pivots.c.value == values["value"],
                )
            ).mappings().first()
            if existing is None:
                try:
                    connection.execute(insert(pivots).values(values))
                except IntegrityError:
                    existing = connection.execute(
                        select(pivots).where(pivots.c.pivot_id == values["pivot_id"])
                    ).mappings().first()
            return self._pivot_from_row(existing) if existing is not None else pivot

    def save_finding(self, finding: FindingDraft) -> FindingDraft:
        values = {
            "finding_id": str(finding.finding_id),
            "owner_id": str(finding.owner_id),
            "hunt_id": str(finding.hunt_id),
            "title": finding.title,
            "classification": finding.classification.value,
            "statement": finding.statement,
            "confidence": finding.confidence.value,
            "evidence_ids": _as_json_ids(finding.evidence_ids),
            "query_ids": _as_json_ids(finding.query_ids),
            "context_refs": [reference.model_dump(mode="json") for reference in finding.context_refs],
            "inference": finding.inference,
            "limitations": list(finding.limitations),
            "created_at_utc": ensure_utc(finding.created_at_utc),
            "idempotency_key": finding.computed_idempotency_key(),
        }
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(findings).where(
                    findings.c.owner_id == values["owner_id"],
                    findings.c.hunt_id == values["hunt_id"],
                    findings.c.idempotency_key == values["idempotency_key"],
                )
            ).mappings().first()
            if existing is None:
                try:
                    connection.execute(insert(findings).values(values))
                except IntegrityError:
                    existing = connection.execute(
                        select(findings).where(findings.c.finding_id == values["finding_id"])
                    ).mappings().first()
            return self._finding_from_row(existing) if existing is not None else finding

    def get_finding(self, finding_id: UUID, *, owner_id: UUID, hunt_id: UUID) -> FindingDraft | None:
        """Return a finding only within the authenticated owner and hunt."""

        with self.engine.connect() as connection:
            row = connection.execute(
                select(findings).where(
                    findings.c.finding_id == str(finding_id),
                    findings.c.owner_id == str(owner_id),
                    findings.c.hunt_id == str(hunt_id),
                )
            ).mappings().first()
        return None if row is None else self._finding_from_row(row)

    @staticmethod
    def _entity_from_row(row: Any) -> ExtractedEntity:
        return ExtractedEntity(
            entity_id=UUID(str(row["entity_id"])),
            owner_id=UUID(str(row["owner_id"])),
            hunt_id=UUID(str(row["hunt_id"])),
            entity_type=row["entity_type"],
            value=row["value"],
            result_row_refs=row["result_row_refs"] or [],
            created_at_utc=_as_datetime(row["created_at_utc"]),
        )

    @staticmethod
    def _pivot_from_row(row: Any) -> Pivot:
        return Pivot(
            pivot_id=UUID(str(row["pivot_id"])),
            owner_id=UUID(str(row["owner_id"])),
            hunt_id=UUID(str(row["hunt_id"])),
            entity_id=UUID(str(row["entity_id"])) if row["entity_id"] else None,
            pivot_type=row["pivot_type"],
            value=row["value"],
            rationale=row["rationale"],
            evidence_ids=[UUID(value) for value in (row["evidence_ids"] or [])],
            query_ids=[UUID(value) for value in (row["query_ids"] or [])],
            created_at_utc=_as_datetime(row["created_at_utc"]),
        )

    @staticmethod
    def _finding_from_row(row: Any) -> FindingDraft:
        contexts = [ContextReference.model_validate(value) for value in (row["context_refs"] or [])]
        return FindingDraft(
            finding_id=UUID(str(row["finding_id"])),
            owner_id=UUID(str(row["owner_id"])),
            hunt_id=UUID(str(row["hunt_id"])),
            title=row["title"],
            classification=row["classification"],
            statement=row["statement"],
            confidence=row["confidence"],
            evidence_ids=[UUID(value) for value in (row["evidence_ids"] or [])],
            query_ids=[UUID(value) for value in (row["query_ids"] or [])],
            context_refs=contexts,
            inference=row["inference"],
            limitations=row["limitations"] or [],
            created_at_utc=_as_datetime(row["created_at_utc"]),
            idempotency_key=row["idempotency_key"],
        )


__all__ = [
    "ContextReference",
    "ExtractedEntity",
    "FindingDraft",
    "FindingClassification",
    "FindingsRepository",
    "IncompleteSynthesis",
    "NoEvidenceSynthesis",
    "Pivot",
    "SynthesisContract",
]
