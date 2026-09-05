"""Deterministic normalization and persistence of retained hunt evidence.

Only selected, non-empty Splunk rows are retained as evidence.  The model
never creates these records: application code normalizes source metadata,
freezes the selected snapshot, and computes an integrity hash over a
documented canonical envelope.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
import hashlib
import json
import math
from types import MappingProxyType
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    field_serializer,
    field_validator,
    model_validator,
)
from sqlalchemy import Engine, insert, select
from sqlalchemy.exc import IntegrityError

from threat_hunting.domain.common import (
    DomainModel,
    UTCDateTime,
    UnknownOrUTCDateTime,
    canonical_utc,
    ensure_utc,
    utc_now,
    validate_sha256,
)

from .schema import evidence_records


Identifier = StrictStr
SchemaVersion = Literal["1.0"]
EvidenceKindValue = Literal["raw_event", "aggregate_row"]
NonNegativeInt = Field(ge=0)


class EvidenceIntegrityError(ValueError):
    """Raised when an evidence snapshot does not match its stored hash."""


def _freeze(value: Any) -> Any:
    """Recursively copy JSON values into immutable, JSON-compatible values."""

    if isinstance(value, Mapping):
        if not all(isinstance(key, str) for key in value):
            raise ValueError("selected_result mapping keys must be strings")
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (str, bool, int)) or value is None:
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("selected_result cannot contain non-finite numbers")
        return value
    raise ValueError(f"selected_result contains unsupported value type: {type(value).__name__}")


def _json_value(value: Any) -> Any:
    """Convert immutable JSON values to ordinary values for canonical JSON."""

    if isinstance(value, Mapping):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    return value


def _normalize_source_event_ref(value: Any) -> Any:
    """Represent missing source-row references with the explicit unknown value."""

    if isinstance(value, str) and not value.strip():
        return "unknown"
    return value


class TruncationMetadata(DomainModel):
    """Bounded-result metadata retained alongside selected evidence."""

    truncated: StrictBool = False
    reason: StrictStr | Literal["unknown"] = "unknown"
    source_row_count: StrictInt | None = Field(default=None, ge=0)
    retained_row_count: StrictInt | None = Field(default=None, ge=0)
    source_byte_count: StrictInt | None = Field(default=None, ge=0)
    retained_byte_count: StrictInt | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_counts(self) -> "TruncationMetadata":
        """Ensure retained counts cannot exceed known source counts."""

        if (
            self.source_row_count is not None
            and self.retained_row_count is not None
            and self.retained_row_count > self.source_row_count
        ):
            raise ValueError("retained_row_count cannot exceed source_row_count")
        if (
            self.source_byte_count is not None
            and self.retained_byte_count is not None
            and self.retained_byte_count > self.source_byte_count
        ):
            raise ValueError("retained_byte_count cannot exceed source_byte_count")
        if self.truncated and self.reason == "unknown":
            raise ValueError("truncated evidence requires a reason")
        return self


class EvidenceSource(DomainModel):
    """Immutable source links shared by a retained evidence snapshot."""

    source_id: Identifier
    query_id: UUID
    splunk_job_id: Identifier
    index: Identifier
    sourcetype: StrictStr | Literal["unknown"]
    event_time_utc: UnknownOrUTCDateTime
    collected_at_utc: UTCDateTime
    source_event_ref: StrictStr | Literal["unknown"]

    _normalize_source_event_ref = field_validator("source_event_ref", mode="before")(
        _normalize_source_event_ref
    )


class NormalizedEvidence(DomainModel):
    """Immutable normalized evidence selected from one completed result row."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_version: SchemaVersion = "1.0"
    evidence_id: UUID = Field(default_factory=uuid4)
    owner_id: UUID | None = None
    hunt_id: UUID
    query_id: UUID
    source_id: Identifier
    splunk_job_id: Identifier
    evidence_kind: EvidenceKindValue
    index: Identifier
    sourcetype: StrictStr | Literal["unknown"]
    event_time_utc: UnknownOrUTCDateTime
    collected_at_utc: UTCDateTime
    source_event_ref: StrictStr | Literal["unknown"]
    selected_result: Mapping[str, Any] = Field(min_length=1)
    truncation: TruncationMetadata = Field(default_factory=TruncationMetadata)
    sha256: StrictStr
    dedupe_key: StrictStr | None = None

    _normalize_source_event_ref = field_validator("source_event_ref", mode="before")(
        _normalize_source_event_ref
    )

    @field_validator("selected_result", mode="before")
    @classmethod
    def validate_selected_result(cls, value: Any) -> dict[str, Any]:
        """Copy and validate the selected result before it is frozen."""

        if not isinstance(value, Mapping) or not value:
            raise ValueError("selected_result must contain at least one field")
        frozen = _freeze(value)
        return dict(frozen)

    def model_post_init(self, __context: Any) -> None:
        """Freeze nested selected-result values after Pydantic validation."""

        object.__setattr__(self, "selected_result", _freeze(self.selected_result))

    @field_serializer("selected_result")
    def serialize_selected_result(self, value: Mapping[str, Any]) -> dict[str, Any]:
        """Serialize the immutable snapshot as ordinary JSON containers."""

        return _json_value(value)

    @model_validator(mode="after")
    def validate_hash(self) -> "NormalizedEvidence":
        """Reject a record whose hash is not the canonical envelope hash."""

        validate_sha256(self.sha256)
        expected = evidence_sha256(self)
        if self.sha256 != expected:
            raise ValueError("sha256 does not match the canonical evidence envelope")
        return self


def _timestamp_value(value: datetime | str) -> str:
    if value == "unknown":
        return "unknown"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be RFC 3339 UTC or unknown") from exc
    return canonical_utc(value)


def canonical_evidence_envelope(evidence: NormalizedEvidence | Mapping[str, Any]) -> dict[str, Any]:
    """Return the documented hash envelope for one evidence snapshot.

    The envelope includes source/query/job/index/sourcetype/event references,
    UTC collection timestamps, the selected result, and truncation metadata.
    Evidence IDs and hashes themselves are intentionally excluded so the same
    content can be verified after persistence.
    """

    if isinstance(evidence, NormalizedEvidence):
        values: Mapping[str, Any] = evidence.model_dump(mode="python")
    else:
        values = evidence

    def identifier(name: str) -> str | None:
        item = values.get(name)
        return None if item is None else str(item)

    event_time = values.get("event_time_utc", "unknown")
    collected_at = values.get("collected_at_utc")
    if collected_at is None:
        raise ValueError("collected_at_utc is required for evidence hashing")
    truncation = values.get("truncation") or TruncationMetadata().model_dump(mode="python")
    if isinstance(truncation, TruncationMetadata):
        truncation = truncation.model_dump(mode="python")
    envelope = {
        "schema_version": str(values.get("schema_version", "1.0")),
        "owner_id": identifier("owner_id"),
        "hunt_id": identifier("hunt_id"),
        "query_id": identifier("query_id"),
        "source_id": identifier("source_id"),
        "splunk_job_id": identifier("splunk_job_id"),
        "evidence_kind": identifier("evidence_kind"),
        "index": identifier("index"),
        "sourcetype": values.get("sourcetype"),
        "event_time_utc": _timestamp_value(event_time),
        "collected_at_utc": _timestamp_value(collected_at),
        "source_event_ref": _normalize_source_event_ref(values.get("source_event_ref")),
        "selected_result": _json_value(values.get("selected_result")),
        "truncation": _json_value(truncation),
    }
    return envelope


def evidence_sha256(evidence: NormalizedEvidence | Mapping[str, Any]) -> str:
    """Calculate the lowercase SHA-256 of a canonical evidence envelope."""

    encoded = json.dumps(
        canonical_evidence_envelope(evidence),
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _evidence_dedupe_key(evidence: NormalizedEvidence | Mapping[str, Any]) -> str:
    """Calculate a replay key from immutable source identity.

    Collection time remains part of :func:`evidence_sha256` so that each
    retained snapshot is integrity-bound to when it was collected.  It is not
    part of this key because a replay of the same hunt/query/job/source row
    can legitimately be collected at a different time.
    """

    if isinstance(evidence, NormalizedEvidence):
        values: Mapping[str, Any] = evidence.model_dump(mode="python")
    else:
        values = evidence

    source_event_ref = _normalize_source_event_ref(values.get("source_event_ref", "unknown"))
    identity: dict[str, Any] = {
        "schema_version": str(values.get("schema_version", "1.0")),
        "owner_id": None if values.get("owner_id") is None else str(values["owner_id"]),
        "hunt_id": None if values.get("hunt_id") is None else str(values["hunt_id"]),
        "query_id": None if values.get("query_id") is None else str(values["query_id"]),
        "source_id": None if values.get("source_id") is None else str(values["source_id"]),
        "splunk_job_id": None
        if values.get("splunk_job_id") is None
        else str(values["splunk_job_id"]),
        "evidence_kind": None
        if values.get("evidence_kind") is None
        else str(values["evidence_kind"]),
        "index": None if values.get("index") is None else str(values["index"]),
        "sourcetype": values.get("sourcetype"),
        "event_time_utc": _timestamp_value(values.get("event_time_utc", "unknown")),
        "source_event_ref": source_event_ref,
    }
    # A missing adapter-issued row reference should not collapse every row in
    # a job into one record.  The selected row is the only available stable
    # fallback in that case; its canonical JSON representation is order-safe.
    if source_event_ref == "unknown":
        identity["selected_result"] = _json_value(values.get("selected_result"))
    encoded = json.dumps(
        identity,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def verify_evidence_integrity(evidence: NormalizedEvidence | Mapping[str, Any]) -> bool:
    """Return whether the stored hash still matches the immutable envelope."""

    stored = evidence.sha256 if isinstance(evidence, NormalizedEvidence) else evidence.get("sha256")
    if not isinstance(stored, str):
        return False
    try:
        validate_sha256(stored)
    except ValueError:
        return False
    return stored == evidence_sha256(evidence)


def build_evidence(
    *,
    hunt_id: UUID,
    query_id: UUID,
    source_id: str,
    splunk_job_id: str,
    evidence_kind: EvidenceKindValue,
    index: str,
    selected_result: Mapping[str, Any],
    owner_id: UUID | None = None,
    sourcetype: str = "unknown",
    event_time_utc: datetime | str = "unknown",
    collected_at_utc: datetime | None = None,
    source_event_ref: str = "unknown",
    truncation: TruncationMetadata | Mapping[str, Any] | None = None,
    evidence_id: UUID | None = None,
) -> NormalizedEvidence:
    """Normalize a selected result and assign its deterministic integrity hash."""

    collected = ensure_utc(collected_at_utc or utc_now())
    normalized_source_event_ref = _normalize_source_event_ref(source_event_ref)
    truncation_model = (
        truncation
        if isinstance(truncation, TruncationMetadata)
        else TruncationMetadata.model_validate(truncation or {})
    )
    # Build the hash from a plain envelope before constructing the validated
    # model; NormalizedEvidence rejects any hash that does not match it.
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "owner_id": owner_id,
        "hunt_id": hunt_id,
        "query_id": query_id,
        "source_id": source_id,
        "splunk_job_id": splunk_job_id,
        "evidence_kind": evidence_kind,
        "index": index,
        "sourcetype": sourcetype,
        "event_time_utc": event_time_utc,
        "collected_at_utc": collected,
        "source_event_ref": normalized_source_event_ref,
        "selected_result": selected_result,
        "truncation": truncation_model,
    }
    digest = evidence_sha256(values)
    return NormalizedEvidence(
        evidence_id=evidence_id or uuid4(),
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        source_id=source_id,
        splunk_job_id=splunk_job_id,
        evidence_kind=evidence_kind,
        index=index,
        sourcetype=sourcetype,
        event_time_utc=event_time_utc,
        collected_at_utc=collected,
        source_event_ref=normalized_source_event_ref,
        selected_result=dict(selected_result),
        truncation=truncation_model,
        sha256=digest,
        dedupe_key=_evidence_dedupe_key(values),
    )


def _db_timestamp(value: datetime | str) -> datetime | None:
    if value == "unknown":
        return None
    return ensure_utc(value)  # type: ignore[arg-type]


class EvidenceRepository:
    """Engine-backed repository with owner-scoped, idempotent evidence writes."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def initialize(self) -> None:
        """Create service tables for isolated tests or a fresh local database."""

        evidence_records.metadata.create_all(self.engine, tables=[evidence_records])

    def save(self, evidence: NormalizedEvidence) -> NormalizedEvidence:
        """Persist evidence once and return the existing row on replay."""

        if evidence.owner_id is None:
            raise ValueError("owner_id is required before persisting evidence")
        if not verify_evidence_integrity(evidence):
            raise EvidenceIntegrityError("refusing to persist evidence with an invalid hash")
        values = {
            "evidence_id": str(evidence.evidence_id),
            "owner_id": str(evidence.owner_id),
            "hunt_id": str(evidence.hunt_id),
            "query_id": str(evidence.query_id),
            "source_id": evidence.source_id,
            "splunk_job_id": evidence.splunk_job_id,
            "evidence_kind": evidence.evidence_kind,
            "index": evidence.index,
            "sourcetype": evidence.sourcetype,
            "event_time_utc": _db_timestamp(evidence.event_time_utc),
            "collected_at_utc": ensure_utc(evidence.collected_at_utc),
            "source_event_ref": evidence.source_event_ref,
            "selected_result": _json_value(evidence.selected_result),
            "truncation": evidence.truncation.model_dump(mode="json"),
            "sha256": evidence.sha256,
            "dedupe_key": _evidence_dedupe_key(evidence),
            "created_at_utc": ensure_utc(evidence.collected_at_utc),
        }
        with self.engine.begin() as connection:
            existing = connection.execute(
                select(evidence_records).where(
                    evidence_records.c.owner_id == str(evidence.owner_id),
                    evidence_records.c.hunt_id == str(evidence.hunt_id),
                    evidence_records.c.dedupe_key == values["dedupe_key"],
                )
            ).mappings().first()
            if existing is None:
                try:
                    connection.execute(insert(evidence_records).values(values))
                except IntegrityError:
                    # A concurrent retry may have won the unique-key race.
                    existing = connection.execute(
                        select(evidence_records).where(
                            evidence_records.c.owner_id == str(evidence.owner_id),
                            evidence_records.c.hunt_id == str(evidence.hunt_id),
                            evidence_records.c.dedupe_key == values["dedupe_key"],
                        )
                    ).mappings().first()
                    if existing is None:
                        raise
            if existing is not None:
                return self._from_row(existing)
        return evidence

    def get(self, evidence_id: UUID, *, owner_id: UUID, hunt_id: UUID) -> NormalizedEvidence | None:
        """Return evidence only when both owner and hunt scope match."""

        with self.engine.connect() as connection:
            row = connection.execute(
                select(evidence_records).where(
                    evidence_records.c.evidence_id == str(evidence_id),
                    evidence_records.c.owner_id == str(owner_id),
                    evidence_records.c.hunt_id == str(hunt_id),
                )
            ).mappings().first()
        return None if row is None else self._from_row(row)

    def _from_row(self, row: Mapping[str, Any]) -> NormalizedEvidence:
        event_time: datetime | str = row["event_time_utc"] or "unknown"
        if isinstance(event_time, datetime) and event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        collected = row["collected_at_utc"]
        if isinstance(collected, datetime) and collected.tzinfo is None:
            collected = collected.replace(tzinfo=timezone.utc)
        return NormalizedEvidence(
            evidence_id=UUID(str(row["evidence_id"])),
            owner_id=UUID(str(row["owner_id"])),
            hunt_id=UUID(str(row["hunt_id"])),
            query_id=UUID(str(row["query_id"])),
            source_id=row["source_id"],
            splunk_job_id=row["splunk_job_id"],
            evidence_kind=row["evidence_kind"],
            index=row["index"],
            sourcetype=row["sourcetype"],
            event_time_utc=event_time,
            collected_at_utc=collected,
            source_event_ref=row["source_event_ref"],
            selected_result=row["selected_result"],
            truncation=row["truncation"],
            sha256=row["sha256"],
            dedupe_key=row["dedupe_key"],
        )


__all__ = [
    "EvidenceIntegrityError",
    "EvidenceRepository",
    "EvidenceSource",
    "NormalizedEvidence",
    "TruncationMetadata",
    "build_evidence",
    "canonical_evidence_envelope",
    "evidence_sha256",
    "verify_evidence_integrity",
]
