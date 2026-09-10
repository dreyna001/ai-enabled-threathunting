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
from threat_hunting.domain.spl_policy import parse_spl, source_pairs
from threat_hunting.domain.errors import Validation

from .schema import evidence_records


Identifier = StrictStr
SchemaVersion = Literal["1.0"]
EvidenceKindValue = Literal["raw_event", "aggregate_row"]
NonNegativeInt = Field(ge=0)


def query_results_incomplete(query: Mapping[str, Any]) -> bool:
    """Identify failed or incomplete retrieval in an already scoped query ledger.

    Older completed-query contexts omitted status/outcome flags. Preserve that
    representation while rejecting explicit failure or missing result coverage.
    This check does not prove that a query or its interpretation is correct.
    """
    retained, available = query.get("result_count"), query.get("available_result_count")
    return (
        query.get("status", "completed") != "completed"
        or query.get("outcome") not in {None, "success", "succeeded"}
        or bool(query.get("truncated")) or bool(query.get("partial_fetch"))
        or type(retained) is int and type(available) is int and available > retained
    )


def result_source(row: Mapping[str, Any], pairs: frozenset[tuple[str, str]]) -> tuple[str, str]:
    """Resolve projected source fields only when they identify one possible pair.

    A single-source search also establishes omitted source fields. Ambiguous,
    conflicting multivalue or contradictory projections remain unknown.
    Repeated identical values still identify one source, not several events.
    """
    candidates = [pair for pair in pairs if all(
        field not in row or row[field] == value
        or isinstance(row[field], (list, tuple)) and bool(row[field]) and all(item == value for item in row[field])
        for field, value in zip(("index", "sourcetype"), pair)
    )]
    return candidates[0] if len(candidates) == 1 else ("unknown", "unknown")


def query_source_coverage(
    results: Mapping[str, Any], *, supplied_evidence: Sequence[Mapping[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Measure identified retained sources and outstanding bounded source checks.

    Counts describe selected rows, never source event totals or answered hunt
    questions. Historical top-level evidence labels are not trusted: older
    executions incorrectly copied the first proposal source onto every row.
    """
    ledger = [item for item in results.get("query_ledger", []) if isinstance(item, Mapping)]
    proposals = {str(item.get("query_id")): item.get("proposal", {}) for item in ledger}
    queries = [item for item in results.get("queries", []) if isinstance(item, Mapping) and item.get("status") == "completed"]
    completed = {str(item.get("query_id")): item for item in queries}
    evidence = [item for item in results.get("evidence", []) if isinstance(item, Mapping)]
    coverage = []
    for query in queries:
        query_id = str(query.get("query_id"))
        proposal = proposals.get(query_id, {})
        spl = str(query.get("spl", proposal.get("spl", "")))
        try:
            pairs = source_pairs(spl)
            raw_query = not parse_spl(spl).aggregates_events
        except ValueError:
            pairs, raw_query = frozenset(), False
        mode = query.get("result_mode", proposal.get("result_mode"))
        rows = [item for item in evidence if str(item.get("query_id")) == query_id]
        identified = [result_source(item.get("selected_result", {}), pairs) for item in rows]
        supplied = None if supplied_evidence is None else [
            result_source(item.get("selected_result", {}), pairs)
            for item in supplied_evidence if str(item.get("query_id")) == query_id
        ]
        sources = []
        for pair in sorted(pairs):
            checks = [item for item in ledger if item.get("phase") == "source_coverage"
                      and str(item.get("source_query_id")) == query_id and item.get("source_pair") == list(pair)]
            completed_check = next((item for item in checks if str(item.get("query_id")) in completed), None)
            check = completed_check or (checks[0] if checks else None)
            count = identified.count(pair)
            missing = bool(query.get("truncated")) and raw_query and len(pairs) > 1 and count == 0
            sources.append({
                "index": pair[0], "sourcetype": pair[1], "identified_retained_count": count,
                **({"supplied_count": supplied.count(pair)} if supplied is not None else {}),
                "missing_from_truncated_result": missing,
                "coverage_query_id": str(check["query_id"]) if check else None,
                "coverage_query_completed": completed_check is not None,
                "needs_source_check": missing and completed_check is None,
            })
        coverage.append({
            "query_id": query_id, "question_id": query.get("question_id"), "result_mode": mode,
            "query_truncated": query.get("truncated"), "source_scope_known": bool(pairs),
            "unidentified_retained_count": identified.count(("unknown", "unknown")), "sources": sources,
        })
    return coverage


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
    return NormalizedEvidence.model_validate(dict(
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
    ))


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
                return self._from_row(dict(existing))
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
        return None if row is None else self._from_row(dict(row))

    def _from_row(self, row: Mapping[str, Any]) -> NormalizedEvidence:
        event_time: datetime | str = row["event_time_utc"] or "unknown"
        if isinstance(event_time, datetime) and event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        collected = row["collected_at_utc"]
        if isinstance(collected, datetime) and collected.tzinfo is None:
            collected = collected.replace(tzinfo=timezone.utc)
        return NormalizedEvidence.model_validate(dict(
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
        ))


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


def raw_event_time(record: Mapping[str, Any]) -> datetime | None:
    """Return a retained point-event timestamp; aggregates and naive times are unknown."""
    if record.get("evidence_kind", "raw_event") != "raw_event":
        return None
    value = record.get("event_time_utc")
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00")) if isinstance(value, str) else value
        return ensure_utc(stamp) if isinstance(stamp, datetime) else None
    except (ValueError, OverflowError):
        return None


def retained_timeline(results: Mapping[str, Any]) -> list[dict[str, str]]:
    """Index every retained raw observation without changing evidence or inferring links."""
    queries = {str(query.get("query_id")): query for query in results.get("queries", [])
               if isinstance(query, Mapping)}
    observations = [(raw_event_time(record), record) for record in results.get("evidence", [])
                    if isinstance(record, Mapping) and record.get("evidence_kind", "raw_event") == "raw_event"]
    observations.sort(key=lambda item: (item[0] is None, item[0] or datetime.max.replace(tzinfo=timezone.utc)))
    timeline = []
    for stamp, record in observations:
        query_id = str(record.get("query_id", "unknown"))
        query = queries.get(query_id)
        coverage = "unknown"
        if query is not None:
            if query_results_incomplete(query):
                coverage = "incomplete"
            elif query.get("status") == "completed":
                coverage = "complete"
        timeline.append({
            "evidence_id": str(record.get("evidence_id", "unknown")),
            "query_id": query_id,
            "event_time_utc": stamp.isoformat().replace("+00:00", "Z") if stamp else "unknown",
            "query_coverage": coverage,
        })
    return timeline


def evidence_time_bounds(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    """Compute point-event bounds; samples and aggregate rows never prove continuity."""
    times: list[datetime] = []
    unknown = 0
    aggregate = 0
    for record in records:
        if record.get("evidence_kind", "raw_event") != "raw_event":
            aggregate += 1
            continue
        stamp = raw_event_time(record)
        if stamp is None:
            unknown += 1
        else:
            times.append(stamp)
    first = min(times).isoformat().replace("+00:00", "Z") if times else "unknown"
    last = max(times).isoformat().replace("+00:00", "Z") if times else "unknown"
    note = (
        f"Retained raw-event timestamps: {first} to {last} ({len(times)} record(s)). "
        if times else "Retained records do not establish raw-event time bounds. "
    )
    if unknown or aggregate:
        note += f"Excluded {unknown} record(s) with unknown time and {aggregate} aggregate row(s) from those bounds. "
    note += "Point observations do not establish continuous activity or telemetry coverage throughout the approved hunt window."
    return {
        "first_observed_utc": first, "last_observed_utc": last,
        "timestamped_record_count": len(times), "unknown_time_record_count": unknown,
        "aggregate_row_count": aggregate, "continuous_coverage_established": False,
        "limitation": note,
    }


def compact_evidence_records(
    records: Sequence[Mapping[str, Any]], queries: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Group identical raw representations while retaining every citation origin.

    Differing fields, times, or source namespaces remain separate. Unknown
    sources can be grouped only within the same query. This does not establish
    a count of unique source events and never changes persisted evidence.
    """
    pairs = {}
    for query in queries:
        try:
            pairs[str(query["query_id"])] = source_pairs(str(query.get("spl", "")))
        except ValueError:
            pairs[str(query["query_id"])] = frozenset()
    groups: dict[str, dict[str, Any]] = {}
    output: list[dict[str, Any]] = []
    for record in records:
        row = _json_value(record)
        event = row.get("selected_result", {})
        identity = next((event.get(key) for key in ("_cd", "event_id")
                         if isinstance(event.get(key), str) and event[key]), None)
        if row.get("evidence_kind", "raw_event") != "raw_event" or identity is None:
            output.append(row)
            continue
        source = result_source(event, pairs.get(str(row["query_id"]), frozenset()))
        namespace = source if source != ("unknown", "unknown") else ("query", row["query_id"])
        key = json.dumps([namespace, identity, row.get("event_time_utc"), event],
                         sort_keys=True, ensure_ascii=False)
        if key not in groups:
            groups[key] = row
            output.append(row)
        else:
            # The complete selected result is identical; retain other envelope
            # fields with the original evidence/query reference for audit.
            origin = {key: value for key, value in row.items() if key != "selected_result"}
            groups[key].setdefault("duplicate_references", []).append(origin)
    return output


def advisory_lead_groups(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Group advisory matches for review, preserving every evidence origin.

    Shared literal host/process GUID/user/session values define a review group,
    not proof of one process lifetime. Missing or multivalue identity fields
    keep records separate. No stored records or source facts are changed.
    """
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in sorted(records, key=lambda row: (
        (stamp := raw_event_time(row)) is None, stamp or datetime.max.replace(tzinfo=timezone.utc),
    )):
        comparison = row.get("advisory_ioc_comparison", {})
        if row.get("evidence_kind", "raw_event") != "raw_event" or not (
            comparison.get("matched_file_name_literals") or comparison.get("matched_domain_literals")
            or any(item.get("matches_extracted_advisory_hash") for item in comparison.get("hash_literals", []))
        ):
            continue
        event = row.get("selected_result", {})
        identity = {name: event[name] for name in ("host", "process_guid", "user", "session_id")
                    if isinstance(event.get(name), str) and event[name].strip()
                    and event[name].casefold() not in {"unknown", "null", "none"}}
        # Optional identity fields must also agree, including their absence.
        ambiguous = any(name in event and name not in identity for name in ("host", "process_guid", "user", "session_id"))
        key = tuple(identity.items()) if not ambiguous and {"host", "process_guid"}.issubset(identity) else ("record", str(row["evidence_id"]))
        group = groups.setdefault(key, {"lead_evidence_id": str(row["evidence_id"]),
                                        "identity_fields": identity, "evidence_ids": []})
        identifiers = [str(row["evidence_id"]), *(str(origin["evidence_id"]) for origin in row.get("duplicate_references", []))]
        group["evidence_ids"] = list(dict.fromkeys([*group["evidence_ids"], *identifiers]))
    return list(groups.values())


def lookup_retained_evidence(
    results: Mapping[str, Any], *, query_ids: set[str],
    filters: Mapping[str, Any] | None = None,
    earliest_utc: datetime | None = None, latest_utc: datetime | None = None,
    offset: int = 0, limit: int = 500, max_rows: int = 500,
    distinct_fields: Sequence[str] = ("host", "user", "src_ip", "dest_ip", "process_guid", "process", "session_id"),
    include_records: bool = True,
) -> dict[str, Any]:
    """Look up raw retained rows without changing search or retention metadata.

    Filters match complete typed scalar values, including members of multivalue
    fields. Counts describe the matching retained subset, never incident scope.
    The caller supplies the already owner-scoped hunt state; no external query
    or database access is performed here.
    With include_records=False, return inventory metadata without materializing
    copied/compacted record pages or claiming a representation-group count.
    """

    completed = {str(item["query_id"]): item for item in results.get("queries", [])
                 if isinstance(item, Mapping) and item.get("status") == "completed"}
    if not query_ids or not query_ids.issubset(completed):
        raise Validation("retained evidence lookup requires completed queries from this hunt")
    if any(type(value) is not int for value in (offset, limit, max_rows)) or offset < 0 or min(limit, max_rows) <= 0:
        raise Validation("retained evidence lookup requires a nonnegative offset and positive row limits")
    for bound in (earliest_utc, latest_utc):
        if bound is not None and (not isinstance(bound, datetime) or bound.tzinfo is None or bound.utcoffset() is None):
            raise Validation("retained evidence lookup time bounds must include a timezone")
    if earliest_utc is not None and latest_utc is not None and earliest_utc >= latest_utc:
        raise Validation("retained evidence lookup requires an increasing time window")
    filters = dict(filters or {})
    if any(not isinstance(field, str) or not field.strip() for field in (*filters, *distinct_fields)):
        raise Validation("retained evidence lookup field names must be nonempty strings")

    def scalar_key(value: Any) -> tuple[str, str] | None:
        if type(value) not in (str, int, float, bool) or isinstance(value, float) and not math.isfinite(value):
            return None
        return type(value).__name__, json.dumps(value, ensure_ascii=False)

    if any(scalar_key(value) is None for value in filters.values()):
        raise Validation("retained evidence lookup filters require finite scalar values")

    retained = [item for item in results.get("evidence", [])
                if isinstance(item, Mapping) and str(item.get("query_id")) in query_ids]
    observed_fields = {field for item in retained if item.get("evidence_kind", "raw_event") == "raw_event"
                       and isinstance(item.get("selected_result"), Mapping) for field in item["selected_result"]}
    unobserved_filter_fields = sorted(set(filters).difference(observed_fields))
    matching: list[tuple[datetime | None, int, Mapping[str, Any]]] = []
    unknown_time_excluded = 0
    aggregate_rows = 0
    for position, item in enumerate(retained):
        if item.get("evidence_kind", "raw_event") != "raw_event":
            aggregate_rows += 1
            continue
        event = item.get("selected_result", {})
        if not isinstance(event, Mapping):
            continue
        if any(scalar_key(value) not in {scalar_key(member) for member in (
            event[field] if isinstance(event.get(field), (list, tuple)) else [event.get(field)]
        )} for field, value in filters.items()):
            continue
        stamp = raw_event_time(item)
        if earliest_utc is not None or latest_utc is not None:
            if stamp is None:
                unknown_time_excluded += 1
                continue
            if earliest_utc is not None and stamp < earliest_utc or latest_utc is not None and stamp >= latest_utc:
                continue
        matching.append((stamp, position, item))
    matching.sort(key=lambda item: (item[0] is None, item[0] or datetime.max.replace(tzinfo=timezone.utc), item[1]))
    rows = [item[2] for item in matching]
    counts = []
    for field in dict.fromkeys(distinct_fields):
        values: set[tuple[str, str]] = set()
        single_values: set[tuple[str, str]] = set()
        missing = ambiguous = 0
        for item in rows:
            value = item["selected_result"].get(field)
            members = value if isinstance(value, (list, tuple)) else [value]
            keys = {key for member in members if (key := scalar_key(member)) is not None}
            values.update(keys)
            if not keys:
                missing += 1
            elif len(keys) == 1:
                single_values.update(keys)
            else:
                ambiguous += 1
        counts.append({"field": field, "distinct_literal_value_count": len(values),
                       "distinct_unambiguous_value_count": len(single_values),
                       "rows_with_missing_or_nonscalar_value": missing, "rows_with_multiple_distinct_values": ambiguous})
    inventory = {
        "scope": {"query_ids": sorted(query_ids), "filters": filters,
                  "earliest_utc": canonical_utc(earliest_utc) if earliest_utc else None,
                  "latest_utc": canonical_utc(latest_utc) if latest_utc else None},
        "query_coverage": [{"query_id": query_id, "result_count": completed[query_id].get("result_count"),
                            "retained_evidence_count": sum(str(item.get("query_id")) == query_id for item in retained),
                            "query_truncated": completed[query_id].get("truncated"),
                            "available_result_count": completed[query_id].get("available_result_count"),
                            "retrieval_stop_reason": completed[query_id].get("retrieval_stop_reason")}
                           for query_id in sorted(query_ids)],
        "matching_raw_record_count": len(rows),
        "aggregate_rows_excluded": aggregate_rows,
        "unobserved_filter_fields": unobserved_filter_fields,
        "unknown_time_rows_excluded_by_window": unknown_time_excluded,
        "observed_time_bounds": evidence_time_bounds(rows), "distinct_fields": counts,
        "limitation": "Counts cover matching retained raw rows and literal field values, not all source events or confirmed affected entities. Multivalue fields remain ambiguous. Repeated records do not increase distinct literal counts. Missing values and truncated searches prevent complete scope claims."
                      + (" A filter field was not observed in the retained raw records; zero matches does not establish absence in the searched source." if unobserved_filter_fields else ""),
    }
    if not include_records:
        return inventory
    effective_limit = min(limit, max_rows)
    compacted = compact_evidence_records(rows, list(completed.values()))
    page = compacted[offset:offset + effective_limit]
    next_offset = offset + len(page)
    return inventory | {
        "matching_representation_group_count": len(compacted),
        "offset": offset, "effective_limit": effective_limit,
        "next_offset": next_offset if next_offset < len(compacted) else None,
        "records": [_json_value(item) for item in page],
    }


def _flatten_scalar_values(value: Any) -> list[Any]:
    """Return scalar values from a retained result without interpreting field semantics."""

    if isinstance(value, Mapping):
        return [item for nested in value.values() for item in _flatten_scalar_values(nested)]
    if isinstance(value, list):
        return [item for nested in value for item in _flatten_scalar_values(nested)]
    if isinstance(value, str):
        # Some Splunk configurations expose the complete JSON event as a
        # single _raw string.  Parse only JSON containers so entity grounding
        # can use their exact scalar values without accepting substrings from
        # arbitrary text fields.
        try:
            parsed = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return [value]
        if isinstance(parsed, Mapping):
            return [
                value,
                *[
                    item
                    for nested in parsed.values()
                    for item in _flatten_scalar_values(nested)
                ],
            ]
        if isinstance(parsed, list):
            return [
                value,
                *[
                    item
                    for nested in parsed
                    for item in _flatten_scalar_values(nested)
                ],
            ]
    return [value] if value is not None else []
