"""Focused deterministic tests for evidence, findings, and citations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine

from threat_hunting.services.citations import CitationValidator, QueryCitationRecord
from threat_hunting.services.evidence import (
    EvidenceIntegrityError,
    EvidenceRepository,
    TruncationMetadata,
    build_evidence,
    evidence_sha256,
    verify_evidence_integrity,
)
from threat_hunting.services.findings import (
    ContextReference,
    ExtractedEntity,
    FindingDraft,
    FindingsRepository,
    Pivot,
    SynthesisContract,
)


STAMP = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _evidence(
    *,
    owner_id,
    hunt_id,
    query_id,
    selected_result=None,
    truncation=None,
    collected_at=STAMP,
    source_event_ref="event-1",
):
    return build_evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        source_id="splunk-test",
        splunk_job_id="job-1",
        evidence_kind="raw_event",
        index="main",
        sourcetype="sysmon",
        event_time_utc=STAMP,
        collected_at_utc=collected_at,
        source_event_ref=source_event_ref,
        selected_result=selected_result or {"host": "host-1", "process": "whoami"},
        truncation=truncation,
    )


def test_evidence_hash_is_order_independent_and_nested_snapshot_is_immutable() -> None:
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    first = _evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        selected_result={"b": 2, "a": {"values": [1, 2]}},
    )
    second = _evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        selected_result={"a": {"values": [1, 2]}, "b": 2},
        # Same evidence ID is not required for the hash envelope.
    )
    assert first.sha256 == second.sha256
    assert verify_evidence_integrity(first)
    with pytest.raises(TypeError):
        first.selected_result["b"] = 3
    with pytest.raises((AttributeError, TypeError)):
        first.selected_result["a"]["values"].append(3)
    with pytest.raises(TypeError):
        first.selected_result |= {"new": "value"}
    with pytest.raises(TypeError):
        dict.__setitem__(first.selected_result, "forged", True)

    tampered = first.model_dump(mode="json")
    tampered["selected_result"]["b"] = 3
    assert not verify_evidence_integrity(tampered)


def test_truncation_metadata_requires_reason_and_is_hash_bound() -> None:
    with pytest.raises(ValidationError):
        TruncationMetadata(truncated=True)
    with pytest.raises(ValidationError):
        TruncationMetadata(source_row_count=1, retained_row_count=2)
    metadata = TruncationMetadata(
        truncated=True,
        reason="row_limit",
        source_row_count=10,
        retained_row_count=2,
    )
    evidence = _evidence(owner_id=uuid4(), hunt_id=uuid4(), query_id=uuid4(), truncation=metadata)
    assert evidence_sha256(evidence) == evidence.sha256


def test_evidence_repository_is_idempotent_and_owner_scoped() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    repository = EvidenceRepository(engine)
    repository.initialize()
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    evidence = _evidence(owner_id=owner_id, hunt_id=hunt_id, query_id=query_id)
    assert repository.save(evidence).evidence_id == evidence.evidence_id
    assert repository.save(evidence).evidence_id == evidence.evidence_id
    assert repository.get(evidence.evidence_id, owner_id=owner_id, hunt_id=hunt_id) is not None
    assert repository.get(evidence.evidence_id, owner_id=uuid4(), hunt_id=hunt_id) is None
    assert repository.get(evidence.evidence_id, owner_id=owner_id, hunt_id=uuid4()) is None

    tampered = evidence.model_copy(update={"sha256": "a" * 64})
    with pytest.raises((ValidationError, EvidenceIntegrityError)):
        repository.save(tampered)


def test_evidence_replay_key_ignores_collection_time_but_hash_does_not() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    repository = EvidenceRepository(engine)
    repository.initialize()
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    first = _evidence(owner_id=owner_id, hunt_id=hunt_id, query_id=query_id)
    replay = _evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        collected_at=STAMP + timedelta(minutes=5),
    )

    assert first.dedupe_key == replay.dedupe_key
    assert first.sha256 != replay.sha256
    assert verify_evidence_integrity(first)
    assert verify_evidence_integrity(replay)
    assert repository.save(first).evidence_id == first.evidence_id
    assert repository.save(replay).evidence_id == first.evidence_id
    persisted = repository.get(first.evidence_id, owner_id=owner_id, hunt_id=hunt_id)
    assert persisted is not None
    assert persisted.sha256 == first.sha256


def test_evidence_persistence_ignores_caller_dedupe_keys() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    repository = EvidenceRepository(engine)
    repository.initialize()
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    first = _evidence(owner_id=owner_id, hunt_id=hunt_id, query_id=query_id, source_event_ref="event-1")
    second = _evidence(owner_id=owner_id, hunt_id=hunt_id, query_id=query_id, source_event_ref="event-2")
    first_with_collision = first.model_copy(update={"dedupe_key": "a" * 64})
    second_with_collision = second.model_copy(update={"dedupe_key": "a" * 64})

    assert repository.save(first_with_collision).evidence_id == first.evidence_id
    assert repository.save(second_with_collision).evidence_id == second.evidence_id
    assert repository.get(first.evidence_id, owner_id=owner_id, hunt_id=hunt_id) is not None
    assert repository.get(second.evidence_id, owner_id=owner_id, hunt_id=hunt_id) is not None


def test_blank_source_event_refs_use_unknown_row_fallback() -> None:
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    selected = {"host": "host-1", "process": "whoami"}
    blank = _evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        selected_result=selected,
        source_event_ref=" \t",
    )
    unknown = _evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        selected_result=selected,
        source_event_ref="unknown",
    )
    other_row = _evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        selected_result={"host": "host-2", "process": "whoami"},
        source_event_ref="",
    )

    assert blank.source_event_ref == "unknown"
    assert blank.dedupe_key == unknown.dedupe_key
    assert blank.sha256 == unknown.sha256
    assert blank.dedupe_key != other_row.dedupe_key


def test_entities_pivots_and_findings_persist_with_replay_safe_keys() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    repository = FindingsRepository(engine)
    repository.initialize()
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    evidence = _evidence(owner_id=owner_id, hunt_id=hunt_id, query_id=query_id)
    entity = ExtractedEntity(
        owner_id=owner_id,
        hunt_id=hunt_id,
        entity_type="host",
        value="host-1",
        evidence_ids=[evidence.evidence_id],
    )
    assert repository.save_entity(entity).entity_id == entity.entity_id
    assert repository.save_entity(entity).entity_id == entity.entity_id
    pivot = Pivot(
        owner_id=owner_id,
        hunt_id=hunt_id,
        entity_id=entity.entity_id,
        pivot_type="user",
        value="alice",
        rationale="Pivot from retained host evidence.",
        evidence_ids=[evidence.evidence_id],
    )
    assert repository.save_pivot(pivot).pivot_id == pivot.pivot_id
    finding = FindingDraft(
        owner_id=owner_id,
        hunt_id=hunt_id,
        title="Observed process",
        classification="supported_observation",
        statement="The process was observed in retained telemetry.",
        confidence="high",
        evidence_ids=[evidence.evidence_id],
        context_refs=[ContextReference(context_id=uuid4(), context_kind="advisory", provenance="runbook-1")],
        inference="unknown",
    )
    assert repository.save_finding(finding).finding_id == finding.finding_id
    assert repository.save_finding(finding).finding_id == finding.finding_id
    assert repository.get_finding(finding.finding_id, owner_id=owner_id, hunt_id=hunt_id) is not None
    assert repository.get_finding(finding.finding_id, owner_id=uuid4(), hunt_id=hunt_id) is None


def test_citations_reject_cross_owner_hunt_integrity_and_incomplete_queries() -> None:
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    evidence = _evidence(owner_id=owner_id, hunt_id=hunt_id, query_id=query_id)
    query = QueryCitationRecord(query_id=query_id, owner_id=owner_id, hunt_id=hunt_id, status="completed")
    validator = CitationValidator({evidence.evidence_id: evidence}, {query_id: query})
    positive = FindingDraft(
        owner_id=owner_id,
        hunt_id=hunt_id,
        title="Observed",
        classification="supported_observation",
        statement="Observed in telemetry.",
        confidence="medium",
        evidence_ids=[evidence.evidence_id],
    )
    assert validator.validate_finding(positive).valid
    assert not validator.validate_finding(positive, owner_id=uuid4()).valid

    negative = FindingDraft(
        owner_id=owner_id,
        hunt_id=hunt_id,
        title="Not supported",
        classification="not_supported_within_scope",
        statement="No matching activity was observed in the searched scope.",
        confidence="medium",
        query_ids=[query_id],
        limitations=["Only the approved index and time range were searched."],
    )
    assert validator.validate_finding(negative).valid
    with pytest.raises(ValidationError):
        FindingDraft(
            owner_id=owner_id,
            hunt_id=hunt_id,
            title="Wrong semantics",
            classification="not_supported_within_scope",
            statement="No activity.",
            confidence="low",
            evidence_ids=[evidence.evidence_id],
        )
    pending_query = QueryCitationRecord(query_id=uuid4(), owner_id=owner_id, hunt_id=hunt_id, status="running")
    negative_pending = negative.model_copy(update={"query_ids": [pending_query.query_id]})
    assert not CitationValidator({}, {pending_query.query_id: pending_query}).validate_finding(negative_pending).valid


@pytest.mark.parametrize("source", [None, {"status": "running"}, {"status": "completed", "outcome": "failed"}])
def test_positive_citation_requires_successful_source_query_lineage(source) -> None:
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    evidence = _evidence(owner_id=owner_id, hunt_id=hunt_id, query_id=query_id)
    finding = FindingDraft(owner_id=owner_id, hunt_id=hunt_id, title="Observed",
                           classification="supported_observation", statement="An event was retained.",
                           confidence="low", evidence_ids=[evidence.evidence_id])
    queries = {} if source is None else {query_id: {
        "query_id": query_id, "owner_id": owner_id, "hunt_id": hunt_id, **source}}
    result = CitationValidator({evidence.evidence_id: evidence}, queries).validate_finding(finding)
    assert not result.valid
    assert any(issue.startswith("query_not_") for issue in result.issues)


@pytest.mark.parametrize("coverage", [{"outcome": "failed"}, {"truncated": True}, {"partial_fetch": True}])
def test_negative_citation_requires_complete_successful_query_coverage(coverage) -> None:
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    finding = FindingDraft(owner_id=owner_id, hunt_id=hunt_id, title="Not observed",
                           classification="not_supported_within_scope", statement="No matches in the searched scope.",
                           confidence="low", query_ids=[query_id], limitations=["Approved scope only."])
    query = {"query_id": query_id, "owner_id": owner_id, "hunt_id": hunt_id, "status": "completed", **coverage}
    assert not CitationValidator({}, {query_id: query}).validate_finding(finding).valid


def test_truncated_positive_evidence_requires_a_limitation_and_context_stays_separate() -> None:
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    evidence = _evidence(
        owner_id=owner_id,
        hunt_id=hunt_id,
        query_id=query_id,
        truncation={"truncated": True, "reason": "byte_limit", "retained_row_count": 1},
    )
    finding = FindingDraft(
        owner_id=owner_id,
        hunt_id=hunt_id,
        title="Partial observation",
        classification="hunt_lead",
        statement="A lead is present in retained telemetry.",
        confidence="low",
        evidence_ids=[evidence.evidence_id],
    )
    query = QueryCitationRecord(query_id=query_id, owner_id=owner_id, hunt_id=hunt_id, status="completed", truncated=True)
    validator = CitationValidator({evidence.evidence_id: evidence}, {query_id: query})
    result = validator.validate_finding(finding)
    assert not result.valid
    assert "truncation_not_disclosed" in result.issues
    limited = finding.model_copy(update={"limitations": ["Result was truncated by byte limit."]})
    assert validator.validate_finding(limited).valid


def test_no_evidence_and_incomplete_synthesis_are_explicitly_limited() -> None:
    owner_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    query = QueryCitationRecord(query_id=query_id, owner_id=owner_id, hunt_id=hunt_id, status="completed")
    no_evidence = SynthesisContract(
        owner_id=owner_id,
        hunt_id=hunt_id,
        status="no_evidence",
        disposition="not_supported_within_scope",
        summary="No matching evidence was retained in the approved scope.",
        query_ids=[query_id],
        coverage=["main/sysmon in the approved UTC range"],
        limitations=["This does not establish absence outside the searched scope."],
    )
    assert CitationValidator({}, {query_id: query}).validate_synthesis(no_evidence).valid
    with pytest.raises(ValidationError):
        SynthesisContract(
            owner_id=owner_id,
            hunt_id=hunt_id,
            status="no_evidence",
            disposition="not_supported_within_scope",
            summary="No evidence.",
            query_ids=[query_id],
            coverage=["scope"],
            limitations=[],
        )
    with pytest.raises(ValidationError):
        SynthesisContract(
            owner_id=owner_id,
            hunt_id=hunt_id,
            status="incomplete",
            disposition="inconclusive",
            summary="The hunt stopped before all queries completed.",
        )
