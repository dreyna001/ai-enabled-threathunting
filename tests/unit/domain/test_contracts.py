"""Deterministic tests for canonical domain contracts."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from threat_hunting.domain.contracts import (
    Confidence,
    Disposition,
    EvidenceKind,
    EvidenceRecord,
    Finding,
    FindingClassification,
    HuntPlan,
    QueryProposal,
    QueryValidationResult,
    ResultMode,
    StopDecision,
)


def _timestamp(offset_minutes: int = 0) -> str:
    """Return a stable RFC 3339 UTC timestamp for test payloads."""

    return (datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=offset_minutes)).isoformat().replace(
        "+00:00", "Z"
    )


def _plan_payload() -> dict[str, object]:
    """Build one complete canonical hunt-plan payload."""

    return {
        "schema_version": "1.0",
        "plan_id": str(uuid4()),
        "plan_version": 1,
        "hunt_id": str(uuid4()),
        "discovery_snapshot_id": str(uuid4()),
        "execution_config_snapshot_id": str(uuid4()),
        "hypothesis": "A suspicious process may have executed on a host.",
        "objective": "Determine whether the activity is supported by telemetry.",
        "scope": {
            "earliest_utc": _timestamp(),
            "latest_utc": _timestamp(60),
            "indexes": ["main"],
            "sourcetypes": ["sysmon"],
        },
        "intelligence_refs": ["intel-1"],
        "data_sources": [{"index": "main", "sourcetypes": ["sysmon"], "purpose": "process events"}],
        "questions": [
            {
                "question_id": "q-1",
                "question": "Which hosts show the behavior?",
                "rationale": "Establish affected entities.",
                "expected_information_gain": "Identify hosts for targeted review.",
            }
        ],
        "query_strategy": ["Start with a bounded process search."],
        "coverage_limitations": ["Only the selected index is in scope."],
        "created_at_utc": _timestamp(),
    }


def test_complete_hunt_plan_validates_and_serializes_utc() -> None:
    plan = HuntPlan.model_validate(_plan_payload())

    assert plan.scope.earliest_utc.tzinfo is timezone.utc
    assert plan.model_dump(mode="json")["created_at_utc"].endswith("Z")


def test_contract_rejects_unknown_and_incomplete_fields() -> None:
    payload = _plan_payload()
    payload["unexpected"] = "reject me"
    with pytest.raises(ValidationError):
        HuntPlan.model_validate(payload)

    payload = _plan_payload()
    del payload["objective"]
    with pytest.raises(ValidationError):
        HuntPlan.model_validate(payload)


def test_contract_rejects_naive_or_reversed_utc_ranges() -> None:
    payload = _plan_payload()
    payload["scope"] = {
        "earliest_utc": "2026-01-01T00:00:00",
        "latest_utc": _timestamp(60),
        "indexes": ["main"],
        "sourcetypes": ["sysmon"],
    }
    with pytest.raises(ValidationError):
        HuntPlan.model_validate(payload)

    payload = _plan_payload()
    payload["scope"]["latest_utc"] = _timestamp(-1)  # type: ignore[index]
    with pytest.raises(ValidationError):
        HuntPlan.model_validate(payload)


def test_query_proposal_enforces_result_mode_caps() -> None:
    base = {
        "question_id": "q-1",
        "purpose": "Find representative process events.",
        "expected_information_gain": "Confirm whether execution is widespread.",
        "spl": "search index=main | head 100",
        "earliest_utc": _timestamp(),
        "latest_utc": _timestamp(5),
        "indexes": ["main"],
        "sourcetypes": ["sysmon"],
        "requested_fields": ["host", "process"],
        "result_mode": "representative",
        "max_results": 100,
    }
    assert QueryProposal.model_validate(base).result_mode is ResultMode.REPRESENTATIVE

    for mode, cap in (("aggregate", 500), ("representative", 10_000), ("targeted", 10_000)):
        base.update(result_mode=mode, max_results=cap)
        assert QueryProposal.model_validate(base).max_results == cap
        base["max_results"] = cap + 1
        with pytest.raises(ValidationError):
            QueryProposal.model_validate(base)


def test_query_schema_exposes_mode_specific_limits() -> None:
    schema = QueryProposal.model_json_schema()
    limits = {
        item["if"]["properties"]["result_mode"]["const"]:
        item["then"]["properties"]["max_results"]["maximum"]
        for item in schema["allOf"]
    }
    assert limits == {"aggregate": 500, "representative": 10_000, "targeted": 10_000}
    description = schema["properties"]["max_results"]["description"]
    for mode, cap in limits.items():
        assert f"{mode}={cap}" in description
    assert schema["additionalProperties"] is False


def test_query_validation_result_requires_consistent_execution_fields() -> None:
    base = {
        "schema_version": "1.0",
        "query_id": str(uuid4()),
        "allowed": False,
        "normalized_spl": "search index=main",
        "earliest_utc": _timestamp(),
        "latest_utc": _timestamp(1),
        "cache_key": None,
        "reason_codes": ["policy_rejected"],
        "enforced_limits": {"max_results": 100, "max_bytes": 1000, "timeout_seconds": 120},
        "query_policy_version": "2026-01",
    }
    assert QueryValidationResult.model_validate(base).allowed is False
    base["reason_codes"] = []
    with pytest.raises(ValidationError):
        QueryValidationResult.model_validate(base)


def test_evidence_and_finding_grounding_rules_are_enforced() -> None:
    evidence_id, hunt_id, query_id = uuid4(), uuid4(), uuid4()
    evidence = EvidenceRecord.model_validate(
        {
            "schema_version": "1.0",
            "evidence_id": str(evidence_id),
            "hunt_id": str(hunt_id),
            "query_id": str(query_id),
            "splunk_job_id": "job-1",
            "evidence_kind": "raw_event",
            "index": "main",
            "sourcetype": "sysmon",
            "event_time_utc": _timestamp(2),
            "collected_at_utc": _timestamp(3),
            "source_event_ref": "event-1",
            "selected_result": {"host": "host-1"},
            "sha256": "a" * 64,
        }
    )
    assert evidence.evidence_kind is EvidenceKind.RAW_EVENT

    finding_payload = {
        "finding_id": str(uuid4()),
        "title": "Observed process",
        "classification": "supported_observation",
        "statement": "The process was observed in retained evidence.",
        "confidence": "high",
        "evidence_ids": [],
        "query_ids": [],
        "inference": "unknown",
        "limitations": [],
    }
    with pytest.raises(ValidationError):
        Finding.model_validate(finding_payload)
    finding_payload["evidence_ids"] = [str(evidence.evidence_id)]
    assert Finding.model_validate(finding_payload).confidence is Confidence.HIGH


def test_stop_decision_requires_scope_grounding_for_negative_disposition() -> None:
    payload = {
        "disposition": "not_supported_within_scope",
        "reason_code": "hypothesis_disposed",
        "summary": "No supporting event was observed in the searched scope.",
        "evidence_ids": [],
        "query_ids": [],
        "coverage": ["main index"],
        "limitations": ["Only selected sourcetypes were searched."],
        "open_questions": [],
    }
    with pytest.raises(ValidationError):
        StopDecision.model_validate(payload)
    payload["query_ids"] = [str(uuid4())]
    assert StopDecision.model_validate(payload).disposition is Disposition.NOT_SUPPORTED_WITHIN_SCOPE


def test_stop_decision_rejects_incoherent_terminal_reasons() -> None:
    base = {
        "disposition": "inconclusive",
        "reason_code": "low_yield",
        "summary": "The investigation did not produce enough information.",
        "evidence_ids": [],
        "query_ids": [],
        "coverage": ["The approved process telemetry scope was searched."],
        "limitations": ["The available results did not resolve the hypothesis."],
        "open_questions": [],
    }

    for update in (
        {"disposition": "inconclusive", "reason_code": "budget_reached"},
        {"disposition": "inconclusive", "reason_code": "unrecoverable_error"},
        {"disposition": "not_supported_within_scope", "reason_code": "budget_reached"},
    ):
        invalid = {**base, **update, "query_ids": [str(uuid4())]}
        with pytest.raises(ValidationError):
            StopDecision.model_validate(invalid)

    budget = {**base, "disposition": "budget_exhausted", "reason_code": "budget_reached"}
    assert StopDecision.model_validate(budget).disposition is Disposition.BUDGET_EXHAUSTED

    failed = {**base, "disposition": "failed", "reason_code": "unrecoverable_error"}
    assert StopDecision.model_validate(failed).disposition is Disposition.FAILED


def test_stop_decision_requires_coverage_or_limitations_for_non_positive_outcomes() -> None:
    base = {
        "summary": "The investigation ended without a supported conclusion.",
        "evidence_ids": [],
        "query_ids": [str(uuid4())],
        "coverage": [],
        "limitations": [],
        "open_questions": [],
    }
    outcomes = (
        {"disposition": "not_supported_within_scope", "reason_code": "hypothesis_disposed"},
        {"disposition": "inconclusive", "reason_code": "low_yield"},
        {"disposition": "budget_exhausted", "reason_code": "budget_reached"},
    )
    for outcome in outcomes:
        with pytest.raises(ValidationError):
            StopDecision.model_validate({**base, **outcome})

    with_coverage = {**base, **outcomes[1], "coverage": ["Only the approved scope was searched."]}
    assert StopDecision.model_validate(with_coverage).disposition is Disposition.INCONCLUSIVE

    with_limitations = {**base, **outcomes[2], "limitations": ["The hard result budget was reached."]}
    assert StopDecision.model_validate(with_limitations).disposition is Disposition.BUDGET_EXHAUSTED
