"""Application-owned activity remains available without model findings."""

from copy import deepcopy

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.errors import NotFound, Validation
from threat_hunting.services.evidence import retained_lead_activity
from threat_hunting.services.jobs import metadata as jobs_metadata
from threat_hunting.services.reports import _concise_report_content, _formatted_pdf, _validate_report_content
from threat_hunting.services.workflow import WorkflowService, workflow_metadata


def _row(identifier: str, stamp: str, action: str, **fields: object) -> dict:
    return {"evidence_id": identifier, "query_id": "q", "evidence_kind": "raw_event", "event_time_utc": stamp,
            "selected_result": {"host": "host", "user": "user", "session_id": "session", "process_guid": "lead",
                                "action": action, **fields}}


def _results(rows: list[dict]) -> dict:
    return {"evidence": rows, "queries": [{"query_id": "q", "status": "completed", "result_count": len(rows)}],
            "findings": [], "question_answers": [{"question_id": "q1", "question": "Related activity?",
                "summary": "Not interpreted.", "finding_ids": [], "limitations": ["Unanswered."], "lead_coverage": [{
                "lead_evidence_ids": ["lead"], "identity_fields": {
                    "host": "host", "user": "user", "session_id": "session", "process_guid": "lead"},
                "finding_ids": [], "limitation": "Not interpreted."}]}]}


def test_activity_preserves_both_sides_of_lead_and_separates_process_from_session() -> None:
    rows = [_row("end", "2026-01-06T13:19:09Z", "process_end"),
            _row("dns-after", "2026-01-06T13:23:16Z", "dns_query", process_guid="browser", src_ip="10.1.1.1"),
            _row("lead", "2026-01-06T13:07:43Z", "process_start"),
            _row("module", "2026-01-06T08:06:56Z", "image_load", process_guid="browser"),
            _row("dns-before", "2026-01-06T08:10:54Z", "dns_query", process_guid="browser", src_ip="10.1.1.1"),
            _row("unknown", "unknown", "logoff", process_guid="browser"),
            _row("other-session", "2026-01-06T08:00:00Z", "logon", session_id="other")]
    source = _results(rows)
    before = deepcopy(source)
    activity = retained_lead_activity(source)
    lead, = activity["leads"]
    scopes = {scope["scope_id"]: scope for scope in activity["scopes"]}
    process, session = [scopes[item["scope_id"]] for item in lead["scopes"]]
    assert process["evidence_ids"] == ["lead", "end"]
    assert session["evidence_ids"] == ["module", "dns-before", "lead", "end", "dns-after", "unknown"]
    assert lead["anchor_event_time_utc"] == "2026-01-06T13:07:43Z"
    assert {period["relative_to_lead"]: period["raw_record_count"] for period in lead["scopes"][1]["periods"]} == {
        "before": 2, "at": 1, "after": 2, "unknown": 1}
    assert {item["action"]: item["raw_record_count"] for item in session["actions"]} == {
        "image_load": 1, "dns_query": 2, "process_start": 1, "process_end": 1, "logoff": 1}
    address = next(item for item in session["fields"] if item["field"] == "src_ip")
    assert address["distinct_literal_value_count"] == 1
    assert address["rows_with_missing_or_nonscalar_value"] == 4
    assert source == before
    session["identity_fields"]["host"] = "changed"
    assert source == before


def test_partial_failed_and_unknown_sources_remain_distinct_with_original_representations() -> None:
    source = _results([_row("lead", "2026-01-06T09:00:00Z", "process_start"),
                       _row("copy", "2026-01-06T09:00:00Z", "process_start"),
                       _row("partial", "2026-01-06T09:01:00Z", "connection"),
                       _row("failed", "2026-01-06T09:02:00Z", "connection"),
                       _row("legacy", "unknown", "connection")])
    source["evidence"][2]["query_id"] = "partial"
    source["evidence"][3]["query_id"] = "failed"
    source["evidence"][4]["query_id"] = "missing"
    source["queries"] += [{"query_id": "partial", "status": "completed", "truncated": True},
                          {"query_id": "failed", "status": "failed"}]
    scope = retained_lead_activity(source)["scopes"][0]
    assert scope["raw_record_count"] == 5
    assert scope["evidence_ids"] == ["lead", "copy", "partial", "failed", "legacy"]
    assert {q["query_id"]: q["retrieval_status"] for q in scope["query_coverage"]} == {
        "q": "complete", "partial": "incomplete", "failed": "incomplete", "missing": "unknown"}


def test_ambiguous_identity_is_not_joined_and_unknown_anchor_does_not_assign_periods() -> None:
    source = _results([_row("lead", "unknown", "process_start"),
                       _row("later", "2026-01-06T10:00:00Z", "process_end"),
                       _row("ambiguous", "2026-01-06T11:00:00Z", "connection", host=["host", "other"])])
    activity = retained_lead_activity(source)
    assert activity["scopes"][0]["evidence_ids"] == ["later", "lead"]
    assert activity["leads"][0]["scopes"][0]["periods"] == [{
        "relative_to_lead": "unknown", "raw_record_count": 2,
        "first_event_time_utc": None, "last_event_time_utc": None}]
    source["evidence"][0]["selected_result"]["host"] = ["host", "other"]
    activity = retained_lead_activity(source)
    assert activity["leads"][0]["scopes"] == []
    assert activity["leads"][0]["limitation"]


def test_shared_session_scope_is_stored_once_across_many_leads_and_questions() -> None:
    rows = [_row(f"lead-{i}", "2026-01-06T09:00:00Z", "process_start", process_guid=f"process-{i}") for i in range(200)]
    source = _results(rows)
    coverage = [{"lead_evidence_ids": [row["evidence_id"]],
                 "identity_fields": {key: row["selected_result"][key] for key in ("host", "user", "session_id", "process_guid")},
                 "finding_ids": [], "limitation": "Unanswered."} for row in rows]
    source["question_answers"] = [{"question_id": str(i), "lead_coverage": coverage} for i in range(4)]
    activity = retained_lead_activity(source)
    assert len(activity["leads"]) == 200
    assert len(activity["scopes"]) == 201
    assert sum(len(scope["evidence_ids"]) for scope in activity["scopes"]) == 400


def test_missing_lead_sources_and_absent_answers_remain_explicit() -> None:
    assert retained_lead_activity({"evidence": []}) == {"leads": [], "scopes": []}
    activity = retained_lead_activity(_results([]))
    assert activity["leads"][0]["scopes"] == []
    assert "unavailable" in activity["leads"][0]["limitation"]


def test_known_session_context_remains_available_when_process_guid_is_missing() -> None:
    source = _results([_row("lead", "2026-01-06T09:00:00Z", "file_write"),
                       _row("other", "2026-01-06T10:00:00Z", "logon", process_guid="different")])
    del source["evidence"][0]["selected_result"]["process_guid"]
    del source["question_answers"][0]["lead_coverage"][0]["identity_fields"]["process_guid"]
    activity = retained_lead_activity(source)
    assert len(activity["scopes"]) == 1
    assert activity["scopes"][0]["evidence_ids"] == ["lead", "other"]
    assert "process_guid" not in activity["scopes"][0]["identity_fields"]
    assert "Process identity is unavailable" in activity["leads"][0]["limitation"]


def test_activity_is_owner_scoped_read_only_and_report_facts_cannot_be_changed_or_dropped() -> None:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    service = WorkflowService(engine)
    hunt_id = service.create_hunt("owner", title="Activity", hypothesis="h", objective="o")["hunt_id"]
    source = _results([_row("lead", "2026-01-06T09:00:00Z", "process_start"),
                       _row("before", "2026-01-06T08:00:00Z", "dns_query", process_guid="browser"),
                       _row("after", "2026-01-06T10:00:00Z", "dns_query", process_guid="browser")])
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=["endpoint"], results=source,
                                     coverage_and_limitations=[], conclusion_and_disposition="Unanswered.")
    assert _validate_report_content(report, source) == report
    assert "evidence_ids" not in report["observed_activity"]["scopes"][0]
    service._update("owner", hunt_id, expected_state="created", state="report_draft", results=source,
                    report_id="test-report", report_version=1, report_state="report_draft", report_content=report)
    with pytest.raises(NotFound):
        service.results("another-owner", hunt_id)
    returned = service.results("owner", hunt_id)
    assert returned["lead_activity"]["leads"][0]["scopes"][1]["periods"][0]["relative_to_lead"] == "before"
    returned["lead_activity"]["scopes"].clear()
    assert service._owned_row("owner", hunt_id)["results"] == source
    changed = deepcopy(report)
    changed["observed_activity"]["scopes"][0]["raw_record_count"] = True
    with pytest.raises(Validation, match="observed activity"):
        service.save_report("owner", hunt_id, expected_version=1, content=changed)
    removed = {key: value for key, value in report.items() if key != "observed_activity"}
    with pytest.raises(Validation, match="cannot be removed"):
        service.save_report("owner", hunt_id, expected_version=1, content=removed)
    assert service.report("owner", hunt_id)["content"] == report
    assert service.save_report("owner", hunt_id, expected_version=1, content=report)["version"] == 2
    pdf = _formatted_pdf("Activity", report)
    assert b"OBSERVED ACTIVITY BY LEAD" in pdf
    assert b"before: 1" in pdf and b"after: 1" in pdf
    assert b"dns_query: 2" in pdf


def test_report_excerpt_declares_omissions_and_legacy_reports_are_not_rewritten() -> None:
    rows = [_row(f"lead-{i}", "2026-01-06T09:00:00Z", "process_start", process_guid=f"process-{i}") for i in range(12)]
    source = _results(rows)
    source["question_answers"][0]["lead_coverage"] = [{
        "lead_evidence_ids": [row["evidence_id"]], "identity_fields": {
            key: row["selected_result"][key] for key in ("host", "user", "session_id", "process_guid")},
        "finding_ids": [], "limitation": "Unanswered."} for row in rows]
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=source,
                                     coverage_and_limitations=[], conclusion_and_disposition="Unanswered.")
    assert len(report["observed_activity"]["leads"]) == 10
    assert report["observed_activity"]["total_lead_count"] == 12
    assert b"Showing 10 of 12 retained lead groups" in _formatted_pdf("Activity", report)
    legacy = {key: value for key, value in report.items() if key != "observed_activity"}
    assert _validate_report_content(legacy, source) == legacy
