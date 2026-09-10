"""Owner- and state-scoped production execution persistence tests."""

from copy import deepcopy

import pytest
from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.contracts import QueryAssessment
from threat_hunting.domain.errors import NotFound
from threat_hunting.domain.state import HuntState
from threat_hunting.services.jobs import metadata as jobs_metadata
from threat_hunting.services.workflow import Validation, WorkflowService, hunts, workflow_metadata
from threat_hunting.services.reports import _concise_report_content, _validate_report_content
from threat_hunting.services.investigation import _materialize_follow_up_questions
from threat_hunting.services.evidence import retained_timeline


def _service() -> tuple[WorkflowService, str, str, str]:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    service = WorkflowService(engine, local_demo=False)
    owner, worker = "owner", "worker"
    hunt = service.create_hunt(owner, title="production", hypothesis="h", objective="o")
    hunt_id = str(hunt["hunt_id"])
    with engine.begin() as connection:
        connection.execute(update(hunts).where(hunts.c.hunt_id == hunt_id).values(state=HuntState.QUEUED.value, plan_version=1, plan={"scope": {}}, approval={"plan_version": 1}))
    job = service.jobs.enqueue(owner, hunt_id, idempotency_key=f"test:{hunt_id}")
    service.jobs.claim(worker)
    return service, owner, hunt_id, str(job["job_id"])


def test_worker_lifecycle_persists_running_synthesis_and_report_draft() -> None:
    service, owner, hunt_id, job_id = _service()
    service.start_execution(owner, hunt_id, job_id, "worker")
    results = {"evidence": []}
    report = _concise_report_content(
        hypothesis="h", objective="o", data_sources=["Splunk"], results=results,
        coverage_and_limitations=[], conclusion_and_disposition="No supported findings.",
    )
    result = service.persist_execution_result(owner, hunt_id, results, report)
    assert result["state"] == HuntState.REPORT_DRAFT.value
    assert result["results"] == {"evidence": []}


def test_synthesizing_state_is_restartable_without_duplicate_results() -> None:
    service, owner, hunt_id, job_id = _service()
    service.start_execution(owner, hunt_id, job_id, "worker")
    service._update(owner, hunt_id, expected_state=HuntState.RUNNING.value, state=HuntState.SYNTHESIZING.value, results={"evidence": []})
    results = {"evidence": []}
    report = _concise_report_content(
        hypothesis="h", objective="o", data_sources=["Splunk"], results=results,
        coverage_and_limitations=[], conclusion_and_disposition="No supported findings.",
    )
    result = service.persist_execution_result(owner, hunt_id, results, report)
    assert result["state"] == HuntState.REPORT_DRAFT.value


def test_late_result_is_rejected_after_owner_cancellation() -> None:
    service, owner, hunt_id, job_id = _service()
    service.start_execution(owner, hunt_id, job_id, "worker")
    service.cancel(owner, hunt_id)
    try:
        service.persist_execution_result(owner, hunt_id, {"evidence": []}, {"x": 1})
    except Exception as exc:
        assert "cancelled" in str(exc)
    else:
        raise AssertionError("late result was accepted")


def test_failure_is_terminal_and_idempotent() -> None:
    service, owner, hunt_id, _job_id = _service()
    first = service.fail_execution(owner, hunt_id, "adapter unavailable")
    second = service.fail_execution(owner, hunt_id, "late error")
    assert first["state"] == HuntState.FAILED.value
    assert second["state"] == HuntState.FAILED.value
    assert second["results"]["failure"] == "adapter unavailable"


def test_concise_report_uses_evidence_citations_not_raw_events() -> None:
    results = {
        "evidence": [
            {"evidence_id": str(index), "query_id": "q1", "index": "endpoint", "selected_result": {"host": "host-1"}}
            for index in range(25)
        ],
        "queries": [{"query_id": "q1", "purpose": "Check endpoint", "spl": "index=endpoint", "status": "completed", "result_count": 25}],
    }
    report = _concise_report_content(
        hypothesis="h", objective="o", data_sources=["Splunk"], results=results,
        coverage_and_limitations=[], conclusion_and_disposition="No supported findings.",
    )

    assert len(report["selected_evidence"]) == 20
    assert "selected_result" not in report["selected_evidence"][0]
    assert _validate_report_content(report, results) == report


def test_report_rejects_raw_evidence_records() -> None:
    results = {"evidence": [{"evidence_id": "e1", "query_id": "q1", "selected_result": {"host": "host-1"}}]}
    report = _concise_report_content(
        hypothesis="h", objective="o", data_sources=["Splunk"], results=results,
        coverage_and_limitations=[], conclusion_and_disposition="No supported findings.",
    )
    report["selected_evidence"] = results["evidence"]

    try:
        _validate_report_content(report, results)
    except Exception as exc:
        assert "citations only" in str(exc)
    else:
        raise AssertionError("raw evidence record was accepted")


def test_report_adds_readable_entities_and_timeline() -> None:
    report = _concise_report_content(
        hypothesis="h", objective="o", data_sources=["main (sysmon)"], coverage_and_limitations=[],
        conclusion_and_disposition="No supported findings.",
        results={"evidence": [{"evidence_id": "evidence-1", "query_id": "query-1", "index": "main", "sourcetype": "sysmon", "event_time_utc": "2026-01-01T00:00:00Z", "selected_result": {"host": "host-1", "user": "analyst", "src_ip": "198.51.100.20", "action": "failure", "result": "failure"}}]},
    )

    assert {"entity_type": "host", "value": "host-1"} in report["entities"]
    assert report["timeline"][0]["action"] == "failure"


@pytest.mark.parametrize("state", ["running", "failed", "cancelled"])
def test_results_show_all_retained_raw_observations_without_synthesis_or_state_mutation(state: str) -> None:
    service, owner, hunt_id, _ = _service()
    evidence = [
        {"evidence_id": "end", "query_id": "q1", "event_time_utc": "2026-01-06T17:00:00Z", "selected_result": {"action": "process_end"}},
        {"evidence_id": "unknown", "query_id": "q1", "event_time_utc": "2026-01-06T08:00:00", "selected_result": {"action": "image_load"}},
        {"evidence_id": "start", "query_id": "q1", "event_time_utc": "2026-01-06T04:00:00-05:00", "selected_result": {"action": "process_start"}},
        {"evidence_id": "start-copy", "query_id": "q2", "event_time_utc": "2026-01-06T09:00:00Z", "selected_result": {"action": "process_start"}},
        {"evidence_id": "aggregate", "query_id": "q1", "evidence_kind": "aggregate_row", "event_time_utc": "2026-01-06T07:00:00Z", "selected_result": {"count": 10}},
    ]
    original = {"evidence": evidence, "timeline": [], "findings": [], "queries": [
        {"query_id": "q1", "status": "completed", "truncated": True},
        {"query_id": "q2", "status": "completed", "truncated": False},
    ]}
    with service.engine.begin() as connection:
        connection.execute(update(hunts).where(hunts.c.hunt_id == hunt_id).values(state=state, results=original))
    returned = service.results(owner, hunt_id)
    assert returned["timeline"] == [
        {"evidence_id": "start", "query_id": "q1", "event_time_utc": "2026-01-06T09:00:00Z", "query_coverage": "incomplete"},
        {"evidence_id": "start-copy", "query_id": "q2", "event_time_utc": "2026-01-06T09:00:00Z", "query_coverage": "complete"},
        {"evidence_id": "end", "query_id": "q1", "event_time_utc": "2026-01-06T17:00:00Z", "query_coverage": "incomplete"},
        {"evidence_id": "unknown", "query_id": "q1", "event_time_utc": "unknown", "query_coverage": "incomplete"},
    ]
    assert returned["evidence"] == evidence and returned["findings"] == []
    returned["timeline"].clear()
    returned["evidence"][0]["selected_result"]["action"] = "changed"
    persisted = service._owned_row(owner, hunt_id)
    assert persisted["state"] == state and persisted["results"] == original
    with pytest.raises(NotFound, match="not found"):
        service.results("different-owner", hunt_id)


def test_report_timeline_spans_retained_observations_independently_of_model_citations() -> None:
    evidence = [{"evidence_id": str(index), "query_id": "q1", "event_time_utc": f"2026-01-06T{index:02d}:00:00Z",
                 "selected_result": {"host": "host-a", "session_id": "session-a", "process_guid": "process-a", "action": "process_end" if index == 23 else "image_load"}}
                for index in range(24)]
    evidence.append({"evidence_id": "unknown", "query_id": "q1", "event_time_utc": "unknown", "selected_result": {"action": "connection"}})
    source = {"evidence": evidence, "findings": [{"evidence_ids": [str(i) for i in range(20)]}],
              "queries": [{"query_id": "q1", "status": "completed", "truncated": True}]}
    original = deepcopy(source)
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=["endpoint"], results=source,
                                    coverage_and_limitations=[], conclusion_and_disposition="Analysis incomplete.")
    assert len(report["timeline"]) == 20
    assert report["timeline"][0]["evidence_id"] == "0"
    assert report["timeline"][-2]["evidence_id"] == "23"
    assert report["timeline"][-1]["evidence_id"] == "unknown"
    last = report["timeline"][-2]
    assert last["process_guid"] == "process-a" and last["session_id"] == "session-a"
    assert last["query_coverage"] == "incomplete"
    assert any("20 of 25" in limit and "timeline" in limit.lower() for limit in report["coverage_and_limitations"])
    assert source == original


@pytest.mark.parametrize(("known_count", "unknown_count"), [(0, 0), (25, 0), (0, 25), (1, 24), (4, 100)])
def test_report_timeline_excerpt_handles_missing_times_and_preserves_source_fields(known_count: int, unknown_count: int) -> None:
    evidence = [{"evidence_id": str(index), "query_id": "missing-query", "event_time_utc": f"2026-01-06T00:00:{index:02d}Z" if index < known_count else "invalid-time",
                 "selected_result": {"host": ["collector", "target"], "process_guid": "literal-guid"}}
                for index in range(known_count + unknown_count)]
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results={"evidence": evidence},
                                    coverage_and_limitations=[], conclusion_and_disposition="Not assessed.")
    timeline = report["timeline"]
    assert len(timeline) == min(20, len(evidence))
    assert len({item["evidence_id"] for item in timeline}) == len(timeline)
    if known_count:
        assert timeline[0]["evidence_id"] == "0"
        assert str(known_count - 1) in {item["evidence_id"] for item in timeline}
    if unknown_count:
        assert timeline[-1]["event_time_utc"] == "unknown"
    if timeline:
        assert all(item["query_coverage"] == "unknown" for item in timeline)
        timeline[0]["host"].append("changed")
        assert all(item["selected_result"]["host"] == ["collector", "target"] for item in evidence)


def test_retained_timeline_keeps_positive_observations_from_failed_and_legacy_searches() -> None:
    results = {"evidence": [{"evidence_id": f"e-{query}", "query_id": query, "event_time_utc": None} for query in ("failed", "legacy", "partial")],
               "queries": [{"query_id": "failed", "status": "failed"}, {"query_id": "legacy"}, {"query_id": "partial", "partial_fetch": True}]}
    assert [(item["evidence_id"], item["query_coverage"]) for item in retained_timeline(results)] == [
        ("e-failed", "incomplete"), ("e-legacy", "unknown"), ("e-partial", "incomplete"),
    ]


def test_report_preserves_synthetic_provenance() -> None:
    report = _concise_report_content(
        hypothesis="h", objective="o", data_sources=["main"], results={},
        coverage_and_limitations=["Synthetic data sources may not fully represent endpoint telemetry."],
        conclusion_and_disposition="No supported findings.",
    )

    assert report["coverage_and_limitations"] == ["Synthetic data sources may not fully represent endpoint telemetry."]


def test_report_prefers_time_resolved_cited_events_and_omits_full_spl() -> None:
    results = {
        "findings": [{"evidence_ids": ["event-1"]}],
        "evidence": [
            {"evidence_id": "aggregate-1", "query_id": "q1", "evidence_kind": "aggregate_row", "event_time_utc": "unknown", "selected_result": {}},
            {"evidence_id": "event-1", "query_id": "q1", "evidence_kind": "raw_event", "event_time_utc": "2026-01-01T00:00:00Z", "selected_result": {"host": ["127.0.0.1:8080", "host-1"], "process": "tool.exe", "file_hash": "abc"}},
        ],
        "queries": [{"query_id": "q1", "purpose": "Check", "spl": "index=main " + "x" * 500, "status": "completed", "result_count": 2}],
    }
    report = _concise_report_content(
        hypothesis="h", objective="o", data_sources=["main"], results=results,
        coverage_and_limitations=[], conclusion_and_disposition="No supported findings.",
    )

    assert [item["evidence_id"] for item in report["selected_evidence"]] == ["event-1"]
    assert report["entities"] == [{"entity_type": "host", "value": "host-1"}]
    assert report["timeline"][0]["host"] == ["127.0.0.1:8080", "host-1"]
    assert report["timeline"][0]["process"] == "tool.exe"
    assert "spl" not in report["query_appendix"][0]


def test_adaptive_assessment_rejects_an_entity_not_present_in_cited_evidence() -> None:
    results = {
        "queries": [{
            "query_id": "00000000-0000-4000-8000-000000000001",
            "question_id": "q1",
            "status": "completed",
        }],
        "evidence": [{
            "evidence_id": "evidence-1",
            "query_id": "00000000-0000-4000-8000-000000000001",
            "selected_result": {"host": "host-1"},
        }],
    }
    assessment = QueryAssessment.model_validate({
        "query_id": "00000000-0000-4000-8000-000000000001",
        "question_id": "q1",
        "answered_question": True,
        "material_progress": True,
        "summary": "A host was observed.",
        "new_entities": [{
            "entity_type": "host",
            "value": "invented-host",
            "result_row_refs": ["evidence-1"],
        }],
        "evidence_candidate_row_refs": ["evidence-1"],
        "coverage_changes": [],
        "limitations": [],
        "proposed_next_question": None,
    })

    try:
        _materialize_follow_up_questions([assessment], results)
    except Validation as exc:
        assert "not present" in str(exc)
    else:
        raise AssertionError("an invented pivot entity was accepted")
