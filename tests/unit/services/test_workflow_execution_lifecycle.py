"""Owner- and state-scoped production execution persistence tests."""

from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.contracts import QueryAssessment
from threat_hunting.domain.state import HuntState
from threat_hunting.services.jobs import metadata as jobs_metadata
from threat_hunting.services.workflow import Validation, WorkflowService, hunts, workflow_metadata
from threat_hunting.services.reports import _concise_report_content, _validate_report_content
from threat_hunting.services.investigation import _materialize_follow_up_questions


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
    assert report["timeline"][0]["host"] == "host-1"
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
