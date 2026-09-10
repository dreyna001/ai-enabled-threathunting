from __future__ import annotations

import json

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.budgets import BudgetLimits
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector
from threat_hunting.services.jobs import execution_jobs, metadata as jobs_metadata
from threat_hunting.services.workflow import Conflict, WorkflowService, workflow_metadata


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Job:
    name = "sid-production-1"
    content = {"isDone": "1", "eventCount": "1"}

    def results(self, **_: object) -> list[dict[str, str]]:
        return [{"_time": "2026-01-01T00:30:00Z", "host": "host-1", "event_id": "evt-1"}]


class CatalogJob(Job):
    def results(self, **_: object) -> list[dict[str, str]]:
        return [{"sourcetype": "syslog", "count": "1"}]


class Jobs(dict[str, Job]):
    def create(self, _query: str, **_: object) -> Job:
        if _query.startswith("| tstats "):
            return CatalogJob()
        job = Job()
        job.name = str(_.get("id", job.name))
        self[job.name] = job
        return job


class Splunk:
    def __init__(self) -> None:
        self.jobs = Jobs()

    def get(self, path: str, **_: object) -> object:
        return {
            "authentication/current-context": {"entry": [{"content": {"roles": ["searcher"]}}]},
            "authorization/roles/searcher": {"entry": [{"name": "searcher", "content": {"srchIndexesAllowed": ["main"]}}]},
            "data/indexes": {"entry": [{"name": "main"}]},
            "saved/sourcetypes": {"entry": [{"name": "syslog", "content": {"fields": ["host", "event_id"]}}]},
            "data/fields": {"entry": [{"name": "host"}, {"name": "event_id"}]},
            "data/models": {"entry": []},
        }.get(path, {"entry": []})


def _model(*, invalid_pivot: str | None = None, invalid_citation: bool = False, draft_question_ids: tuple[str, ...] = ("q1",)) -> FakeModelAdapter:
    def response(request):
        context = json.loads(request.messages[0]["content"])
        if "HuntPlan" in (request.system or ""):
            ids = context["application_assigned_ids"]
            latest = datetime.now(timezone.utc).replace(microsecond=0)
            earliest = latest - timedelta(hours=1)
            return json.dumps({
                "schema_version": "1.0",
                "plan_id": ids["plan_id"],
                "plan_version": 1,
                "hunt_id": context["hunt_id"],
                "discovery_snapshot_id": ids["discovery_snapshot_id"],
                "execution_config_snapshot_id": ids["execution_config_snapshot_id"],
                "hypothesis": context["hypothesis"],
                "objective": context["objective"],
                "scope": {"earliest_utc": earliest.isoformat().replace("+00:00", "Z"), "latest_utc": latest.isoformat().replace("+00:00", "Z"), "indexes": ["main"], "sourcetypes": ["syslog"]},
                "intelligence_refs": [],
                "data_sources": [{"index": "main", "sourcetypes": ["syslog"], "purpose": "authentication"}],
                "questions": [{"question_id": question_id, "question": "Which hosts generated events?", "rationale": "Identify affected hosts.", "expected_information_gain": "Host pivot."} for question_id in draft_question_ids],
                "query_strategy": ["Start with one bounded representative query."],
                "coverage_limitations": [],
                "created_at_utc": latest.isoformat().replace("+00:00", "Z"),
            })
        if "QueryProposal[]" in (request.system or "") or "FollowUpDecision[]" in (request.system or ""):
            plan = context["approved_plan"]
            scope = plan["scope"]
            if context.get("follow_up_questions"):
                question = context["follow_up_questions"][0]
                bad_pivot = invalid_pivot == "always" or (
                    invalid_pivot == "once" and not context.get("rejected_proposals")
                )
                return json.dumps([{
                    "question_id": question["question_id"],
                    "skip_reason": None,
                    "proposal": {
                    "question_id": question["question_id"],
                    "purpose": "Pivot from the observed host to related events.",
                    "expected_information_gain": "Identify related activity on the observed host.",
                    "spl": f"search index=main sourcetype=syslog host={'unobserved-host' if bad_pivot else 'host-1'} | head 1",
                    "earliest_utc": scope["earliest_utc"],
                    "latest_utc": scope["latest_utc"],
                    "indexes": ["main"],
                    "sourcetypes": ["syslog"],
                    "requested_fields": ["host", "event_id"],
                    "result_mode": "targeted",
                    "max_results": 1,
                    },
                }])
            return json.dumps([{
                "question_id": "q1",
                "purpose": "Find representative authentication events.",
                "expected_information_gain": "Identify affected hosts.",
                "spl": "search index=main sourcetype=syslog | head 1",
                "earliest_utc": scope["earliest_utc"],
                "latest_utc": scope["latest_utc"],
                "indexes": ["main"],
                "sourcetypes": ["syslog"],
                "requested_fields": ["host", "event_id"],
                "result_mode": "representative",
                "max_results": 1,
            }])
        if "QueryAssessment[]" in (request.system or ""):
            query = context["completed_queries"][0]
            evidence = query["retained_evidence"][0]
            citation = evidence["evidence_id"]
            if invalid_citation and len(request.messages) == 1:
                citation = query["query_id"]
            elif invalid_citation:
                assert "unknown evidence_candidate_row_refs label" in request.messages[-1]["content"]
                assert citation in query["allowed_evidence_ids"]
            proposed_next_question = (
                {
                    "question": "What related activity occurred on host-1?",
                    "rationale": "Expand from the observed host into surrounding activity.",
                    "expected_information_gain": "Related processes and events on the target asset.",
                }
                if query["question_id"] == "q1"
                else None
            )
            return json.dumps([{
                "query_id": query["query_id"],
                "question_id": query["question_id"],
                "answered_question": True,
                "material_progress": True,
                "summary": "The query identified host-1 for a bounded follow-up.",
                "new_entities": [{
                    "entity_type": "host",
                    "value": "host-1",
                    "result_row_refs": [evidence["evidence_id"]],
                }],
                "evidence_candidate_row_refs": [citation],
                "coverage_changes": [],
                "limitations": [],
                "proposed_next_question": proposed_next_question,
            }])
        if "Required contract: QuestionSynthesis." in (request.system or ""):
            evidence = context["retained_evidence"][0]
            query = context["completed_queries"][0]
            finding = {
                "title": "Representative event observed",
                "classification": "supported_observation",
                "statement": "The completed query returned a retained event for host-1.",
                "confidence": "low",
                "evidence_ids": [evidence["evidence_id"]],
                "query_ids": [],
                "inference": "unknown",
                "limitations": ["One representative event does not establish incident scope."],
            }
            searched = {item.get("question_id") for item in context["completed_queries"]}
            return json.dumps({question["answer_slot"]: (
                {"summary": "An event for host-1 was retained.", "findings": [finding], "limitations": []} if question["question_id"] in searched
                else {"summary": "This question remains unanswered.", "findings": [], "limitations": ["No completed search answered this question."]})
                               for question in context["approved_plan"]["questions"]})
        raise AssertionError("unexpected model contract")

    return FakeModelAdapter(responses=[response] * 8)


def test_discovery_exposes_token_cutoff_without_repair() -> None:
    from threat_hunting.services.workflow import IntegrationUnavailable

    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    model = FakeModelAdapter(responses=[{"text": "", "finish_reason": "length"}])
    service = WorkflowService(
        engine,
        splunk_connector=SplunkConnector(
            SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk(),
        ),
        model_adapter=model,
    )
    hunt = service.create_hunt("owner-1", title="Budget test", hypothesis="h", objective="o")
    with pytest.raises(IntegrationUnavailable, match="token limit"):
        service.discover("owner-1", str(hunt["hunt_id"]))
    assert model.call_count == 1
    assert service.get_hunt("owner-1", str(hunt["hunt_id"]))["state"] == "failed"


@pytest.mark.parametrize("draft_question_ids", [("q1",), ("unknown",)])
def test_injected_production_adapters_persist_discovery_snapshots_and_results(draft_question_ids: tuple[str, ...]) -> None:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    splunk = SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk())
    service = WorkflowService(
        engine,
        splunk_connector=splunk,
        model_adapter=(model := _model(draft_question_ids=draft_question_ids)),
        budget_limits=BudgetLimits(),
        execution_config={"provider": "fake", "model_name": "test", "provider_data_boundary": "local", "provider_data_handling_approval_ref": None, "spl_policy_version": "1.0", "splunk_poll_interval_seconds": 0.1},
    )

    hunt = service.create_hunt("owner-1", title="Production adapter", hypothesis="h", objective="o")
    discovered = service.discover("owner-1", str(hunt["hunt_id"]))
    assert discovered["state"] == "awaiting_plan_review"
    assert discovered["discovery_snapshot"]["mode"] == "production"
    assert discovered["discovery_snapshot"]["execution_config_snapshot"]["sha256"]
    assert discovered["plan"]["execution_config_snapshot_id"]
    assert discovered["discovery_snapshot"]["execution_config_snapshot"]["payload"]["budget_limits"]["max_model_calls"] == 12
    assert discovered["discovery_snapshot"]["execution_config_snapshot"]["payload"]["execution_config"]["provider_data_boundary"] == "local"
    assert discovered["discovery_snapshot"]["execution_config_snapshot"]["payload"]["execution_config"]["provider_data_handling_approval_ref"] is None
    assert service.splunk_poll_interval_seconds == 0.1

    approved = service.approve("owner-1", str(hunt["hunt_id"]), "reviewed")
    assert approved["approval"]["plan_sha256"]
    assert approved["approval"]["execution_config_sha256"]
    service.execution_config["model_name"] = "drifted"
    with pytest.raises(Conflict):
        service.execute("owner-1", str(hunt["hunt_id"]))
    service.execution_config["model_name"] = "test"
    service.budget_limits = BudgetLimits(max_model_calls=11)
    with pytest.raises(Conflict):
        service.execute("owner-1", str(hunt["hunt_id"]))
    service.budget_limits = BudgetLimits()
    queued = service.execute("owner-1", str(hunt["hunt_id"]))
    assert queued["state"] == "queued"
    lease = service.jobs.claim("worker-1")
    assert lease is not None
    service.execute_job(lease)
    result = service.results("owner-1", str(hunt["hunt_id"]))
    assert result["mode"] == "production"
    assert result["queries"][0]["status"] == "completed"
    assert len(result["queries"]) == 2
    assert result["evidence"][0]["selected_result"]["host"] == "host-1"
    assert result["adaptive_status"] == "assessed"
    assert result["adaptive_complete"] is True
    assert len(result["query_assessments"]) == 2
    assert result["follow_up_questions"][0]["source_question_id"] == "q1"
    assert result["query_ledger"][1]["phase"] == "adaptive_follow_up"
    assert result["findings"][0]["classification"] == "supported_observation"
    assert service.get_hunt("owner-1", str(hunt["hunt_id"]))["state"] == "report_draft"
    proposal_request = next(request for request in model.requests if "QueryProposal[]" in (request.system or ""))
    proposal_context = json.loads(proposal_request.messages[0]["content"])
    assert proposal_context["discovery_scope"]["fields"] == ["event_id", "host"]
    assert proposal_context["discovery_scope"]["query_execution_rules"]
    assert proposal_context["discovery_scope"]["representative_schemas"] == {"syslog": ["host", "event_id"]}
    assert proposal_context["open_question_ids"] == ["q1"]
    assert "Use only discovery_scope.fields" in proposal_context["proposal_rules"][1]
    follow_up_request = next(
        request
        for request in model.requests
        if "FollowUpDecision[]" in (request.system or "")
        and "follow_up_questions" in json.loads(request.messages[0]["content"])
    )
    follow_up_context = json.loads(follow_up_request.messages[0]["content"])
    assert "Never silently omit a question" in " ".join(follow_up_context["proposal_rules"])
    assert result["follow_up_decisions"][0]["proposal"] is not None
    synthesis_request = next(request for request in model.requests if "Required contract: QuestionSynthesis." in (request.system or ""))
    synthesis_context = json.loads(synthesis_request.messages[0]["content"])
    assert synthesis_context["retained_evidence"][0]["evidence_id"] == "E1"
    assert synthesis_context["retained_evidence"][0]["selected_result"] == result["evidence"][0]["selected_result"]
    assert result["findings"][0]["evidence_ids"] == [result["evidence"][0]["evidence_id"]]
    assert "prior_assessments" not in synthesis_context
    assert len(result["query_assessments"]) == 2  # Retained for investigation/audit, outside final synthesis.
    assert result["question_answers"][0]["question_id"] == "q1"
    assert result["question_answers"][0]["finding_ids"] == [result["findings"][0]["finding_id"]]


@pytest.mark.parametrize("draft_ids", [("unknown",) * 6, ("duplicate", "duplicate"), ("q2", "q1")])
def test_discovery_assigns_question_ids_before_review(draft_ids: tuple[str, ...]) -> None:
    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    model = _model(draft_question_ids=draft_ids)
    service = WorkflowService(
        engine,
        splunk_connector=SplunkConnector(
            SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk(),
        ),
        model_adapter=model,
    )
    hid = str(service.create_hunt("owner-1", title="Question identity", hypothesis="h", objective="o")["hunt_id"])

    discovered = service.discover("owner-1", hid)

    expected_ids = [f"q{number}" for number in range(1, len(draft_ids) + 1)]
    questions = discovered["plan"]["questions"]
    assert [question["question_id"] for question in questions] == expected_ids
    assert all(question["question"] == "Which hosts generated events?" for question in questions)
    assert model.call_count == 1
    approved = service.approve("owner-1", hid, "reviewed")
    assert [question["question_id"] for question in approved["plan"]["questions"]] == expected_ids


def test_discovery_with_no_questions_fails_without_leaving_hunt_discovering() -> None:
    from threat_hunting.services.workflow import IntegrationUnavailable

    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    model = _model(draft_question_ids=())
    service = WorkflowService(
        engine,
        splunk_connector=SplunkConnector(
            SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk(),
        ),
        model_adapter=model,
    )
    hid = str(service.create_hunt("owner-1", title="Empty plan", hypothesis="h", objective="o")["hunt_id"])
    with pytest.raises(IntegrationUnavailable, match="production discovery failed"):
        service.discover("owner-1", hid)
    assert service.get_hunt("owner-1", hid)["state"] == "failed"
    assert model.call_count == 1


@pytest.mark.parametrize("invalid_pivot,invalid_citation", [("once", False), ("always", False), (None, True)])
def test_adaptive_validation_repairs_once_or_rejects(invalid_pivot: str | None, invalid_citation: bool) -> None:
    from threat_hunting.services.workflow import Validation

    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    service = WorkflowService(
        engine,
        splunk_connector=SplunkConnector(
            SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"),
            client=Splunk(),
        ),
        model_adapter=_model(invalid_pivot=invalid_pivot, invalid_citation=invalid_citation),
        budget_limits=BudgetLimits(),
        execution_config={"provider": "fake", "model_name": "test"},
    )
    hid = str(service.create_hunt("owner-1", title="Pivot repair", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    lease = service.jobs.claim("worker-1")
    assert lease is not None
    if invalid_pivot == "always":
        with pytest.raises(Validation, match="evidence-grounded pivot"):
            service.execute_job(lease)
    else:
        service.execute_job(lease)
    result = service.results("owner-1", hid)
    assert result["usage"]["model_repair_attempts"] == (2 if invalid_citation else 1)
    if invalid_citation:
        # Unknown labels are rejected at the response boundary before semantic checks.
        checks = result["usage"]["model_output_checks"]
        assert sum(check["contract_valid"] is False for check in checks) == 2
        assert all(check["contract_valid"] for check in checks if check["repair"])
    if invalid_pivot:
        assert "unobserved-host" in result["query_policy_rejections"][0]["proposal"]["spl"]
    if invalid_pivot == "always":
        assert result["latest_assessment_round"]["query_assessments"]
        assert result["latest_assessment_round"]["follow_up_questions"][0]["grounded_entities"]
    assert all("unobserved-host" not in query["spl"] for query in result["queries"])
    assert len(result["queries"]) == (1 if invalid_pivot == "always" else 2)
    assert service.get_hunt("owner-1", hid)["state"] == (
        "failed" if invalid_pivot == "always" else "report_draft"
    )


class SimulatedWorkerCrash(BaseException):
    pass


@pytest.mark.parametrize("repair_output", ["correct", "wrong_citation", "extra_assessment", "missing_assessment", "duplicate_assessment"])
def test_cross_query_assessment_repair_preserves_valid_output_and_remains_fail_closed(repair_output: str) -> None:
    from threat_hunting.services.workflow import Validation

    base_model = _model(draft_question_ids=("q1", "q2"))
    initial_assessments = []

    def response(request):
        context = json.loads(request.messages[0]["content"])
        if "QueryProposal[]" in (request.system or ""):
            first = json.loads(base_model.complete(request).text)[0]
            return json.dumps([first, {
                **first,
                "question_id": "q2",
                "spl": "search index=main sourcetype=syslog host=host-1 | head 1",
            }])
        if "QueryAssessment[]" not in (request.system or ""):
            return base_model.complete(request)
        assessments = [{
            "query_id": query["query_id"],
            "question_id": query["question_id"],
            "answered_question": True,
            "material_progress": True,
            "summary": f"Observed host-1 in {query['question_id']}.",
            "new_entities": [{
                "entity_type": "host", "value": "host-1",
                "result_row_refs": query["allowed_evidence_ids"].copy(),
            }],
            "evidence_candidate_row_refs": query["allowed_evidence_ids"].copy(),
            "coverage_changes": [], "limitations": [], "proposed_next_question": None,
        } for query in context["completed_queries"]]
        if len(request.messages) == 1:
            assert len(assessments) == 2
            assessments[1]["new_entities"][0]["result_row_refs"].extend(
                assessments[0]["evidence_candidate_row_refs"]
            )
            initial_assessments.extend(assessments)
        else:
            assert [query["question_id"] for query in context["completed_queries"]] == ["q2"]
            prior = json.loads(request.messages[1]["content"])
            assert len(prior) == 1 and prior[0]["summary"] == initial_assessments[1]["summary"]
            assert prior[0]["query_id"] == "Q1"
            assert "UNAVAILABLE" in prior[0]["new_entities"][0]["result_row_refs"]
            assert "retained_evidence" not in context
            assert set(context["validation_errors"]) == {"Q1"}
            assert all(
                row["query_id"] == "Q1"
                for query in context["completed_queries"] for row in query["retained_evidence"]
            )
            if repair_output == "wrong_citation":
                assessments[0]["new_entities"][0]["result_row_refs"].extend(
                    ["E9999"]
                )
            elif repair_output == "extra_assessment":
                assessments.append({**initial_assessments[0], "summary": "Unrequested rewrite."})
            elif repair_output == "missing_assessment":
                assessments = []
            elif repair_output == "duplicate_assessment":
                assessments.append(assessments[0])
        return json.dumps({"QueryAssessment": assessments})

    model = FakeModelAdapter(responses=[response] * 6)
    engine = create_engine("sqlite+pysqlite://", poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    service = WorkflowService(
        engine,
        splunk_connector=SplunkConnector(
            SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk(),
        ),
        model_adapter=model,
        budget_limits=BudgetLimits(),
        execution_config={"provider": "fake", "model_name": "test"},
    )
    hid = str(service.create_hunt("owner-1", title="Citation repair", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    lease = service.jobs.claim("worker-1")
    assert lease is not None
    if repair_output == "correct":
        service.execute_job(lease)
    else:
        from threat_hunting.services.orchestration import ModelContractError
        with pytest.raises((Validation, ModelContractError)):
            service.execute_job(lease)
    results = service.results("owner-1", hid)
    assert results["usage"]["model_repair_attempts"] == 1
    assert len(results["queries"]) == 2
    rejection = results["assessment_validation_rejections"][0]
    assert rejection["repair_query_ids"] == [rejection["assessments"][1]["query_id"]]
    if repair_output == "correct":
        assert service.get_hunt("owner-1", hid)["state"] == "report_draft"
        assert results["query_assessments"][0] == rejection["assessments"][0]
        assert results["query_assessments"][1]["new_entities"][0]["result_row_refs"] == rejection["assessments"][1]["evidence_candidate_row_refs"]
        assert rejection["repair_outcome"] == "accepted"
        assert model.call_count == 5  # Plan, queries, assessment, one repair, synthesis.
    else:
        assert service.get_hunt("owner-1", hid)["state"] == "failed"
        assert rejection["repair_outcome"] == "rejected"
        assert model.call_count == 4  # No extra retries or synthesis of invalid assessments.


def test_assessment_citations_are_query_scoped_and_filter_before_sampling() -> None:
    from types import SimpleNamespace
    from threat_hunting.services.investigation import _assessment_context

    plan = SimpleNamespace(
        hypothesis="h", objective="o", questions=[],
        scope=SimpleNamespace(model_dump=lambda **_: {}),
    )
    results = {
        "queries": [
            {"query_id": q, "question_id": q, "status": "completed", "result_count": count}
            for q, count in [("old", 100), ("new", 1), ("empty", 0)]
        ],
        "evidence": [
            {"evidence_id": f"old-{i}", "query_id": "old", "selected_result": {}}
            for i in range(100)
        ] + [{"evidence_id": "new-row", "query_id": "new", "selected_result": {"host": "host-1"}}],
    }
    context = _assessment_context(plan, results, query_ids={"new", "empty"})
    assert {q["query_id"]: q["allowed_evidence_ids"] for q in context["completed_queries"]} == {
        "new": ["new-row"], "empty": [],
    }
    assert "retained_evidence" not in context
    assert [
        e["evidence_id"] for q in context["completed_queries"] for e in q["retained_evidence"]
    ] == ["new-row"]


class RecoverableJob(Job):
    def __init__(self) -> None:
        self.crash_on_status = True

    @property
    def content(self) -> dict[str, str]:
        if self.crash_on_status:
            raise SimulatedWorkerCrash
        return {"isDone": "1", "eventCount": "1"}


class RecoverableJobs(dict[str, RecoverableJob]):
    def __init__(self) -> None:
        super().__init__()
        self.create_calls = 0

    def create(self, _query: str, **_: object) -> Job:
        if _query.startswith("| tstats "):
            return CatalogJob()
        if _query.endswith("| fieldsummary"):
            # Planning discovery precedes the worker crash being simulated.
            return Job()
        self.create_calls += 1
        job = RecoverableJob()
        job.crash_on_status = self.create_calls == 1
        job.name = str(_.get("id", job.name))
        self[job.name] = job
        return job


class RecoverableSplunk(Splunk):
    def __init__(self) -> None:
        self.jobs = RecoverableJobs()


def test_expired_worker_resumes_recorded_sid_without_duplicate_submission() -> None:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    client = RecoverableSplunk()
    service = WorkflowService(
        engine,
        splunk_connector=SplunkConnector(
            SplunkConnectionConfig(
                endpoint="https://splunk.example",
                token="test-token",
            ),
            client=client,
        ),
        model_adapter=_model(),
        budget_limits=BudgetLimits(),
        execution_config={
            "provider": "fake",
            "model_name": "test",
            "provider_data_boundary": "local",
            "provider_data_handling_approval_ref": None,
            "spl_policy_version": "1.0",
            "splunk_poll_interval_seconds": 0.1,
        },
    )
    hunt = service.create_hunt(
        "owner-1",
        title="Recoverable execution",
        hypothesis="h",
        objective="o",
    )
    hunt_id = str(hunt["hunt_id"])
    service.discover("owner-1", hunt_id)
    service.approve("owner-1", hunt_id, "reviewed")
    service.execute("owner-1", hunt_id)
    dead_lease = service.jobs.claim("dead-worker")
    assert dead_lease is not None

    with pytest.raises(SimulatedWorkerCrash):
        service.execute_job(dead_lease)

    checkpoint = service.results("owner-1", hunt_id)
    assert checkpoint["query_ledger"][0]["status"] == "submitted"
    recorded_sid = checkpoint["query_ledger"][0]["splunk_job_id"]
    assert recorded_sid == checkpoint["query_ledger"][0]["query_id"]
    assert client.jobs.create_calls == 1

    client.jobs[recorded_sid].crash_on_status = False
    now = datetime.now(timezone.utc)
    with engine.begin() as connection:
        connection.execute(
            update(execution_jobs)
            .where(execution_jobs.c.job_id == dead_lease.job_id)
            .values(lease_expires_at_utc=now - timedelta(seconds=1))
        )
    assert service.jobs.recover_expired(now=now) == 1
    replacement = service.jobs.claim("replacement-worker", now=now)
    assert replacement is not None

    service.execute_job(replacement)

    assert client.jobs.create_calls == 2
    results = service.results("owner-1", hunt_id)
    assert results["query_ledger"][0]["status"] == "completed"
    assert results["query_ledger"][1]["status"] == "completed"
    assert results["queries"][0]["splunk_job_id"] == recorded_sid
    assert service.get_hunt("owner-1", hunt_id)["state"] == "report_draft"


@pytest.mark.parametrize("elapsed", [780, 1190])
def test_elapsed_cutoff_skips_new_queries_and_preserves_synthesis(monkeypatch: pytest.MonkeyPatch, elapsed: int) -> None:
    """Clock advancement exercises the persisted workflow without waiting 20 minutes."""
    from copy import deepcopy
    from uuid import uuid4
    from threat_hunting.services import workflow, orchestration

    clock = [datetime.now(timezone.utc)]
    start = clock[0]
    monkeypatch.setattr(workflow, "_now", lambda: clock[0])
    monkeypatch.setattr(orchestration, "_utc_now", lambda: clock[0])
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    model = _model(draft_question_ids=("q1", "q2"))
    service = WorkflowService(
        engine, model_adapter=model,
        splunk_connector=SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk()),
        budget_limits=BudgetLimits(query_start_cutoff_seconds=780, synthesis_allowance_seconds=300,
                                   max_model_call_timeout_seconds=300),
        execution_config={"provider": "fake", "model_name": "test"},
    )
    hid = str(service.create_hunt("owner-1", title="Elapsed limit", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    lease = service.jobs.claim("worker-1")
    assert lease is not None
    draft = service._draft_execution_ledger

    def two_queries(**kwargs):
        ledger = draft(**kwargs)
        second = deepcopy(ledger[0])
        second["query_id"] = str(uuid4())
        second["proposal"]["question_id"] = "q2"
        return [*ledger, second]

    monkeypatch.setattr(service, "_draft_execution_ledger", two_queries)
    execute = orchestration.ProductionHuntExecutor.execute_query

    def elapsed_after_retained_query(executor, *args, **kwargs):
        result = execute(executor, *args, **kwargs)
        clock[0] = start + timedelta(seconds=elapsed)
        return result

    monkeypatch.setattr(orchestration.ProductionHuntExecutor, "execute_query", elapsed_after_retained_query)
    complete = model.complete
    synthesis_timeouts = []

    def record_timeout(request, **kwargs):
        if "Required contract: QuestionSynthesis." in (request.system or ""):
            synthesis_timeouts.append(kwargs["timeout_seconds"])
        return complete(request, **kwargs)

    monkeypatch.setattr(model, "complete", record_timeout)
    service.execute_job(lease)
    result = service.results("owner-1", hid)
    assert service.get_hunt("owner-1", hid)["state"] == "report_draft"
    assert result["usage"]["splunk_queries"] == 1
    assert result["usage"]["model_calls"] == 2  # proposal and synthesis; no late assessment
    assert [q["status"] for q in result["query_ledger"]] == ["completed", "skipped_time_cutoff"]
    assert result["adaptive_status"] == "time_reserved_for_synthesis"
    assert len(result["evidence"]) == len(result["findings"]) == 1
    # All retained evidence fits, so final synthesis gets the remaining time
    # without reserving an unnecessary retrieval round.
    assert synthesis_timeouts == [300 if elapsed == 780 else 10]
    from threat_hunting.services.reports import _derive_report_limitations
    assert any("time cutoff" in text for text in _derive_report_limitations(result))


@pytest.mark.parametrize("interrupt_after_checkpoint,repeat_page", [(False, False), (True, False), (False, True), ("cancel", False)])
def test_synthesis_pages_checkpoint_completed_answers_and_resume_without_repeating_work(monkeypatch, interrupt_after_checkpoint, repeat_page):
    base = _model(draft_question_ids=("q1", "q2"))._responses[0]
    synthesis_questions = []

    def response(request):
        context = json.loads(request.messages[0]["content"])
        if "QueryProposal[]" in (request.system or ""):
            proposals = json.loads(base(request))
            return json.dumps([*proposals, {**proposals[0], "question_id": "q2"}])
        if "QueryAssessment[]" in (request.system or ""):
            return json.dumps([{
                "query_id": query["query_id"], "answered_question": False, "material_progress": False,
                "summary": "Retained evidence needs synthesis.", "new_entities": [],
                "evidence_candidate_row_refs": [], "coverage_changes": [],
                "limitations": ["This bounded sample does not answer the question."],
                "proposed_next_question": None,
            } for query in context["completed_queries"]])
        if "FollowUpDecision[]" in (request.system or ""):
            return json.dumps([{"question_id": question["question_id"], "proposal": None,
                                "skip_reason": "Inspect the retained events during synthesis."}
                               for question in context["follow_up_questions"]])
        if "Required contract: QuestionSynthesis." not in (request.system or ""):
            return base(request)
        synthesis_questions.append([q["question_id"] for q in context["approved_plan"]["questions"]])
        answer = json.loads(base(request))
        if len(synthesis_questions) == 1:
            answer["question_2"] = {
                "summary": "Retained context is needed.", "findings": [],
                "limitations": ["Inspect a retained page before answering."],
                "retained_evidence_requests": [{"query_ids": [context["completed_queries"][0]["query_id"]],
                                                "filters": [{"field": "host", "value": "host-1"}], "limit": 1}],
            }
        else:
            answer["question_1"] = {"summary": "The requested analysis remains limited.", "findings": [],
                                    "limitations": ["The retained event does not fully answer this question."]}
            assert context["retained_lookup_pages"][0]["matching_raw_record_count"] == 1
            assert context["retained_lookup_pages"][0]["returned_evidence_ids"]
            assert context["retained_lookup_pages"][0]["query_coverage"][0]["result_count"] == 1
            if repeat_page and len(synthesis_questions) == 2:
                answer["question_1"] = {
                    "summary": "Inspect the page again.", "findings": [], "limitations": ["Review retained context."],
                    "retained_evidence_requests": [{"query_ids": [context["completed_queries"][0]["query_id"]],
                                                    "filters": [{"field": "host", "value": "host-1"}], "limit": 1}],
                }
            elif repeat_page:
                assert "retained_evidence_requests" not in json.dumps(request.response_format)
        return json.dumps(answer)

    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    model = FakeModelAdapter(responses=[response] * 20)
    service = WorkflowService(engine, model_adapter=model,
                              splunk_connector=SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk()),
                              budget_limits=BudgetLimits(max_representative_events=1, max_targeted_events=1),
                              execution_config={"provider": "fake", "model_name": "test"})
    hid = str(service.create_hunt("owner-1", title="Recover synthesis", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    lease = service.jobs.claim("worker-1")
    update = service._update

    def crash_after_persist(*args, **kwargs):
        result = update(*args, **kwargs)
        value = kwargs.get("results", {})
        if value.get("synthesis_retrievals") and len(value.get("question_answers", [])) == 1:
            raise SystemExit("simulated worker loss after durable checkpoint")
        return result

    if interrupt_after_checkpoint:
        monkeypatch.setattr(service, "_update", crash_after_persist)
        with pytest.raises(SystemExit):
            service.execute_job(lease)
        checkpoint = service.results("owner-1", hid)
        assert len(checkpoint["question_answers"]) == len(checkpoint["findings"]) == 1
        saved_finding = checkpoint["findings"][0]
        saved_queries = checkpoint["queries"]
        monkeypatch.setattr(service, "_update", update)
        if interrupt_after_checkpoint == "cancel":
            service.cancel("owner-1", hid)
            calls = model.call_count
            with pytest.raises(Conflict, match="lease"):
                service.execute_job(lease)
            assert service.get_hunt("owner-1", hid)["state"] == "cancelled"
            assert service.results("owner-1", hid) == checkpoint
            assert model.call_count == calls
            return
    service.execute_job(lease)
    result = service.results("owner-1", hid)
    assert synthesis_questions == [["q1", "q2"], ["q2"]] + ([["q2"]] if repeat_page else [])
    assert [item["question_id"] for item in result["question_answers"]] == ["q1", "q2"]
    assert len(result["synthesis_retrievals"]) == 1
    if repeat_page:
        assert result["synthesis_retrieval_status"] == "no_new_pages"
    assert len(result["findings"]) == 1
    assert service.get_hunt("owner-1", hid)["state"] == "report_draft"
    if interrupt_after_checkpoint:
        assert result["findings"][0] == saved_finding
        assert result["queries"] == saved_queries


def test_synthesis_context_exhaustion_preserves_explicit_unanswered_question(monkeypatch):
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    model = _model()
    service = WorkflowService(engine, model_adapter=model,
                              splunk_connector=SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk()),
                              execution_config={"provider": "fake", "model_name": "test"})
    hid = str(service.create_hunt("owner-1", title="Bounded synthesis", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    lease = service.jobs.claim("worker-1")
    from threat_hunting.services import workflow
    context = workflow._synthesis_context
    monkeypatch.setattr(workflow, "_synthesis_context", lambda **kwargs: {**context(**kwargs), "advisory_context": "x" * 500_001})
    service.execute_job(lease)
    result = service.results("owner-1", hid)
    assert result["synthesis_retrieval_status"] == "budget_limited"
    assert result["findings"] == []
    assert result["question_answers"][0]["finding_ids"] == []
    assert "budget" in result["question_answers"][0]["limitations"][0]
    assert not any("Required contract: QuestionSynthesis." in (r.system or "") for r in model.requests)
    assert service.get_hunt("owner-1", hid)["state"] == "report_draft"


@pytest.mark.parametrize("context_limit,finish_reason", [(500_000, "stop"), (250_000, "stop"), (500_000, "length")])
def test_complete_retained_context_is_not_sampled_to_reserve_unneeded_retrieval(context_limit, finish_reason):
    class LargeJob(Job):
        def results(self, **kwargs):
            return [{**super().results()[0], "event_id": self.name, "message": "x" * 135_000}]

    class LargeJobs(Jobs):
        def create(self, query, **kwargs):
            if query.startswith("| tstats "):
                return CatalogJob()
            job = LargeJob()
            job.name = str(kwargs["id"])
            self[job.name] = job
            return job

    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    base = _model()._responses[0]

    def response(request):
        if finish_reason == "length" and "Required contract: QuestionSynthesis." in (request.system or ""):
            return {"text": "", "finish_reason": "length"}
        return base(request)

    model = FakeModelAdapter(responses=[response] * 8)
    client = Splunk()
    client.jobs = LargeJobs()
    service = WorkflowService(engine, model_adapter=model,
                              splunk_connector=SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=client),
                              budget_limits=BudgetLimits(max_context_characters=context_limit),
                              execution_config={"provider": "fake", "model_name": "test"})
    hid = str(service.create_hunt("owner-1", title="Complete retained context", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    service.execute_job(service.jobs.claim("worker-1"))
    result = service.results("owner-1", hid)
    assert len(result["evidence"]) == 2
    requests = [r for r in model.requests if "Required contract: QuestionSynthesis." in (r.system or "")]
    assert len(requests) == 1
    supplied = json.loads(requests[0].messages[0]["content"])
    complete = context_limit == 500_000
    assert sum(row["supplied_evidence_count"] for row in supplied["evidence_coverage"]) == (2 if complete else 1)
    assert any(row["sample_omitted"] for row in supplied["evidence_coverage"]) is not complete
    assert ("retained_evidence_requests" in json.dumps(requests[0].response_format)) is not complete
    if finish_reason == "length":
        assert result["synthesis_retrieval_status"] == "budget_limited"
        assert result["findings"] == []
        assert "budget" in result["question_answers"][0]["limitations"][0]
    assert service.get_hunt("owner-1", hid)["state"] == "report_draft"


def test_truncated_search_reaches_report_with_limitations_after_negative_finding_repair():
    base = _model()._responses[0]
    synthesis_calls = 0

    class PartialJob(Job):
        content = {"isDone": "1", "resultCount": "2"}

        def results(self, **kwargs):
            rows = [*super().results(), {"_time": "2026-01-01T00:35:00Z", "host": "host-2", "event_id": "evt-2"}]
            offset = int(kwargs.get("offset", 0))
            return rows[offset:offset + int(kwargs.get("count", 2))]

    class PartialJobs(Jobs):
        def create(self, query, **kwargs):
            if query.startswith("| tstats "):
                return CatalogJob()
            job = PartialJob()
            job.name = str(kwargs.get("id", job.name))
            self[job.name] = job
            return job

    def response(request):
        nonlocal synthesis_calls
        context = json.loads(request.messages[0]["content"])
        if "FollowUpDecision[]" in (request.system or ""):
            return json.dumps([{"question_id": question["question_id"], "proposal": None,
                                "skip_reason": "Retained results are limited."} for question in context["follow_up_questions"]])
        if "QueryProposal[]" in (request.system or ""):
            proposals = json.loads(base(request))
            proposals[0]["spl"] = "search index=main sourcetype=syslog | head 2"
            return json.dumps(proposals)
        if "Required contract: QuestionSynthesis." not in (request.system or ""):
            return base(request)
        synthesis_calls += 1
        assert context["completed_queries"][0]["truncated"] is True
        if synthesis_calls == 1:
            return json.dumps({"question_1": {"summary": "No related activity.", "limitations": [], "findings": [{
                "title": "No related activity", "classification": "not_supported_within_scope", "statement": "No related activity was present.",
                "confidence": "low", "evidence_ids": [], "query_ids": [context["completed_queries"][0]["query_id"]],
                "inference": "unknown", "limitations": ["Approved sources only."]}]}})
        assert "complete query results" in request.messages[-1]["content"]
        return json.dumps({"question_1": {"summary": "The search cannot establish absence.", "findings": [],
                                         "limitations": ["Search results were truncated; omitted rows remain unassessed."]}})

    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    client = Splunk()
    client.jobs = PartialJobs()
    service = WorkflowService(engine, model_adapter=FakeModelAdapter(responses=[response] * 20),
                              splunk_connector=SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=client),
                              execution_config={"provider": "fake", "model_name": "test"})
    hid = str(service.create_hunt("owner-1", title="Partial search", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    service.execute_job(service.jobs.claim("worker-1"))
    result = service.results("owner-1", hid)
    assert synthesis_calls == 2 and result["findings"] == []
    assert len(result["evidence"]) == 1
    assert result["usage"]["model_repair_attempts"] == 1
    assert any(check["validation_error_code"] == "query_coverage" for check in result["usage"]["model_output_checks"])
    assert service.get_hunt("owner-1", hid)["state"] == "report_draft"


def test_oversized_assessment_preserves_retained_evidence_for_final_synthesis(monkeypatch):
    from threat_hunting.services import workflow

    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    model = _model()
    service = WorkflowService(engine, model_adapter=model,
                              splunk_connector=SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk()),
                              execution_config={"provider": "fake", "model_name": "test"})
    hid = str(service.create_hunt("owner-1", title="Reserve final answer", hypothesis="h", objective="o")["hunt_id"])
    service.discover("owner-1", hid)
    service.approve("owner-1", hid, "reviewed")
    service.execute("owner-1", hid)
    lease = service.jobs.claim("worker-1")
    original = workflow._assessment_context
    monkeypatch.setattr(workflow, "_assessment_context", lambda *args, **kwargs: {
        **original(*args, **kwargs), "advisory_context": "x" * 500_001})
    service.execute_job(lease)
    result = service.results("owner-1", hid)
    assert result["adaptive_status"] == "budget_reserved_for_synthesis"
    assert len(result["evidence"]) == len(result["findings"]) == 1
    assert result["usage"]["model_calls"] == 2
    assert not any("Required contract: QueryAssessment[]." in (r.system or "") for r in model.requests)
    assert service.get_hunt("owner-1", hid)["state"] == "report_draft"
