"""WorkflowService test fakes adapted from production composition tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import uuid4

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.budgets import BudgetLimits
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector
from threat_hunting.services.jobs import metadata as jobs_metadata
from threat_hunting.services.workflow import WorkflowService, workflow_metadata

from known_answer.bindings import ScenarioBinding

OWNER = "known-answer-owner"
WORKER = "known-answer-worker"
NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _real_id(abstract: str) -> str:
    return f"fixture-{abstract}"


class SimulatedWorkerCrash(BaseException):
    """Deterministic worker-loss marker reused from production composition tests."""


class Job:
    name = "sid-known-answer"
    content = {"isDone": "1", "eventCount": "1"}

    def results(self, **_: object) -> list[dict[str, str]]:
        return [{"_time": "2026-01-01T00:30:00Z", "host": "host-1", "event_id": "evt-default"}]


class CatalogJob(Job):
    name = "catalog-job"
    content = {"isDone": "1", "eventCount": "1"}

    def results(self, **_: object) -> list[dict[str, str]]:
        return [{"sourcetype": "syslog", "count": "1"}]


class BoundEventJob(Job):
    def __init__(self, *, event_id: str, host: str = "host-ka") -> None:
        self.name = str(uuid4())
        self.event_id = event_id
        self.host = host

    def results(self, **_: object) -> list[dict[str, str]]:
        return [{
            "_time": "2026-01-01T00:30:00Z",
            "host": self.host,
            "event_id": self.event_id,
        }]


class Jobs(dict[str, Job]):
    def __init__(self, *, event_id: str, host: str = "host-ka") -> None:
        super().__init__()
        self.event_id = event_id
        self.host = host

    def create(self, _query: str, **kwargs: object) -> Job:
        if _query.startswith("| tstats "):
            return CatalogJob()
        job = BoundEventJob(event_id=self.event_id, host=self.host)
        job.name = str(kwargs.get("id", job.name))
        self[job.name] = job
        return job


class Splunk:
    def __init__(self, *, event_id: str = "evt-default", host: str = "host-ka") -> None:
        self.event_id = event_id
        self.host = host
        self.jobs = Jobs(event_id=event_id, host=host)

    def get(self, path: str, **_: object) -> object:
        return {
            "authentication/current-context": {"entry": [{"content": {"roles": ["searcher"]}}]},
            "authorization/roles/searcher": {"entry": [{"name": "searcher", "content": {"srchIndexesAllowed": ["main"]}}]},
            "data/indexes": {"entry": [{"name": "main"}]},
            "saved/sourcetypes": {"entry": [{"name": "syslog", "content": {"fields": ["host", "event_id"]}}]},
            "data/fields": {"entry": [{"name": "host"}, {"name": "event_id"}]},
            "data/models": {"entry": []},
        }.get(path, {"entry": []})


class RecoverableJob(BoundEventJob):
    def __init__(self, *, event_id: str, host: str = "host-ka") -> None:
        super().__init__(event_id=event_id, host=host)
        self.crash_on_status = True

    @property
    def content(self) -> dict[str, str]:  # type: ignore[override]
        if self.crash_on_status:
            raise SimulatedWorkerCrash
        return {"isDone": "1", "eventCount": "1"}


class RecoverableJobs(Jobs):
    def __init__(self, *, event_id: str, host: str) -> None:
        super().__init__(event_id=event_id)
        self.host = host
        self.create_calls = 0

    def create(self, _query: str, **kwargs: object) -> Job:
        if _query.startswith("| tstats "):
            return CatalogJob()
        if _query.endswith("| fieldsummary"):
            return BoundEventJob(event_id=self.event_id, host=self.host)
        self.create_calls += 1
        job = RecoverableJob(event_id=self.event_id, host=self.host)
        job.crash_on_status = self.create_calls == 1
        job.name = str(kwargs.get("id", job.name))
        self[job.name] = job
        return job


class RecoverableSplunk(Splunk):
    def __init__(self, *, event_id: str, host: str) -> None:
        super().__init__(event_id=event_id, host=host)
        self.jobs = RecoverableJobs(event_id=event_id, host=host)


class HangingJob(BoundEventJob):
    content = {"isDone": "0", "eventCount": "0"}


class HangingJobs(Jobs):
    def __init__(self, *, event_id: str, host: str) -> None:
        super().__init__(event_id=event_id)
        self.host = host

    def create(self, _query: str, **kwargs: object) -> Job:
        if _query.startswith("| tstats "):
            return CatalogJob()
        job = HangingJob(event_id=self.event_id, host=self.host)
        job.name = str(kwargs.get("id", job.name))
        self[job.name] = job
        return job


class HangingSplunk(Splunk):
    def __init__(self, *, event_id: str, host: str) -> None:
        super().__init__(event_id=event_id, host=host)
        self.jobs = HangingJobs(event_id=event_id, host=host)


def create_workflow_service(
    *,
    splunk_client: object,
    model: FakeModelAdapter,
    budget_limits: BudgetLimits | None = None,
) -> WorkflowService:
    engine = create_engine(
        "sqlite+pysqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    return WorkflowService(
        engine,
        splunk_connector=SplunkConnector(
            SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"),
            client=splunk_client,
        ),
        model_adapter=model,
        budget_limits=budget_limits or BudgetLimits(),
        execution_config={
            "provider": "fake",
            "model_name": "test",
            "provider_data_boundary": "local",
            "provider_data_handling_approval_ref": None,
            "spl_policy_version": "1.0",
            "splunk_poll_interval_seconds": 0.01,
        },
    )


def primary_fixture_event(binding: ScenarioBinding, case: dict[str, Any]) -> tuple[str, str]:
    events = [event for event in case.get("events", []) if isinstance(event, dict)]
    if not events:
        return _real_id("ka01-e1"), "host-default"
    event = events[0]
    abstract = str(event["evidence_id"])
    return binding.evidence_id_map[abstract], str(event.get("host", "host-ka"))


def build_scenario_model(
    binding: ScenarioBinding,
    case: dict[str, Any],
    *,
    repair_contract: str | None = None,
) -> FakeModelAdapter:
    """Return a deterministic model adapter for one bound known-answer scenario."""

    fixture_event_id, fixture_host = primary_fixture_event(binding, case)
    repair_remaining = repair_contract is not None

    def response(request: Any) -> str:
        nonlocal repair_remaining
        context = json.loads(request.messages[0]["content"])
        system = request.system or ""
        if "HuntPlan" in system:
            latest = NOW.replace(microsecond=0)
            earliest = latest - timedelta(hours=1)
            ids = context["application_assigned_ids"]
            return json.dumps({
                "schema_version": "1.0",
                "plan_id": ids["plan_id"],
                "plan_version": 1,
                "hunt_id": context["hunt_id"],
                "discovery_snapshot_id": ids["discovery_snapshot_id"],
                "execution_config_snapshot_id": ids["execution_config_snapshot_id"],
                "hypothesis": context["hypothesis"],
                "objective": context["objective"],
                "scope": {
                    "earliest_utc": earliest.isoformat().replace("+00:00", "Z"),
                    "latest_utc": latest.isoformat().replace("+00:00", "Z"),
                    "indexes": ["main"],
                    "sourcetypes": ["syslog"],
                },
                "intelligence_refs": [],
                "data_sources": [{"index": "main", "sourcetypes": ["syslog"], "purpose": "scenario"}],
                "questions": [{
                    "question_id": "q1",
                    "question": str(case.get("hypothesis", "Inspect scoped activity.")),
                    "rationale": "Validate the bound fixture event.",
                    "expected_information_gain": "Confirm retained evidence.",
                }],
                "query_strategy": ["Run one bounded search against the bound fixture event."],
                "coverage_limitations": [],
                "created_at_utc": latest.isoformat().replace("+00:00", "Z"),
            })
        if repair_contract and repair_contract in system and repair_remaining:
            repair_remaining = False
            return "not-json"
        if "QueryProposal[]" in system:
            scope = context["approved_plan"]["scope"]
            return json.dumps([{
                "question_id": "q1",
                "purpose": "Find the bound fixture event.",
                "expected_information_gain": "Retain scenario evidence.",
                "spl": f'search index=main sourcetype=syslog {binding.identity_field}="{fixture_event_id}" | head 1',
                "earliest_utc": scope["earliest_utc"],
                "latest_utc": scope["latest_utc"],
                "indexes": ["main"],
                "sourcetypes": ["syslog"],
                "requested_fields": ["host", binding.identity_field],
                "result_mode": "representative",
                "max_results": 1,
            }])
        if "QueryAssessment[]" in system:
            query = context["completed_queries"][0]
            evidence = query["retained_evidence"][0]
            observed_host = evidence["selected_result"].get("host", fixture_host)
            return json.dumps([{
                "query_id": query["query_id"],
                "question_id": query["question_id"],
                "answered_question": True,
                "material_progress": True,
                "summary": "The bound fixture event was retained.",
                "new_entities": [{
                    "entity_type": "host",
                    "value": observed_host,
                    "result_row_refs": [evidence["evidence_id"]],
                }],
                "evidence_candidate_row_refs": [evidence["evidence_id"]],
                "coverage_changes": [],
                "limitations": [],
                "proposed_next_question": None,
            }])
        if "FollowUpDecision[]" in system:
            return json.dumps([
                {
                    "question_id": question["question_id"],
                    "proposal": None,
                    "skip_reason": "Inspect retained events during synthesis.",
                }
                for question in context.get("follow_up_questions", [])
            ])
        if "Required contract: QuestionSynthesis." in system:
            retained = context.get("retained_evidence", [])
            if not retained:
                return json.dumps({
                    "question_1": {
                        "summary": "No evidence was retained before the hunt stopped.",
                        "findings": [],
                        "limitations": ["The configured budget stopped execution before evidence was retained."],
                    },
                })
            evidence = retained[0]
            query = context["completed_queries"][0] if context.get("completed_queries") else {"query_id": evidence["query_id"]}
            finding = {
                "title": "Bound fixture event observed",
                "classification": "supported_observation",
                "statement": "The completed query retained the bound fixture event.",
                "confidence": "low",
                "evidence_ids": [evidence["evidence_id"]],
                "query_ids": [query["query_id"]],
                "inference": "unknown",
                "limitations": [],
            }
            return json.dumps({
                "question_1": {
                    "summary": "The bound fixture event was retained.",
                    "findings": [finding],
                    "limitations": [],
                },
            })
        raise AssertionError(f"unexpected model contract: {system}")

    return FakeModelAdapter(responses=[response] * 32)


def prepare_queued_hunt(
    service: WorkflowService,
    *,
    hypothesis: str,
    objective: str = "Validate deterministic fault behavior.",
) -> tuple[str, Any]:
    hunt = service.create_hunt(OWNER, title="Known-answer fault", hypothesis=hypothesis, objective=objective)
    hunt_id = str(hunt["hunt_id"])
    service.discover(OWNER, hunt_id)
    service.approve(OWNER, hunt_id, "reviewed")
    service.execute(OWNER, hunt_id)
    lease = service.jobs.claim(WORKER)
    assert lease is not None
    return hunt_id, lease


def append_planned_query(service: WorkflowService, hunt_id: str) -> Callable[[], None]:
    """Return a restore callback after forcing a second planned query into the ledger."""

    original = service._draft_execution_ledger

    def draft_with_second_query(**kwargs: object) -> list[dict[str, object]]:
        ledger = original(**kwargs)  # type: ignore[arg-type]
        if len(ledger) >= 2:
            return ledger
        second = json.loads(json.dumps(ledger[0]))
        second["query_id"] = str(uuid4())
        return [*ledger, second]

    service._draft_execution_ledger = draft_with_second_query  # type: ignore[method-assign]

    def restore() -> None:
        service._draft_execution_ledger = original  # type: ignore[method-assign]

    return restore
