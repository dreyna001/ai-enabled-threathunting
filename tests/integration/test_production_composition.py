from __future__ import annotations

import json

import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.budgets import BudgetLimits
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector
from threat_hunting.services.jobs import metadata as jobs_metadata
from threat_hunting.services.workflow import Conflict, WorkflowService, workflow_metadata


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Job:
    name = "sid-production-1"
    content = {"isDone": "1", "eventCount": "1"}

    def results(self, **_: object) -> list[dict[str, str]]:
        return [{"_time": "2026-01-01T00:30:00Z", "host": "host-1", "event_id": "evt-1"}]


class Jobs(dict[str, Job]):
    def create(self, _query: str, **_: object) -> Job:
        job = Job()
        self[job.name] = job
        return job


class Splunk:
    def __init__(self) -> None:
        self.jobs = Jobs()

    def get(self, path: str, **_: object) -> object:
        return {
            "data/indexes": {"entry": [{"name": "main"}]},
            "data/sourcetypes": {"entry": [{"name": "syslog", "content": {"fields": ["host", "event_id"]}}]},
            "data/fields": {"entry": [{"name": "host"}, {"name": "event_id"}]},
            "data/models": {"entry": []},
        }.get(path, {"entry": []})


def _model() -> FakeModelAdapter:
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
                "questions": [{"question_id": "q1", "question": "Which hosts generated events?", "rationale": "Identify affected hosts.", "expected_information_gain": "Host pivot."}],
                "query_strategy": ["Start with one bounded representative query."],
                "coverage_limitations": [],
                "created_at_utc": latest.isoformat().replace("+00:00", "Z"),
            })
        if "QueryProposal[]" in (request.system or ""):
            plan = context["approved_plan"]
            scope = plan["scope"]
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
        raise AssertionError("unexpected model contract")

    return FakeModelAdapter(responses=[response, response])


def test_injected_production_adapters_persist_discovery_snapshots_and_results() -> None:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    splunk = SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="test-token"), client=Splunk())
    service = WorkflowService(
        engine,
        splunk_connector=splunk,
        model_adapter=_model(),
        budget_limits=BudgetLimits(),
        execution_config={"provider": "fake", "model_name": "test", "spl_policy_version": "1.0", "splunk_poll_interval_seconds": 0.1},
    )

    hunt = service.create_hunt("owner-1", title="Production adapter", hypothesis="h", objective="o")
    discovered = service.discover("owner-1", str(hunt["hunt_id"]))
    assert discovered["state"] == "awaiting_plan_review"
    assert discovered["discovery_snapshot"]["mode"] == "production"
    assert discovered["discovery_snapshot"]["execution_config_snapshot"]["sha256"]
    assert discovered["plan"]["execution_config_snapshot_id"]
    assert discovered["discovery_snapshot"]["execution_config_snapshot"]["payload"]["budget_limits"]["max_model_calls"] == 12
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
    assert result["evidence"][0]["selected_result"]["host"] == "host-1"
    assert service.get_hunt("owner-1", str(hunt["hunt_id"]))["state"] == "report_draft"
