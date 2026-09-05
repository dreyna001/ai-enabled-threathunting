from __future__ import annotations

from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import HuntPlan, QueryProposal, ResultMode
from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector
from threat_hunting.services.orchestration import (
    ImmutableSnapshot,
    ModelContractError,
    ProductionHuntExecutor,
    ProductionOrchestrator,
    StrictModelRunner,
    sha256_json,
)
from threat_hunting.domain.spl_policy import SPLPolicy


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _plan() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "plan_id": str(uuid4()),
        "plan_version": 1,
        "hunt_id": str(uuid4()),
        "discovery_snapshot_id": str(uuid4()),
        "execution_config_snapshot_id": str(uuid4()),
        "hypothesis": "A process may be suspicious.",
        "objective": "Determine whether it is supported by telemetry.",
        "scope": {
            "earliest_utc": "2026-01-01T00:00:00Z",
            "latest_utc": "2026-01-01T01:00:00Z",
            "indexes": ["main"],
            "sourcetypes": ["sysmon"],
        },
        "intelligence_refs": [],
        "data_sources": [{"index": "main", "sourcetypes": ["sysmon"], "purpose": "process events"}],
        "questions": [{
            "question_id": "q1",
            "question": "Which hosts show the behavior?",
            "rationale": "Find affected hosts.",
            "expected_information_gain": "Host pivots.",
        }],
        "query_strategy": ["Start with a bounded search."],
        "coverage_limitations": [],
        "created_at_utc": "2026-01-01T00:00:00Z",
    }


def test_strict_runner_repairs_once_and_accounts_for_both_calls() -> None:
    adapter = FakeModelAdapter(responses=["not-json", json.dumps(_plan())])
    counters = BudgetCounters()
    runner = StrictModelRunner(adapter, counters=counters)

    result = runner.run(HuntPlan, user_payload={"facts": "untrusted"})

    assert result.plan_version == 1
    assert counters.model_calls == 2
    assert counters.model_repair_attempts == 1
    assert adapter.call_count == 2
    assert len(adapter.requests) == 2


def test_strict_runner_stops_after_one_repair() -> None:
    adapter = FakeModelAdapter(responses=["not-json", "still-not-json"])
    runner = StrictModelRunner(adapter)

    with pytest.raises(ModelContractError) as error:
        runner.run(HuntPlan, user_payload={"facts": "untrusted"})

    assert error.value.attempts == 2
    assert runner.counters.model_calls == 2


def test_execution_snapshot_rejects_secret_material_and_is_hashed() -> None:
    orchestrator = ProductionOrchestrator.__new__(ProductionOrchestrator)
    with pytest.raises(ValueError):
        orchestrator.execution_snapshot({"model": "gpt", "api_key": "secret"})

    snapshot = orchestrator.execution_snapshot({"model": "gpt", "policy": "1.0"})
    assert isinstance(snapshot, ImmutableSnapshot)
    assert snapshot.sha256 == sha256_json({"kind": "execution_configuration", "payload": snapshot.payload})
    exported = snapshot.to_dict()
    exported["payload"]["model"] = "tampered"
    assert snapshot.payload["model"] == "gpt"


class FakeJob:
    def __init__(self) -> None:
        self.name = "sid-1"
        self.content = {"isDone": "1"}

    def results(self, **_: object) -> list[dict[str, object]]:
        return [{"_time": "2026-01-01T00:10:00Z", "host": "host-1", "event_id": "evt-1"}]


class FakeJobs(dict[str, FakeJob]):
    def create(self, _query: str, **_: object) -> FakeJob:
        self["sid-1"] = FakeJob()
        return self["sid-1"]


class FakeSplunk:
    def __init__(self) -> None:
        self.jobs = FakeJobs()


def _executor() -> ProductionHuntExecutor:
    connector = SplunkConnector(
        SplunkConnectionConfig(endpoint="https://splunk.example", token="unit-test-token"),
        client=FakeSplunk(),
    )
    policy = SPLPolicy(
        discovered_indexes={"main"},
        discovered_sourcetypes={"sysmon"},
        discovered_fields={"host", "event_id"},
        approved_indexes={"main"},
        approved_sourcetypes={"sysmon"},
        approved_earliest_utc=NOW,
        approved_latest_utc=datetime(2026, 1, 2, tzinfo=timezone.utc),
        connection_id="splunk-1",
        execution_config_snapshot_id="snapshot-1",
    )
    return ProductionHuntExecutor(connector, policy)


def _proposal() -> QueryProposal:
    return QueryProposal(
        question_id="q1",
        purpose="Find one representative process event.",
        expected_information_gain="Identify affected host.",
        spl="search index=main sourcetype=sysmon | head 1",
        earliest_utc=NOW,
        latest_utc=datetime(2026, 1, 2, tzinfo=timezone.utc),
        indexes=["main"],
        sourcetypes=["sysmon"],
        requested_fields=["host", "event_id"],
        result_mode=ResultMode.REPRESENTATIVE,
        max_results=1,
    )


def test_production_executor_validates_before_submit_and_retains_hashed_evidence() -> None:
    executor = _executor()
    execution = executor.execute_query(_proposal())
    assert execution.splunk_job_id == "sid-1"
    assert executor.counters.splunk_queries == 1
    evidence = executor.evidence_for_query(execution, hunt_id=uuid4(), proposal=_proposal())
    assert len(evidence) == 1
    assert evidence[0].sha256 == sha256_json(evidence[0].selected_result)


def test_production_executor_never_submits_policy_rejected_spl() -> None:
    executor = _executor()
    proposal = _proposal()
    proposal = proposal.model_copy(update={"spl": "search index=other sourcetype=sysmon | head 1"})

    with pytest.raises(AdapterError) as error:
        executor.execute_query(proposal)
    assert error.value.category is FailureCategory.QUERY_POLICY_REJECTED
    assert executor.counters.splunk_queries == 0

