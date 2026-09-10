from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from pydantic import BaseModel, TypeAdapter

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import HuntPlan, QueryProposal, ResultMode
from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector, SplunkDiscovery
from threat_hunting.services.orchestration import (
    ImmutableSnapshot,
    ModelContractError,
    ProductionHuntExecutor,
    ProductionOrchestrator,
    StrictModelRunner,
    sha256_json,
)
from threat_hunting.domain.spl_policy import SPLPolicy
from threat_hunting.services.threat_intel import intelligence_sources


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_request_budget_counts_model_text_without_http_json_escaping():
    class Answer(BaseModel):
        value: str

    model = FakeModelAdapter(responses=['{"value":"ok"}'])
    runner = StrictModelRunner(model, limits=BudgetLimits(max_context_characters=30_000, max_model_input_tokens=30_000))
    assert runner.run(Answer, user_payload={"retained_text": '"' * 10_000}).value == "ok"
    assert model.call_count == 1
    assert len(model.requests[0].messages[0]["content"]) > 20_000


def test_multibyte_input_still_respects_byte_estimate_when_character_limit_fits():
    class Answer(BaseModel):
        value: str

    model = FakeModelAdapter(responses=[])
    runner = StrictModelRunner(model, limits=BudgetLimits(max_context_characters=30_000, max_model_input_tokens=15_000))
    with pytest.raises(AdapterError, match="input budget"):
        runner.run(Answer, user_payload={"retained_text": "é" * 10_000})
    assert model.call_count == 0


def test_model_checks_record_actual_usage_for_invalid_output_and_its_repair():
    model = FakeModelAdapter(responses=[
        {"text": "not-json", "usage": {"input_tokens": 91, "output_tokens": 23}},
        {"text": json.dumps(_plan()), "usage": {"input_tokens": 141, "output_tokens": 10}},
    ])
    runner = StrictModelRunner(model)
    runner.run(HuntPlan, user_payload={"facts": "test input"})
    checks = runner.counters.model_output_checks
    assert [(check.input_tokens, check.output_tokens) for check in checks] == [(91, 23), (141, 10)]
    assert all(check.estimated_input_tokens >= check.input_tokens for check in checks)
    assert all(check.context_characters > 0 for check in checks)
    assert runner.counters.model_input_tokens == 232
    assert runner.counters.model_output_tokens == 33


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


def test_plan_source_reference_failure_repairs_to_application_owned_binding():
    original = _plan()
    original["intelligence_refs"] = ["invented-advisory-document"]
    repaired = {key: value for key, value in original.items() if key != "intelligence_refs"}
    sources = intelligence_sources(str(original["hunt_id"]), "Supplied advisory text")
    model = FakeModelAdapter(responses=[json.dumps(original), json.dumps(repaired)])
    runner = StrictModelRunner(model)
    result = runner.run(HuntPlan, user_payload={"analyst_supplied_context": {"intelligence_sources": sources}})
    assert result.intelligence_refs == [sources[0]["source_id"]]
    assert runner.counters.model_repair_attempts == 1
    assert "plan intelligence reference" in model.requests[-1].messages[-1]["content"]


def test_empty_advisory_context_does_not_create_a_plan_source():
    output = {key: value for key, value in _plan().items() if key != "intelligence_refs"}
    runner = StrictModelRunner(FakeModelAdapter(responses=[json.dumps(output)]))
    assert runner.run(HuntPlan, user_payload={}).intelligence_refs == []


@pytest.mark.parametrize("finish_reason", ["length", "max_tokens"])
@pytest.mark.parametrize("text", ["", '{"plan_id":', json.dumps(_plan())])
def test_token_cutoff_is_not_json_repaired(finish_reason: str, text: str) -> None:
    adapter = FakeModelAdapter(responses=[{
        "text": text,
        "finish_reason": finish_reason,
        "usage": {"input_tokens": 10, "output_tokens": 8000, "total_tokens": 8010},
    }])
    runner = StrictModelRunner(adapter)
    with pytest.raises(AdapterError, match="token limit") as error:
        runner.run(HuntPlan, user_payload={})
    assert error.value.category == FailureCategory.BUDGET_EXHAUSTED
    assert adapter.call_count == 1
    assert runner.counters.model_repair_attempts == 0
    assert runner.counters.failed_model_calls == 1
    assert runner.counters.model_output_tokens == 8000
    assert "for HuntPlan" in str(error.value)
    assert "input_tokens=10, output_tokens=8000" in str(error.value)
    assert f"visible_characters={len(text)}" in str(error.value)
    if text:
        assert text not in str(error.value)


def test_explicit_repair_cutoff_identifies_contract_without_exposing_output() -> None:
    private_output = "private telemetry must not appear in the job error"
    adapter = FakeModelAdapter(responses=[{
        "text": private_output,
        "finish_reason": "length",
        "usage": {"input_tokens": 20, "output_tokens": 8000, "total_tokens": 8020},
    }])
    runner = StrictModelRunner(adapter)
    with pytest.raises(AdapterError, match=r"for QueryProposal\[\]") as error:
        runner.repair_once(
            TypeAdapter(list[QueryProposal]), user_payload={}, previous_output=[],
            repair_instruction="Repair structure only.", contract_name="QueryProposal[]",
        )
    assert private_output not in str(error.value)
    assert "input_tokens=20, output_tokens=8000" in str(error.value)
    assert adapter.call_count == 1


def test_configured_output_limit_applies_to_initial_and_repair_calls() -> None:
    adapter = FakeModelAdapter(responses=["not-json", json.dumps(_plan())])
    runner = StrictModelRunner(adapter, limits=BudgetLimits(max_model_output_tokens_per_call=24000))
    runner.run(HuntPlan, user_payload={})
    assert [request.max_output_tokens for request in adapter.requests] == [24000, 24000]


def test_strict_runner_policy_repair_is_one_bounded_call() -> None:
    proposal = _proposal().model_dump(mode="json")
    repaired = {**proposal, "spl": "search index=main sourcetype=sysmon | head 1"}
    adapter = FakeModelAdapter(responses=[json.dumps([repaired])])
    runner = StrictModelRunner(adapter)

    result = runner.repair_once(
        TypeAdapter(list[QueryProposal]),
        user_payload={"approved_scope": {"indexes": ["main"]}},
        previous_output=[{**proposal, "spl": "search index=other sourcetype=sysmon | head 1"}],
        repair_instruction="Repair reason code index_outside_scope only; return JSON.",
        contract_name="QueryProposal[]",
    )

    assert result == [QueryProposal.model_validate(repaired)]
    assert adapter.call_count == 1
    assert runner.counters.model_repair_attempts == 1
    assert "index_outside_scope" in adapter.requests[0].messages[-1]["content"]


def test_strict_runner_accepts_exact_contract_named_wrapper_for_root_list() -> None:
    proposal = _proposal().model_dump(mode="json")
    adapter = FakeModelAdapter(responses=[json.dumps({"QueryProposal": [proposal]})])

    result = StrictModelRunner(adapter).run(
        TypeAdapter(list[QueryProposal]),
        user_payload={"facts": "untrusted"},
        contract_name="QueryProposal[]",
    )

    assert result == [QueryProposal.model_validate(proposal)]


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


def test_production_discovery_samples_only_after_a_scope_is_proposed() -> None:
    class DiscoveryConnector:
        def __init__(self) -> None:
            self.kwargs: dict[str, object] | None = None

        def discover(self, **kwargs: object) -> SplunkDiscovery:
            self.kwargs = kwargs
            return SplunkDiscovery(
                discovered_at_utc=NOW,
                indexes=("main",),
                sourcetypes=("sysmon",),
                fields=("host",),
                representative_schemas={},
                time_coverage={"main": {"earliest": "2026-01-01T00:00:00Z", "latest": "2026-01-02T00:00:00Z"}},
                accelerated_data_models=(),
                tstats_available=None,
                coverage_limitations=(),
                errors=(),
                complete=True,
            )

    connector = DiscoveryConnector()
    orchestrator = ProductionOrchestrator(connector, FakeModelAdapter())  # type: ignore[arg-type]
    discovery, snapshot = orchestrator.discover()

    assert discovery.indexes == ("main",)
    assert snapshot.kind == "splunk_discovery"
    assert connector.kwargs == {"include_indexed_sources": True}
    plan = HuntPlan.model_validate(_plan())
    _, scoped_snapshot = orchestrator.discover(plan=plan)
    assert connector.kwargs == {
        "approved_indexes": ["main"], "approved_sourcetypes": ["sysmon"],
        "source_pairs": [("main", "sysmon")], "earliest_utc": NOW,
        "latest_utc": NOW + timedelta(hours=1),
        "include_indexed_sources": True,
    }
    assert scoped_snapshot.payload["schema_requested_scope"]["earliest_utc"] == "2026-01-01T00:00:00Z"
    assert scoped_snapshot.snapshot_id != snapshot.snapshot_id
    plan.scope.latest_utc = NOW + timedelta(days=30)
    _, long_scope = orchestrator.discover(plan=plan)
    assert connector.kwargs["earliest_utc"] == NOW + timedelta(days=23)
    assert long_scope.payload["schema_requested_scope"]["earliest_utc"] == "2026-01-01T00:00:00Z"


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


def test_execution_sends_the_approved_window_as_splunk_search_job_parameters() -> None:
    class BoundedJobs(FakeJobs):
        def create(self, query, **kwargs):
            # The SDK forwards these names unchanged; the server ignores the
            # unsupported earliest/latest aliases used by the original bug.
            assert kwargs["earliest_time"] == "2026-01-01T00:00:00Z"
            assert kwargs["latest_time"] == "2026-01-02T00:00:00Z"
            assert "earliest" not in kwargs and "latest" not in kwargs
            return super().create(query, **kwargs)

    executor = _executor()
    executor.connector = SplunkConnector(
        SplunkConnectionConfig(endpoint="https://splunk.example", token="unit-test-token"),
        client=type("BoundedSplunk", (), {"jobs": BoundedJobs()})(),
    )
    assert executor.execute_query(_proposal()).rows


@pytest.mark.parametrize("spl", [
    "search index=other sourcetype=sysmon | head 1",
    "search index=main sourcetype=sysmon invented=anything | head 1",
    "search index=main sourcetype=sysmon | where isnull(invented) | head 1",
    'search index=main sourcetype=sysmon | where searchmatch("invented=x") | head 1',
    'search index=main sourcetype=sysmon | eval data=lookup("outside.csv", host) | head 1',
])
def test_production_executor_never_submits_policy_rejected_spl(spl: str) -> None:
    executor = _executor()
    client = FakeSplunk()
    executor.connector = SplunkConnector(
        SplunkConnectionConfig(endpoint="https://splunk.example", token="unit-test-token"), client=client,
    )
    proposal = _proposal()
    proposal = proposal.model_copy(update={"spl": spl})

    with pytest.raises(AdapterError) as error:
        executor.execute_query(proposal)
    assert error.value.category is FailureCategory.QUERY_POLICY_REJECTED
    assert executor.counters.splunk_queries == 0
    assert not client.jobs


def test_production_executor_reports_exact_policy_rejection_reasons() -> None:
    executor = _executor()
    proposal = _proposal().model_copy(update={"spl": "search index=other sourcetype=sysmon | head 1"})
    rejected: list[object] = []
    executor.on_rejected = lambda _proposal, validation: rejected.append(validation)

    with pytest.raises(AdapterError):
        executor.execute_query(proposal)

    assert rejected
    assert rejected[0].reason_codes == ["index_metadata_mismatch"]
    assert executor.counters.splunk_queries == 0



class PollingConnector:
    def __init__(self, statuses: list[dict[str, object]]) -> None:
        self.statuses = statuses
        self.status_calls = 0
        self.fetch_calls = 0
        self.cancelled: list[str] = []

    def submit(self, _query: str, **_: object) -> str:
        return "sid-poll"

    def status(self, _job_id: str, **_: object) -> dict[str, object]:
        self.status_calls += 1
        return self.statuses[min(self.status_calls - 1, len(self.statuses) - 1)]

    def fetch_results(self, _job_id: str, **_: object) -> list[dict[str, object]]:
        self.fetch_calls += 1
        return [{"host": "host-poll", "event_id": "evt-poll"}]

    def cancel(self, job_id: str, **_: object) -> bool:
        self.cancelled.append(job_id)
        return True


class PagedConnector(PollingConnector):
    def __init__(self, count: int, *, report_count: bool = True) -> None:
        super().__init__([{"isDone": "1", **({"resultCount": str(count)} if report_count else {})}])
        self.rows = [{"event_id": f"evt-{i}", "host": "host-1"} for i in range(count)]
        self.pages: list[tuple[int, int]] = []

    def fetch_results(self, _job_id: str, page: int = 0, limit: int = 100, **_: object) -> list[dict[str, object]]:
        self.pages.append((page, limit))
        return self.rows[page * limit:(page + 1) * limit]


@pytest.mark.parametrize("count,cap,retained,truncated", [
    (1207, 10_000, 1207, False), (1250, 1250, 1250, False),
    (1600, 1250, 1250, True), (10_050, 10_000, 10_000, True), (0, 10_000, 0, False),
])
def test_paged_query_retains_order_without_duplicates_and_counts_one_search(count, cap, retained, truncated):
    connector = PagedConnector(count)
    executor = ProductionHuntExecutor(connector, _executor().policy)
    proposal = _proposal().model_copy(update={"spl": "search index=main sourcetype=sysmon", "max_results": cap})

    result = executor.execute_query(proposal)

    assert list(result.rows) == connector.rows[:retained]
    assert result.truncated is truncated
    assert result.available_result_count == count
    assert result.retrieval_stop_reason == ("query_row_limit" if truncated else None)
    assert all(limit == 500 for _, limit in connector.pages)
    assert executor.counters.splunk_queries == 1
    assert executor.counters.cached_rows == retained
    assert result.result_bytes == len(json.dumps(result.rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())
    assert executor.counters.cached_bytes == result.result_bytes


def test_paged_query_preserves_fixed_offsets_at_remaining_hunt_limit():
    connector = PagedConnector(1500)
    counters = BudgetCounters(cached_rows=48_750)
    executor = ProductionHuntExecutor(connector, _executor().policy, counters=counters)
    result = executor.execute_query(_proposal().model_copy(update={"max_results": 10_000}))
    assert list(result.rows) == connector.rows[:1250]
    assert connector.pages == [(0, 500), (1, 500), (2, 500)]
    assert result.retrieval_stop_reason == "hunt_row_limit"
    assert counters.cached_rows == 50_000
    with pytest.raises(AdapterError) as error:
        executor.execute_query(_proposal())
    assert error.value.category is FailureCategory.BUDGET_EXHAUSTED
    assert counters.splunk_queries == 1


@pytest.mark.parametrize("count,cap,truncated", [(501, 1000, False), (1000, 1000, True)])
def test_paging_without_server_total_discloses_uncertain_cap(count, cap, truncated):
    connector = PagedConnector(count, report_count=False)
    result = ProductionHuntExecutor(connector, _executor().policy).execute_query(
        _proposal().model_copy(update={"max_results": cap})
    )
    assert len(result.rows) == count
    assert result.available_result_count is None
    assert result.truncated is truncated
    assert result.retrieval_stop_reason == ("query_row_limit" if truncated else None)


def test_short_page_contradicting_server_total_remains_incomplete():
    connector = PagedConnector(1200)
    connector.rows = connector.rows[:501]
    result = ProductionHuntExecutor(connector, _executor().policy).execute_query(
        _proposal().model_copy(update={"max_results": 10_000})
    )
    assert len(result.rows) == 501
    assert result.truncated
    assert result.retrieval_stop_reason == "incomplete_page"


@pytest.mark.parametrize("category,reason", [
    (FailureCategory.HARD_TIMEOUT, "query_timeout"),
    (FailureCategory.BUDGET_EXHAUSTED, "query_byte_limit"),
])
def test_later_page_failure_keeps_prior_rows_with_explicit_limit(category, reason):
    connector = PagedConnector(1200)
    fetch = connector.fetch_results

    def fail_second_page(job_id, page=0, **kwargs):
        if page == 1:
            raise AdapterError(category, "Page could not be retained", operation="fetch_results")
        return fetch(job_id, page=page, **kwargs)

    connector.fetch_results = fail_second_page
    executor = ProductionHuntExecutor(connector, _executor().policy)
    result = executor.execute_query(_proposal().model_copy(update={"max_results": 10_000}))
    assert list(result.rows) == connector.rows[:500]
    assert result.truncated
    assert result.retrieval_stop_reason == reason
    assert executor.counters.cached_rows == 500


def test_late_page_is_not_accepted_and_prior_pages_survive(monkeypatch):
    from threat_hunting.services import orchestration

    clock = [NOW]
    monkeypatch.setattr(orchestration, "_utc_now", lambda: clock[0])
    connector = PagedConnector(1200)
    fetch = connector.fetch_results

    def late_page(job_id, page=0, **kwargs):
        if page == 1:
            clock[0] = NOW + timedelta(seconds=121)
        return fetch(job_id, page=page, **kwargs)

    connector.fetch_results = late_page
    result = ProductionHuntExecutor(connector, _executor().policy).execute_query(
        _proposal().model_copy(update={"max_results": 10_000})
    )
    assert len(result.rows) == 500
    assert result.retrieval_stop_reason == "query_timeout"


def test_paging_never_exceeds_remaining_hunt_bytes():
    connector = PagedConnector(600)
    limits = BudgetLimits()
    counters = BudgetCounters(cached_bytes=limits.max_cached_bytes_per_hunt - 100)
    result = ProductionHuntExecutor(connector, _executor().policy, counters=counters).execute_query(
        _proposal().model_copy(update={"max_results": 10_000})
    )
    assert len(result.rows) > 0
    assert result.result_bytes <= 100
    assert result.retrieval_stop_reason == "hunt_byte_limit"
    assert counters.cached_bytes <= limits.max_cached_bytes_per_hunt


def test_paged_results_and_budget_stop_are_checkpointed_once_with_executed_spl():
    from copy import deepcopy
    from types import SimpleNamespace
    from threat_hunting.services.workflow import WorkflowService

    proposal = _proposal().model_copy(update={
        "spl": "search index=main sourcetype=sysmon | table host event_id", "max_results": 1250,
    })
    query_id, second_id = str(uuid4()), str(uuid4())
    row = {"results": {"query_ledger": [
        {"query_id": identifier, "status": "planned", "proposal": proposal.model_dump(mode="json")}
        for identifier in (query_id, second_id)
    ]}}
    service = SimpleNamespace(_owned_row=lambda *_: deepcopy(row), _update=lambda *_, **values: row.update(values))
    counters = BudgetCounters(splunk_queries=49)
    connector = PagedConnector(1600)
    executor = ProductionHuntExecutor(connector, _executor().policy, counters=counters)
    lease = SimpleNamespace(owner_id="owner", hunt_id=str(uuid4()))
    for _ in range(2):
        WorkflowService._run_checkpoint_queries(service, lease=lease, executor=executor, counters=counters, require_lease=lambda: None)
    saved = row["results"]
    assert [item["status"] for item in saved["query_ledger"]] == ["completed", "skipped_budget"]
    assert len(saved["queries"]) == 1
    assert len(saved["evidence"]) == 1250
    assert saved["queries"][0]["spl"] == executor.policy.validate(proposal).normalized_spl
    assert saved["queries"][0]["spl"].endswith("index sourcetype _time _cd")
    assert saved["queries"][0]["available_result_count"] == 1600
    assert saved["queries"][0]["retrieval_stop_reason"] == "query_row_limit"
    assert saved["query_ledger"][0]["result_pages"] == 3
    assert saved["usage"]["cached_rows"] == 1250
    assert counters.splunk_queries == 50
    assert connector.pages == [(0, 500), (1, 500), (2, 500)]


def test_production_executor_polls_until_terminal_and_records_sid_before_poll() -> None:
    connector = PollingConnector([{"isDone": "0"}, {"isDone": "1"}])
    ledger: list[tuple[str, str]] = []
    executor = ProductionHuntExecutor(
        connector, _executor().policy,
        on_submitted=lambda query_id, sid, _proposal: ledger.append((str(query_id), sid)),
    )
    execution = executor.execute_query(_proposal())
    assert connector.status_calls == 2
    assert connector.fetch_calls == 1
    assert ledger == [(str(execution.query_id), "sid-poll")]
    assert connector.cancelled == []


def test_production_executor_does_not_submit_after_deadline() -> None:
    connector = PollingConnector([{"isDone": "0"}])
    executor = ProductionHuntExecutor(
        connector, _executor().policy,
        deadline=NOW - timedelta(seconds=1),
    )
    with pytest.raises(AdapterError) as error:
        executor.execute_query(_proposal())
    assert error.value.category is FailureCategory.HARD_TIMEOUT
    assert connector.cancelled == []
    assert executor.counters.splunk_queries == 0
    assert connector.status_calls == connector.fetch_calls == 0


@pytest.mark.parametrize("resumed", [False, True])
def test_query_timeout_remains_two_minutes_under_twenty_minute_hunt(monkeypatch: pytest.MonkeyPatch, resumed: bool) -> None:
    from threat_hunting.services import orchestration

    clock = [NOW + timedelta(seconds=119 if resumed else 0)]
    monkeypatch.setattr(orchestration, "_utc_now", lambda: clock[0])
    connector = PollingConnector([{"isDone": "0"}])
    original_status = connector.status

    def status(job_id: str, **kwargs: object) -> dict[str, object]:
        clock[0] = NOW + timedelta(seconds=121)
        return original_status(job_id, **kwargs)

    connector.status = status
    executor = ProductionHuntExecutor(connector, _executor().policy, deadline=NOW + timedelta(minutes=20))
    if resumed:
        executor.counters.record_splunk_query()
    with pytest.raises(AdapterError) as error:
        executor.execute_query(_proposal(), existing_job_id="sid-poll" if resumed else None,
                               submitted_at_utc=NOW if resumed else None)
    assert error.value.category is FailureCategory.HARD_TIMEOUT
    assert connector.status_calls == 1
    assert connector.fetch_calls == 0
    assert connector.cancelled == ["sid-poll"]
    assert executor.counters.splunk_queries == executor.counters.failed_splunk_queries == 1


@pytest.mark.parametrize("elapsed,timeout", [(721, 300), (1190, 10), (1200, None)])
def test_model_uses_twenty_minute_deadline_with_five_minute_call_limit(monkeypatch: pytest.MonkeyPatch, elapsed: int, timeout: int | None) -> None:
    from threat_hunting.services import orchestration

    monkeypatch.setattr(orchestration, "_utc_now", lambda: NOW + timedelta(seconds=elapsed))
    adapter = FakeModelAdapter(responses=[json.dumps(_plan())])
    complete = adapter.complete
    actual_timeouts = []

    def record_timeout(request, **kwargs):
        actual_timeouts.append(kwargs["timeout_seconds"])
        return complete(request, **kwargs)

    monkeypatch.setattr(adapter, "complete", record_timeout)
    runner = StrictModelRunner(adapter, limits=BudgetLimits(max_model_call_timeout_seconds=300),
                               deadline=NOW + timedelta(minutes=20))
    if timeout is None:
        with pytest.raises(AdapterError) as error:
            runner.run(HuntPlan, user_payload={})
        assert error.value.category is FailureCategory.HARD_TIMEOUT
        assert actual_timeouts == []
        assert runner.counters.model_calls == 0
    else:
        runner.run(HuntPlan, user_payload={})
        assert actual_timeouts == [timeout]


def test_late_model_response_is_accounted_but_not_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    from threat_hunting.services import orchestration

    clock = [NOW + timedelta(minutes=19)]
    monkeypatch.setattr(orchestration, "_utc_now", lambda: clock[0])

    def late_response(request):
        clock[0] = NOW + timedelta(minutes=20)
        return {"text": json.dumps(_plan()), "usage": {"input_tokens": 100, "output_tokens": 50}}

    runner = StrictModelRunner(FakeModelAdapter(responses=[late_response]), deadline=NOW + timedelta(minutes=20))
    with pytest.raises(AdapterError) as error:
        runner.run(HuntPlan, user_payload={})
    assert error.value.category is FailureCategory.HARD_TIMEOUT
    assert runner.counters.model_calls == runner.counters.failed_model_calls == 1
    assert runner.counters.model_input_tokens == 100
    assert runner.counters.model_output_tokens == 50
    assert runner.counters.model_repair_attempts == 0
