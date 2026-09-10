"""Regressions for source starvation in the real multi-source hunt."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import QueryProposal
from threat_hunting.domain.spl_policy import SPLPolicy, source_pairs
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.integrations.splunk import SplunkConnectionConfig, SplunkConnector
from threat_hunting.services.evidence import query_source_coverage
from threat_hunting.services.investigation import _assessment_context, _balanced_evidence_sample, _synthesis_context
from threat_hunting.services.orchestration import ProductionHuntExecutor
from threat_hunting.services.reports import _derive_report_limitations
from threat_hunting.services.workflow import WorkflowService


START = datetime(2026, 1, 1, tzinfo=timezone.utc)
END = START + timedelta(days=1)
SPL = 'search ((index=dns sourcetype=dns) OR (index=network sourcetype=net)) (host="host-1" OR user="alice") | table _time index sourcetype host user'


def proposal():
    return QueryProposal.model_validate({
        "question_id": "q4", "purpose": "Related DNS and network activity", "expected_information_gain": "Source coverage",
        "spl": SPL, "earliest_utc": START, "latest_utc": END,
        "indexes": ["dns", "network"], "sourcetypes": ["dns", "net"],
        "requested_fields": ["_time", "index", "sourcetype", "host", "user"], "result_mode": "representative", "max_results": 100,
    })


@pytest.mark.parametrize("row,expected", [
    ({"index": "network", "sourcetype": "net", "host": "host-1"}, ("network", "net")),
    ({"host": "host-1"}, ("unknown", "unknown")),
    ({"index": "dns", "sourcetype": "net", "host": "host-1"}, ("unknown", "unknown")),
    ({"index": ["network", "network"], "sourcetype": ["net", "net"], "host": "host-1"}, ("network", "net")),
    ({"index": ["dns", "network"], "sourcetype": ["dns", "net"], "host": "host-1"}, ("unknown", "unknown")),
])
def test_multi_source_evidence_uses_observed_pair_or_explicit_unknown(row, expected):
    execution = SimpleNamespace(query_id=uuid4(), splunk_job_id="sid", rows=[row])
    evidence = ProductionHuntExecutor.evidence_for_query(execution, hunt_id=uuid4(), proposal=proposal())
    assert (evidence[0].index, evidence[0].sourcetype) == expected
    assert evidence[0].selected_result == row


def state():
    query_id = str(uuid4())
    return {"threat_intelligence": "", "results": {
        "queries": [{"query_id": query_id, "question_id": "q4", "status": "completed", "spl": SPL, "truncated": True, "result_count": 100}],
        "query_ledger": [{"query_id": query_id, "status": "completed", "proposal": proposal().model_dump(mode="json")}],
        "evidence": [{"query_id": query_id, "evidence_id": str(uuid4()), "index": "dns", "sourcetype": "dns",
                      "selected_result": {"index": "dns", "sourcetype": "dns", "host": "host-1"}} for _ in range(100)],
        "assessed_query_ids": [query_id],
    }}


def run_round(row, *, query_limit=12, model_calls=3):
    now = datetime.now(timezone.utc)
    model = FakeModelAdapter(responses=[])
    limits = BudgetLimits(max_splunk_queries=query_limit)
    service = SimpleNamespace(model_adapter=model, budget_limits=limits, _owned_row=lambda *_: deepcopy(row),
                              _update=lambda *_, **values: row.update(values))
    plan = SimpleNamespace(questions=[], hypothesis="h", objective="o", scope=SimpleNamespace(model_dump=lambda **_: {}), model_dump=lambda **_: {})
    policy = SPLPolicy(discovered_indexes={"dns", "network"}, discovered_sourcetypes={"dns", "net"}, discovered_fields={"host", "user"},
                       approved_indexes={"dns", "network"}, approved_sourcetypes={"dns", "net"}, approved_earliest_utc=START, approved_latest_utc=END,
                       connection_id="test", execution_config_snapshot_id=str(uuid4()))
    counters = BudgetCounters(model_calls=model_calls, splunk_queries=1)
    result = WorkflowService._assess_execution_round(
        service, lease=SimpleNamespace(owner_id="owner", hunt_id="hunt"), plan=plan, policy=policy, discovery_scope={},
        counters=counters, token=SimpleNamespace(is_cancelled=lambda: False), deadline=now + timedelta(minutes=1), require_lease=lambda: None,
    )
    assert model.call_count == 0
    return result, policy, counters


@pytest.mark.parametrize("declared_mode", ["representative", "aggregate"])
def test_truncated_dns_only_result_schedules_network_search_without_model_decision(declared_mode):
    row = state()
    row["results"]["query_ledger"][0]["proposal"]["result_mode"] = declared_mode
    reschedule, policy, _ = run_round(row)
    assert reschedule is True
    planned = [entry for entry in row["results"]["query_ledger"] if entry["status"] == "planned"]
    assert len(planned) == 1
    assert planned[0]["phase"] == "source_coverage"
    assert planned[0]["source_query_id"] == row["results"]["queries"][0]["query_id"]
    assert planned[0]["source_pair"] == ["network", "net"]
    generated = QueryProposal.model_validate(planned[0]["proposal"])
    assert generated.question_id == "q4"
    assert (generated.earliest_utc, generated.latest_utc, generated.max_results) == (START, END, 100)
    assert generated.spl.endswith('| table _time index sourcetype host user')
    assert '(host="host-1" OR user="alice")' in generated.spl
    assert source_pairs(generated.spl) == {("network", "net")}
    assert policy.validate(generated).allowed


@pytest.mark.parametrize("budget", ["queries", "model"])
def test_budget_stop_reports_source_gap_even_when_model_called_question_answered(budget):
    row = state()
    row["results"]["query_assessments"] = [{"query_id": row["results"]["queries"][0]["query_id"], "answered_question": True}]
    assert run_round(row, query_limit=1 if budget == "queries" else 12, model_calls=11 if budget == "model" else 3)[0] is False
    assert len(row["results"]["query_ledger"]) == 1
    assert any("network (net)" in item and "unresolved coverage" in item for item in _derive_report_limitations(row["results"]))


@pytest.mark.parametrize("variant", ["untruncated", "aggregate_pipeline", "both_sources"])
def test_source_check_is_not_invented_for_results_without_raw_source_starvation(variant):
    row = state()
    if variant == "untruncated":
        row["results"]["queries"][0]["truncated"] = False
    elif variant == "aggregate_pipeline":
        row["results"]["queries"][0]["spl"] = SPL.split("|")[0] + "| stats count"
    else:
        row["results"]["evidence"][-1]["selected_result"].update(index="network", sourcetype="net")
        # Historical top-level labels may still incorrectly say DNS.
    assert run_round(row)[0] is False
    assert not any(source["needs_source_check"] for source in query_source_coverage(row["results"])[0]["sources"])


def test_unknown_projection_requires_checks_for_both_sources_instead_of_trusting_old_labels():
    row = state()
    for event in row["results"]["evidence"]:
        event["selected_result"] = {"host": "host-1"}
    assert run_round(row)[0] is True
    planned = [entry for entry in row["results"]["query_ledger"] if entry["status"] == "planned"]
    assert {tuple(entry["source_pair"]) for entry in planned} == {("dns", "dns"), ("network", "net")}
    assert query_source_coverage(row["results"])[0]["unidentified_retained_count"] == 100


@pytest.mark.parametrize("empty", [False, True])
def test_checkpoint_executes_source_check_once_and_preserves_actual_evidence(empty):
    row = state()
    _, policy, counters = run_round(row)
    calls = []
    network_row = {"_time": "2026-01-01T00:30:00Z", "index": "network", "sourcetype": "net", "host": "host-1"}

    class Jobs(dict):
        def create(self, spl, **kwargs):
            calls.append((spl, kwargs))
            self[kwargs["id"]] = SimpleNamespace(name=kwargs["id"], content={"isDone": "1"}, results=lambda **_: [] if empty else [network_row])
            return self[kwargs["id"]]

    connector = SplunkConnector(SplunkConnectionConfig(endpoint="https://splunk.example", token="unit-test"), client=SimpleNamespace(jobs=Jobs()))
    executor = ProductionHuntExecutor(connector, policy, counters=counters)
    service = SimpleNamespace(_owned_row=lambda *_: deepcopy(row), _update=lambda *_, **values: row.update(values))
    lease = SimpleNamespace(owner_id="owner", hunt_id=str(uuid4()))
    for _ in range(2):
        WorkflowService._run_checkpoint_queries(service, lease=lease, executor=executor, counters=counters, require_lease=lambda: None)
    assert len(calls) == 1
    assert source_pairs(calls[0][0]) == {("network", "net")}
    assert len(row["results"]["queries"]) == 2
    assert len(row["results"]["evidence"]) == (100 if empty else 101)
    if not empty:
        assert row["results"]["evidence"][-1]["index"] == "network"
        assert row["results"]["evidence"][-1]["selected_result"] == network_row
    row["results"]["assessed_query_ids"] = [query["query_id"] for query in row["results"]["queries"]]
    assert run_round(row)[0] is False
    assert len(row["results"]["query_ledger"]) == 2
    original = query_source_coverage(row["results"])[0]
    checked = next(source for source in original["sources"] if source["index"] == "network")
    assert checked["coverage_query_completed"] is True
    assert checked["needs_source_check"] is False
    assert not any("unresolved coverage" in item for item in _derive_report_limitations(row["results"]))


def test_context_sample_preserves_minority_source_and_exposes_source_counts():
    row = state()
    row["results"]["evidence"][-1]["selected_result"].update(index="network", sourcetype="net")
    sampled, _ = _balanced_evidence_sample(row["results"]["evidence"], row["results"]["queries"], limit=2)
    assert {item["selected_result"]["index"] for item in sampled} == {"dns", "network"}
    plan = SimpleNamespace(questions=[], hypothesis="h", objective="o", scope=SimpleNamespace(model_dump=lambda **_: {}))
    for context in [_assessment_context(plan, row["results"]), _synthesis_context(plan=plan, threat_intelligence="", results=row["results"])]:
        sources = context["source_coverage"][0]["sources"]
        assert [(item["index"], item["identified_retained_count"], item["supplied_count"]) for item in sources] == [("dns", 99, 99), ("network", 1, 1)]


def test_single_effective_source_can_establish_omitted_source_fields():
    selected = proposal().model_copy(update={"spl": f'search ({SPL.split("|", 1)[0][7:]}) AND index=network AND sourcetype=net | table host'})
    evidence = ProductionHuntExecutor.evidence_for_query(SimpleNamespace(query_id=uuid4(), splunk_job_id="sid", rows=[{"host": "host-1"}]), hunt_id=uuid4(), proposal=selected)
    assert (evidence[0].index, evidence[0].sourcetype) == ("network", "net")


@pytest.mark.parametrize("pipeline,declared_mode,expected_kind", [
    ('| table _time host user', 'aggregate', 'raw_event'),
    ('| eval note="stats count" | fields _time host', 'aggregate', 'raw_event'),
    ('| stats count by host | table host count', 'representative', 'aggregate_row'),
    ('| timechart span=1h count', 'targeted', 'aggregate_row'),
])
def test_evidence_kind_and_time_bounds_follow_actual_query_not_model_mode(pipeline, declared_mode, expected_kind):
    from threat_hunting.services.evidence import evidence_time_bounds

    selected = QueryProposal.model_validate({**proposal().model_dump(mode="json"),
        "spl": SPL.split("|")[0] + pipeline, "result_mode": declared_mode, "max_results": 10,
    })
    row = {"_time": "2026-01-01T00:30:00Z", "host": "host-1", "index": "network", "sourcetype": "net"}
    execution = SimpleNamespace(query_id=uuid4(), splunk_job_id="sid", rows=[row])

    evidence = ProductionHuntExecutor.evidence_for_query(execution, hunt_id=uuid4(), proposal=selected)

    assert evidence[0].evidence_kind.value == expected_kind
    assert evidence[0].selected_result == row
    bounds = evidence_time_bounds([evidence[0].model_dump(mode="json")])
    assert bounds["timestamped_record_count"] == (1 if expected_kind == "raw_event" else 0)
    assert bounds["aggregate_row_count"] == (0 if expected_kind == "raw_event" else 1)
