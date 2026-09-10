"""Regressions for the live hunt that exhausted pivots before approved q4."""

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import PlanQuestion
from threat_hunting.domain.spl_policy import SPLPolicy
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.services.investigation import _pending_investigation_questions
from threat_hunting.services.workflow import WorkflowService


def question(identifier):
    return PlanQuestion(question_id=identifier, question="Investigate scoped activity", rationale="Approved coverage", expected_information_gain="Related activity")


def test_pending_queue_preserves_approved_order_and_old_pivots_without_retrying_skips():
    plan = SimpleNamespace(questions=[question("q1"), question("q4")])
    old = {"question_id": "old-pivot", "source_question_id": "q1"}
    results = {"queries": [{"question_id": "q1", "status": "completed"}], "follow_up_questions": [old],
               "follow_up_decisions": [{"question_id": "skipped", "skip_reason": "No telemetry."}]}
    pending = _pending_investigation_questions(plan, results, [old, {"question_id": "new-pivot"}, {"question_id": "skipped"}])
    assert [item["question_id"] for item in pending] == ["q4", "old-pivot", "new-pivot"]
    assert pending[0]["approved_question"] is True
    assert pending[1]["source_question_id"] == "q1"


def test_skipped_question_is_reconsidered_only_after_new_queries_complete():
    plan = SimpleNamespace(questions=[question("q1"), question("q2"), question("q3"), question("q4")])
    results = {"queries": [{"query_id": "initial", "question_id": "q1", "status": "completed"}],
               "follow_up_decisions": [
                   {"question_id": "q3", "proposal": None, "skip_reason": "Wait for q2's timeline", "considered_query_ids": ["initial"]},
                   {"question_id": "q4", "proposal": None, "skip_reason": "Wait for auth context", "considered_query_ids": ["initial"]},
               ]}
    assert [q["question_id"] for q in _pending_investigation_questions(plan, results)] == ["q2"]
    results["queries"].append({"query_id": "timeline", "question_id": "q2", "status": "completed"})
    assert [q["question_id"] for q in _pending_investigation_questions(plan, results)] == ["q3", "q4"]
    results["follow_up_decisions"].append({"question_id": "q3", "proposal": None, "skip_reason": "No usable auth telemetry", "considered_query_ids": ["initial", "timeline"]})
    assert [q["question_id"] for q in _pending_investigation_questions(plan, results)] == ["q4"]


def test_unsearched_approved_question_gets_last_query_slot_before_new_pivot():
    _run_round(max_model_calls=12)


def test_budget_stop_preserves_unsearched_approved_question_without_model_calls():
    _run_round(max_model_calls=2)


def test_skipped_question_preserves_query_slot_for_next_approved_question():
    _run_round(max_model_calls=5, skip_first=True)


@pytest.mark.parametrize("variant", ["identical", "different_window", "different_limit", "completed"])
def test_duplicate_pivot_does_not_consume_repair_or_block_distinct_approved_work(variant):
    now = datetime.now(timezone.utc)
    start, end = now - timedelta(hours=1), now
    plan = SimpleNamespace(questions=[question("q1"), question("q2"), question("q3"), question("q4")],
                           hypothesis="h", objective="o", scope=SimpleNamespace(model_dump=lambda **_: {}),
                           model_dump=lambda **_: {})
    query_id = str(uuid4())
    row = {"threat_intelligence": "", "results": {
        "queries": [{"query_id": query_id, "question_id": "q1", "status": "completed", "spl": "search index=network sourcetype=net | head 1"}],
        "assessed_query_ids": [query_id], "evidence": [], "query_ledger": [],
        "follow_up_questions": [{"question_id": "pivot", "grounded_entities": [{"value": "host-1"}]}],
    }}
    requests = []

    def proposal(identifier, host):
        return {"question_id": identifier, "skip_reason": None, "proposal": {
            "question_id": identifier, "purpose": "Investigate related activity", "expected_information_gain": "Scoped coverage",
            "spl": f'search index=network sourcetype=net host="{host}" | head 10',
            "earliest_utc": start.isoformat(), "latest_utc": end.isoformat(),
            "indexes": ["network"], "sourcetypes": ["net"], "requested_fields": ["host"],
            "result_mode": "representative", "max_results": 10,
        }}

    originals = [proposal("q2", "host-1"), proposal("q3", "host-2"), proposal("q4", "host-3"), proposal("pivot", "host-1")]
    if variant == "different_window":
        originals[-1]["proposal"]["earliest_utc"] = (start + timedelta(minutes=10)).isoformat()
    if variant == "different_limit":
        originals[-1]["proposal"]["max_results"] = 20
    if variant == "completed":
        completed_proposal = {**originals[0]["proposal"], "question_id": "q1"}
        row["results"]["queries"][0]["spl"] = completed_proposal["spl"]
        row["results"]["query_ledger"] = [{"query_id": query_id, "status": "completed", "proposal": completed_proposal}]

    def response(request):
        requests.append(json.loads(request.messages[0]["content"]))
        assert len(requests) == 1  # No model repair for an exact duplicate.
        return json.dumps(originals[::-1])  # Application preserves approved-question priority.

    model = FakeModelAdapter(responses=[response])
    limits = BudgetLimits(max_model_calls=8)
    service = SimpleNamespace(model_adapter=model, budget_limits=limits, _owned_row=lambda *_: deepcopy(row),
                              _update=lambda *_, **values: row.update(values))
    policy = SPLPolicy(discovered_indexes={"network"}, discovered_sourcetypes={"net"}, discovered_fields={"host"},
                       approved_indexes={"network"}, approved_sourcetypes={"net"}, approved_earliest_utc=start, approved_latest_utc=end,
                       connection_id="test", execution_config_snapshot_id=str(uuid4()))
    counters = BudgetCounters(model_calls=1, splunk_queries=1)
    assert WorkflowService._assess_execution_round(
        service, lease=SimpleNamespace(owner_id="owner", hunt_id="hunt"), plan=plan, policy=policy, discovery_scope={},
        counters=counters, token=SimpleNamespace(is_cancelled=lambda: False),
        deadline=now + timedelta(minutes=1), require_lease=lambda: None,
    )
    planned = [entry["proposal"] for entry in row["results"]["query_ledger"] if entry["status"] == "planned"]
    expected = ["q3", "q4"] if variant == "completed" else ["q2", "q3", "q4"]
    if variant in {"different_window", "different_limit"}:
        expected.append("pivot")
    assert [p["question_id"] for p in planned] == expected
    skips = [d for d in row["results"]["follow_up_decisions"] if d.get("decision_source") == "application_duplicate_suppression"]
    assert {d["question_id"] for d in skips} == ({"q2", "pivot"} if variant == "completed" else {"pivot"} if variant == "identical" else set())
    assert all(d["proposal"] is None and "not separately searched" in d["skip_reason"] for d in skips)
    assert counters.model_repair_attempts == 0
    assert len(requests) == 1


def _run_round(*, max_model_calls, skip_first=False):
    now = datetime.now(timezone.utc)
    start, end = now - timedelta(hours=1), now
    plan = SimpleNamespace(questions=[question("q1"), question("q4")], hypothesis="h", objective="o",
                           scope=SimpleNamespace(model_dump=lambda **_: {}), model_dump=lambda **_: {})
    if skip_first:
        plan.questions.append(question("q5"))
    query_id, evidence_id = str(uuid4()), str(uuid4())
    row = {"threat_intelligence": "", "results": {
        "queries": [{"query_id": query_id, "question_id": "q1", "status": "completed", "result_count": 1}],
        "evidence": [{"query_id": query_id, "evidence_id": evidence_id, "selected_result": {"host": "host-1"}}],
        "query_ledger": [],
    }}

    def response(request):
        context = json.loads(request.messages[0]["content"])
        if "QueryAssessment[]" in request.system:
            group = context["completed_queries"][0]
            return json.dumps([{
                "query_id": group["query_id"], "question_id": "q1", "answered_question": True,
                "material_progress": True, "summary": "Observed host-1", "new_entities": [],
                "evidence_candidate_row_refs": [group["allowed_evidence_ids"][0]], "coverage_changes": [], "limitations": [],
                "proposed_next_question": {"question": "Pivot host-1", "rationale": "Related activity", "expected_information_gain": "Spread"},
            }])
        identifier = context["follow_up_questions"][0]["question_id"]
        assert len(context["follow_up_questions"]) == 1
        assert context["remaining_budget"]["splunk_queries"] == 1
        if skip_first and identifier == "q4":
            return json.dumps([{"question_id": identifier, "skip_reason": "Required DNS telemetry unavailable.", "proposal": None}])
        assert identifier == ("q5" if skip_first else "q4")
        return json.dumps([{"question_id": identifier, "skip_reason": None, "proposal": {
            "question_id": identifier, "purpose": "Approved network question", "expected_information_gain": "Network coverage",
            "spl": "search index=network sourcetype=net | head 1", "earliest_utc": start.isoformat(), "latest_utc": end.isoformat(),
            "indexes": ["network"], "sourcetypes": ["net"], "requested_fields": ["host"], "result_mode": "representative", "max_results": 1,
        }}])

    model = FakeModelAdapter(responses=[response] * 3)
    limits = BudgetLimits(max_model_calls=max_model_calls, max_splunk_queries=2)
    service = SimpleNamespace(model_adapter=model, budget_limits=limits, _owned_row=lambda *_: deepcopy(row),
                              _update=lambda *_, **values: row.update(values))
    policy = SPLPolicy(discovered_indexes={"network"}, discovered_sourcetypes={"net"}, discovered_fields={"host"},
                       approved_indexes={"network"}, approved_sourcetypes={"net"}, approved_earliest_utc=start, approved_latest_utc=end,
                       connection_id="test", execution_config_snapshot_id=str(uuid4()))
    counters = BudgetCounters(model_calls=1, splunk_queries=1)
    reschedule = WorkflowService._assess_execution_round(
        service, lease=SimpleNamespace(owner_id="owner", hunt_id="hunt"), plan=plan, policy=policy, discovery_scope={},
        counters=counters, token=SimpleNamespace(is_cancelled=lambda: False), deadline=now + timedelta(minutes=1), require_lease=lambda: None,
    )
    if skip_first:
        assert reschedule
        assert row["results"]["follow_up_decisions"][0]["considered_query_ids"] == [query_id]
        assert "q4" not in row["results"]["pending_question_ids"]
        assert "q5" in row["results"]["pending_question_ids"]
        reschedule = WorkflowService._assess_execution_round(
            service, lease=SimpleNamespace(owner_id="owner", hunt_id="hunt"), plan=plan, policy=policy, discovery_scope={},
            counters=counters, token=SimpleNamespace(is_cancelled=lambda: False), deadline=now + timedelta(minutes=1), require_lease=lambda: None,
        )
    else:
        assert "q4" in row["results"]["pending_question_ids"]
    if max_model_calls == 2:
        assert not reschedule
        assert row["results"]["adaptive_status"] == "budget_reserved_for_synthesis"
        assert model.call_count == 0
    else:
        assert reschedule
        assert row["results"]["query_ledger"][0]["proposal"]["question_id"] == ("q5" if skip_first else "q4")
        assert len(row["results"]["follow_up_questions"]) == 1
        assert row["results"]["follow_up_questions"][0]["source_question_id"] == "q1"
        assert counters.model_calls == (4 if skip_first else 3)
