"""Retained retrieval and request fitting preserve facts, scope and budgets."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from threat_hunting.domain.budgets import BudgetCounters, BudgetLimits
from threat_hunting.domain.contracts import RetainedEvidenceRequest
from threat_hunting.domain.errors import Validation
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.services.evidence import compact_evidence_records, lookup_retained_evidence
from threat_hunting.services.investigation import (
    _materialize_question_answers, _question_synthesis_contract,
    _retained_synthesis_pages, _synthesis_context,
)
from threat_hunting.services.model_output import prepare_model_context
from threat_hunting.services.orchestration import StrictModelRunner


def plan():
    scope = SimpleNamespace(earliest_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
                            latest_utc=datetime(2026, 1, 2, tzinfo=timezone.utc))
    scope.model_dump = lambda **_: {"earliest_utc": "2026-01-01T00:00:00Z", "latest_utc": "2026-01-02T00:00:00Z"}
    questions = []
    for i in range(2):
        item = SimpleNamespace(question_id=f"q{i}", question=f"Question {i}")
        item.model_dump = lambda i=i, **_: {"question_id": f"q{i}", "question": f"Question {i}"}
        questions.append(item)
    return SimpleNamespace(questions=questions, hypothesis="h", objective="o", scope=scope)


def results():
    q1, q2 = str(uuid4()), str(uuid4())
    return {"queries": [{"query_id": q, "status": "completed", "result_count": 1,
                         "spl": "search index=main sourcetype=endpoint", "truncated": False} for q in (q1, q2)],
            "evidence": [{"query_id": q, "evidence_id": str(uuid4()), "evidence_kind": "raw_event",
                          "event_time_utc": "2026-01-01T10:00:00Z",
                          "selected_result": {"event_id": "native-1", "host": "host-1", "process_id": "10"}} for q in (q1, q2)]}


def limited():
    return {"summary": "Unknown", "findings": [], "limitations": ["More retained evidence is needed."]}


def test_identical_representations_keep_every_citation_and_query_origin():
    state = results()
    original = deepcopy(state)
    compacted = compact_evidence_records(state["evidence"], state["queries"])
    assert len(compacted) == 1
    assert compacted[0]["duplicate_references"][0]["evidence_id"] == state["evidence"][1]["evidence_id"]
    context, refs = prepare_model_context({"completed_queries": state["queries"], "retained_evidence": state["evidence"]}, "QuestionSynthesis")
    assert len(context["retained_evidence"]) == 1
    assert set(refs.evidence) == {"E1", "E2"}
    decoded = refs.decode([{"evidence_ids": ["E2"], "query_ids": []}], findings=True)
    assert decoded[0]["query_ids"] == [state["queries"][1]["query_id"]]
    assert state == original


@pytest.mark.parametrize("change", ["conflict", "additional_field", "source", "unknown_source", "partial_source", "aggregate", "no_identity"])
def test_distinct_or_uncertain_representations_are_preserved(change):
    state = results()
    if change == "conflict":
        state["evidence"][1]["selected_result"]["host"] = "host-2"
    elif change == "additional_field":
        state["evidence"][1]["selected_result"]["command_line"] = "additional fact"
    elif change == "source":
        state["queries"][1]["spl"] = "search index=other sourcetype=endpoint"
    elif change in {"unknown_source", "partial_source"}:
        for query in state["queries"]:
            query.pop("spl")
        if change == "partial_source":
            for row in state["evidence"]:
                row["selected_result"]["index"] = "main"
    elif change == "aggregate":
        for row in state["evidence"]:
            row["evidence_kind"] = "aggregate_row"
    else:
        for row in state["evidence"]:
            row["selected_result"].pop("event_id")
    assert len(compact_evidence_records(state["evidence"], state["queries"])) == 2


def test_lookup_pages_groups_without_changing_retained_representation_counts():
    state = results()
    last = deepcopy(state["evidence"][1])
    last.update(evidence_id=str(uuid4()), event_time_utc="2026-01-01T11:00:00Z")
    last["selected_result"]["event_id"] = "native-2"
    state["evidence"].append(last)
    state["queries"][1]["result_count"] = 2
    first = lookup_retained_evidence(state, query_ids={q["query_id"] for q in state["queries"]}, limit=1)
    assert first["matching_raw_record_count"] == 3
    assert first["matching_representation_group_count"] == 2
    assert first["next_offset"] == 1
    assert len(first["records"][0]["duplicate_references"]) == 1
    second = lookup_retained_evidence(state, query_ids={q["query_id"] for q in state["queries"]}, offset=1, limit=1)
    assert second["records"][0]["evidence_id"] == last["evidence_id"]
    assert second["next_offset"] is None


def test_requested_pages_defer_only_their_question_and_preserve_original_query_scope():
    state = results()
    request = {"query_ids": [state["queries"][0]["query_id"]], "filters": [{"field": "host", "value": "host-1"}], "limit": 1}
    response = {"question_1": limited(), "question_2": {**limited(), "retained_evidence_requests": [request]}}
    answer = _question_synthesis_contract(plan(), allow_retrieval=True).model_validate(response)
    generated = _materialize_question_answers(answer, plan(), state)
    assert [item["question_id"] for item in generated["question_answers"]] == ["q0"]
    pages = _retained_synthesis_pages(answer, plan(), state)
    assert pages[0]["question_id"] == "q1"
    assert pages[0]["returned_evidence_ids"] == [state["evidence"][0]["evidence_id"]]
    assert pages[0]["query_coverage"][0]["result_count"] == 1
    state["synthesis_retrievals"] = pages
    context = _synthesis_context(plan=plan(), results=state, threat_intelligence="", limit=1)
    assert context["retained_lookup_pages"][0]["matching_raw_record_count"] == 1


def test_lookup_metadata_uses_only_supplied_request_labels_and_preserves_source_literals():
    state = results()
    state["evidence"][0]["selected_result"]["returned_evidence_ids"] = ["source-literal"]
    state["synthesis_retrievals"] = [{"question_id": "q0", "returned_evidence_ids": [
        row["evidence_id"] for row in state["evidence"]]}]
    context = _synthesis_context(plan=plan(), results=state, threat_intelligence="", limit=1)
    encoded, refs = prepare_model_context(context, "QuestionSynthesis")
    page = encoded["retained_lookup_pages"][0]
    assert page["returned_evidence_ids"] == ["E1", "UNAVAILABLE"]
    assert page["supplied_evidence_ids"] == ["E1"]
    assert page["sample_omitted"]
    assert encoded["retained_evidence"][0]["selected_result"]["returned_evidence_ids"] == ["source-literal"]


def test_requested_page_reaches_model_even_when_query_balancing_would_omit_it():
    state = results()
    requested = state["evidence"][1]["evidence_id"]
    state["synthesis_retrievals"] = [{"question_id": "q0", "returned_evidence_ids": [requested]}]
    context = _synthesis_context(plan=plan(), results=state, threat_intelligence="", limit=1)
    assert context["retained_evidence"][0]["evidence_id"] == requested
    assert context["retained_lookup_pages"][0]["sample_omitted"] is False
    assert context["evidence_coverage"][0]["sample_omitted"]


def test_latest_requested_page_is_not_starved_by_older_pages():
    state = results()
    old, latest = (row["evidence_id"] for row in state["evidence"])
    state["synthesis_retrievals"] = [
        {"question_id": "q0", "returned_evidence_ids": [old]},
        {"question_id": "q0", "returned_evidence_ids": [latest]},
    ]
    context = _synthesis_context(plan=plan(), results=state, threat_intelligence="", limit=1)
    assert context["retained_evidence"][0]["evidence_id"] == latest
    assert context["retained_lookup_pages"][0]["sample_omitted"]
    assert not context["retained_lookup_pages"][1]["sample_omitted"]


def test_one_sided_lookup_time_bound_is_constrained_to_approved_window():
    state = results()
    state["evidence"][0]["event_time_utc"] = "2026-01-03T10:00:00Z"
    request = {"query_ids": [state["queries"][0]["query_id"]], "earliest_utc": "2026-01-01T00:00:00Z"}
    answer = _question_synthesis_contract(plan(), allow_retrieval=True).model_validate({
        "question_1": {**limited(), "retained_evidence_requests": [request]}, "question_2": limited()})
    page = _retained_synthesis_pages(answer, plan(), state)[0]
    assert page["matching_raw_record_count"] == 0
    assert page["scope"]["latest_utc"] == "2026-01-02T00:00:00Z"


@pytest.mark.parametrize("change", ["foreign_query", "outside_time"])
def test_model_lookup_cannot_cross_hunt_or_approved_time_scope(change):
    state = results()
    request = {"query_ids": [state["queries"][0]["query_id"]]}
    request.update({"query_ids": ["foreign-query"]} if change == "foreign_query" else {"earliest_utc": "2025-12-31T00:00:00Z"})
    payload = {"question_1": {**limited(), "retained_evidence_requests": [request]}, "question_2": limited()}
    if change == "outside_time":
        with pytest.raises(ValidationError, match="approved time window"):
            _question_synthesis_contract(plan(), allow_retrieval=True).model_validate(payload)
        return
    answer = _question_synthesis_contract(plan(), allow_retrieval=True).model_validate(payload)
    with pytest.raises(Validation):
        _retained_synthesis_pages(answer, plan(), state)


def test_out_of_scope_lookup_is_repaired_with_original_context():
    state = results()
    response = {"question_1": {**limited(), "retained_evidence_requests": [{
        "query_ids": ["Q1"], "earliest_utc": "2025-01-01T00:00:00Z"}]}, "question_2": limited()}
    model = FakeModelAdapter(responses=[json.dumps(response), json.dumps({"question_1": limited(), "question_2": limited()})])
    runner = StrictModelRunner(model)
    answer = runner.run(_question_synthesis_contract(plan(), allow_retrieval=True),
                        user_payload=_synthesis_context(plan=plan(), results=state, threat_intelligence=""),
                        contract_name="QuestionSynthesis")
    assert not answer.question_1.retained_evidence_requests
    assert model.call_count == 2
    assert model.requests[0].messages[0] == model.requests[1].messages[0]
    assert runner.counters.model_repair_attempts == 1


def test_lookup_reports_unobserved_filter_fields_instead_of_implying_source_absence():
    state = results()
    page = lookup_retained_evidence(state, query_ids={state["queries"][0]["query_id"]}, filters={"not_observed": "value"})
    assert page["unobserved_filter_fields"] == ["not_observed"]
    assert page["matching_raw_record_count"] == 0
    assert "does not establish absence" in page["limitation"]
    assert page["query_coverage"][0]["retained_evidence_count"] == 1


@pytest.mark.parametrize("change", [{"offset": -1}, {"limit": 501}, {"limit": True}, {"query_ids": ["q", "q"]},
                                  {"earliest_utc": "2026-01-01T00:00:00"},
                                  {"filters": [{"field": "   ", "value": "host"}]},
                                  {"filters": [{"field": "h", "value": {"regex": ".*"}}]}])
def test_model_lookup_rejects_unbounded_or_ambiguous_parameters(change):
    with pytest.raises(ValidationError):
        RetainedEvidenceRequest.model_validate({"query_ids": ["q"], **change})


def test_context_fitting_rebuilds_coverage_and_never_changes_retained_data():
    state = results()
    state["evidence"] = [{**deepcopy(state["evidence"][0]), "evidence_id": str(uuid4()),
                           "selected_result": {"event_id": f"event-{i}", "host": "host-1", "text": "x" * 5000}}
                          for i in range(8)]
    state["queries"] = [state["queries"][0]]
    state["queries"][0]["result_count"] = 8
    original = deepcopy(state)
    adapter = FakeModelAdapter(responses=[json.dumps({"question_1": limited(), "question_2": limited()})])
    runner = StrictModelRunner(adapter, limits=BudgetLimits(max_context_characters=60_000))
    runner.run(_question_synthesis_contract(plan()), user_payload={}, contract_name="QuestionSynthesis",
               context_builder=lambda limit: _synthesis_context(plan=plan(), results=state, threat_intelligence="", limit=limit))
    sent = json.loads(adapter.requests[0].messages[0]["content"])
    assert 0 < len(sent["retained_evidence"]) < 8
    assert sent["evidence_coverage"][0]["sample_omitted"]
    assert sent["evidence_coverage"][0]["retained_evidence_count"] == 8
    assert state == original
    assert adapter.call_count == 1


def test_unsplittable_request_is_rejected_before_spending_a_call():
    adapter = FakeModelAdapter(responses=[])
    runner = StrictModelRunner(adapter, limits=BudgetLimits(max_model_input_tokens=1))
    with pytest.raises(AdapterError, match="remaining input budget"):
        runner.run(_question_synthesis_contract(plan()), user_payload={})
    assert runner.counters.model_calls == adapter.call_count == 0


def test_repair_growth_is_checked_with_original_evidence_and_no_second_paid_call():
    adapter = FakeModelAdapter(responses=["x" * 40_000])
    runner = StrictModelRunner(adapter, limits=BudgetLimits(max_context_characters=30_000))
    with pytest.raises(AdapterError, match="context"):
        runner.run(_question_synthesis_contract(plan()), user_payload={})
    assert adapter.call_count == 1
    assert runner.counters.model_repair_attempts == 0


def test_output_allowance_respects_remaining_hunt_tokens():
    adapter = FakeModelAdapter(responses=[json.dumps({"question_1": limited(), "question_2": limited()})])
    runner = StrictModelRunner(adapter, counters=BudgetCounters(model_output_tokens=95_990))
    runner.run(_question_synthesis_contract(plan()), user_payload={})
    assert adapter.requests[0].max_output_tokens == 10


def test_context_fitting_uses_the_available_capacity_between_halving_steps():
    from pydantic import BaseModel

    class Answer(BaseModel):
        summary: str

    adapter = FakeModelAdapter(responses=[json.dumps({"summary": "bounded"})])
    runner = StrictModelRunner(adapter, limits=BudgetLimits(
        max_context_characters=6200, max_targeted_events=8, max_representative_events=8))
    runner.run(Answer, user_payload={}, context_builder=lambda limit: {"rows": ["x" * 1000] * limit})
    assert len(json.loads(adapter.requests[0].messages[0]["content"])["rows"]) == 5
    assert adapter.call_count == 1
