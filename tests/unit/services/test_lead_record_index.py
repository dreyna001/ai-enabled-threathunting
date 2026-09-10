"""Supplied lead context preserves chronology and literal relationship scope."""

from copy import deepcopy
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from threat_hunting.services.evidence import advisory_lead_groups
from threat_hunting.services.model_output import prepare_model_context
from threat_hunting.domain.budgets import BudgetLimits
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.services.investigation import _question_synthesis_contract
from threat_hunting.services.orchestration import StrictModelRunner


def row(identifier, action, stamp=None, *, lead=False, **fields):
    return {
        "evidence_id": identifier, "query_id": "query-a", "evidence_kind": "raw_event",
        "event_time_utc": stamp,
        "selected_result": {"host": "host-a", "user": "user-a", "session_id": "session-a",
                            "process_guid": "process-a", "action": action, **fields},
        "advisory_ioc_comparison": {"matched_file_name_literals": ["observed.exe"] if lead else []},
    }


def supplied():
    end = row("end", "process_end", "2026-01-06T17:00:00Z", lead=True)
    start = row("start", "process_start", "2026-01-06T09:00:00Z", lead=True)
    start["duplicate_references"] = [{"evidence_id": "start-copy", "query_id": "query-a"}]
    return {
        "completed_queries": [{"query_id": "query-a", "status": "completed", "truncated": True}],
        "retained_evidence": [end, start,
                              row("module", "image_load", "2026-01-06T08:00:00Z", process_guid="process-b"),
                              row("auth", "logon", process_guid=None)],
    }


def indexed_actions(record_set):
    return [action for period in record_set["periods"] for action in period["actions"]]


def action_ids(record_set):
    actions = {}
    for item in indexed_actions(record_set):
        actions.setdefault(item["action"], []).extend(item["evidence_ids"])
    return actions


def test_lead_anchor_is_earliest_known_observation_and_preserves_all_origins():
    context = supplied()
    original = deepcopy(context)
    groups = advisory_lead_groups(context["retained_evidence"])
    assert groups[0]["lead_evidence_id"] == "start"
    assert groups[0]["evidence_ids"] == ["start", "start-copy", "end"]
    assert context == original


def test_related_periods_compare_utc_instants_and_keep_every_observation():
    context = {"completed_queries": [{"query_id": "query-a", "status": "completed"}],
               "retained_evidence": [
                   row("anchor", "image_load", "2026-01-06T10:00:00Z", lead=True),
                   row("unknown", "connection"),
                   row("late", "connection", "2026-01-06T10:02:00Z"),
                   row("early", "connection", "2026-01-06T09:58:00Z"),
                   row("same", "connection", "2026-01-06T05:00:00-05:00"),
                   row("just-before", "connection", "2026-01-06T09:59:59.999999Z"),
                   row("just-after", "connection", "2026-01-06T10:00:00.000001Z"),
               ]}
    original = deepcopy(context)
    encoded, refs = prepare_model_context(context, "QuestionSynthesis")
    lead, = encoded["advisory_leads"]
    assert lead["anchor_event_time_utc"] == "2026-01-06T10:00:00Z"
    for scope in lead["record_index"]:
        periods = scope["periods"]
        assert [period["relative_to_lead"] for period in periods] == ["before", "at", "after", "unknown"]
        actions = {period["relative_to_lead"]: {action["action"]: action for action in period["actions"]}
                   for period in periods}
        assert actions["before"]["connection"] == {
            "action": "connection", "first_event_time_utc": "2026-01-06T09:58:00Z",
            "last_event_time_utc": "2026-01-06T09:59:59.999999Z", "evidence_ids": ["E4", "E6"],
        }
        assert actions["at"]["image_load"]["evidence_ids"] == ["E1"]
        assert actions["at"]["connection"] == {
            "action": "connection", "first_event_time_utc": "2026-01-06T10:00:00Z",
            "last_event_time_utc": "2026-01-06T10:00:00Z", "evidence_ids": ["E5"],
        }
        assert actions["after"]["connection"] == {
            "action": "connection", "first_event_time_utc": "2026-01-06T10:00:00.000001Z",
            "last_event_time_utc": "2026-01-06T10:02:00Z", "evidence_ids": ["E7", "E3"],
        }
        assert actions["unknown"]["connection"] == {
            "action": "connection", "first_event_time_utc": None,
            "last_event_time_utc": None, "evidence_ids": ["E2"],
        }
        indexed = [identifier for group in actions.values() for action in group.values()
                   for identifier in action["evidence_ids"]]
        assert len(indexed) == len(set(indexed)) == len(refs.evidence)
    assert context == original


@pytest.mark.parametrize("stamp", [None, "2026-01-06T10:00:00", "invalid"])
def test_unknown_anchor_does_not_assign_relative_times_to_known_related_records(stamp):
    context = {"completed_queries": [{"query_id": "query-a", "status": "completed"}],
               "retained_evidence": [
                   row("anchor", "image_load", stamp, lead=True),
                   row("last", "connection", "2026-01-06T17:00:00Z"),
                   row("unknown", "connection"),
                   row("first", "connection", "2026-01-06T08:00:00Z"),
               ]}
    encoded, _ = prepare_model_context(context, "QuestionSynthesis")
    lead, = encoded["advisory_leads"]
    assert lead["anchor_event_time_utc"] is None
    for scope in lead["record_index"]:
        period, = scope["periods"]
        assert period["relative_to_lead"] == "unknown"
        actions = {item["action"]: item for item in period["actions"]}
        assert actions["connection"] == {
            "action": "connection", "first_event_time_utc": "2026-01-06T08:00:00Z",
            "last_event_time_utc": "2026-01-06T17:00:00Z", "evidence_ids": ["E4", "E2", "E3"],
        }
        assert actions["image_load"]["first_event_time_utc"] is None


def test_time_anchor_is_the_earliest_advisory_match_not_an_assumed_process_start():
    context = {"completed_queries": [{"query_id": "query-a", "status": "completed", "truncated": True}],
               "retained_evidence": [
                   row("end", "process_end", "2026-01-06T17:00:00Z", lead=True),
                   row("module", "image_load", "2026-01-06T10:00:00Z", lead=True),
                   row("start", "process_start", "2026-01-06T09:00:00Z"),
               ]}
    encoded, _ = prepare_model_context(context, "QuestionSynthesis")
    lead, = encoded["advisory_leads"]
    assert lead["lead_evidence_id"] == "E2"
    assert lead["anchor_event_time_utc"] == "2026-01-06T10:00:00Z"
    for scope in lead["record_index"]:
        assert {period["relative_to_lead"]: [item["action"] for item in period["actions"]]
                for period in scope["periods"]} == {
                    "before": ["process_start"], "at": ["image_load"], "after": ["process_end"],
                }
    assert encoded["completed_queries"][0]["truncated"] is True


def test_related_index_preserves_positive_rows_from_truncated_queries_and_labels():
    context = supplied()
    original = deepcopy(context)
    encoded, refs = prepare_model_context(context, "QuestionSynthesis")
    lead, = encoded["advisory_leads"]
    assert lead["lead_evidence_id"] == "E2"
    process, session = lead["record_index"]
    assert process["filters"] == {"host": "host-a", "process_guid": "process-a", "user": "user-a", "session_id": "session-a"}
    assert action_ids(process) == {"process_start": ["E2"], "process_end": ["E1"]}
    assert session["filters"] == {"host": "host-a", "user": "user-a", "session_id": "session-a"}
    assert action_ids(session) == {"image_load": ["E3"], "process_start": ["E2"], "process_end": ["E1"], "logon": ["E4"]}
    assert set(lead["evidence_ids"]) == {"E1", "E2", "E5"}
    assert all(identifier in refs.evidence for index in lead["record_index"] for item in indexed_actions(index) for identifier in item["evidence_ids"])
    assert encoded["completed_queries"][0]["truncated"] is True
    assert context == original


@pytest.mark.parametrize("fields", [
    {"host": "host-b"}, {"host": ["host-a"]}, {"user": None},
    {"session_id": "session-b"}, {"session_id": ["session-a", "session-b"]},
])
def test_related_index_does_not_join_ambiguous_or_different_identity_fields(fields):
    context = supplied()
    context["retained_evidence"].append(row("unrelated", "connection", **fields))
    encoded, _ = prepare_model_context(context, "QuestionSynthesis")
    assert all("E5" not in item["evidence_ids"] for index in encoded["advisory_leads"][0]["record_index"] for item in indexed_actions(index))


def test_related_index_excludes_aggregates_and_separates_unknown_times_and_actions():
    context = supplied()
    context["retained_evidence"].extend([
        row("late", "image_load", "2026-01-06T18:00:00Z", process_guid="process-b"),
        row("unknown", "image_load", "2026-01-06T10:00:00", process_guid="process-b"),
        row("ambiguous", ["connection", "dns_query"]),
        {**row("aggregate", "connection"), "evidence_kind": "aggregate"},
    ])
    encoded, _ = prepare_model_context(context, "QuestionSynthesis")
    session = encoded["advisory_leads"][0]["record_index"][1]
    assert action_ids(session)["image_load"] == ["E3", "E5", "E6"]
    assert action_ids(session)[None] == ["E7"]
    assert all("E8" not in item["evidence_ids"] for item in indexed_actions(session))


@pytest.mark.parametrize("fields", [{"session_id": ["session-a"]}, {"host": None}, {"process_guid": "unknown"}])
def test_ambiguous_lead_identity_has_no_automatic_related_record_index(fields):
    context = supplied()
    context["retained_evidence"] = [row("lead", "process_start", lead=True, **fields)]
    encoded, _ = prepare_model_context(context, "QuestionSynthesis")
    assert encoded["advisory_leads"][0]["record_index"] == []


def test_budget_fitting_rebuilds_index_with_only_supplied_records():
    query_id = str(uuid4())
    records = [{**row(str(uuid4()), "process_start", lead=True, detail="x" * 200), "query_id": query_id}
               for _ in range(100)]
    model = FakeModelAdapter(responses=[json.dumps({"question_1": {
        "summary": "The supplied subset remains unreviewed.", "findings": [], "limitations": ["Unreviewed."],
        "lead_coverage": [{"lead_evidence_id": "E1", "finding_numbers": [], "limitation": "Unreviewed."}],
    }})])
    limits = BudgetLimits(max_context_characters=40_000, max_model_input_tokens=40_000)
    runner = StrictModelRunner(model, limits=limits)
    runner.run(_question_synthesis_contract(SimpleNamespace(questions=[object()])), user_payload={},
               contract_name="QuestionSynthesis", context_builder=lambda limit: {
                   "completed_queries": [{"query_id": query_id, "status": "completed"}],
                   "retained_evidence": records[:limit],
               })
    encoded = json.loads(model.requests[0].messages[0]["content"])
    provided = {item["evidence_id"] for item in encoded["retained_evidence"]}
    assert 1 < len(provided) < len(records)
    assert all(set(item["evidence_ids"]) == provided for index in encoded["advisory_leads"][0]["record_index"] for item in indexed_actions(index))
    assert runner.counters.model_output_checks[0].context_characters <= limits.max_context_characters
    assert runner.counters.model_output_checks[0].estimated_input_tokens <= limits.max_model_input_tokens
    assert model.call_count == 1
