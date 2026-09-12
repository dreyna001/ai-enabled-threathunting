"""Question inventories are measured from retained rows, never model quantities."""

from copy import deepcopy
from datetime import datetime, timezone
import json
from types import SimpleNamespace
from uuid import uuid4

import pytest

from threat_hunting.domain.contracts import MAX_STORED_QUESTION_INVENTORIES
from threat_hunting.domain.errors import Validation
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.services.evidence import (
    advisory_lead_groups,
    lead_session_spl_disjunction,
    question_requires_all_lead_coverage,
    retained_lead_session_filters,
    spl_covers_all_lead_sessions,
    spl_covers_lead_session,
    spl_literal,
    widen_spl_for_lead_sessions,
)
from threat_hunting.services.investigation import _materialize_question_answers, _question_synthesis_contract
from threat_hunting.services.orchestration import ModelContractError, StrictModelRunner
from threat_hunting.services.reports import ReportValidationError, _concise_report_content, _formatted_pdf, _validate_report_content, render_report_html


def plan():
    return SimpleNamespace(questions=[SimpleNamespace(question_id="approved-1", question="How many process GUID values occur?")],
                           scope=SimpleNamespace(earliest_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
                                                 latest_utc=datetime(2026, 1, 2, tzinfo=timezone.utc)))


def state():
    query = str(uuid4())
    return {"queries": [{"query_id": query, "status": "completed", "result_count": 52, "truncated": False}],
            "evidence": [{"query_id": query, "evidence_id": str(uuid4()), "evidence_kind": "raw_event",
                          "event_time_utc": "2026-01-01T12:00:00Z",
                          "selected_result": {"host": "host-a", "process_guid": "guid-a"}} for _ in range(52)]}


def response():
    return {"question_1": {"summary": "The inventory measures the selected retained records.", "findings": [],
                           "lead_coverage": [], "limitations": ["Counts do not establish incident scope."],
                           "inventory_scopes": [{"query_ids": ["Q1"], "filters": [], "earliest_utc": None, "latest_utc": None}]}}


def materialized(source=None, answer=None, *, hunt_plan=None):
    source = source or state()
    hunt_plan = hunt_plan or plan()
    model = FakeModelAdapter(responses=[json.dumps(answer or response())])
    parsed = StrictModelRunner(model).run(_question_synthesis_contract(hunt_plan), contract_name="QuestionSynthesis", user_payload={
        "completed_queries": source["queries"], "retained_evidence": source["evidence"][:1],
        "retained_query_inventories": [{"should_not_reach_model": True}],
    })
    return _materialize_question_answers(parsed, hunt_plan, source), model


def test_inventory_counts_all_retained_rows_without_model_transcription():
    stored, model = materialized()
    inventory, = stored["question_answers"][0]["inventories"]
    assert inventory["raw_record_count"] == 52
    metric = next(item for item in inventory["fields"] if item["field"] == "process_guid")
    assert metric["distinct_literal_value_count"] == 1
    sent = json.loads(model.requests[0].messages[0]["content"])
    assert "retained_query_inventories" not in sent
    assert len(sent["retained_evidence"]) == 1
    assert model.call_count == 1


@pytest.mark.parametrize("failure", ["invented_count", "unknown_query", "outside_window", "duplicate_field"])
def test_invalid_inventory_selection_uses_existing_bounded_repair(failure):
    answer = response()
    scope = answer["question_1"]["inventory_scopes"][0]
    if failure == "invented_count":
        scope["distinct_process_guids"] = 2
    elif failure == "unknown_query":
        scope["query_ids"] = ["Q99"]
    elif failure == "outside_window":
        scope["earliest_utc"] = "2025-12-31T00:00:00Z"
    else:
        scope["filters"] = [{"field": "host", "value": "host-a"}] * 2
    source = state()
    model = FakeModelAdapter(responses=[json.dumps(answer), json.dumps(response())])
    result = StrictModelRunner(model).run(_question_synthesis_contract(plan()), contract_name="QuestionSynthesis", user_payload={
        "completed_queries": source["queries"], "retained_evidence": source["evidence"][:1],
    })
    assert len(result.question_1.inventory_scopes) == 1
    assert model.call_count == 2


def test_inventories_preserve_missing_multivalue_and_partial_scope_limits():
    source = state()
    source["queries"][0]["truncated"] = True
    source["evidence"][0]["selected_result"]["process_guid"] = ["guid-a", "guid-b"]
    source["evidence"][1]["selected_result"].pop("process_guid")
    source["evidence"][2]["evidence_kind"] = "aggregate_row"
    stored, _ = materialized(source)
    inventory = stored["question_answers"][0]["inventories"][0]
    metric = next(item for item in inventory["fields"] if item["field"] == "process_guid")
    assert inventory["raw_record_count"] == 51
    assert metric == {"field": "process_guid", "distinct_literal_value_count": 2, "distinct_unambiguous_value_count": 1,
                      "rows_with_missing_or_nonscalar_value": 1, "rows_with_multiple_distinct_values": 1}
    assert any("incomplete" in text for text in inventory["limitations"])


def test_report_inventory_quantities_and_scope_cannot_be_changed_or_dropped():
    stored, _ = materialized()
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=stored,
                                     coverage_and_limitations=[], conclusion_and_disposition="Review remains open.")
    assert _validate_report_content(report, stored) == report
    for mutation in ("drop", "count", "scope"):
        changed = deepcopy(report)
        answer = changed["question_answers"][0]
        if mutation == "drop":
            answer.pop("inventories")
        elif mutation == "count":
            answer["inventories"][0]["raw_record_count"] = 2
        else:
            answer["inventories"][0]["scope"]["query_ids"] = [str(uuid4())]
        with pytest.raises(Validation, match="inventor"):
            _validate_report_content(changed, stored)
    assert b"52 retained raw rows" in _formatted_pdf("Inventory report", report)
    report["question_answers"][0]["inventories"][0]["raw_record_count"] = 999
    assert stored["question_answers"][0]["inventories"][0]["raw_record_count"] == 52


@pytest.mark.parametrize("mutation", ["boolean_count", "float_count", "typed_filter"])
def test_report_inventory_preservation_compares_scalar_types(mutation):
    source = state()
    for row in source["evidence"]:
        row["selected_result"]["host"] = 1
    answer = response()
    answer["question_1"]["inventory_scopes"][0]["filters"] = [{"field": "host", "value": 1}]
    stored, _ = materialized(source, answer)
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=stored,
                                     coverage_and_limitations=[], conclusion_and_disposition="Review remains open.")
    inventory = report["question_answers"][0]["inventories"][0]
    if mutation == "typed_filter":
        inventory["scope"]["filters"][0]["value"] = True
    else:
        metric = next(item for item in inventory["fields"] if item["field"] == "process_guid")
        metric["distinct_literal_value_count"] = True if mutation == "boolean_count" else 1.0
    with pytest.raises(Validation, match="inventor"):
        _validate_report_content(report, stored)


def test_inventory_html_escapes_filter_values_and_rejects_invalid_quantities():
    source = state()
    for row in source["evidence"]:
        row["selected_result"]["host"] = "<script>host</script>"
    answer = response()
    answer["question_1"]["inventory_scopes"][0]["filters"] = [{"field": "host", "value": "<script>host</script>"}]
    stored, _ = materialized(source, answer)
    canonical = {"hypothesis": "h", "objective_and_scope": "o", "data_sources_used": [], "finding_ids": [],
                 "evidence_ids": [], "query_ids": [source["queries"][0]["query_id"]], "entities": [], "timeline": [],
                 "coverage": [], "conclusion": "Review remains open.", "disposition": "inconclusive", "limitations": [],
                 "query_appendix": [], "question_answers": stored["question_answers"]}
    rendered = render_report_html(canonical)
    assert "52 retained raw rows" in rendered and "process guid: 1 distinct literal values" in rendered
    assert "&lt;script&gt;host&lt;/script&gt;" in rendered and "<script>host</script>" not in rendered
    canonical["question_answers"][0]["inventories"][0]["raw_record_count"] = True
    with pytest.raises(ReportValidationError, match="inventory"):
        render_report_html(canonical)


@pytest.mark.parametrize("scope_change", ["unknown_query", "outside_window"])
def test_inventory_persistence_rechecks_scope(scope_change):
    source = state()
    context = {"completed_queries": source["queries"], "retained_evidence": source["evidence"][:1]}
    parsed = StrictModelRunner(FakeModelAdapter(responses=[json.dumps(response())])).run(
        _question_synthesis_contract(plan()), user_payload=context, contract_name="QuestionSynthesis")
    if scope_change == "unknown_query":
        parsed.question_1.inventory_scopes[0].query_ids = [str(uuid4())]
    else:
        parsed.question_1.inventory_scopes[0].earliest_utc = datetime(2025, 12, 1, tzinfo=timezone.utc)
    with pytest.raises((Validation, ValueError)):
        _materialize_question_answers(parsed, plan(), source)


def _five_lead_state():
    query = str(uuid4())
    evidence = []
    for index in range(5):
        evidence.append({
            "query_id": query, "evidence_id": str(uuid4()), "evidence_kind": "raw_event",
            "event_time_utc": f"2026-01-0{index + 1}T12:00:00Z",
            "selected_result": {
                "host": f"host-{index}", "user": f"user-{index}",
                "session_id": f"session-{index}", "process_guid": f"guid-{index}",
                "file_name": "observed.exe",
            },
            "advisory_ioc_comparison": {"matched_file_name_literals": ["observed.exe"]},
        })
    return {
        "queries": [{"query_id": query, "question_id": "approved-spread", "status": "completed", "result_count": 5, "truncated": False}],
        "evidence": evidence,
    }


def _materialize_direct(source, answer, *, hunt_plan):
    parsed = _question_synthesis_contract(hunt_plan).model_validate(answer)
    return _materialize_question_answers(
        parsed, hunt_plan, source, threat_intelligence="[file:name = 'observed.exe']",
    )


def test_count_question_materializes_five_application_owned_session_inventories():
    source = _five_lead_state()
    plan = SimpleNamespace(
        questions=[SimpleNamespace(
            question_id="approved-spread",
            question="Across how many distinct related hosts, users, source or destination IPs, and processes were communications observed?",
        )],
        scope=SimpleNamespace(earliest_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
                              latest_utc=datetime(2026, 1, 10, tzinfo=timezone.utc)),
    )
    answer = {"question_1": {"summary": "Refer to measured tables.", "findings": [], "lead_coverage": [],
                             "inventory_scopes": [], "limitations": ["Counts remain scoped."]}}
    stored = _materialize_direct(source, answer, hunt_plan=plan)
    inventories = stored["question_answers"][0]["inventories"]
    assert len(inventories) == 5
    sessions = {json.dumps(item["scope"]["filters"], sort_keys=True) for item in inventories}
    assert len(sessions) == 5


def test_unrelated_question_does_not_auto_add_inventories():
    source = _five_lead_state()
    plan = SimpleNamespace(
        questions=[SimpleNamespace(question_id="approved-spread",
                                   question="What authentication activity is associated with related hosts and users?")],
        scope=SimpleNamespace(earliest_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
                              latest_utc=datetime(2026, 1, 10, tzinfo=timezone.utc)),
    )
    answer = {"question_1": {"summary": "No inventories requested.", "findings": [], "lead_coverage": [],
                             "inventory_scopes": [], "limitations": ["Authentication only."]}}
    stored = _materialize_direct(source, answer, hunt_plan=plan)
    assert "inventories" not in stored["question_answers"][0]


def test_report_accepts_five_inventories_and_rejects_overflow():
    source = _five_lead_state()
    plan = SimpleNamespace(
        questions=[SimpleNamespace(
            question_id="approved-spread",
            question="Across how many distinct related hosts, users, source or destination IPs, and processes were communications observed?",
        )],
        scope=SimpleNamespace(earliest_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
                              latest_utc=datetime(2026, 1, 10, tzinfo=timezone.utc)),
    )
    answer = {"question_1": {"summary": "Refer to measured tables.", "findings": [], "lead_coverage": [],
                             "inventory_scopes": [], "limitations": ["Counts remain scoped."]}}
    stored = _materialize_direct(source, answer, hunt_plan=plan)
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=stored,
                                     coverage_and_limitations=[], conclusion_and_disposition="Review remains open.")
    assert len(report["question_answers"][0]["inventories"]) == 5
    assert _validate_report_content(report, stored) == report
    overflow = deepcopy(report)
    overflow["question_answers"][0]["inventories"].extend(
        [deepcopy(overflow["question_answers"][0]["inventories"][0])] * (MAX_STORED_QUESTION_INVENTORIES - 4)
    )
    with pytest.raises(Validation, match="inventor"):
        _validate_report_content(overflow, stored)


def test_filtered_inventory_reports_unknown_time_and_missing_filter_boundaries():
    source = state()
    source["evidence"][0]["event_time_utc"] = "unknown"
    answer = response()
    answer["question_1"]["inventory_scopes"][0]["earliest_utc"] = "2026-01-01T11:00:00Z"
    stored, _ = materialized(source, answer)
    inventory = stored["question_answers"][0]["inventories"][0]
    assert inventory["raw_record_count"] == 51
    assert any("excluded 1 rows with unknown timestamps" in item for item in inventory["limitations"])
    answer["question_1"]["inventory_scopes"][0]["filters"] = [{"field": "unobserved", "value": "x"}]
    stored, _ = materialized(source, answer)
    inventory = stored["question_answers"][0]["inventories"][0]
    assert inventory["raw_record_count"] == 0
    assert any("zero matches does not establish absence" in item for item in inventory["limitations"])


@pytest.mark.parametrize("question,expected", [
    ("What related endpoint execution records occur around each lead?", True),
    ("Review all leads for related authentication activity.", True),
    ("What authentication activity is associated with related hosts and users?", True),
    ("What DNS and network activity is associated with related processes and hosts?", True),
    ("Do scoped endpoint records contain an exact advisory hash or filename match?", False),
    ("Pivot the observed host for unrelated telemetry.", False),
])
def test_question_requires_all_lead_coverage(question, expected):
    assert question_requires_all_lead_coverage(question) is expected


def test_lead_session_disjunction_covers_five_sessions_and_escapes_literals():
    sessions = [
        {"host": f"host-{index}", "user": f"user-{index}", "session_id": f"session-{index}"}
        for index in range(5)
    ]
    sessions[0]["user"] = r'CORP\j."smith'
    disjunction = lead_session_spl_disjunction(sessions)
    for session in sessions:
        assert spl_covers_lead_session(disjunction, session)
    assert spl_literal(r'CORP\j."smith') in disjunction
    assert 'host="host-4"' in disjunction
    assert disjunction.count(" OR ") == 4


def test_spl_covers_lead_session_requires_and_conjunction_not_or_pivot():
    session = {"host": "ws-17.corp.example", "user": r"CORP\j.smith", "session_id": "799a2e31-bb86-53af-818e-7a4fc8b5b766"}
    narrow = (
        '(host="ws-17.corp.example" OR user="CORP\\j.smith" '
        'OR session_id="799a2e31-bb86-53af-818e-7a4fc8b5b766")'
    )
    wide = (
        f'(host={spl_literal(session["host"])} AND user={spl_literal(session["user"])} '
        f'AND session_id={spl_literal(session["session_id"])})'
    )
    assert not spl_covers_lead_session(narrow, session)
    assert spl_covers_lead_session(wide, session)


def test_widen_spl_replaces_ws17_only_auth_filter_with_all_five_sessions():
    sessions = retained_lead_session_filters(advisory_lead_groups(_five_lead_state()["evidence"]))
    assert len(sessions) == 5
    original = (
        'search index=auth sourcetype=auth '
        '(host="host-0" OR user="user-0" OR session_id="session-0") | table host user session_id'
    )
    assert not spl_covers_all_lead_sessions(original, sessions)
    widened = widen_spl_for_lead_sessions(original, sessions)
    assert spl_covers_all_lead_sessions(widened, sessions)
    assert "index=auth" in widened
    assert "| table host user session_id" in widened
    assert "host-4" in widened and "session-4" in widened
