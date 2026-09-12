"""Compact chronology obligations derived from advisory lead record_index."""

import json
from datetime import datetime, timezone
from types import SimpleNamespace

from threat_hunting.services.investigation import _synthesis_context
from threat_hunting.services.model_output import prepare_model_context


def row(identifier, action, stamp=None, *, lead=False, **fields):
    return {
        "evidence_id": identifier, "query_id": "query-a", "evidence_kind": "raw_event",
        "event_time_utc": stamp,
        "selected_result": {"host": "host-a", "user": "user-a", "session_id": "session-a",
                            "process_guid": "process-a", "action": action, **fields},
        "advisory_ioc_comparison": {"matched_file_name_literals": ["observed.exe"] if lead else []},
    }


def supplied():
    return {
        "completed_queries": [{"query_id": "query-a", "status": "completed", "truncated": True}],
        "retained_evidence": [
            row("end", "process_end", "2026-01-06T17:00:00Z", lead=True, file_name="observed.exe"),
            row("start", "process_start", "2026-01-06T09:00:00Z", lead=True, file_name="observed.exe"),
            row("module", "image_load", "2026-01-06T08:00:00Z", process_guid="process-b"),
            row("auth", "logon", process_guid=None),
            row("after-dns", "dns_query", "2026-01-06T18:00:00Z"),
            row("before-dns", "dns_query", "2026-01-06T08:30:00Z"),
        ],
    }


def test_chronology_obligations_include_action_period_count_and_representative_label():
    encoded, _ = prepare_model_context(supplied(), "QuestionSynthesis")
    lead, = encoded["advisory_leads"]
    obligations = lead["chronology_obligations"]
    session = next(item for item in obligations if item["scope"] == "session" and item["action"] == "image_load")
    assert session == {
        "scope": "session",
        "filters": {"host": "host-a", "user": "user-a", "session_id": "session-a"},
        "period": "before",
        "action": "image_load",
        "count": 1,
        "representative_evidence_id": "E3",
        "first_event_time_utc": "2026-01-06T08:00:00Z",
        "last_event_time_utc": "2026-01-06T08:00:00Z",
    }
    after_dns = next(item for item in obligations if item["action"] == "dns_query" and item["period"] == "after")
    assert after_dns["count"] == 1
    assert after_dns["representative_evidence_id"] == "E5"
    indexed_ids = {
        identifier
        for scope in lead["record_index"]
        for period in scope["periods"]
        for action in period["actions"]
        for identifier in action["evidence_ids"]
    }
    obligation_ids = {item["representative_evidence_id"] for item in obligations}
    assert obligation_ids.issubset(indexed_ids)
    assert len({json.dumps(item, sort_keys=True) for item in obligations}) == len(obligations)


def test_record_index_action_groups_expose_count_and_representative_without_duplicating_rows():
    encoded, _ = prepare_model_context(supplied(), "QuestionSynthesis")
    lead, = encoded["advisory_leads"]
    session = lead["record_index"][1]
    module = next(action for period in session["periods"] for action in period["actions"] if action["action"] == "image_load")
    assert module["raw_record_count"] == 1
    assert module["representative_evidence_id"] == "E3"
    assert "selected_result" not in json.dumps(lead["chronology_obligations"])


def test_synthesis_context_fits_expanded_profile_with_obligations_and_inventory_summaries():
    plan = SimpleNamespace(
        hypothesis="h", objective="o",
        scope=SimpleNamespace(
            earliest_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
            latest_utc=datetime(2026, 1, 10, tzinfo=timezone.utc),
            model_dump=lambda **_: {},
        ),
        questions=[SimpleNamespace(
            question_id="q4",
            question="Across how many distinct related hosts, users, source or destination IPs, and processes were communications observed?",
            model_dump=lambda **_: {},
        )],
    )
    results = {
        "queries": [{"query_id": "query-a", "question_id": "q4", "status": "completed", "result_count": 6}],
        "evidence": supplied()["retained_evidence"],
    }
    context = _synthesis_context(plan=plan, threat_intelligence="[file:name = 'observed.exe']", results=results)
    encoded, _ = prepare_model_context(context, "QuestionSynthesis")
    body = json.dumps(encoded, ensure_ascii=False, sort_keys=True, default=str)
    assert "question_inventory_summaries" in context
    assert len(context["question_inventory_summaries"]["question_1"]) == 1
    assert encoded["advisory_leads"][0]["chronology_obligations"]
    assert len(body) <= 800_000
