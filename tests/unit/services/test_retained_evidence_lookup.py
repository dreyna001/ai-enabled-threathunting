from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from threat_hunting.domain.errors import Validation
from threat_hunting.services.evidence import lookup_retained_evidence
from threat_hunting.services.investigation import _balanced_evidence_sample, _synthesis_context


def results():
    return {
        "queries": [{"query_id": "q1", "status": "completed", "result_count": 9, "available_result_count": 100, "truncated": True}],
        "evidence": [
            {"query_id": "q1", "evidence_id": f"e{i}", "event_time_utc": f"2026-01-01T{i:02d}:00:00Z", "selected_result": {
                "host": "host-1" if i < 6 else "host-2", "user": "account", "process": "browser", "process_guid": f"process-{i % 2}", "port": 443,
            }} for i in range(9)
        ],
    }


def test_lookup_filters_a_page_without_changing_query_or_retention_counts():
    state = results()
    original = deepcopy(state)
    first = lookup_retained_evidence(state, query_ids={"q1"}, filters={"host": "host-2"}, limit=100, max_rows=2)
    assert first["matching_raw_record_count"] == 3
    assert first["query_coverage"] == [{"query_id": "q1", "result_count": 9, "retained_evidence_count": 9,
                                       "query_truncated": True, "available_result_count": 100, "retrieval_stop_reason": None}]
    assert first["effective_limit"] == 2
    assert [row["evidence_id"] for row in first["records"]] == ["e6", "e7"]
    second = lookup_retained_evidence(state, query_ids={"q1"}, filters={"host": "host-2"}, offset=first["next_offset"], limit=2)
    assert [row["evidence_id"] for row in second["records"]] == ["e8"]
    assert second["next_offset"] is None
    assert state == original
    first["records"][0]["selected_result"]["host"] = "changed in caller"
    assert state == original


def test_filters_use_complete_typed_values_and_preserve_multivalue_ambiguity():
    state = results()
    state["evidence"][0]["selected_result"]["host"] = ["host-1", "collector"]
    state["evidence"][1]["selected_result"]["host"] = ["host-1", "host-1"]
    state["evidence"][2]["selected_result"]["host"] = None
    assert lookup_retained_evidence(state, query_ids={"q1"}, filters={"host": "host"})["matching_raw_record_count"] == 0
    assert lookup_retained_evidence(state, query_ids={"q1"}, filters={"port": "443"})["matching_raw_record_count"] == 0
    match = lookup_retained_evidence(state, query_ids={"q1"}, filters={"host": "host-1", "port": 443})
    assert match["matching_raw_record_count"] == 5
    field = next(item for item in match["distinct_fields"] if item["field"] == "host")
    assert field["distinct_literal_value_count"] == 2
    assert field["rows_with_multiple_distinct_values"] == 1
    assert match["records"][0]["selected_result"]["host"] == ["host-1", "collector"]


def test_time_window_is_half_open_and_never_invents_timestamps_for_unknowns_or_aggregates():
    state = results()
    state["evidence"][0]["event_time_utc"] = "unknown"
    state["evidence"][1]["event_time_utc"] = "2026-01-01T01:00:00"
    state["evidence"][2]["evidence_kind"] = "aggregate_row"
    state["evidence"][3]["event_time_utc"] = "2025-12-31T22:00:00-05:00"
    page = lookup_retained_evidence(state, query_ids={"q1"}, earliest_utc=datetime(2026, 1, 1, 2, tzinfo=timezone.utc),
                                    latest_utc=datetime(2026, 1, 1, 5, tzinfo=timezone.utc))
    assert [item["evidence_id"] for item in page["records"]] == ["e3", "e4"]
    assert page["aggregate_rows_excluded"] == 1
    assert page["unknown_time_rows_excluded_by_window"] == 2
    assert page["observed_time_bounds"]["first_observed_utc"] == "2026-01-01T03:00:00Z"
    assert page["query_coverage"][0]["retained_evidence_count"] == 9


def test_distinct_values_do_not_count_duplicate_rows_as_new_entities_or_process_names_as_instances():
    state = results()
    state["evidence"].append(deepcopy(state["evidence"][0]))
    page = lookup_retained_evidence(state, query_ids={"q1"}, limit=1)
    counts = {item["field"]: item for item in page["distinct_fields"]}
    assert page["matching_raw_record_count"] == 10
    assert counts["host"]["distinct_literal_value_count"] == 2
    assert counts["process"]["distinct_literal_value_count"] == 1
    assert counts["process_guid"]["distinct_literal_value_count"] == 2
    assert counts["src_ip"]["rows_with_missing_or_nonscalar_value"] == 10
    assert "not all source events or confirmed affected entities" in page["limitation"]


@pytest.mark.parametrize("options", [
    {"query_ids": {"other-hunt"}}, {"query_ids": set()}, {"offset": -1}, {"limit": 0}, {"limit": True},
    {"filters": {"host": {"regex": ".*"}}}, {"filters": {"port": float("inf")}},
    {"earliest_utc": datetime(2026, 1, 1)},
    {"earliest_utc": datetime(2026, 1, 2, tzinfo=timezone.utc), "latest_utc": datetime(2026, 1, 1, tzinfo=timezone.utc)},
])
def test_invalid_lookups_fail_closed(options):
    with pytest.raises(Validation):
        lookup_retained_evidence(results(), **({"query_ids": {"q1"}} | options))


def test_time_spread_keeps_early_late_and_interior_rows_without_changing_storage_order():
    state = results()
    original = deepcopy(state)
    rows, coverage = _balanced_evidence_sample(state["evidence"], state["queries"], limit=3)
    assert [row["evidence_id"] for row in rows] == ["e0", "e8", "e4"]
    assert coverage[0]["retained_evidence_count"] == 9
    assert coverage[0]["omitted_evidence_count"] == 6
    assert state == original


def test_time_spread_preserves_query_source_and_indicator_priorities():
    state = results()
    state["queries"][0]["spl"] = 'search ((index=a sourcetype=x) OR (index=b sourcetype=y))'
    for i, row in enumerate(state["evidence"]):
        row["selected_result"].update(index="a" if i < 8 else "b", sourcetype="x" if i < 8 else "y")
    state["queries"].append({"query_id": "q2", "status": "completed", "result_count": 1})
    state["evidence"].append({"query_id": "q2", "evidence_id": "other", "selected_result": {}})
    rows, _ = _balanced_evidence_sample(state["evidence"], state["queries"], limit=3, preferred_evidence_ids={"e3"})
    assert {row["evidence_id"] for row in rows} == {"e3", "e8", "other"}


def test_synthesis_receives_full_retained_counts_separately_from_its_small_sample():
    state = results()
    plan = SimpleNamespace(hypothesis="h", objective="o", questions=[], scope=SimpleNamespace(model_dump=lambda **_: {}))
    context = _synthesis_context(plan=plan, threat_intelligence="", results=state, limit=3)
    assert len(context["retained_evidence"]) == 3
    inventory = context["retained_query_inventories"][0]
    assert inventory["matching_raw_record_count"] == 9
    assert inventory["query_coverage"][0]["query_truncated"] is True
    assert "records" not in inventory
    assert next(item for item in inventory["distinct_fields"] if item["field"] == "host")["distinct_literal_value_count"] == 2
    assert context["evidence_coverage"][0]["supplied_evidence_count"] == 3
