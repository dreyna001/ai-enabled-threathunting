"""Timestamp ranges establish observation bounds, never continuous coverage."""

from threat_hunting.services.evidence import evidence_time_bounds
from threat_hunting.services.investigation import _balanced_evidence_sample


def test_same_time_heartbeats_cannot_establish_a_two_hour_window():
    records = [{"evidence_id": str(i), "query_id": "q", "event_time_utc": "2026-09-08T12:00:00Z"} for i in range(560)]
    sampled, coverage = _balanced_evidence_sample(records, [{"query_id": "q", "status": "completed", "result_count": 560}])
    assert len(sampled) == 500
    bounds = coverage[0]["observed_time_bounds"]
    assert bounds["first_observed_utc"] == bounds["last_observed_utc"] == "2026-09-08T12:00:00Z"
    assert bounds["timestamped_record_count"] == 560
    assert bounds["continuous_coverage_established"] is False
    assert "do not establish continuous" in bounds["limitation"]


def test_endpoints_do_not_prove_coverage_between_them():
    bounds = evidence_time_bounds([
        {"event_time_utc": "2026-09-08T07:00:00-04:00"},
        {"event_time_utc": "2026-09-08T13:00:00Z"},
    ])
    assert bounds["first_observed_utc"] == "2026-09-08T11:00:00Z"
    assert bounds["last_observed_utc"] == "2026-09-08T13:00:00Z"
    assert bounds["continuous_coverage_established"] is False


def test_unknown_times_and_aggregates_never_extend_raw_event_bounds():
    bounds = evidence_time_bounds([
        {"event_time_utc": "2026-09-08T12:00:00Z"},
        {"event_time_utc": "2020-01-01T00:00:00Z", "evidence_kind": "aggregate_row"},
        {"event_time_utc": "unknown"}, {"event_time_utc": "2026-09-08T11:00:00"}, {},
    ])
    assert bounds["first_observed_utc"] == "2026-09-08T12:00:00Z"
    assert bounds["timestamped_record_count"] == 1
    assert bounds["unknown_time_record_count"] == 3
    assert bounds["aggregate_row_count"] == 1
    assert evidence_time_bounds([])["last_observed_utc"] == "unknown"
