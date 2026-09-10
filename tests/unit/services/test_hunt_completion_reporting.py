"""Report coverage and investigation-completion wording tests."""

from threat_hunting.services.reports import _concise_report_content, _derive_report_limitations


def _report(results: dict) -> dict:
    return _concise_report_content(
        hypothesis="h",
        objective="o",
        data_sources=["Splunk"],
        results=results,
        coverage_and_limitations=[],
        conclusion_and_disposition="One evidence-grounded hunt lead was identified.",
    )


def test_report_marks_unanswered_adaptive_and_truncated_coverage() -> None:
    results = {
        "queries": [{"query_id": "q1", "question_id": "q1", "status": "completed", "result_count": 1}],
        "query_assessments": [{
            "query_id": "q1",
            "question_id": "q1",
            "answered_question": False,
            "limitations": ["Authentication telemetry was unavailable."],
        }],
        "follow_up_questions": [{"question_id": "q2", "question": "What else was affected?"}],
        "adaptive_status": "no_follow_up_query",
        "evidence": [{"truncation": {"truncated": True, "reason": "row_limit"}}],
    }

    report = _report(results)

    assert any("q1 remains unanswered" in item for item in report["coverage_and_limitations"])
    assert any("follow-up questions were not executed" in item for item in report["coverage_and_limitations"])
    assert any("truncated" in item for item in report["coverage_and_limitations"])
    assert any("Assessment limitation: Authentication telemetry" in item for item in report["coverage_and_limitations"])
    assert "full blast radius is not established" in report["conclusion_and_disposition"]


def test_report_marks_budget_stop_and_unassessed_search() -> None:
    results = {
        "queries": [
            {"query_id": "q1", "question_id": "q1", "status": "completed", "result_count": 1},
            {"query_id": "q2", "question_id": "q2", "status": "completed", "result_count": 1},
        ],
        "assessed_query_ids": ["q1"],
        "adaptive_status": "budget_reserved_for_synthesis",
    }

    limitations = _derive_report_limitations(results)

    assert any("not assessed" in item for item in limitations)
    assert any("configured budget" in item for item in limitations)


def test_report_explains_paging_and_storage_stops_without_claiming_absence():
    results = {
        "queries": [{"query_id": "q1", "status": "completed", "result_count": 0,
                     "truncated": True, "retrieval_stop_reason": "hunt_byte_limit", "available_result_count": 800}],
        "query_ledger": [{"query_id": "q2", "status": "skipped_budget"}],
    }
    limitations = _derive_report_limitations(results)
    assert any("per-hunt byte limit" in item for item in limitations)
    assert any("budget was exhausted" in item and "do not establish absence" in item for item in limitations)


def test_model_context_does_not_call_empty_partial_retrieval_zero_matches():
    from threat_hunting.services.investigation import _balanced_evidence_sample

    rows, coverage = _balanced_evidence_sample([], [{
        "query_id": "q1", "status": "completed", "result_count": 0, "truncated": True,
        "available_result_count": 800, "retrieval_stop_reason": "query_byte_limit",
    }])
    assert rows == []
    assert coverage[0]["coverage_status"] == "retrieval_incomplete"
    assert coverage[0]["available_result_count"] == 800
    assert "does not establish zero matching events" in coverage[0]["coverage_note"]


def test_report_does_not_add_incomplete_scope_warning_when_all_queries_are_assessed() -> None:
    results = {
        "queries": [
            {"query_id": "q1", "question_id": "q1", "status": "completed", "result_count": 1},
            {"query_id": "q2", "question_id": "q2", "status": "completed", "result_count": 0},
        ],
        "assessed_query_ids": ["q1", "q2"],
        "query_assessments": [
            {"query_id": "q1", "answered_question": True, "limitations": []},
            {"query_id": "q2", "answered_question": True, "limitations": []},
        ],
        "adaptive_status": "no_unassessed_queries",
    }

    report = _report(results)

    assert report["coverage_and_limitations"] == []
    assert "full blast radius" not in report["conclusion_and_disposition"]



def test_narrow_empty_search_does_not_claim_full_approved_time_coverage() -> None:
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from threat_hunting.services.reports import _execution_report_content

    plan = SimpleNamespace(
        data_sources=[], questions=[], coverage_limitations=[],
        scope=SimpleNamespace(earliest_utc=datetime(2026, 1, 1, tzinfo=timezone.utc),
                              latest_utc=datetime(2026, 1, 5, tzinfo=timezone.utc)),
    )
    results = {
        "queries": [{"query_id": "dns-search", "status": "completed", "result_count": 0}],
        "query_ledger": [{"query_id": "dns-search", "proposal": {
            "indexes": ["dns"], "sourcetypes": ["dns:events"],
            "earliest_utc": "2026-01-02T00:00:00Z", "latest_utc": "2026-01-03T01:00:00Z",
        }}],
    }
    report = _execution_report_content({"hypothesis": "h", "objective": "o"}, plan, results)
    assert any("dns-search searched only 2026-01-02T00:00:00Z to 2026-01-03T01:00:00Z" in line
               and "subset of the approved time range" in line for line in report["coverage_and_limitations"])


def test_live_report_counts_actual_citations_classifications_and_searched_sources() -> None:
    from types import SimpleNamespace
    from threat_hunting.services.reports import _execution_report_content

    plan = SimpleNamespace(
        data_sources=[SimpleNamespace(index=f"th_test_{name}", sourcetypes=[f"synthetic:{kind}"])
                      for name, kind in [("endpoint", "process"), ("auth", "auth"), ("dns", "dns"), ("network", "network")]],
        questions=[SimpleNamespace(question_id="q4", question="Related DNS/network activity?")],
        coverage_limitations=["Synthetic fixture; synthetic:process uses synthetic_event_id; synthetic data only"],
    )
    queries = [{"query_id": f"query-{i}", "question_id": "q1", "status": "completed"} for i in range(6)]
    results = {
        "queries": queries,
        "query_ledger": [{"query_id": q["query_id"], "proposal": {
            "indexes": ["th_test_endpoint" if i == 0 else "th_test_auth"],
            "sourcetypes": ["synthetic:process" if i == 0 else "synthetic:auth"],
        }} for i, q in enumerate(queries)],
        "evidence": [{"evidence_id": f"e-{i}"} for i in range(328)],
        "findings": [
            {"classification": "hunt_lead", "evidence_ids": [f"e-{i}" for i in range(30)] + ["e-0"]},
            {"classification": "supported_observation", "evidence_ids": [f"e-{i}" for i in range(30, 68)]},
            {"classification": "supported_observation", "evidence_ids": ["e-30"] * 11},
        ],
    }
    report = _execution_report_content({"hypothesis": "h", "objective": "o"}, plan, results)
    conclusion = report["conclusion_and_disposition"]
    assert [len(item["evidence_ids"]) for item in report["findings"]] == [30, 38, 1]
    assert len(results["findings"][0]["evidence_ids"]) == 31
    assert "68 distinct record(s)" in conclusion
    assert "328 record(s) were retained" in conclusion
    assert "1 hunt_lead, 2 supported_observation" in conclusion
    assert report["data_sources_used"] == ["th_test_auth (synthetic:auth)", "th_test_endpoint (synthetic:process)"]
    assert plan.coverage_limitations[0] in report["coverage_and_limitations"]
    assert any("q4 was not executed" in item for item in report["coverage_and_limitations"])
    assert any("Planned source not searched: th_test_dns" in item for item in report["coverage_and_limitations"])


def test_zero_result_search_counts_as_searched_but_failed_or_planned_query_does_not() -> None:
    from types import SimpleNamespace
    from threat_hunting.services.reports import _execution_report_content

    plan = SimpleNamespace(data_sources=[], questions=[], coverage_limitations=[])
    results = {
        "queries": [{"query_id": "empty", "status": "completed", "result_count": 0},
                    {"query_id": "failed", "status": "failed"}],
        "query_ledger": [{"query_id": identifier, "proposal": {"indexes": [identifier], "sourcetypes": ["synthetic:dns"]}}
                         for identifier in ["empty", "failed", "planned"]],
        "evidence": [], "findings": [],
    }
    report = _execution_report_content({"hypothesis": "h", "objective": "o"}, plan, results)
    assert report["data_sources_used"] == ["empty (synthetic:dns)"]


def test_paired_source_query_keeps_grouped_scope_without_inventing_source_pairs() -> None:
    from types import SimpleNamespace
    from threat_hunting.services.reports import _execution_report_content

    plan = SimpleNamespace(data_sources=[], questions=[], coverage_limitations=[])
    results = {
        "queries": [{"query_id": "q4-search", "status": "completed", "result_count": 0,
                     "spl": "search (index=th_test_dns sourcetype=synthetic:dns OR index=th_test_network sourcetype=synthetic:network)"}],
        "query_ledger": [{"query_id": "q4-search", "proposal": {
            "indexes": ["th_test_dns", "th_test_network"], "sourcetypes": ["synthetic:dns", "synthetic:network"],
        }}],
        "evidence": [], "findings": [],
    }
    report = _execution_report_content({"hypothesis": "h", "objective": "o"}, plan, results)
    assert report["data_sources_used"] == ["th_test_dns, th_test_network (query sourcetypes: synthetic:dns, synthetic:network)"]
    assert "0 retained record(s)" in report["conclusion_and_disposition"]
