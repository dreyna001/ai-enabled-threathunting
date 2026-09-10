from types import SimpleNamespace
from uuid import uuid4

import pytest

from threat_hunting.services.investigation import _assessment_context, _balanced_evidence_sample, _materialize_follow_up_questions, _synthesis_context
from threat_hunting.services.workflow import Validation
from threat_hunting.domain.contracts import EntityType, QueryAssessment


def _plan() -> SimpleNamespace:
    return SimpleNamespace(
        hypothesis="h",
        objective="o",
        questions=[],
        scope=SimpleNamespace(model_dump=lambda **_: {}),
    )


def test_balanced_sample_does_not_starve_later_queries() -> None:
    queries = [
        {"query_id": "early", "status": "completed", "result_count": 580},
        {"query_id": "later", "status": "completed", "result_count": 3},
        {"query_id": "last", "status": "completed", "result_count": 1},
    ]
    evidence = [
        {"evidence_id": f"early-{index}", "query_id": "early"}
        for index in range(580)
    ] + [
        {"evidence_id": f"later-{index}", "query_id": "later"}
        for index in range(3)
    ] + [{"evidence_id": "last-0", "query_id": "last"}]

    sampled, coverage = _balanced_evidence_sample(evidence, queries)

    assert len(sampled) == 500
    assert {row["query_id"] for row in sampled} == {"early", "later", "last"}
    assert {item["query_id"]: item["supplied_evidence_count"] for item in coverage} == {
        "early": 496,
        "later": 3,
        "last": 1,
    }
    early = next(item for item in coverage if item["query_id"] == "early")
    assert early["retained_evidence_count"] == 580
    assert early["omitted_evidence_count"] == 84
    assert early["sample_omitted"] is True


def test_assessment_context_filters_pending_queries_before_sampling() -> None:
    results = {
        "queries": [
            {"query_id": "old", "question_id": "old", "status": "completed", "result_count": 100},
            {"query_id": "new", "question_id": "new", "status": "completed", "result_count": 1},
            {"query_id": "empty", "question_id": "empty", "status": "completed", "result_count": 0},
        ],
        "evidence": [
            {"evidence_id": f"old-{index}", "query_id": "old", "selected_result": {}}
            for index in range(100)
        ] + [{"evidence_id": "new-row", "query_id": "new", "selected_result": {"host": "host-1"}}],
    }

    context = _assessment_context(_plan(), results, query_ids={"new", "empty"})

    assert "retained_evidence" not in context
    assert {
        query["query_id"]: [row["evidence_id"] for row in query["retained_evidence"]]
        for query in context["completed_queries"]
    } == {"new": ["new-row"], "empty": []}
    assert {item["query_id"] for item in context["evidence_coverage"]} == {"new", "empty"}
    assert next(item for item in context["evidence_coverage"] if item["query_id"] == "empty")["coverage_status"] == "no_results"


def test_synthesis_context_exposes_sample_coverage() -> None:
    queries = [{"query_id": "q1", "status": "completed", "result_count": 501}]
    results = {
        "queries": queries,
        "evidence": [
            {"evidence_id": f"e-{index}", "query_id": "q1", "selected_result": {}}
            for index in range(501)
        ],
    }

    context = _synthesis_context(plan=_plan(), threat_intelligence="", results=results)

    assert len(context["retained_evidence"]) == 500
    assert [{key: value for key, value in item.items() if key != "observed_time_bounds"} for item in context["evidence_coverage"]] == [{
        "query_id": "q1",
        "result_count": 501,
        "retained_evidence_count": 501,
        "supplied_evidence_count": 500,
        "omitted_evidence_count": 1,
        "sample_omitted": True,
        "query_truncated": None,
        "available_result_count": None,
        "retrieval_stop_reason": None,
        "coverage_status": "sampled",
        "coverage_note": "Only a bounded sample was supplied; omitted retained records may contain relevant activity.",
    }]
    assert any("sample_omitted" in rule for rule in context["synthesis_rules"])


def test_synthesis_samples_all_queries_independently_of_assessment_support() -> None:
    plan = _plan()
    plan.questions = [SimpleNamespace(question_id=f"approved-{i}", model_dump=lambda **_: {}) for i in range(4)]
    # Large earlier citation groups must not monopolize the final source sample.
    sizes = [24, 4, 4, 37, 20, 4, 24, 24, 24]
    questions = ["pivot-0", "pivot-1", "pivot-2", "pivot-3", "approved-0", "approved-1", "approved-2", "approved-3", "approved-3"]
    queries = [
        {"query_id": f"query-{i}", "question_id": question, "status": "completed", "result_count": max(size, 100)}
        for i, (question, size) in enumerate(zip(questions, sizes))
    ]
    evidence = [
        {"query_id": query["query_id"], "evidence_id": f"row-{i}-{j}", "selected_result": {"host": f"host-{i}"}}
        for i, query in enumerate(queries) for j in range(query["result_count"])
    ]
    assessments = [
        {"query_id": query["query_id"], "question_id": query["question_id"], "summary": "Observed activity with unknown intent.",
         "evidence_candidate_row_refs": [f"row-{i}-{j}" for j in range(size)], "new_entities": []}
        for i, (query, size) in enumerate(zip(queries, sizes))
    ]
    results = {"queries": queries, "evidence": evidence, "query_assessments": assessments}

    context = _synthesis_context(plan=plan, threat_intelligence="", results=results)

    assert len(context["retained_evidence"]) == 500
    supplied = {row["evidence_id"] for row in context["retained_evidence"]}
    assert {row["query_id"] for row in context["retained_evidence"]} == {query["query_id"] for query in queries}
    sizes = [item["supplied_evidence_count"] for item in context["evidence_coverage"]]
    assert max(sizes) - min(sizes) <= 1
    assert "prior_assessments" not in context
    assert context == _synthesis_context(plan=plan, threat_intelligence="", results={**results, "query_assessments": []})
    assert sum(item["supplied_evidence_count"] for item in context["evidence_coverage"]) == 500
    assert context == _synthesis_context(plan=plan, threat_intelligence="", results=results)
    assert [row["evidence_id"] for row in evidence[:3]] == ["row-0-0", "row-0-1", "row-0-2"]


def test_synthesis_oversized_or_wrong_query_support_cannot_hide_other_sources() -> None:
    queries = [
        {"query_id": "large", "status": "completed", "result_count": 501,
         "spl": "search ((index=dns sourcetype=dns) OR (index=network sourcetype=net)) | table index sourcetype"},
        {"query_id": "small", "status": "completed", "result_count": 2},
        {"query_id": "wrong", "status": "completed", "result_count": 1},
        {"query_id": "empty", "status": "completed", "result_count": 0},
    ]
    evidence = [
        {"query_id": "large", "evidence_id": f"dns-{i}", "selected_result": {"index": "dns", "sourcetype": "dns"}}
        for i in range(500)
    ] + [{"query_id": "large", "evidence_id": "network", "selected_result": {"index": "network", "sourcetype": "net"}}]
    evidence += [{"query_id": "small", "evidence_id": f"small-{i}", "selected_result": {}} for i in range(2)]
    evidence += [{"query_id": "wrong", "evidence_id": "wrong-0", "selected_result": {}}]
    assessments = [
        {"query_id": "large", "evidence_candidate_row_refs": [row["evidence_id"] for row in evidence[:501]]},
        {"query_id": "wrong", "evidence_candidate_row_refs": ["small-0"]},
        {"query_id": "small", "evidence_candidate_row_refs": ["small-0", "small-1"]},
        {"query_id": "empty", "evidence_candidate_row_refs": []},
    ]

    context = _synthesis_context(plan=_plan(), threat_intelligence="", results={
        "queries": queries, "evidence": evidence, "query_assessments": assessments,
    })

    supplied = {row["evidence_id"] for row in context["retained_evidence"]}
    assert len(supplied) == len(context["retained_evidence"]) == 500
    assert {"network", "small-0", "small-1", "wrong-0"} <= supplied
    assert "prior_assessments" not in context
    assert next(item for item in context["evidence_coverage"] if item["query_id"] == "large")["sample_omitted"] is True
    assert next(item for item in context["evidence_coverage"] if item["query_id"] == "empty")["coverage_status"] == "no_results"


def test_empty_query_context_preserves_its_actual_window_from_checkpoint() -> None:
    window = {"earliest_utc": "2026-01-02T00:00:00Z", "latest_utc": "2026-01-03T01:00:00Z"}
    results = {
        "queries": [{"query_id": "narrow", "question_id": "q4", "status": "completed", "result_count": 0}],
        "query_ledger": [{"query_id": "narrow", "proposal": {"question_id": "q4", **window}}],
        "evidence": [],
    }
    for context in [
        _assessment_context(_plan(), results),
        _synthesis_context(plan=_plan(), threat_intelligence="", results=results),
    ]:
        query = context["completed_queries"][0]
        assert {key: query[key] for key in window} == window
        assert query["result_count"] == 0


def _raw_assessment(*, query_id: str, evidence_id: str, value: str) -> QueryAssessment:
    return QueryAssessment.model_validate({
        "query_id": query_id,
        "question_id": "q1",
        "answered_question": True,
        "material_progress": True,
        "summary": "Observed one entity.",
        "new_entities": [{
            "entity_type": "user",
            "value": value,
            "result_row_refs": [evidence_id],
        }],
        "evidence_candidate_row_refs": [evidence_id],
        "coverage_changes": [],
        "limitations": [],
        "proposed_next_question": None,
    })


def test_raw_json_container_values_are_grounded_without_changing_raw_event() -> None:
    query_id = str(uuid4())
    evidence_id = str(uuid4())
    raw = '{"user":"alice","src_ip":"192.0.2.7"}'
    results = {
        "queries": [{"query_id": query_id, "question_id": "q1", "status": "completed", "result_count": 1}],
        "evidence": [{
            "evidence_id": evidence_id,
            "query_id": query_id,
            "selected_result": {"_raw": raw},
        }],
    }

    assessment = _raw_assessment(query_id=query_id, evidence_id=evidence_id, value="alice")
    stored, _ = _materialize_follow_up_questions([assessment], results)

    assert stored[0]["new_entities"][0]["value"] == "alice"
    assert results["evidence"][0]["selected_result"]["_raw"] == raw


@pytest.mark.parametrize("value", ["lic", "alice.example"])
def test_raw_json_entity_grounding_rejects_substrings(value: str) -> None:
    query_id = str(uuid4())
    evidence_id = str(uuid4())
    results = {
        "queries": [{"query_id": query_id, "question_id": "q1", "status": "completed", "result_count": 1}],
        "evidence": [{
            "evidence_id": evidence_id,
            "query_id": query_id,
            "selected_result": {"_raw": '{"user":"alice"}'},
        }],
    }

    with pytest.raises(Validation, match="not present"):
        _materialize_follow_up_questions(
            [_raw_assessment(query_id=query_id, evidence_id=evidence_id, value=value)],
            results,
        )


def test_raw_json_entity_grounding_rejects_value_from_wrong_row() -> None:
    query_id = str(uuid4())
    first_id, second_id = str(uuid4()), str(uuid4())
    results = {
        "queries": [{"query_id": query_id, "question_id": "q1", "status": "completed", "result_count": 2}],
        "evidence": [
            {"evidence_id": first_id, "query_id": query_id, "selected_result": {"_raw": '{"user":"alice"}'}},
            {"evidence_id": second_id, "query_id": query_id, "selected_result": {"_raw": '{"user":"bob"}'}},
        ],
    }

    with pytest.raises(Validation, match="not present"):
        _materialize_follow_up_questions(
            [_raw_assessment(query_id=query_id, evidence_id=second_id, value="alice")],
            results,
        )


def test_entity_repair_identifies_all_command_line_substrings_without_exposing_values() -> None:
    from threat_hunting.services.investigation import _assessment_repair_context

    query_id, evidence_id = str(uuid4()), str(uuid4())
    command = '"C:\\Restricted\\agent.exe" /quiet'
    results = {
        "queries": [{"query_id": query_id, "question_id": "q1", "status": "completed", "result_count": 1}],
        "evidence": [{"evidence_id": evidence_id, "query_id": query_id, "selected_result": {
            "host": ["host-1", "host-2"], "file_name": "agent.exe", "command_line": command,
        }}],
    }
    assessment = _raw_assessment(query_id=query_id, evidence_id=evidence_id, value="host-1")
    entity = assessment.new_entities[0]
    assessment.new_entities = [
        entity.model_copy(update={"entity_type": EntityType.HOST}),
        entity.model_copy(update={"entity_type": EntityType.FILE, "value": "C:\\Restricted\\agent.exe"}),
        entity.model_copy(update={"entity_type": EntityType.FILE, "value": "agent.exe"}),
        entity.model_copy(update={"entity_type": EntityType.FILE, "value": "agent.exe\" /quiet"}),
    ]
    context = _assessment_context(_plan(), results)
    repair = _assessment_repair_context(context, [assessment], results)
    reason = repair["validation_errors"][query_id]
    assert "new_entities[1].value, new_entities[3].value" in reason
    assert "new_entities[0]" not in reason and "new_entities[2]" not in reason
    assert "Restricted" not in reason and "agent.exe" not in reason
    assert "complete scalar" in reason
    assessment.new_entities = [assessment.new_entities[0], assessment.new_entities[2]]
    stored, _ = _materialize_follow_up_questions([assessment], results)
    assert [entity["value"] for entity in stored[0]["new_entities"]] == ["host-1", "agent.exe"]
    assert results["evidence"][0]["selected_result"]["command_line"] == command


def test_assessment_repair_isolates_auth_from_process_citations_and_keeps_original_sample() -> None:
    from threat_hunting.services.investigation import _assessment_repair_context

    # Reproduce the failed hunt's account shared by process and authentication rows.
    process_id = "32d3ba57-a85d-402a-a107-b54426e56605"
    auth_id = "a6d8f281-9693-4e3f-814e-54f4d1b187b1"
    process_refs = ["c42d64a6-47f1-4e24-b279-f241d23dd420", "a9985b25-b9e4-4c2c-b11a-0796c709bab7"]
    results = {
        "queries": [
            {"query_id": process_id, "question_id": "q1", "status": "completed", "result_count": 2},
            {"query_id": auth_id, "question_id": "q2", "status": "completed", "result_count": 500},
        ],
        "evidence": [
            {"query_id": process_id, "evidence_id": ref, "selected_result": {"user": "svc_backup"}}
            for ref in process_refs
        ] + [
            {"query_id": auth_id, "evidence_id": f"auth-{i}", "selected_result": {"user": "svc_backup"}}
            for i in range(500)
        ],
    }
    context = _assessment_context(_plan(), results)
    valid = _raw_assessment(query_id=process_id, evidence_id=process_refs[0], value="svc_backup")
    invalid = _raw_assessment(query_id=auth_id, evidence_id="auth-0", value="svc_backup")
    invalid.question_id = "q2"
    invalid.new_entities[0].result_row_refs.extend(process_refs)

    repair_context = _assessment_repair_context(context, [valid, invalid], results)

    assert [q["query_id"] for q in repair_context["completed_queries"]] == [auth_id]
    group = repair_context["completed_queries"][0]
    assert group == context["completed_queries"][1]  # Do not expand the original repair sample.
    assert len(group["retained_evidence"]) == 498
    assert group["allowed_evidence_ids"] == [f"auth-{i}" for i in range(498)]
    assert set(repair_context["validation_errors"]) == {auth_id}
    allowed_message = repair_context["validation_errors"][auth_id].split("allowed_evidence_ids=", 1)[1]
    assert "auth-499" not in allowed_message
    assert all(ref not in allowed_message for ref in process_refs)
    assert len(results["evidence"]) == 502  # Stored evidence remains intact.
    assert invalid.new_entities[0].result_row_refs == ["auth-0", *process_refs]

    # Even a real but unsupplied stored row must not become an allowed citation.
    invalid.new_entities[0].result_row_refs = ["auth-0"]
    invalid.evidence_candidate_row_refs = ["auth-499"]
    repair_context = _assessment_repair_context(context, [valid, invalid], results)
    assert "invalid evidence_candidate_row_refs=['auth-499']" in repair_context["validation_errors"][auth_id]
    assert "auth-499" not in repair_context["validation_errors"][auth_id].split("allowed_evidence_ids=", 1)[1]


def test_search_truncation_and_model_sample_omission_are_separate_facts():
    queries = [
        {"query_id": "complete-20", "status": "completed", "result_count": 20, "truncated": False},
        {"query_id": "capped-500", "status": "completed", "result_count": 500, "truncated": True},
    ]
    evidence = [{"evidence_id": f"{query['query_id']}-{i}", "query_id": query["query_id"]}
                for query in queries for i in range(query["result_count"])]
    _, coverage = _balanced_evidence_sample(evidence, queries)
    assert coverage[0]["query_truncated"] is False
    assert coverage[0]["sample_omitted"] is False
    assert coverage[0]["supplied_evidence_count"] == 20
    assert coverage[1]["query_truncated"] is True
    assert coverage[1]["sample_omitted"] is True
    assert coverage[1]["supplied_evidence_count"] == 480


@pytest.mark.parametrize("limit", [25, 500])
def test_context_builders_honor_the_supplied_model_batch_limit(limit):
    results = {
        "queries": [{"query_id": "q1", "question_id": "q1", "status": "completed", "result_count": 600}],
        "evidence": [{"query_id": "q1", "evidence_id": f"e-{i}", "selected_result": {}} for i in range(600)],
    }
    assessment = _assessment_context(_plan(), results, limit=limit)
    synthesis = _synthesis_context(plan=_plan(), threat_intelligence="", results=results, limit=limit)
    assert len(assessment["completed_queries"][0]["retained_evidence"]) == limit
    assert len(synthesis["retained_evidence"]) == limit
    assert synthesis["evidence_coverage"][0]["omitted_evidence_count"] == 600 - limit
