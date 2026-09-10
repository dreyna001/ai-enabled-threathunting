"""Required question slots preserve coverage and finite evidence grounding."""

from copy import deepcopy
import json
from types import SimpleNamespace
from uuid import uuid4

from jsonschema import Draft202012Validator
import pytest

from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.domain.errors import Validation
from threat_hunting.services.investigation import _materialize_question_answers, _question_synthesis_contract
from threat_hunting.services.model_output import ReferenceLabels, structured_response_format
from threat_hunting.services.orchestration import ModelContractError, StrictModelRunner
from threat_hunting.services.reports import ReportValidationError, _concise_report_content, _formatted_pdf, _validate_report_content, render_report_html


def plan(count=2):
    return SimpleNamespace(questions=[SimpleNamespace(question_id=f"approved-{i}", question=f"Investigate question {i}.") for i in range(count)])


def context():
    query_id, evidence_id = str(uuid4()), str(uuid4())
    return {
        "completed_queries": [{"query_id": query_id, "status": "completed", "result_count": 1}],
        "retained_evidence": [{"query_id": query_id, "evidence_id": evidence_id, "selected_result": {"host": "host-1"}}],
    }


def positive():
    return {"title": "Event observed", "statement": "A retained event names host-1.",
            "classification": "supported_observation", "confidence": "high", "evidence_ids": ["E1"],
            "query_ids": [], "inference": "unknown", "limitations": []}


def response():
    return {"question_1": {"summary": "A retained event names host-1.", "findings": [positive()], "lead_coverage": [], "inventory_scopes": [], "limitations": []},
            "question_2": {"summary": "This question remains unanswered.", "findings": [], "lead_coverage": [], "inventory_scopes": [], "limitations": ["The supplied telemetry does not answer this question."]}}


def lead_context():
    supplied = context()
    first = supplied["retained_evidence"][0]
    first["selected_result"].update(process_guid="process-a", session_id="session-a", file_name="observed.exe")
    first["advisory_ioc_comparison"] = {"matched_file_name_literals": ["observed.exe"]}
    second = deepcopy(first)
    second["evidence_id"] = str(uuid4())
    second["selected_result"].update(host="host-2", process_guid="process-b", session_id="session-b")
    supplied["retained_evidence"].append(second)
    supplied["completed_queries"][0]["result_count"] = 2
    return supplied


def covered_response():
    answer = response()
    answer["question_1"]["lead_coverage"] = [
        {"lead_evidence_id": "E1", "finding_numbers": [1], "limitation": None},
        {"lead_evidence_id": "E2", "finding_numbers": [], "limitation": "No related support was established for this lead."},
    ]
    answer["question_2"]["lead_coverage"] = [
        {"lead_evidence_id": label, "finding_numbers": [], "limitation": "The supplied records do not answer this question for the lead."}
        for label in ("E1", "E2")
    ]
    return answer


@pytest.mark.parametrize("lead_count", [0, 450, 500])
@pytest.mark.parametrize("allow_retrieval", [False, True])
def test_maximum_evidence_and_leads_fit_native_enum_limit_without_weakening_citations(lead_count, allow_retrieval):
    supplied = context()
    supplied["completed_queries"] = [
        {"query_id": str(uuid4()), "status": "completed"} for _ in range(50)
    ]
    supplied["retained_evidence"] = [
        {"evidence_id": str(uuid4()), "query_id": supplied["completed_queries"][index % 50]["query_id"],
         "selected_result": {"host": "host-1", "process_guid": f"process-{index}"},
         "advisory_ioc_comparison": {"matched_file_name_literals": ["observed.exe"]} if index < lead_count else {}}
        for index in range(500)
    ]
    labels = ReferenceLabels.from_context(supplied)
    contract = _question_synthesis_contract(plan(), allow_retrieval=allow_retrieval)
    schema = structured_response_format(contract, "QuestionSynthesis", labels)["json_schema"]["schema"]
    Draft202012Validator.check_schema(schema)
    pending, enum_count = [schema], 0
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            enum_count += len(node.get("enum", []))
            pending.extend(value for key, value in node.items() if key != "enum")
        elif isinstance(node, list):
            pending.extend(node)
    assert enum_count <= 1000

    answer = response()
    answer["question_1"]["findings"][0]["evidence_ids"] = ["E1", "E500"]
    for slot in answer.values():
        slot["lead_coverage"] = [
            {"lead_evidence_id": f"E{index}", "finding_numbers": [], "limitation": "This lead remains unreviewed."}
            for index in range(1, lead_count + 1)
        ]
        if allow_retrieval:
            slot["retained_evidence_requests"] = []
    validator = Draft202012Validator(schema)
    assert validator.is_valid(answer)
    decoded = labels.decode(answer, findings=True)
    assert decoded["question_1"]["findings"][0]["evidence_ids"] == [
        supplied["retained_evidence"][index]["evidence_id"] for index in (0, 499)
    ]
    invalid = deepcopy(answer)
    invalid["question_1"]["findings"][0]["evidence_ids"] = ["E501"]
    assert not validator.is_valid(invalid)
    if lead_count:
        invalid = deepcopy(answer)
        invalid["question_1"]["lead_coverage"][0]["lead_evidence_id"] = "E501"
        assert not validator.is_valid(invalid)
        if lead_count < 500:
            invalid["question_1"]["lead_coverage"][0]["lead_evidence_id"] = "E500"
            assert not validator.is_valid(invalid)
            with pytest.raises(ValueError, match="every supplied advisory lead"):
                labels.decode(invalid, findings=True)


def test_missing_lead_coverage_uses_existing_repair_before_accepting_answer():
    model = FakeModelAdapter(responses=[json.dumps(response()), json.dumps(covered_response())])
    runner = StrictModelRunner(model)
    runner.run(_question_synthesis_contract(plan()), user_payload=lead_context(), contract_name="QuestionSynthesis")
    assert model.call_count == 2
    assert runner.counters.model_repair_attempts == 1
    assert model.requests[0].messages[0] == model.requests[1].messages[0]


@pytest.mark.parametrize("failure", ["unknown_lead", "duplicate_lead", "missing_lead", "bad_position", "boolean_position", "missing_endpoint", "no_disposition"])
def test_lead_dispositions_reject_omissions_and_unsupported_relationships(failure):
    answer = covered_response()
    coverage = answer["question_1"]["lead_coverage"]
    if failure == "unknown_lead":
        coverage[0]["lead_evidence_id"] = "E99"
    elif failure == "duplicate_lead":
        coverage.append(deepcopy(coverage[0]))
    elif failure == "missing_lead":
        coverage.pop()
    elif failure == "bad_position":
        coverage[0]["finding_numbers"] = [2]
    elif failure == "boolean_position":
        coverage[0]["finding_numbers"] = [True]
    elif failure == "missing_endpoint":
        coverage[1].update(finding_numbers=[1], limitation=None)
    else:
        coverage[1]["limitation"] = None
    model = FakeModelAdapter(responses=[json.dumps(answer)] * 2)
    with pytest.raises(ModelContractError):
        StrictModelRunner(model).run(_question_synthesis_contract(plan()), user_payload=lead_context(), contract_name="QuestionSynthesis")
    assert model.call_count == 2


def test_lead_dispositions_preserve_app_owned_fields_and_explicit_missing_analysis():
    supplied = lead_context()
    state = {"queries": supplied["completed_queries"], "evidence": supplied["retained_evidence"]}
    model = FakeModelAdapter(responses=[json.dumps(covered_response())])
    answer = StrictModelRunner(model).run(_question_synthesis_contract(plan()), user_payload=supplied, contract_name="QuestionSynthesis")
    stored = _materialize_question_answers(answer, plan(), state, threat_intelligence="[file:name = 'observed.exe']")
    first = stored["question_answers"][0]
    assert len(first["lead_coverage"]) == 2
    assert first["lead_coverage"][0]["identity_fields"]["process_guid"] == "process-a"
    assert first["lead_coverage"][0]["finding_ids"] == first["finding_ids"]
    assert first["lead_coverage"][1]["finding_ids"] == []
    assert "1 of 2" in first["limitations"][-1]
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=stored,
                                     coverage_and_limitations=[], conclusion_and_disposition="Incomplete lead analysis.")
    assert _validate_report_content(report, stored) == report
    assert b"process-a" in _formatted_pdf("Lead report", report)
    assert b"No related support" in _formatted_pdf("Lead report", report)
    report["question_answers"][0]["lead_coverage"][1]["limitation"] = None
    with pytest.raises(Validation, match="lead coverage"):
        _validate_report_content(report, stored)


@pytest.mark.parametrize("change", [None, "host", "process_guid", "session_id", "multivalue", "missing"])
def test_lead_review_groups_preserve_distinct_and_uncertain_identities(change):
    from threat_hunting.services.evidence import advisory_lead_groups

    first = lead_context()["retained_evidence"][0]
    second = deepcopy(first)
    second["evidence_id"] = str(uuid4())
    if change in {"host", "process_guid", "session_id"}:
        second["selected_result"][change] = "different"
    elif change == "multivalue":
        second["selected_result"]["session_id"] = ["session-a", "other"]
    elif change == "missing":
        second["selected_result"].pop("process_guid")
    original = deepcopy([first, second])
    groups = advisory_lead_groups([first, second])
    assert len(groups) == (1 if change is None else 2)
    assert {identifier for group in groups for identifier in group["evidence_ids"]} == {first["evidence_id"], second["evidence_id"]}
    assert [first, second] == original


def test_native_contract_requires_all_lead_slots_or_a_bounded_retrieval_request():
    refs = ReferenceLabels.from_context(lead_context())
    schema = structured_response_format(_question_synthesis_contract(plan(), allow_retrieval=True), "QuestionSynthesis", refs)["json_schema"]["schema"]
    validator = Draft202012Validator(schema)
    answer = covered_response()
    for item in answer.values():
        item["retained_evidence_requests"] = []
    validator.validate(answer)
    answer["question_1"]["lead_coverage"].pop()
    assert list(validator.iter_errors(answer))
    answer["question_1"].update(findings=[], lead_coverage=[], limitations=["Need a retained page."],
                              retained_evidence_requests=[{"query_ids": ["Q1"], "filters": [], "earliest_utc": None,
                                                           "latest_utc": None, "offset": 0, "limit": 1}])
    validator.validate(answer)


def test_another_record_in_the_same_lead_group_can_support_the_finding():
    supplied = lead_context()
    supplied["retained_evidence"][1]["selected_result"] = deepcopy(supplied["retained_evidence"][0]["selected_result"])
    supplied["retained_evidence"][1]["selected_result"]["action"] = "process_end"
    answer = response()
    answer["question_1"]["findings"][0]["evidence_ids"] = ["E2"]
    answer["question_1"]["lead_coverage"] = [{"lead_evidence_id": "E1", "finding_numbers": [1], "limitation": None}]
    answer["question_2"]["lead_coverage"] = [{"lead_evidence_id": "E1", "finding_numbers": [], "limitation": "Unknown."}]
    model = FakeModelAdapter(responses=[json.dumps(answer)])
    result = StrictModelRunner(model).run(_question_synthesis_contract(plan()), user_payload=supplied, contract_name="QuestionSynthesis")
    assert [str(identifier) for identifier in result.question_1.findings[0].evidence_ids] == [supplied["retained_evidence"][1]["evidence_id"]]


def test_native_schema_requires_every_question_and_an_answer_or_limitation():
    schema = structured_response_format(_question_synthesis_contract(plan()), "QuestionSynthesis", ReferenceLabels.from_context(context()))["json_schema"]["schema"]
    validator = Draft202012Validator(schema)
    validator.validate(response())
    for mutation in ("missing_slot", "empty_slot", "unknown_slot", "unknown_evidence", "ungrounded_positive"):
        invalid = deepcopy(response())
        if mutation == "missing_slot":
            invalid.pop("question_2")
        elif mutation == "empty_slot":
            invalid["question_2"]["limitations"] = []
        elif mutation == "unknown_slot":
            invalid["invented"] = invalid.pop("question_2")
        elif mutation == "unknown_evidence":
            invalid["question_1"]["findings"][0]["evidence_ids"] = ["E2"]
        else:
            invalid["question_1"]["findings"][0]["evidence_ids"] = []
        assert list(validator.iter_errors(invalid)), mutation


def test_application_assigns_question_and_finding_links_and_restores_nested_citations():
    supplied = context()
    runner = StrictModelRunner(FakeModelAdapter(responses=[json.dumps(response())]))
    answer = runner.run(_question_synthesis_contract(plan()), user_payload=supplied, contract_name="QuestionSynthesis")
    stored = _materialize_question_answers(answer, plan(), {"queries": supplied["completed_queries"], "evidence": supplied["retained_evidence"]})
    finding = stored["findings"][0]
    assert finding["evidence_ids"] == [supplied["retained_evidence"][0]["evidence_id"]]
    assert finding["query_ids"] == [supplied["completed_queries"][0]["query_id"]]
    assert stored["question_answers"][0]["finding_ids"] == [finding["finding_id"]]
    assert stored["question_answers"][0]["summary"] == response()["question_1"]["summary"]
    assert [item["question_id"] for item in stored["question_answers"]] == ["approved-0", "approved-1"]
    assert stored["question_answers"][1]["finding_ids"] == []
    assert stored["question_answers"][1]["limitations"]
    assert runner.counters.model_calls == 1


def test_missing_question_uses_existing_repair_and_does_not_invent_an_answer():
    invalid = response()
    invalid.pop("question_2")
    model = FakeModelAdapter(responses=[json.dumps(invalid), json.dumps(response())])
    runner = StrictModelRunner(model)
    result = runner.run(_question_synthesis_contract(plan()), user_payload=context(), contract_name="QuestionSynthesis")
    assert result.question_2.findings == []
    assert runner.counters.model_repair_attempts == 1
    assert model.requests[0].response_format == model.requests[1].response_format


def test_unknown_nested_citation_remains_a_contract_failure():
    invalid = response()
    invalid["question_1"]["findings"][0]["evidence_ids"] = ["unavailable"]
    model = FakeModelAdapter(responses=[json.dumps(invalid)] * 2)
    with pytest.raises(ModelContractError, match="unknown evidence_ids label"):
        StrictModelRunner(model).run(_question_synthesis_contract(plan()), user_payload=context(), contract_name="QuestionSynthesis")


def test_report_preserves_later_question_answers_and_rejects_deleted_coverage():
    findings = [{"finding_id": f"f-{i}", "title": f"Finding {i}", "statement": "Observed.", "evidence_ids": []} for i in range(12)]
    answers = [{"question_id": f"q-{i}", "question": f"Question {i}", "summary": f"Answer {i}", "finding_ids": [f"f-{i}"], "limitations": []} for i in range(12)]
    results = {"findings": findings, "question_answers": answers}
    original = deepcopy(results)
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=results,
                                     coverage_and_limitations=[], conclusion_and_disposition="Observed findings.")
    assert len(report["findings"]) == 10
    assert report["question_answers"] == answers
    assert results == original
    assert any("All 12 retained findings remain available" in text for text in report["coverage_and_limitations"])
    assert _validate_report_content(report, results) == report
    assert b"Question 11" in _formatted_pdf("Report", report)
    assert b"Answer 11" in _formatted_pdf("Report", report)
    report["findings"] = deepcopy(findings)
    assert _validate_report_content(report, results) == report  # Draft detail count is not an investigation cap.
    report["question_answers"].pop()
    with pytest.raises(Validation, match="every approved question"):
        _validate_report_content(report, results)


def test_question_references_cannot_be_dropped_or_reassigned_to_another_answer():
    answers = [{"question_id": f"q{i}", "question": f"Question {i}", "summary": "Answer.",
                "finding_ids": [f"f{i}"], "limitations": []} for i in range(2)]
    results = {"findings": [{"finding_id": f"f{i}", "title": "Finding"} for i in range(2)], "question_answers": answers}
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=results,
                                     coverage_and_limitations=[], conclusion_and_disposition="Observed findings.")
    for identifiers in (["f1"], ["f0", "f0"], []):
        invalid = deepcopy(report)
        invalid["question_answers"][0]["finding_ids"] = identifiers
        invalid["question_answers"][0]["limitations"] = ["Limitations do not justify silently removing a reference."]
        with pytest.raises(Validation, match="finding references"):
            _validate_report_content(invalid, results)


def test_thousands_of_findings_remain_available_without_printing_thousands_of_references():
    findings = [{"finding_id": f"finding-{i:05d}", "title": f"Observed activity {i}",
                 "classification": "supported_observation", "statement": "Observed.",
                 "evidence_ids": [f"evidence-{n:05d}" for n in range(100)]} for i in range(2000)]
    findings[-1].update(title="Material late finding", classification="hunt_lead")
    answers = [{"question_id": "q1", "question": "What was observed?", "summary": "Recurring activity and a distinct material lead were observed.",
                "finding_ids": [item["finding_id"] for item in findings], "limitations": []}]
    results = {"findings": findings, "question_answers": answers}
    original = deepcopy(results)
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=results,
                                     coverage_and_limitations=[], conclusion_and_disposition="Observed findings.")
    assert results == original
    assert len(report["question_answers"][0]["finding_ids"]) == 2000
    assert report["findings"][0]["title"] == "Material late finding"
    assert _validate_report_content(report, results) == report
    pdf = _formatted_pdf("Report", report)
    assert b"2000 finding" in pdf
    assert b"distinct material lead" in pdf
    assert b"finding-01000" not in pdf
    assert b"evidence-00099" not in pdf
    assert len(pdf) < 30_000


def test_report_does_not_repeat_earlier_answer_interpretations():
    from threat_hunting.services.reports import _derive_report_limitations

    results = {"queries": [], "question_answers": [{"question_id": "q1", "finding_ids": ["f1"], "limitations": []}],
               "query_assessments": [{"question_id": "q1", "answered_question": False, "limitations": ["Old unsupported interpretation"]}],
               "follow_up_decisions": [{"question_id": "q1", "skip_reason": "Old unsupported interpretation"}]}
    assert not any("Old unsupported" in value or "remains unanswered" in value for value in _derive_report_limitations(results))


def test_report_can_select_cited_evidence_beyond_the_first_query_storage_limit():
    evidence = [{"evidence_id": f"e{i}", "query_id": "query", "event_time_utc": "2026-01-01T00:00:00Z"} for i in range(10_001)]
    results = {"evidence": evidence, "findings": [{"finding_id": "finding", "title": "Later query observation", "evidence_ids": ["e10000"]}]}
    report = _concise_report_content(hypothesis="h", objective="o", data_sources=[], results=results,
                                     coverage_and_limitations=[], conclusion_and_disposition="Observed findings.")
    assert report["selected_evidence"][0]["evidence_id"] == "e10000"
    assert len(evidence) == 10_001


def test_html_answers_summarize_references_and_reject_malformed_answers():
    content = {"hypothesis": "h", "objective_and_scope": "o", "data_sources_used": [], "finding_ids": [],
               "evidence_ids": [], "query_ids": [], "entities": [], "timeline": [], "coverage": [], "limitations": [],
               "conclusion": "Unknown", "disposition": "inconclusive", "query_appendix": [],
               "question_answers": [{"question_id": "q1", "question": "<script>unsafe</script>", "summary": "Observed events.",
                                     "finding_ids": [f"ref-{i}" for i in range(2000)], "limitations": []}]}
    markup = render_report_html(content)
    assert "2000 finding(s) retained" in markup
    assert "ref-1999" not in markup
    assert "<script>unsafe</script>" not in markup
    content["question_answers"][0]["summary"] = []
    with pytest.raises(ReportValidationError, match="require a summary"):
        render_report_html(content)
