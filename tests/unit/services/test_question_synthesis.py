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
    return {"question_1": {"summary": "A retained event names host-1.", "findings": [positive()], "limitations": []},
            "question_2": {"summary": "This question remains unanswered.", "findings": [], "limitations": ["The supplied telemetry does not answer this question."]}}


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
