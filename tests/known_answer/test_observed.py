import json
from uuid import uuid4

import pytest
from pydantic import TypeAdapter, ValidationError

from known_answer.observed import score_observed_runs
from threat_hunting.domain.contracts import FindingProposal
from threat_hunting.integrations.models.fake import FakeModelAdapter
from threat_hunting.services.orchestration import StrictModelRunner
from threat_hunting.services.investigation import _materialize_findings


def observed_run():
    query_id, evidence_id = str(uuid4()), str(uuid4())
    results = {"queries": [{"query_id": query_id, "status": "completed"}],
               "evidence": [{"evidence_id": evidence_id, "query_id": query_id, "selected_result": {"host": "host-1"}}]}
    proposal = {"title": "Host observed", "classification": "supported_observation", "statement": "host-1 was observed.",
                "confidence": "low", "evidence_ids": ["E1"], "query_ids": [], "inference": "unknown", "limitations": []}
    model = FakeModelAdapter(responses=["invalid JSON", json.dumps({"FindingProposal": [proposal]})])
    runner = StrictModelRunner(model)
    findings = runner.run(TypeAdapter(list[FindingProposal]), user_payload={
        "completed_queries": results["queries"], "retained_evidence": results["evidence"],
    }, contract_name="FindingProposal[]")
    results["findings"] = _materialize_findings(findings, results)
    runner.counters.model_output_checks[-1].grounding_valid = True
    results["usage"] = runner.counters.model_dump(mode="json")
    return {"scenario_id": "observed-1", "model_provider": "fake", "model_name": "fixture",
            "results": results, "expected_finding_ids": ["host-observation"],
            "judgments": [{"finding_id": results["findings"][0]["finding_id"], "supported": True,
                           "expected_finding_ids": ["host-observation"]}]}


def test_observed_scores_distinguish_first_pass_failure_from_repaired_success():
    report = score_observed_runs({"runs": [observed_run()]})
    scenario = report["scenarios"][0]
    assert report["answer_key_matched"] is True
    assert scenario["first_pass_contract_valid_percent"] == 0.0
    assert scenario["first_pass_grounded_output_percent"] == 0.0
    assert scenario["repair_call_percent"] == 50.0
    assert scenario["analytical_quality"]["finding_precision_percent"] == 100.0
    assert scenario["measured_cost_usd"] is None


def test_valid_citations_do_not_establish_claim_truth():
    run = observed_run()
    run["judgments"][0].update(supported=False, expected_finding_ids=[])
    report = score_observed_runs({"runs": [run]})
    assert report["answer_key_matched"] is False
    scenario = report["scenarios"][0]
    assert scenario["citation_failure_count"] == 0
    assert scenario["analytical_quality"]["unsupported_claim_count"] == 1
    assert scenario["analytical_quality"]["finding_recall_percent"] == 0.0


def test_missing_judgments_and_historical_metrics_remain_unassessed():
    run = observed_run()
    run.pop("judgments")
    run["results"]["usage"].pop("model_output_checks")
    report = score_observed_runs({"runs": [run]})
    assert report["answer_key_matched"] is None
    assert report["analytical_quality_assessed"] is False
    assert report["scenarios"][0]["first_pass_contract_valid_percent"] is None


def test_unknown_citation_fails_even_when_analyst_marks_claim_supported():
    run = observed_run()
    run["results"]["findings"][0]["evidence_ids"] = [str(uuid4())]
    report = score_observed_runs({"runs": [run]})
    assert report["answer_key_matched"] is False
    assert report["scenarios"][0]["citation_failure_count"] == 1


@pytest.mark.parametrize("mutation", ["duplicate_judgment", "unknown_expected", "missing_results"])
def test_incomplete_or_inconsistent_observations_are_rejected(mutation):
    run = observed_run()
    if mutation == "duplicate_judgment":
        run["judgments"].append(run["judgments"][0])
    elif mutation == "unknown_expected":
        run["judgments"][0]["expected_finding_ids"] = ["unknown"]
    else:
        del run["results"]["findings"]
    with pytest.raises((ValueError, ValidationError)):
        score_observed_runs({"runs": [run]})


def test_observed_cli_scores_an_export_without_contacting_providers(tmp_path):
    import subprocess
    import sys
    from pathlib import Path

    run = observed_run()
    export = tmp_path / "observations.json"
    export.write_text(json.dumps({"runs": [run]}))
    command = [sys.executable, "scripts/run_known_answer_hunts.py", "--mode", "observed", "--observations", str(export), "--json"]
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["answer_key_matched"] is True
    assert "passed" not in report
    assert report["scenarios"][0]["first_pass_contract_valid_percent"] == 0
    del run["judgments"]
    export.write_text(json.dumps({"runs": [run]}))
    result = subprocess.run(command, cwd=root, capture_output=True, text=True)
    assert result.returncode == 2
    assert json.loads(result.stdout)["analytical_quality_assessed"] is False


def test_judgment_provenance_never_assumes_independent_analyst_review():
    run = observed_run()
    report = score_observed_runs({"runs": [run]})
    assert report["scenarios"][0]["analytical_quality"]["judgment_source"] == "unspecified"
    run["judgment_source"] = "assistant"
    report = score_observed_runs({"runs": [run]})
    assert report["scenarios"][0]["analytical_quality"]["judgment_source"] == "assistant"


def test_retrieval_and_citation_recovery_are_independent_of_claim_judgment():
    run = observed_run()
    evidence = run["results"]["evidence"][0]
    evidence["source_event_ref"] = "event-a"
    run["results"]["evidence"].append({**evidence, "evidence_id": str(uuid4()), "source_event_ref": "event-b"})
    run["results"]["queries"][0]["question_id"] = "q1"
    run["expected_event_ids"] = ["event-a", "event-b", "event-missing"]
    run["approved_question_ids"] = ["q1", "q4"]
    result = score_observed_runs({"runs": [run]})["scenarios"][0]
    assert result["evidence_recovery"]["retrieval_recall_percent"] == 66.67
    assert result["evidence_recovery"]["citation_recall_percent"] == 33.33
    assert result["evidence_recovery"]["retrieved_but_uncited_event_ids"] == ["event-b"]
    assert result["evidence_recovery"]["missed_retrieval_event_ids"] == ["event-missing"]
    assert result["approved_question_coverage"]["execution_coverage_percent"] == 50
    assert result["approved_question_coverage"]["unexecuted_question_ids"] == ["q4"]
    assert result["analytical_quality"]["finding_precision_percent"] == 100


def test_repeated_trials_report_variation_without_claiming_future_reliability():
    runs = [observed_run(), observed_run()]
    for i, run in enumerate(runs):
        run.update(trial_id=str(i), hunt_id=str(uuid4()), fixture_sha256="a" * 64,
                   prompt_contract_version="1.3", image_version="candidate", expected_event_ids=["event-a"])
    runs[0]["results"]["evidence"][0]["source_event_ref"] = "event-a"
    runs[1]["results"]["evidence"][0]["source_event_ref"] = "event-b"
    result = score_observed_runs({"runs": runs})
    assert result["scenario_count"] == 1
    assert result["trial_count"] == 2
    group = result["trial_groups"][0]
    assert group["comparison_metadata_complete"] is True
    assert group["observed_ranges"]["citation_recall_percent"] == {"minimum": 0, "maximum": 100}
    assert "do not predict future reliability" in group["measurement_basis"]
    runs[1]["results"]["evidence"][0]["source_event_ref"] = "unknown"
    result = score_observed_runs({"runs": runs})
    assert result["trial_groups"][0]["observed_ranges"]["citation_recall_percent"] is None


@pytest.mark.parametrize("mutation", ["duplicate_trial", "duplicate_hunt", "changed_fixture", "changed_model", "duplicate_expected", "duplicate_query", "unmeasured_events", "unmeasured_questions"])
def test_comparison_rejects_ambiguous_or_mixed_trial_records(mutation):
    runs = [observed_run(), observed_run()]
    for i, run in enumerate(runs):
        run.update(trial_id=str(i), hunt_id=str(uuid4()), fixture_sha256="a" * 64)
    if mutation == "duplicate_trial":
        runs[1]["trial_id"] = runs[0]["trial_id"]
    elif mutation == "duplicate_hunt":
        runs[1]["hunt_id"] = runs[0]["hunt_id"]
    elif mutation == "changed_fixture":
        runs[1]["fixture_sha256"] = "b" * 64
    elif mutation == "changed_model":
        runs[1]["model_name"] = "different"
    elif mutation == "duplicate_expected":
        runs[0]["expected_event_ids"] = ["event-a", "event-a"]
    elif mutation == "duplicate_query":
        runs[0]["results"]["queries"] *= 2
    elif mutation == "unmeasured_events":
        runs[0]["expected_event_ids"] = []
    elif mutation == "unmeasured_questions":
        runs[0]["approved_question_ids"] = []
    with pytest.raises(ValueError):
        score_observed_runs({"runs": runs})


def test_unmeasured_recovery_and_coverage_are_unknown_for_historical_export():
    result = score_observed_runs({"runs": [observed_run()]})
    assert result["scenarios"][0]["evidence_recovery"] is None
    assert result["scenarios"][0]["approved_question_coverage"] is None
    assert result["trial_groups"][0]["comparison_metadata_complete"] is False


@pytest.mark.parametrize("fixture_id", ["event-a", ["event-a", "event-a"]])
def test_fixture_identity_is_explicit_and_independent_of_splunk_record_identity(fixture_id):
    run = observed_run()
    run.update(expected_event_ids=["event-a"], fixture_event_id_field="event_id")
    record = run["results"]["evidence"][0]
    record.update(source_event_ref="1:2956", selected_result={"event_id": fixture_id})
    result = score_observed_runs({"runs": [run]})["scenarios"][0]["evidence_recovery"]
    assert result["identity_field"] == "selected_result.event_id"
    assert result["retrieval_recall_percent"] == result["citation_recall_percent"] == 100
    assert record["source_event_ref"] == "1:2956"
    del record["selected_result"]["event_id"]
    record["source_event_ref"] = "event-a"
    result = score_observed_runs({"runs": [run]})["scenarios"][0]["evidence_recovery"]
    assert result["unidentified_retained_record_count"] == 1
    assert result["retained_expected_event_count"] == 0  # No silent identity fallback.
    assert result["retrieval_recall_percent"] is None
    assert result["citation_recall_percent"] is None
    assert result["missed_retrieval_event_ids"] is None


def test_missing_uncited_identity_does_not_hide_proven_citation_recall():
    run = observed_run()
    run.update(expected_event_ids=["event-a", "event-b"], fixture_event_id_field="event_id")
    record = run["results"]["evidence"][0]
    record["selected_result"]["event_id"] = "event-a"
    run["results"]["evidence"].append({"evidence_id": str(uuid4()), "query_id": record["query_id"], "selected_result": {}})
    result = score_observed_runs({"runs": [run]})["scenarios"][0]["evidence_recovery"]
    assert result["retrieval_recall_percent"] is None
    assert result["citation_recall_percent"] == 50
    assert result["unidentified_retained_record_count"] == 1
    assert result["unidentified_cited_record_count"] == 0
    run["expected_event_ids"] = ["event-a"]
    result = score_observed_runs({"runs": [run]})["scenarios"][0]["evidence_recovery"]
    assert result["retrieval_recall_percent"] == result["citation_recall_percent"] == 100


@pytest.mark.parametrize("value", [["event-a", "event-b"], 42, {"event_id": "event-a"}])
def test_ambiguous_fixture_identity_is_not_resolved_using_the_answer_key(value):
    run = observed_run()
    run.update(expected_event_ids=["event-a"], fixture_event_id_field="event_id")
    run["results"]["evidence"][0]["selected_result"]["event_id"] = value
    with pytest.raises(ValueError, match="fixture event identity"):
        score_observed_runs({"runs": [run]})


def test_failed_trials_remain_in_completion_denominator_and_cannot_pass():
    runs = [observed_run(), observed_run()]
    for i, run in enumerate(runs):
        run.update(trial_id=str(i), terminal_state="report_draft" if i == 0 else "failed")
    report = score_observed_runs({"runs": runs})
    group = report["trial_groups"][0]
    assert group["report_completion_percent"] == 50
    assert group["terminal_state_counts"] == {"report_draft": 1, "failed": 1}
    assert report["answer_key_matched"] is False
