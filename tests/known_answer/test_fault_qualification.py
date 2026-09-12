from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, cast

import pytest

from known_answer.bindings import (
    HuntResultExport,
    ScenarioBinding,
    SUPPORTED_FAULT_INJECTOR,
    extract_synthetic_run,
    load_bindings,
)
from known_answer.fault_injection import (
    FAULT_SCENARIO_IDS,
    implemented_fault_modes,
    qualify_fault_scenarios,
)
from known_answer.harness import load_answers, load_cases, score_runs
from known_answer.test_bindings import build_valid_bindings, write_bindings

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import run_known_answer_hunts as live_runner  # noqa: E402  # type: ignore[import-not-found]


@pytest.fixture(scope="module")
def fault_exports() -> dict[str, HuntResultExport]:
    return {export.scenario_id: export for export in qualify_fault_scenarios()}


@pytest.mark.parametrize("scenario_id", FAULT_SCENARIO_IDS)
def test_fault_scenario_qualifies_through_real_workflow_export(
    scenario_id: str, fault_exports: dict[str, HuntResultExport]
) -> None:
    case = next(item for item in load_cases() if item["scenario_id"] == scenario_id)
    binding_payload = cast(
        dict[str, Any],
        build_valid_bindings(fault_injector=SUPPORTED_FAULT_INJECTOR)["scenarios"][scenario_id],
    )
    binding = ScenarioBinding.model_validate(binding_payload)
    export = fault_exports[scenario_id]
    run = extract_synthetic_run(export, binding)
    answer = load_answers()[scenario_id]
    expected = tuple(str(item) for item in answer.get("expected_evidence_ids", []))
    recovered = sum(item in run.retained_evidence_ids for item in expected)
    assert run.disposition == answer["disposition"]
    required_limitation = answer.get("required_limitation")
    if required_limitation:
        assert str(required_limitation).casefold() in run.limitation.casefold()
    assert run.fabricated_evidence_ids == ()
    assert run.citation_failures == ()
    assert run.hard_budget_violation is False
    assert recovered == len(expected)
    if scenario_id == "ka-12-cancellation":
        assert run.cited_evidence_ids == ()
    else:
        assert all(item in run.cited_evidence_ids for item in expected)
    assert run.category == case["category"]


def test_query_timeout_marks_timed_out_query_without_evidence(
    fault_exports: dict[str, HuntResultExport],
) -> None:
    export = fault_exports["ka-08-query-timeout"]
    assert export.limitation == "hard_timeout"
    assert export.results["evidence"] == []
    assert export.results["usage"]["splunk_queries"] == 1
    assert any(item["status"] == "timed_out" for item in export.results["query_ledger"])


def test_model_repair_records_exactly_one_repair(
    fault_exports: dict[str, HuntResultExport],
) -> None:
    export = fault_exports["ka-09-model-repair"]
    assert export.results["usage"]["model_repair_attempts"] == 1
    assert export.terminal_state == "report_draft"
    assert export.results["findings"]


def test_restart_recovery_resumes_sid_without_duplicate_evidence(
    fault_exports: dict[str, HuntResultExport],
) -> None:
    export = fault_exports["ka-10-restart-recovery"]
    evidence_ids = [item["evidence_id"] for item in export.results["evidence"]]
    assert len(evidence_ids) == len(set(evidence_ids))
    assert export.results["queries"][0]["splunk_job_id"] == export.results["query_ledger"][0]["query_id"]
    assert len(export.results["query_ledger"]) == 2


def test_hard_budget_skips_planned_queries_without_overspend(
    fault_exports: dict[str, HuntResultExport],
) -> None:
    export = fault_exports["ka-11-hard-budget"]
    assert export.limitation == "budget_exhausted"
    assert export.results["evidence"] == []
    assert export.results["usage"]["splunk_queries"] <= 1
    assert export.results["usage"]["model_calls"] <= 2
    assert sum(item["status"] == "skipped_budget" for item in export.results["query_ledger"]) >= 1


def test_cancellation_preserves_completed_evidence_and_blocks_new_work(
    fault_exports: dict[str, HuntResultExport],
) -> None:
    export = fault_exports["ka-12-cancellation"]
    assert export.terminal_state == "cancelled"
    assert export.limitation == "cancelled"
    assert len(export.results["evidence"]) == 1
    assert len([item for item in export.results["query_ledger"] if item["status"] == "completed"]) == 1


def test_local_fault_exports_keep_cancellation_citation_gap_visible(
    fault_exports: dict[str, HuntResultExport],
) -> None:
    non_fault_cases = [
        case for case in load_cases() if case["category"] not in implemented_fault_modes()
    ]
    non_fault_runs = []
    bindings = {
        scenario_id: ScenarioBinding.model_validate(cast(dict[str, Any], payload))
        for scenario_id, payload in cast(
            dict[str, dict[str, Any]],
            build_valid_bindings(fault_injector=SUPPORTED_FAULT_INJECTOR)["scenarios"],
        ).items()
    }
    for case in non_fault_cases:
        from known_answer.harness import run_synthetic_case

        non_fault_runs.append(run_synthetic_case(case))
    fault_runs = [
        extract_synthetic_run(export, bindings[export.scenario_id])
        for export in fault_exports.values()
    ]
    combined = non_fault_runs + fault_runs
    assert len(combined) == 12
    result = score_runs(combined, load_answers())
    assert result["passed"] is False
    failed = [item["scenario_id"] for item in result["scenarios"] if not item["pass"]]
    assert failed == ["ka-12-cancellation"]


def test_runner_still_fails_closed_without_live_adapter_path(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    bindings_path = write_bindings(tmp_path, build_valid_bindings(fault_injector=SUPPORTED_FAULT_INJECTOR))
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE", str(bindings_path))
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_LIVE_ADAPTER", "known_answer.live_stub:run")
    bindings = load_bindings(bindings_path)
    assert bindings.fault_scenarios_blocked_for_live(live_runner._IMPLEMENTED_FAULT_INJECTORS) == FAULT_SCENARIO_IDS
    configuration = {
        "live_adapter": "known_answer.live_stub:run",
        "fixture_id": "fixture-test",
        "model_provider": "openai",
        "model_name": "gpt-test",
    }
    with pytest.raises(live_runner.LiveConfigurationError, match="deterministic fault injection is required"):
        live_runner.run_live_suite(configuration)
