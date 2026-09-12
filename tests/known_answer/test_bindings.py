from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from known_answer.bindings import (
    BINDINGS_ENV,
    BindingsError,
    HuntResultExport,
    KnownAnswerBindings,
    ScenarioBinding,
    SUPPORTED_FAULT_INJECTOR,
    adapter_configuration_without_bindings,
    assert_no_evaluator_leakage,
    extract_synthetic_run,
    load_bindings,
)
from known_answer.harness import load_cases


def _real_id(abstract: str) -> str:
    return f"fixture-{abstract}"


def _scenario_binding(case: dict[str, object]) -> dict[str, object]:
    category = str(case["category"])
    events = [event for event in case.get("events", []) if isinstance(event, dict)]
    return {
        "category": category,
        "execution_source": f"synthetic:{case['scenario_id']}",
        "export_source": "hunt_results",
        "identity_field": "event_id",
        "evidence_id_map": {
            str(event["evidence_id"]): _real_id(str(event["evidence_id"]))
            for event in events
        },
        "fault_mode": category if category in {
            "timeout", "model_repair", "restart_recovery", "hard_budget", "cancellation"
        } else "none",
    }


def build_valid_bindings(
    *,
    fixture_id: str = "fixture-test",
    fault_injector: str | None = None,
) -> dict[str, object]:
    cases = load_cases()
    return {
        "binding_version": "1.0",
        "fixture_id": fixture_id,
        "fixture_sha256": "a" * 64,
        "fixture_version": "test-v1",
        "fault_injector": fault_injector,
        "scenarios": {
            str(case["scenario_id"]): _scenario_binding(case)
            for case in cases
        },
    }


def write_bindings(tmp_path: Path, payload: dict[str, object] | None = None) -> Path:
    path = tmp_path / "bindings.json"
    path.write_text(json.dumps(payload or build_valid_bindings()), encoding="utf-8")
    return path


def _supported_export(scenario_id: str = "ka-01-supported-process") -> HuntResultExport:
    query_id = str(uuid4())
    evidence_id = str(uuid4())
    return HuntResultExport(
        scenario_id=scenario_id,
        category="supported",
        terminal_state="report_draft",
        limitation="",
        results={
            "queries": [{"query_id": query_id, "status": "completed"}],
            "evidence": [{
                "evidence_id": evidence_id,
                "query_id": query_id,
                "selected_result": {"event_id": _real_id("ka01-e1")},
            }],
            "findings": [{
                "finding_id": str(uuid4()),
                "classification": "supported_observation",
                "evidence_ids": [evidence_id],
                "query_ids": [query_id],
            }],
            "usage": {
                "model_calls": 2,
                "model_repair_attempts": 0,
                "model_input_tokens": 120,
                "model_output_tokens": 60,
            },
        },
    )


def test_valid_bindings_accept_exact_twelve_scenarios(tmp_path: Path) -> None:
    bindings = load_bindings(write_bindings(tmp_path))
    assert len(bindings.scenarios) == 12
    assert bindings.fixture_id == "fixture-test"


@pytest.mark.parametrize(
    "mutation,match",
    [
        ("missing_scenario", "at least 12 items"),
        ("extra_scenario", "at most 12 items"),
        ("category_mismatch", "binding category mismatch"),
        ("map_mismatch", "evidence_id_map must match scenario events"),
        ("duplicate_real", "values must be unique"),
        ("wrong_fault_mode", "must declare fault_mode"),
    ],
)
def test_bindings_reject_malformed_or_inconsistent_payloads(
    tmp_path: Path,
    mutation: str,
    match: str,
) -> None:
    payload = build_valid_bindings()
    scenarios = payload["scenarios"]
    if mutation == "missing_scenario":
        scenarios.pop("ka-12-cancellation")
    elif mutation == "extra_scenario":
        scenarios["ka-99-extra"] = next(iter(scenarios.values()))
    elif mutation == "category_mismatch":
        scenarios["ka-01-supported-process"]["category"] = "timeout"
    elif mutation == "map_mismatch":
        scenarios["ka-01-supported-process"]["evidence_id_map"]["ka01-e2"] = "fixture-ka01-e2"
        scenarios["ka-01-supported-process"]["evidence_id_map"].pop("ka01-e1")
    elif mutation == "duplicate_real":
        scenarios["ka-03-supported-network"]["evidence_id_map"]["ka03-e2"] = _real_id("ka03-e1")
    elif mutation == "wrong_fault_mode":
        scenarios["ka-08-query-timeout"]["fault_mode"] = "none"
    path = write_bindings(tmp_path, payload)
    with pytest.raises(BindingsError, match=match):
        load_bindings(path)


def test_fault_scenarios_block_live_matrix_without_supported_injector() -> None:
    bindings = KnownAnswerBindings.model_validate(build_valid_bindings())
    blocked = bindings.fault_scenarios_blocked_for_live()
    assert blocked == (
        "ka-08-query-timeout",
        "ka-09-model-repair",
        "ka-10-restart-recovery",
        "ka-11-hard-budget",
        "ka-12-cancellation",
    )


def test_fault_injector_declaration_alone_does_not_unlock_live_matrix() -> None:
    bindings = KnownAnswerBindings.model_validate(
        build_valid_bindings(fault_injector=SUPPORTED_FAULT_INJECTOR)
    )
    assert bindings.fault_scenarios_blocked_for_live()


def test_implemented_supported_fault_injector_unlocks_live_matrix() -> None:
    bindings = KnownAnswerBindings.model_validate(
        build_valid_bindings(fault_injector=SUPPORTED_FAULT_INJECTOR)
    )
    assert bindings.fault_scenarios_blocked_for_live(
        frozenset({SUPPORTED_FAULT_INJECTOR})
    ) == ()


def test_extract_maps_fixture_identity_to_abstract_evidence_ids() -> None:
    binding = ScenarioBinding.model_validate(
        build_valid_bindings()["scenarios"]["ka-01-supported-process"]
    )
    run = extract_synthetic_run(_supported_export(), binding)
    assert run.retained_evidence_ids == ("ka01-e1",)
    assert run.cited_evidence_ids == ("ka01-e1",)
    assert run.disposition == "supported"
    assert run.fabricated_evidence_ids == ()


def test_extract_reports_fabricated_and_citation_failures() -> None:
    binding = ScenarioBinding.model_validate(
        build_valid_bindings()["scenarios"]["ka-01-supported-process"]
    )
    export = _supported_export()
    export.results["findings"][0]["evidence_ids"] = [str(uuid4())]
    run = extract_synthetic_run(export, binding)
    assert run.fabricated_evidence_ids
    assert run.citation_failures


def test_assert_no_evaluator_leakage_rejects_binding_and_abstract_ids() -> None:
    with pytest.raises(BindingsError, match="abstract evaluator evidence IDs"):
        assert_no_evaluator_leakage({"query": "find ka01-e1"})
    with pytest.raises(BindingsError, match="evaluator-only key"):
        assert_no_evaluator_leakage({"evidence_id_map": {"ka01-e1": "x"}})


def test_adapter_configuration_excludes_binding_material(tmp_path: Path) -> None:
    bindings = load_bindings(write_bindings(tmp_path))
    configuration = {
        "fixture_id": "fixture-test",
        "model_provider": "openai",
        "model_name": "gpt-test",
        "live_adapter": "example.adapter:run",
    }
    sanitized = adapter_configuration_without_bindings(configuration, bindings)
    assert sanitized == configuration
    assert "ka01-e1" not in json.dumps(sanitized)
    assert "evidence_id_map" not in sanitized


def test_load_bindings_from_env_requires_explicit_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(BINDINGS_ENV, raising=False)
    from known_answer.bindings import load_bindings_from_env

    with pytest.raises(BindingsError, match="private scenario bindings are required"):
        load_bindings_from_env()
