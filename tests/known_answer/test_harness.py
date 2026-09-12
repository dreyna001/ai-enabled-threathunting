from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from known_answer.harness import load_answers, load_cases, run_suite, run_synthetic_case, score_runs

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import run_known_answer_hunts as live_runner  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]


def test_known_answer_suite_contains_required_twelve_behavior_categories() -> None:
    cases = load_cases()
    categories = [case["category"] for case in cases]
    assert len(cases) == 12
    assert categories.count("supported") == 3
    assert categories.count("not_supported") == 2
    assert set(categories) == {
        "supported", "not_supported", "incomplete", "truncated", "timeout",
        "model_repair", "restart_recovery", "hard_budget", "cancellation",
    }


def test_synthetic_suite_meets_recovery_safety_and_budget_gates() -> None:
    result = run_suite()
    assert result["passed"] is True
    assert result["recovery_percent"] == 100.0
    assert result["fabricated_evidence_count"] == 0
    assert result["citation_failure_count"] == 0
    assert result["hard_budget_violation_count"] == 0
    assert result["model_repair_attempts"] == 1
    assert result["scenario_count"] == 12


def test_answer_key_is_not_needed_to_run_a_synthetic_case() -> None:
    case = load_cases()[0]
    run = run_synthetic_case(case)
    assert run.retained_evidence_ids == ("ka01-e1",)
    assert run.cited_evidence_ids == ("ka01-e1",)


def test_scorer_rejects_fabricated_or_uncited_evidence() -> None:
    case = load_cases()[0]
    run = run_synthetic_case(case)
    corrupted = run.__class__(
        **{**run.to_dict(), "fabricated_evidence_ids": ("forged",), "cited_evidence_ids": ()}
    )
    result = score_runs([corrupted, *[run_synthetic_case(item) for item in load_cases()[1:]]], load_answers())
    assert result["passed"] is False
    assert result["fabricated_evidence_count"] == 1


def test_cli_synthetic_mode_is_machine_readable() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/run_known_answer_hunts.py"), "--mode", "synthetic", "--json"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    result = json.loads(completed.stdout)
    assert result["passed"] is True
    assert completed.stderr == ""


def test_cli_live_mode_fails_closed_without_secret_configuration() -> None:
    clean_env = {
        key: value
        for key, value in __import__("os").environ.items()
        if not key.startswith("THREAT_HUNTING_")
    }
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts/run_known_answer_hunts.py"), "--mode", "live"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        env=clean_env,
    )
    assert completed.returncode == 2
    assert "requires configured secret-file/runtime values" in completed.stderr


def test_live_configuration_requires_a_non_production_fixture_and_model_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "splunk-token"
    model_key_file = tmp_path / "model-key"
    token_file.write_text("splunk-secret", encoding="utf-8")
    model_key_file.write_text("model-secret", encoding="utf-8")
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_URL", "https://splunk.test:8089")
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("THREAT_HUNTING_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_NAME", "gpt-test")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_API_KEY_FILE", str(model_key_file))
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_FIXTURE_ID", "fixture-test")

    configuration = live_runner._require_live_configuration()

    assert configuration["fixture_id"] == "fixture-test"
    assert "splunk-secret" not in repr(configuration)
    assert "model-secret" not in repr(configuration)


def test_live_mode_reports_exact_blocker_when_workflow_adapter_is_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "splunk-token"
    model_key_file = tmp_path / "model-key"
    token_file.write_text("splunk-secret", encoding="utf-8")
    model_key_file.write_text("model-secret", encoding="utf-8")
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_URL", "https://splunk.test:8089")
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("THREAT_HUNTING_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_NAME", "gpt-test")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_API_KEY_FILE", str(model_key_file))
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_FIXTURE_ID", "fixture-test")
    monkeypatch.delenv("THREAT_HUNTING_KNOWN_ANSWER_LIVE_ADAPTER", raising=False)
    from known_answer.test_bindings import build_valid_bindings, write_bindings

    monkeypatch.setenv(
        "THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE",
        str(write_bindings(tmp_path, build_valid_bindings(fault_injector="deterministic-v1"))),
    )
    monkeypatch.setattr(
        live_runner, "_IMPLEMENTED_FAULT_INJECTORS", frozenset({"deterministic-v1"})
    )

    configuration = live_runner._require_live_configuration()
    with pytest.raises(live_runner.LiveConfigurationError, match="no configured known-answer workflow adapter"):
        live_runner.run_live_suite(configuration)


def test_live_mode_requires_private_bindings_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_file = tmp_path / "splunk-token"
    model_key_file = tmp_path / "model-key"
    token_file.write_text("splunk-secret", encoding="utf-8")
    model_key_file.write_text("model-secret", encoding="utf-8")
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_URL", "https://splunk.test:8089")
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("THREAT_HUNTING_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_NAME", "gpt-test")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_API_KEY_FILE", str(model_key_file))
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_FIXTURE_ID", "fixture-test")
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_LIVE_ADAPTER", "known_answer.live_stub:run")
    monkeypatch.delenv("THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE", raising=False)

    configuration = live_runner._require_live_configuration()
    with pytest.raises(live_runner.LiveConfigurationError, match="private scenario bindings are required"):
        live_runner.run_live_suite(configuration)


def test_live_mode_rejects_pre_scored_runs_instead_of_exports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from known_answer.test_bindings import build_valid_bindings, write_bindings

    bindings_path = write_bindings(tmp_path, build_valid_bindings(fault_injector="deterministic-v1"))
    cases = load_cases()
    expected_runs = [run_synthetic_case(case).to_dict() for case in cases]

    def callback(**kwargs: object) -> dict[str, object]:
        return {"fixture_id": "fixture-test", "runs": expected_runs}

    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE", str(bindings_path))
    monkeypatch.setattr(
        live_runner, "_IMPLEMENTED_FAULT_INJECTORS", frozenset({"deterministic-v1"})
    )
    monkeypatch.setattr(live_runner, "_load_live_adapter", lambda _spec: callback)
    monkeypatch.setattr(
        live_runner,
        "_build_live_adapters",
        lambda _configuration: (
            SimpleNamespace(healthcheck=lambda: SimpleNamespace(available=True, error_category=None)),
            object(),
        ),
    )

    with pytest.raises(live_runner.LiveConfigurationError, match="pre-scored runs"):
        live_runner.run_live_suite(
            {
                "live_adapter": "known_answer.live_stub:run",
                "fixture_id": "fixture-test",
                "model_provider": "openai",
                "model_name": "gpt-test",
            }
        )


@pytest.mark.parametrize("fault_injector", [None, "deterministic-v1"])
def test_live_mode_blocks_fault_scenarios_without_implemented_fault_injector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault_injector: str | None
) -> None:
    from known_answer.test_bindings import build_valid_bindings, write_bindings

    bindings_path = write_bindings(
        tmp_path, build_valid_bindings(fault_injector=fault_injector)
    )
    token_file = tmp_path / "splunk-token"
    model_key_file = tmp_path / "model-key"
    token_file.write_text("splunk-secret", encoding="utf-8")
    model_key_file.write_text("model-secret", encoding="utf-8")
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE", str(bindings_path))
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_URL", "https://splunk.test:8089")
    monkeypatch.setenv("THREAT_HUNTING_SPLUNK_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("THREAT_HUNTING_MODEL_PROVIDER", "openai")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_NAME", "gpt-test")
    monkeypatch.setenv("THREAT_HUNTING_MODEL_API_KEY_FILE", str(model_key_file))
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_FIXTURE_ID", "fixture-test")
    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_LIVE_ADAPTER", "known_answer.live_stub:run")

    configuration = live_runner._require_live_configuration()
    with pytest.raises(live_runner.LiveConfigurationError, match="deterministic fault injection is required"):
        live_runner.run_live_suite(configuration)


def _category_export(case: dict[str, object], binding: dict[str, object]) -> dict[str, object]:
    scenario_id = str(case["scenario_id"])
    category = str(case["category"])
    events = [event for event in case["events"] if isinstance(event, dict)]
    retained_count = int(case.get("retained_event_count", len(events)))
    retained_count = max(0, min(retained_count, len(events)))
    retained_events = events[:retained_count]
    query_id = "00000000-0000-4000-8000-000000000001"
    duplicate_query_id = "00000000-0000-4000-8000-000000000099"
    queries = [{"query_id": query_id, "status": "completed"}]
    if category == "restart_recovery":
        queries.append({"query_id": duplicate_query_id, "status": "completed"})
    evidence = []
    findings = []
    for index, event in enumerate(retained_events):
        evidence_id = f"00000000-0000-4000-8000-{index + 2:012d}"
        abstract = str(event["evidence_id"])
        real_id = binding["evidence_id_map"][abstract]
        evidence.append({
            "evidence_id": evidence_id,
            "query_id": query_id,
            "selected_result": {"event_id": real_id},
        })
        findings.append({
            "finding_id": f"00000000-0000-4000-8000-{index + 20:012d}",
            "classification": "supported_observation",
            "evidence_ids": [evidence_id],
            "query_ids": [query_id],
        })
    limitation = str(case.get("coverage_limitation", ""))
    terminal_state = "report_draft"
    usage: dict[str, object] = {
        "model_calls": int(case.get("model_calls", 0)),
        "model_repair_attempts": int(case.get("model_repair_attempts", 0)),
        "model_input_tokens": int(case.get("model_input_tokens", 0)),
        "model_output_tokens": int(case.get("model_output_tokens", 0)),
    }
    if category in {"not_supported"}:
        evidence = []
        findings = [{
            "finding_id": "00000000-0000-4000-8000-000000000020",
            "classification": "not_supported_within_scope",
            "evidence_ids": [],
            "query_ids": [query_id],
        }]
        limitation = "No matching evidence was observed."
    elif category == "timeout":
        terminal_state = "failed"
        limitation = str(case.get("failure_code", "hard_timeout"))
        evidence = []
        findings = []
    elif category == "hard_budget":
        terminal_state = "failed"
        limitation = str(case.get("failure_code", "budget_exhausted"))
        evidence = []
        findings = []
    elif category == "cancellation":
        terminal_state = "cancelled"
        limitation = str(case.get("failure_code", "cancelled"))
    return {
        "scenario_id": scenario_id,
        "terminal_state": terminal_state,
        "limitation": limitation,
        "results": {"queries": queries, "evidence": evidence, "findings": findings, "usage": usage},
    }


def test_live_orchestration_extracts_exports_without_binding_leakage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from known_answer.test_bindings import build_valid_bindings, write_bindings

    binding_payload = build_valid_bindings(fault_injector="deterministic-v1")
    bindings_path = write_bindings(tmp_path, binding_payload)
    cases = load_cases()
    seen: dict[str, object] = {}

    def callback(**kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        exports = [
            _category_export(case, binding_payload["scenarios"][str(case["scenario_id"])])
            for case in cases
        ]
        return {"fixture_id": "fixture-test", "exports": exports}

    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE", str(bindings_path))
    monkeypatch.setattr(
        live_runner, "_IMPLEMENTED_FAULT_INJECTORS", frozenset({"deterministic-v1"})
    )
    monkeypatch.setattr(live_runner, "_load_live_adapter", lambda _spec: callback)
    monkeypatch.setattr(
        live_runner,
        "_build_live_adapters",
        lambda _configuration: (
            SimpleNamespace(healthcheck=lambda: SimpleNamespace(available=True, error_category=None)),
            object(),
        ),
    )

    result = live_runner.run_live_suite(
        {
            "live_adapter": "known_answer.live_stub:run",
            "fixture_id": "fixture-test",
            "model_provider": "openai",
            "model_name": "gpt-test",
        }
    )

    assert result["qualification_mode"] == "live"
    assert result["passed"] is True
    assert "cases" not in seen
    execution_plan = seen["execution_plan"]
    assert len(execution_plan) == 12
    for entry in execution_plan:
        assert set(entry) == {
            "scenario_id",
            "fault_mode",
            "execution_source",
            "export_source",
        }
        scenario_id = str(entry["scenario_id"])
        binding = binding_payload["scenarios"][scenario_id]
        assert entry["fault_mode"] == binding["fault_mode"]
        assert entry["execution_source"] == binding["execution_source"]
        assert entry["export_source"] == binding["export_source"]
        serialized = json.dumps(entry)
        assert "evidence_id_map" not in serialized
        assert "identity_field" not in serialized
        assert "ka01-e1" not in serialized
    configuration_payload = json.dumps(seen["configuration"])
    assert "evidence_id_map" not in configuration_payload
    assert "binding_version" not in configuration_payload
    assert "expected_evidence_ids" not in configuration_payload


def test_live_mode_rejects_leaking_execution_plan_before_adapter_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from known_answer.test_bindings import build_valid_bindings, write_bindings

    payload = build_valid_bindings(fault_injector="deterministic-v1")
    payload["scenarios"]["ka-01-supported-process"]["execution_source"] = "synthetic:ka01-e1"
    bindings_path = write_bindings(tmp_path, payload)
    adapter_calls: list[str] = []

    def _fail_if_called(*_args: object, **_kwargs: object) -> tuple[object, object]:
        adapter_calls.append("build_live_adapters")
        raise AssertionError("live adapters must not be constructed for leaking execution_plan")

    def _fail_callback(*_args: object, **_kwargs: object) -> dict[str, object]:
        adapter_calls.append("callback")
        return {"fixture_id": "fixture-test", "exports": []}

    monkeypatch.setenv("THREAT_HUNTING_KNOWN_ANSWER_BINDINGS_FILE", str(bindings_path))
    monkeypatch.setattr(
        live_runner, "_IMPLEMENTED_FAULT_INJECTORS", frozenset({"deterministic-v1"})
    )
    monkeypatch.setattr(live_runner, "_load_live_adapter", lambda _spec: _fail_callback)
    monkeypatch.setattr(live_runner, "_build_live_adapters", _fail_if_called)

    with pytest.raises(live_runner.LiveConfigurationError, match="execution_plan leaks"):
        live_runner.run_live_suite(
            {
                "live_adapter": "known_answer.live_stub:run",
                "fixture_id": "fixture-test",
                "model_provider": "openai",
                "model_name": "gpt-test",
            }
        )
    assert adapter_calls == []
