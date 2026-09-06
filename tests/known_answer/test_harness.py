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

    configuration = live_runner._require_live_configuration()
    with pytest.raises(live_runner.LiveConfigurationError, match="no configured known-answer workflow adapter"):
        live_runner.run_live_suite(configuration)


def test_live_orchestration_scores_terminal_adapter_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    cases = load_cases()
    expected_runs = [run_synthetic_case(case).to_dict() for case in cases]
    seen: dict[str, object] = {}

    def callback(**kwargs: object) -> dict[str, object]:
        seen.update(kwargs)
        return {"fixture_id": "fixture-test", "runs": expected_runs}

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
    assert seen["cases"] == cases
    assert seen["configuration"]["fixture_id"] == "fixture-test"  # type: ignore[index]
