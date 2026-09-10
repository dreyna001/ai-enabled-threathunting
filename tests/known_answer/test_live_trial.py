"""Application API gates and answer-key isolation for repeatable live trials."""

import json
import sys
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from run_live_hunt_trial import run_stage, validate_origin
from threat_hunting.services.orchestration import sha256_json


def setup_trial(tmp_path):
    identifier = str(uuid4())
    scope = {"earliest_utc": "2026-01-01T00:00:00Z", "latest_utc": "2026-01-05T00:00:00Z",
             "indexes": ["th_test_endpoint"], "sourcetypes": ["synthetic:process"]}
    plan = {"schema_version": "1.0", "plan_id": str(uuid4()), "plan_version": 1, "hunt_id": identifier,
            "discovery_snapshot_id": str(uuid4()), "execution_config_snapshot_id": str(uuid4()),
            "hypothesis": "A scoped process was observed", "objective": "Inspect telemetry", "scope": scope,
            "intelligence_refs": [], "data_sources": [{"index": "th_test_endpoint", "sourcetypes": ["synthetic:process"], "purpose": "Processes"}],
            "questions": [{"question_id": "q1", "question": "Which processes ran?", "rationale": "Test hypothesis", "expected_information_gain": "Observed activity"}],
            "query_strategy": ["Read scoped events"], "coverage_limitations": [], "created_at_utc": "2026-09-09T00:00:00Z"}
    hunt = {"hunt_id": identifier, "state": "awaiting_plan_review", "plan": plan}
    scenario = {"scenario_id": "synthetic-process", "variant_id": "candidate", "trial_id": "1", "fixture_sha256": "a" * 64,
                "scope": scope, "hunt_input": {"title": "Synthetic trial", "hypothesis": "A scoped process was observed", "objective": "Inspect telemetry"},
                "expected_event_ids": ["private-answer-only"]}
    scenario_path = tmp_path / "scenario.json"
    scenario_path.write_text(json.dumps(scenario))
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({"username": "test", "password": "test-only"}))
    requests = []

    def handler(request):
        requests.append((request.method, request.url.path, request.content.decode()))
        if request.url.path.endswith("/auth/login"):
            return httpx.Response(200, json={"user": {}}, headers={"Set-Cookie": "threat_hunting_csrf=test-csrf; Path=/"})
        if request.method == "POST":
            assert request.headers["X-CSRF-Token"] == "test-csrf"
        if request.url.path.endswith("/auth/logout"):
            return httpx.Response(200, json={"status": "logged_out"})
        if request.url.path.endswith("/results"):
            return httpx.Response(200, json={"queries": [], "evidence": [], "findings": [], "usage": {}})
        if request.url.path.endswith("/plan/approve"):
            hunt["state"] = "approved"
        if request.url.path.endswith("/execute"):
            hunt["state"] = "queued"
        return httpx.Response(201 if request.url.path == "/api/hunts" else 200, json=hunt)

    client = httpx.Client(base_url="http://127.0.0.1:8080", transport=httpx.MockTransport(handler))
    return client, credentials, scenario_path, tmp_path / "trial", hunt, requests


def test_prepare_keeps_expectations_out_of_requests_and_never_approves(tmp_path):
    client, credentials, scenario, output, hunt, requests = setup_trial(tmp_path)
    with client:
        result = run_stage("prepare", client=client, credentials_file=credentials, output=output, scenario_file=scenario)
    assert result["plan_sha256"] == sha256_json(hunt["plan"])
    assert "private-answer-only" not in str(requests)
    assert not any(path.endswith(("/approve", "/execute")) for _, path, _ in requests)
    assert requests[-1][1] == "/api/auth/logout"
    assert json.loads((output / "trial.json").read_text())["hunt_id"] == hunt["hunt_id"]


def test_execution_requires_exact_reviewed_plan_and_preserves_app_gates(tmp_path):
    client, credentials, scenario, output, hunt, requests = setup_trial(tmp_path)
    with client:
        prepared = run_stage("prepare", client=client, credentials_file=credentials, output=output, scenario_file=scenario)
        with pytest.raises(ValueError, match="reviewed current plan"):
            run_stage("execute", client=client, credentials_file=credentials, output=output, reviewed_plan_sha256="wrong")
        assert not any(path.endswith("/approve") for _, path, _ in requests)
        result = run_stage("execute", client=client, credentials_file=credentials, output=output,
                           reviewed_plan_sha256=prepared["plan_sha256"])
        assert result["state"] == "queued"
        with pytest.raises(ValueError, match="fresh plan"):
            run_stage("execute", client=client, credentials_file=credentials, output=output,
                      reviewed_plan_sha256=prepared["plan_sha256"])
    assert sum(path.endswith("/execute") for _, path, _ in requests) == 1
    assert sum(path.endswith("/plan/approve") for _, path, _ in requests) == 1


def test_scope_expansion_stops_before_approval_and_preserves_generated_plan(tmp_path):
    client, credentials, scenario, output, hunt, requests = setup_trial(tmp_path)
    hunt["plan"]["scope"]["indexes"].append("customer-production")
    with client, pytest.raises(ValueError, match="declared fixture scope"):
        run_stage("prepare", client=client, credentials_file=credentials, output=output, scenario_file=scenario)
    assert (output / "discovered-hunt.json").exists()
    assert not any(path.endswith("/approve") for _, path, _ in requests)


@pytest.mark.parametrize("terminal_state", ["report_draft", "finalized", "failed", "cancelled"])
def test_capture_exports_real_configuration_without_inventing_judgments(tmp_path, terminal_state):
    client, credentials, scenario, output, hunt, requests = setup_trial(tmp_path)
    with client:
        run_stage("prepare", client=client, credentials_file=credentials, output=output, scenario_file=scenario)
        hunt["state"] = terminal_state
        hunt["discovery_snapshot"] = {"execution_config_snapshot": {"payload": {"execution_config": {
            "provider": "openai", "model_name": "configured-model", "reasoning_effort": "none",
            "prompt_contract_version": "1.3", "image_version": "candidate",
        }}}}
        run_stage("capture", client=client, credentials_file=credentials, output=output)
    run = json.loads((output / "observations.json").read_text())["runs"][0]
    assert run["model_name"] == "configured-model"
    assert run["approved_question_ids"] == ["q1"]
    assert run["expected_event_ids"] == ["private-answer-only"]
    assert run["judgment_source"] == "unspecified"
    assert run["terminal_state"] == terminal_state
    assert "judgments" not in run


@pytest.mark.parametrize("origin", ["http://example.test", "https://user:password@example.test", "https://example.test/path", "https://example.test?token=x"])
def test_credentials_cannot_be_sent_to_unapproved_insecure_or_ambiguous_origin(origin):
    with pytest.raises(ValueError):
        validate_origin(origin)


def test_existing_trial_directory_cannot_create_another_hunt(tmp_path):
    client, credentials, scenario, output, hunt, requests = setup_trial(tmp_path)
    output.mkdir()
    with client, pytest.raises(FileExistsError):
        run_stage("prepare", client=client, credentials_file=credentials, output=output, scenario_file=scenario)
    assert requests == []
