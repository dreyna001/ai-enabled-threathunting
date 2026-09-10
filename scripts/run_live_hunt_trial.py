#!/usr/bin/env python3
"""Prepare, explicitly approve, or capture one synthetic trial through the app API.

Each trial uses a new output directory and hunt. The private scenario expectations
are used only when exporting evaluation records, never in an application request.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx
from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.api.workflow import CreateHuntRequest, LoginRequest
from threat_hunting.auth.service import CSRF_COOKIE
from threat_hunting.domain.contracts import HuntPlan, HuntScope
from threat_hunting.services.orchestration import sha256_json


MAX_BYTES = 32 * 1024 * 1024


class TrialScenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scenario_id: str = Field(min_length=1, max_length=200)
    variant_id: str = Field(min_length=1, max_length=200)
    trial_id: str = Field(min_length=1, max_length=200)
    fixture_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope: HuntScope
    hunt_input: CreateHuntRequest
    expected_event_ids: list[str]
    fixture_event_id_field: str | None = Field(default=None, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")


def read_json(path: Path) -> Any:
    """Read a bounded JSON file without exposing its contents in diagnostics."""
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("input exceeds the 32 MiB trial limit")
    return json.loads(raw)


def save_json(directory: Path, name: str, value: Any) -> None:
    """Checkpoint one known artifact name using an atomic replacement."""
    target = directory / name
    temporary = directory / (name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(target)


def validate_origin(base_url: str) -> str:
    """Require HTTPS except for an explicit loopback lab API."""
    url = urlsplit(base_url)
    if url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
        raise ValueError("base URL must be an origin without credentials or a path")
    if not url.hostname or url.scheme not in {"http", "https"}:
        raise ValueError("base URL must use HTTP or HTTPS")
    if url.scheme == "http":
        try:
            loopback = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            loopback = url.hostname == "localhost"
        if not loopback:
            raise ValueError("HTTP is permitted only for a loopback lab API")
    return base_url.rstrip("/")


def request(client: httpx.Client, method: str, path: str, payload: Any = None) -> Any:
    """Make one bounded request; never retry mutations or log response bodies."""
    csrf = client.cookies.get(CSRF_COOKIE)
    headers = {"X-CSRF-Token": csrf} if csrf else {}
    with client.stream(method, "/api" + path, json=payload, headers=headers) as response:
        if response.status_code not in {200, 201}:
            raise RuntimeError(f"application request failed: {method} {path} HTTP {response.status_code}")
        data = bytearray()
        for chunk in response.iter_bytes():
            data.extend(chunk)
            if len(data) > MAX_BYTES:
                raise ValueError("API response exceeds the 32 MiB trial limit")
    return json.loads(data)


def validate_plan(hunt: dict[str, Any], scenario: TrialScenario) -> HuntPlan:
    """Bind the generated plan to the exact predeclared synthetic scope."""
    plan = HuntPlan.model_validate(hunt["plan"])
    if str(plan.hunt_id) != str(hunt["hunt_id"]):
        raise ValueError("plan belongs to another hunt")
    if (plan.scope.earliest_utc != scenario.scope.earliest_utc
            or plan.scope.latest_utc != scenario.scope.latest_utc
            or set(plan.scope.indexes) != set(scenario.scope.indexes)
            or set(plan.scope.sourcetypes) != set(scenario.scope.sourcetypes)):
        raise ValueError("generated plan differs from the declared fixture scope; review in the app")
    return plan


def run_stage(
    stage: str, *, client: httpx.Client, credentials_file: Path, output: Path,
    scenario_file: Path | None = None, reviewed_plan_sha256: str | None = None,
) -> dict[str, Any]:
    """Use normal authentication, approval, enqueue, and owner-scoped export APIs."""
    origin = validate_origin(str(client.base_url))
    if stage == "prepare":
        if scenario_file is None:
            raise ValueError("prepare requires a scenario file")
        scenario = TrialScenario.model_validate(read_json(scenario_file))
        output.mkdir(parents=True, exist_ok=False)
        state: dict[str, Any] = {"origin": origin, "scenario": scenario.model_dump(mode="json"), "hunt_id": None}
        save_json(output, "trial.json", state)
    else:
        state = read_json(output / "trial.json")
        if state["origin"] != origin:
            raise ValueError("trial API origin changed")
        UUID(str(state["hunt_id"]))
        scenario = TrialScenario.model_validate(state["scenario"])
    credentials = LoginRequest.model_validate(read_json(credentials_file))
    request(client, "POST", "/auth/login", credentials.model_dump())
    try:
        if stage == "prepare":
            hunt = request(client, "POST", "/hunts", scenario.hunt_input.model_dump(mode="json"))
            state["hunt_id"] = str(UUID(hunt["hunt_id"]))
            save_json(output, "trial.json", state)
            hunt = request(client, "POST", f"/hunts/{state['hunt_id']}/discover")
            save_json(output, "discovered-hunt.json", hunt)
            validate_plan(hunt, scenario)
            return {"hunt_id": state["hunt_id"], "state": hunt["state"], "plan_sha256": sha256_json(hunt["plan"])}
        hunt_id = state["hunt_id"]
        hunt = request(client, "GET", f"/hunts/{hunt_id}")
        if stage == "execute":
            validate_plan(hunt, scenario)
            if not reviewed_plan_sha256 or sha256_json(hunt["plan"]) != reviewed_plan_sha256:
                raise ValueError("execute requires the SHA-256 of the reviewed current plan")
            if hunt["state"] != "awaiting_plan_review":
                raise ValueError("execute requires a fresh plan awaiting review; inspect existing job state before retrying")
            approved = request(client, "POST", f"/hunts/{hunt_id}/plan/approve", {
                "analyst_note": "Explicitly reviewed synthetic qualification trial. Approval records test execution, not independent analyst acceptance.",
            })
            save_json(output, "approved-hunt.json", approved)
            if sha256_json(approved["plan"]) != reviewed_plan_sha256:
                raise ValueError("approved plan changed; execution was not requested")
            queued = request(client, "POST", f"/hunts/{hunt_id}/execute")
            save_json(output, "queued-hunt.json", queued)
            return {"hunt_id": hunt_id, "state": queued["state"]}
        if stage != "capture":
            raise ValueError("unknown trial stage")
        save_json(output, "latest-hunt.json", hunt)
        result = {"hunt_id": hunt_id, "state": hunt["state"]}
        if hunt["state"] in {"report_draft", "finalized", "failed", "cancelled"}:
            results = request(client, "GET", f"/hunts/{hunt_id}/results")
            save_json(output, "hunt-results.json", results)
            if hunt.get("report_content"):
                save_json(output, "report-content.json", hunt["report_content"])
            plan = validate_plan(hunt, scenario)
            config = hunt["discovery_snapshot"]["execution_config_snapshot"]["payload"]["execution_config"]
            observation = {
                "scenario_id": scenario.scenario_id, "variant_id": scenario.variant_id,
                "trial_id": scenario.trial_id, "hunt_id": hunt_id,
                "terminal_state": hunt["state"],
                "fixture_sha256": scenario.fixture_sha256,
                "model_provider": config["provider"], "model_name": config["model_name"],
                "reasoning_effort": config.get("reasoning_effort"),
                "prompt_contract_version": config.get("prompt_contract_version"),
                "image_version": config.get("image_version"),
                "expected_event_ids": scenario.expected_event_ids,
                "fixture_event_id_field": scenario.fixture_event_id_field,
                "approved_question_ids": [question.question_id for question in plan.questions],
                "results": results, "judgment_source": "unspecified",
            }
            save_json(output, "observations.json", {"runs": [observation]})
        return result
    finally:
        request(client, "POST", "/auth/logout")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stage", choices=("prepare", "execute", "capture"))
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--credentials-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scenario", type=Path)
    parser.add_argument("--reviewed-plan-sha256")
    args = parser.parse_args(argv)
    try:
        origin = validate_origin(args.base_url)
        with httpx.Client(base_url=origin, timeout=420, follow_redirects=False) as client:
            result = run_stage(args.stage, client=client, credentials_file=args.credentials_file, output=args.output,
                               scenario_file=args.scenario, reviewed_plan_sha256=args.reviewed_plan_sha256)
    except (OSError, ValueError, RuntimeError, KeyError, httpx.HTTPError) as exc:
        # Credentials, telemetry and provider error bodies remain out of console output.
        print(json.dumps({"stage": args.stage, "error_type": type(exc).__name__, "status": "failed"}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
