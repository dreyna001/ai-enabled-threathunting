"""Deterministic local fault injection for known-answer qualification."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, cast

from sqlalchemy import update

from threat_hunting.domain.budgets import BudgetLimits
from threat_hunting.domain.errors import FailureCategory
from threat_hunting.integrations.errors import AdapterError
from threat_hunting.services.jobs import JobConflict, execution_jobs
from threat_hunting.services.workflow import Conflict

from known_answer.bindings import FAULT_CATEGORIES, HuntResultExport, ScenarioBinding
from known_answer.harness import load_cases
from known_answer.workflow_support import (
    OWNER,
    WORKER,
    SimulatedWorkerCrash,
    append_planned_query,
    build_scenario_model,
    create_workflow_service,
    prepare_queued_hunt,
    primary_fixture_event,
    RecoverableJob,
    RecoverableJobs,
    RecoverableSplunk,
    HangingSplunk,
    Splunk,
)

FAULT_SCENARIO_IDS = (
    "ka-08-query-timeout",
    "ka-09-model-repair",
    "ka-10-restart-recovery",
    "ka-11-hard-budget",
    "ka-12-cancellation",
)


def implemented_fault_modes() -> frozenset[str]:
    """Return fault modes with local deterministic qualification coverage."""

    return frozenset(FAULT_CATEGORIES)


def _case_and_binding(scenario_id: str) -> tuple[dict[str, Any], ScenarioBinding]:
    cases = {case["scenario_id"]: case for case in load_cases()}
    case = cases[scenario_id]
    category = str(case["category"])
    events = [event for event in case.get("events", []) if isinstance(event, Mapping)]
    binding = ScenarioBinding.model_validate(
        {
            "category": category,
            "execution_source": f"local-fault:{scenario_id}",
            "export_source": "workflow_results",
            "identity_field": "event_id",
            "evidence_id_map": {
                str(event["evidence_id"]): f"fixture-{event['evidence_id']}"
                for event in events
            },
            "fault_mode": category,
        }
    )
    assert binding.fault_mode == binding.category
    return case, binding


def derive_limitation(results: Mapping[str, Any], *, category: str, case: Mapping[str, Any]) -> str:
    failure = results.get("failure")
    if isinstance(failure, Mapping):
        category_value = failure.get("category")
        if isinstance(category_value, str) and category_value:
            return category_value
    if category == "timeout" and any(
        item.get("status") == "timed_out" for item in results.get("query_ledger", []) if isinstance(item, Mapping)
    ):
        return str(case.get("failure_code", "hard_timeout"))
    if category == "hard_budget":
        if any(
            item.get("status") == "skipped_budget"
            for item in results.get("query_ledger", [])
            if isinstance(item, Mapping)
        ):
            return str(case.get("failure_code", "budget_exhausted"))
        if str(results.get("adaptive_status", "")) == "budget_reserved_for_synthesis":
            return str(case.get("failure_code", "budget_exhausted"))
    if category == "cancellation":
        return str(case.get("failure_code", "cancelled"))
    return ""


def export_from_hunt(
    *,
    scenario_id: str,
    category: str,
    case: Mapping[str, Any],
    terminal_state: str,
    results: Mapping[str, Any],
) -> HuntResultExport:
    return HuntResultExport(
        scenario_id=scenario_id,
        category=category,
        terminal_state=terminal_state,
        limitation=derive_limitation(results, category=category, case=case),
        results=dict(results),
    )


def run_query_timeout(scenario_id: str = "ka-08-query-timeout") -> HuntResultExport:
    case, binding = _case_and_binding(scenario_id)
    fixture_event_id, fixture_host = primary_fixture_event(binding, case)
    service = create_workflow_service(
        splunk_client=HangingSplunk(event_id=fixture_event_id, host=fixture_host),
        model=build_scenario_model(binding, case),
        budget_limits=BudgetLimits(
            splunk_query_timeout_seconds=1,
            max_inflight_query_seconds_after_cutoff=1,
        ),
    )
    hunt_id, lease = prepare_queued_hunt(service, hypothesis=str(case["hypothesis"]))
    service.execute_job(lease)
    results = service.results(OWNER, hunt_id)
    assert any(item.get("status") == "timed_out" for item in results["query_ledger"])
    assert results["evidence"] == []
    assert results["usage"]["splunk_queries"] == 1
    return export_from_hunt(
        scenario_id=scenario_id,
        category=binding.category,
        case=case,
        terminal_state=str(service.get_hunt(OWNER, hunt_id)["state"]),
        results=results,
    )


def run_model_repair(scenario_id: str = "ka-09-model-repair") -> HuntResultExport:
    case, binding = _case_and_binding(scenario_id)
    fixture_event_id, fixture_host = primary_fixture_event(binding, case)
    service = create_workflow_service(
        splunk_client=Splunk(event_id=fixture_event_id, host=fixture_host),
        model=build_scenario_model(binding, case, repair_contract="QueryAssessment[]"),
    )
    hunt_id, lease = prepare_queued_hunt(service, hypothesis=str(case["hypothesis"]))
    service.execute_job(lease)
    results = service.results(OWNER, hunt_id)
    assert results["usage"]["model_repair_attempts"] == 1
    assert service.get_hunt(OWNER, hunt_id)["state"] == "report_draft"
    return export_from_hunt(
        scenario_id=scenario_id,
        category=binding.category,
        case=case,
        terminal_state="report_draft",
        results=results,
    )


def run_restart_recovery(scenario_id: str = "ka-10-restart-recovery") -> HuntResultExport:
    case, binding = _case_and_binding(scenario_id)
    fixture_event_id, fixture_host = primary_fixture_event(binding, case)
    client = RecoverableSplunk(event_id=fixture_event_id, host=fixture_host)
    recoverable_jobs = cast(RecoverableJobs, client.jobs)
    service = create_workflow_service(
        splunk_client=client,
        model=build_scenario_model(binding, case),
    )
    restore_ledger = append_planned_query(service, "unused")
    hunt_id, lease = prepare_queued_hunt(service, hypothesis=str(case["hypothesis"]))
    try:
        service.execute_job(lease)
    except SimulatedWorkerCrash:
        pass
    else:
        raise AssertionError("restart recovery must crash before the first durable completion")
    finally:
        restore_ledger()
    checkpoint = service.results(OWNER, hunt_id)
    assert checkpoint["query_ledger"][0]["status"] == "submitted"
    recorded_sid = checkpoint["query_ledger"][0]["splunk_job_id"]
    assert recorded_sid == checkpoint["query_ledger"][0]["query_id"]
    assert recoverable_jobs.create_calls == 1

    recoverable_job = cast(RecoverableJob, recoverable_jobs[recorded_sid])
    recoverable_job.crash_on_status = False
    now = datetime.now(timezone.utc)
    with service.engine.begin() as connection:
        connection.execute(
            update(execution_jobs)
            .where(execution_jobs.c.job_id == lease.job_id)
            .values(lease_expires_at_utc=now - timedelta(seconds=1))
        )
    assert service.jobs.recover_expired(now=now) == 1
    replacement = service.jobs.claim(WORKER, now=now)
    assert replacement is not None
    assert replacement.generation > lease.generation

    try:
        service.execute_job(lease)
    except Conflict as exc:
        if "lease" not in str(exc):
            raise
    else:
        raise AssertionError("stale lease generation must be fenced")

    service.execute_job(replacement)
    results = service.results(OWNER, hunt_id)
    assert recoverable_jobs.create_calls == 2
    assert results["query_ledger"][0]["status"] == "completed"
    assert results["query_ledger"][1]["status"] == "completed"
    assert results["queries"][0]["splunk_job_id"] == recorded_sid
    assert len(results["evidence"]) == len({item["evidence_id"] for item in results["evidence"]})
    assert service.get_hunt(OWNER, hunt_id)["state"] == "report_draft"
    return export_from_hunt(
        scenario_id=scenario_id,
        category=binding.category,
        case=case,
        terminal_state="report_draft",
        results=results,
    )


def run_hard_budget(scenario_id: str = "ka-11-hard-budget") -> HuntResultExport:
    case, binding = _case_and_binding(scenario_id)
    fixture_event_id, fixture_host = primary_fixture_event(binding, case)
    service = create_workflow_service(
        splunk_client=Splunk(event_id=fixture_event_id, host=fixture_host),
        model=build_scenario_model(binding, case),
        budget_limits=BudgetLimits(
            max_splunk_queries=1,
            max_model_calls=2,
            max_cached_bytes_per_hunt=1,
            max_cached_bytes_per_query=1,
        ),
    )
    restore_ledger = append_planned_query(service, "unused")
    hunt_id, lease = prepare_queued_hunt(service, hypothesis=str(case["hypothesis"]))
    restore_ledger()
    service.execute_job(lease)
    results = service.results(OWNER, hunt_id)
    usage = results["usage"]
    assert usage["splunk_queries"] <= 1
    assert any(item.get("status") == "skipped_budget" for item in results["query_ledger"])
    assert results["evidence"] == []
    return export_from_hunt(
        scenario_id=scenario_id,
        category=binding.category,
        case=case,
        terminal_state=str(service.get_hunt(OWNER, hunt_id)["state"]),
        results=results,
    )


def run_cancellation(scenario_id: str = "ka-12-cancellation") -> HuntResultExport:
    case, binding = _case_and_binding(scenario_id)
    fixture_event_id, fixture_host = primary_fixture_event(binding, case)
    service = create_workflow_service(
        splunk_client=Splunk(event_id=fixture_event_id, host=fixture_host),
        model=build_scenario_model(binding, case),
    )
    restore_ledger = append_planned_query(service, "unused")
    hunt_id, lease = prepare_queued_hunt(service, hypothesis=str(case["hypothesis"]))
    restore_ledger()

    original_update = service._update
    cancelled = {"done": False}

    def cancel_after_first_query(*args: object, **kwargs: object) -> None:
        original_update(*args, **kwargs)  # type: ignore[arg-type]
        results = kwargs.get("results")
        if cancelled["done"] or not isinstance(results, Mapping):
            return
        ledger = results.get("query_ledger", [])
        completed = sum(
            1 for item in ledger if isinstance(item, Mapping) and item.get("status") == "completed"
        )
        if completed == 1:
            service.cancel(OWNER, hunt_id)
            cancelled["done"] = True

    service._update = cancel_after_first_query  # type: ignore[method-assign]
    try:
        service.execute_job(lease)
    except (Conflict, JobConflict, AdapterError):
        pass
    finally:
        service._update = original_update  # type: ignore[method-assign]

    assert cancelled["done"], "cancellation must occur after the first completed query"

    results = service.results(OWNER, hunt_id)
    assert service.get_hunt(OWNER, hunt_id)["state"] == "cancelled"
    assert len(results["evidence"]) == 1
    assert len([item for item in results["query_ledger"] if item.get("status") == "completed"]) == 1
    assert all(item.get("status") != "completed" for item in results["query_ledger"][1:])
    calls_before = cast(Any, service.model_adapter).call_count
    try:
        service.execute_job(lease)
    except (Conflict, JobConflict, AdapterError) as exc:
        if isinstance(exc, AdapterError) and exc.category != FailureCategory.CANCELLED:
            raise
        if isinstance(exc, Conflict) and "lease" not in str(exc) and "cancelled" not in str(exc):
            raise
    else:
        raise AssertionError("cancelled hunts must reject additional worker progress")
    assert cast(Any, service.model_adapter).call_count == calls_before
    return export_from_hunt(
        scenario_id=scenario_id,
        category=binding.category,
        case=case,
        terminal_state="cancelled",
        results=results,
    )


def run_fault_scenario(scenario_id: str) -> HuntResultExport:
    runners = {
        "ka-08-query-timeout": run_query_timeout,
        "ka-09-model-repair": run_model_repair,
        "ka-10-restart-recovery": run_restart_recovery,
        "ka-11-hard-budget": run_hard_budget,
        "ka-12-cancellation": run_cancellation,
    }
    runner = runners.get(scenario_id)
    if runner is None:
        raise ValueError(f"unsupported fault scenario: {scenario_id}")
    return runner()


def qualify_fault_scenarios() -> list[HuntResultExport]:
    return [run_fault_scenario(scenario_id) for scenario_id in FAULT_SCENARIO_IDS]
