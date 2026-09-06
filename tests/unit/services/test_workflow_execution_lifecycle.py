"""Owner- and state-scoped production execution persistence tests."""

from sqlalchemy import create_engine, update
from sqlalchemy.pool import StaticPool

from threat_hunting.domain.state import HuntState
from threat_hunting.services.jobs import metadata as jobs_metadata
from threat_hunting.services.workflow import WorkflowService, hunts, workflow_metadata


def _service() -> tuple[WorkflowService, str, str, str]:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    workflow_metadata.create_all(engine)
    jobs_metadata.create_all(engine)
    service = WorkflowService(engine, local_demo=False)
    owner, worker = "owner", "worker"
    hunt = service.create_hunt(owner, title="production", hypothesis="h", objective="o")
    hunt_id = str(hunt["hunt_id"])
    with engine.begin() as connection:
        connection.execute(update(hunts).where(hunts.c.hunt_id == hunt_id).values(state=HuntState.QUEUED.value, plan_version=1, plan={"scope": {}}, approval={"plan_version": 1}))
    job = service.jobs.enqueue(owner, hunt_id, idempotency_key=f"test:{hunt_id}")
    service.jobs.claim(worker)
    return service, owner, hunt_id, str(job["job_id"])


def test_worker_lifecycle_persists_running_synthesis_and_report_draft() -> None:
    service, owner, hunt_id, job_id = _service()
    service.start_execution(owner, hunt_id, job_id, "worker")
    result = service.persist_execution_result(owner, hunt_id, {"evidence": []}, {"hypothesis": "h", "objective_and_scope": "o"})
    assert result["state"] == HuntState.REPORT_DRAFT.value
    assert result["results"] == {"evidence": []}


def test_synthesizing_state_is_restartable_without_duplicate_results() -> None:
    service, owner, hunt_id, job_id = _service()
    service.start_execution(owner, hunt_id, job_id, "worker")
    service._update(owner, hunt_id, expected_state=HuntState.RUNNING.value, state=HuntState.SYNTHESIZING.value, results={"evidence": []})
    result = service.persist_execution_result(owner, hunt_id, {"evidence": []}, {"hypothesis": "h", "objective_and_scope": "o"})
    assert result["state"] == HuntState.REPORT_DRAFT.value


def test_late_result_is_rejected_after_owner_cancellation() -> None:
    service, owner, hunt_id, job_id = _service()
    service.start_execution(owner, hunt_id, job_id, "worker")
    service.cancel(owner, hunt_id)
    try:
        service.persist_execution_result(owner, hunt_id, {"evidence": []}, {"x": 1})
    except Exception as exc:
        assert "cancelled" in str(exc)
    else:
        raise AssertionError("late result was accepted")


def test_failure_is_terminal_and_idempotent() -> None:
    service, owner, hunt_id, _job_id = _service()
    first = service.fail_execution(owner, hunt_id, "adapter unavailable")
    second = service.fail_execution(owner, hunt_id, "late error")
    assert first["state"] == HuntState.FAILED.value
    assert second["state"] == HuntState.FAILED.value
    assert second["results"]["failure"] == "adapter unavailable"
