"""Queue publication and hunt state must share one transaction."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, select

from threat_hunting.domain.contracts import HuntPlan
from threat_hunting.services.jobs import execution_jobs, metadata as jobs_metadata
from threat_hunting.services.orchestration import ImmutableSnapshot, sha256_json
from threat_hunting.services.workflow import Conflict, WorkflowService, workflow_metadata


@pytest.fixture(params=["sqlite", "postgresql"])
def approved_service(request, tmp_path):
    engine = request.getfixturevalue("postgres_engine") if request.param == "postgresql" else create_engine(f"sqlite+pysqlite:///{tmp_path / 'queue.db'}")
    if request.param == "sqlite":
        workflow_metadata.create_all(engine)
        jobs_metadata.create_all(engine)
    service = WorkflowService(engine)
    owner = str(uuid4())
    hunt = service.create_hunt(owner, title="Atomic execution", hypothesis="h", objective="o")
    hunt_id = str(hunt["hunt_id"])
    now = datetime.now(timezone.utc)
    snapshot = ImmutableSnapshot(
        uuid4(), "execution_configuration", now, service._execution_binding_payload(),
    ).to_dict()
    plan = HuntPlan.model_validate({
        "schema_version": "1.0", "plan_id": str(uuid4()), "plan_version": 1,
        "hunt_id": hunt_id, "discovery_snapshot_id": str(uuid4()),
        "execution_config_snapshot_id": snapshot["snapshot_id"],
        "hypothesis": "h", "objective": "o",
        "scope": {"earliest_utc": now - timedelta(hours=1), "latest_utc": now,
                  "indexes": ["main"], "sourcetypes": ["syslog"]},
        "intelligence_refs": [], "data_sources": [],
        "questions": [{"question_id": "q1", "question": "Which hosts appear?",
                       "rationale": "Establish scope", "expected_information_gain": "Observed hosts"}],
        "query_strategy": ["Bounded search"], "coverage_limitations": [], "created_at_utc": now,
    }).model_dump(mode="json")
    service._update(owner, hunt_id, state="approved", plan_version=1, plan=plan,
                    discovery_snapshot={"execution_config_snapshot": snapshot},
                    approval={"plan_version": 1, "plan_sha256": sha256_json(plan),
                              "execution_config_snapshot_id": snapshot["snapshot_id"],
                              "execution_config_sha256": snapshot["sha256"]})
    yield service, owner, hunt_id
    service.close()
    if request.param == "sqlite":
        engine.dispose()


def test_worker_cannot_claim_before_hunt_state_commits(approved_service, monkeypatch) -> None:
    service, owner, hunt_id = approved_service
    enqueue = service.jobs.enqueue
    premature_claims = []

    def publish(*args, **kwargs):
        job = enqueue(*args, **kwargs)
        premature_claims.append(service.jobs.claim("early-worker"))
        return job

    monkeypatch.setattr(service.jobs, "enqueue", publish)
    result = service.execute(owner, hunt_id)
    assert premature_claims == [None]
    assert result["state"] == "queued"
    lease = service.jobs.claim("worker")
    assert lease is not None
    assert service.start_execution(owner, hunt_id, lease.job_id, "worker")["state"] == "running"


def test_enqueue_failure_rolls_back_state_audit_and_job(approved_service, monkeypatch) -> None:
    service, owner, hunt_id = approved_service
    enqueue = service.jobs.enqueue

    def fail_after_insert(*args, **kwargs):
        enqueue(*args, **kwargs)
        raise RuntimeError("injected failure after insertion")

    monkeypatch.setattr(service.jobs, "enqueue", fail_after_insert)
    with pytest.raises(RuntimeError, match="injected failure"):
        service.execute(owner, hunt_id)
    assert service.get_hunt(owner, hunt_id)["state"] == "approved"
    assert service.jobs.get_for_owner(owner, hunt_id) is None
    from threat_hunting.services.workflow import audit_records
    with service.engine.connect() as connection:
        assert connection.execute(select(audit_records.c.audit_id).where(
            audit_records.c.hunt_id == hunt_id, audit_records.c.resulting_state == "queued",
        )).first() is None


def test_simultaneous_execution_requests_preserve_the_winning_job(approved_service, monkeypatch) -> None:
    service, owner, hunt_id = approved_service
    owned_row = service._owned_row
    barrier = Barrier(2)

    def read_together(*args, **kwargs):
        row = owned_row(*args, **kwargs)
        if row["state"] == "approved":
            barrier.wait(timeout=5)
        return row

    monkeypatch.setattr(service, "_owned_row", read_together)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(service.execute, owner, hunt_id) for _ in range(2)]
        successes, conflicts = 0, 0
        for future in futures:
            try:
                assert future.result(timeout=10)["state"] == "queued"
                successes += 1
            except Conflict:
                conflicts += 1
    assert (successes, conflicts) == (1, 1)
    with service.engine.connect() as connection:
        jobs = connection.execute(select(execution_jobs).where(execution_jobs.c.hunt_id == hunt_id)).mappings().all()
    assert len(jobs) == 1 and jobs[0]["status"] == "queued" and not jobs[0]["cancel_requested"]
