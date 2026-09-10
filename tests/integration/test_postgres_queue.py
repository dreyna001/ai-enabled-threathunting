"""Migration and queue guarantees must hold on the deployed database engine."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier
from uuid import uuid4

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, select, text

from threat_hunting.db import MIGRATION_HEAD
from threat_hunting.services.jobs import JobConflict, JobService, execution_jobs
from threat_hunting.services.workflow import WorkflowService


def test_migration_upgrade_downgrade_preserves_hunts(postgres_engine):
    service = WorkflowService(postgres_engine)
    owner = str(uuid4())
    hunt = service.create_hunt(owner, title="Preserve me", hypothesis="h", objective="o")
    config = Config("alembic.ini")
    with postgres_engine.begin() as connection:
        config.attributes["connection"] = connection
        assert connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one() == MIGRATION_HEAD
        command.downgrade(config, "0012_security_hardening")
        assert "ix_workflow_hunts_owner_created_id" not in {item["name"] for item in inspect(connection).get_indexes("workflow_hunts")}
        command.upgrade(config, "head")
        assert "ix_workflow_hunts_owner_created_id" in {item["name"] for item in inspect(connection).get_indexes("workflow_hunts")}
    assert service.get_hunt(owner, hunt["hunt_id"])["title"] == "Preserve me"


def test_simultaneous_claims_respect_the_deployment_cap(postgres_engine):
    service = JobService(postgres_engine, max_active_hunts=2, lease_seconds=60)
    for _ in range(12):
        id = str(uuid4())
        service.enqueue("owner", id, idempotency_key=id)
    start = Barrier(8)
    def claim(index):
        start.wait(timeout=10)
        return service.claim(f"worker-{index}")
    with ThreadPoolExecutor(max_workers=8) as pool:
        leases = list(pool.map(claim, range(8)))
    assert len([lease for lease in leases if lease is not None]) == 2
    with postgres_engine.connect() as connection:
        assert len(connection.execute(select(execution_jobs.c.job_id).where(execution_jobs.c.status == "claimed")).all()) == 2


def test_expired_lease_replacement_fences_stale_mutations(postgres_engine):
    service = JobService(postgres_engine, lease_seconds=1)
    service.enqueue("owner", "hunt", idempotency_key="one")
    now = datetime.now(timezone.utc)
    old = service.claim("first", now=now)
    assert old is not None
    later = now + timedelta(seconds=2)
    assert service.recover_expired(now=later) == 1
    new = service.claim("replacement", now=later)
    assert new is not None and new.generation == old.generation + 1
    for mutation in (service.heartbeat, service.complete):
        with pytest.raises(JobConflict):
            mutation(old, now=later)
    service.complete(new, now=later)
