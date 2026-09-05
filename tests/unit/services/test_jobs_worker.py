"""Focused durable queue and worker recovery behavior."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool

from threat_hunting.services.jobs import JobService, execution_jobs, metadata
from threat_hunting.worker.main import process_one


def _service() -> JobService:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    metadata.create_all(engine)
    return JobService(engine, lease_seconds=10)


def test_expired_lease_requeues_and_worker_reclaims() -> None:
    service = _service()
    service.enqueue("owner", "hunt", idempotency_key="one")
    now = datetime.now(timezone.utc)
    lease = service.claim("dead-worker", now=now)
    assert lease is not None
    with service.engine.begin() as connection:
        connection.execute(execution_jobs.update().values(lease_expires_at_utc=now - timedelta(seconds=1)).where(execution_jobs.c.job_id == lease.job_id))
    seen: list[str] = []
    assert process_one(service, "replacement", handler=lambda item: seen.append(item.hunt_id), now=now)
    assert seen == ["hunt"]


def test_cancelled_queued_job_is_not_claimed() -> None:
    service = _service()
    service.enqueue("owner", "hunt", idempotency_key="one")
    assert service.request_cancel("owner", "hunt") == 1
    assert service.claim("worker") is None
