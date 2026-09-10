"""Lease fencing, renewal, and deployment-scope isolation tests."""

import time
import threading
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.pool import StaticPool

from threat_hunting.services.jobs import JobConflict, JobService, metadata
from threat_hunting.worker.main import process_one


def _service(scope: str = "scope-a", lease_seconds: int = 1) -> JobService:
    engine = create_engine("sqlite+pysqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    metadata.create_all(engine)
    return JobService(engine, deployment_scope_id=scope, lease_seconds=lease_seconds)


def test_scope_isolation_and_generation_fence_stale_completion() -> None:
    service = _service()
    service.enqueue("owner", "other", idempotency_key="other", deployment_scope_id="scope-b")
    service.enqueue("owner", "hunt", idempotency_key="hunt")
    first = service.claim("worker")
    assert first is not None and first.hunt_id == "hunt"
    service.enqueue("owner", "hunt2", idempotency_key="hunt2")
    now = datetime.now(timezone.utc)
    old = service.claim("worker", now=now)
    assert old is not None
    service.recover_expired(now=now + timedelta(seconds=2))
    replacement = service.claim("replacement", now=now + timedelta(seconds=2))
    assert replacement is not None
    assert replacement.generation > old.generation
    with pytest.raises(JobConflict):
        service.complete(old)


def test_long_handler_renews_lease_before_completion(monkeypatch) -> None:
    service = _service(lease_seconds=1)
    clock = [datetime(2026, 9, 8, tzinfo=timezone.utc)]
    start = clock[0]
    monkeypatch.setattr("threat_hunting.services.jobs._now", lambda: clock[0])
    service.enqueue("owner", "hunt", idempotency_key="hunt")
    heartbeat = service.heartbeat
    renewed = threading.Event()

    def advance_and_renew(lease):
        clock[0] += timedelta(seconds=0.4)
        current = heartbeat(lease)
        if clock[0] - start > timedelta(seconds=1):
            renewed.set()
        return current

    monkeypatch.setattr(service, "heartbeat", advance_and_renew)
    def handler(_lease):
        assert renewed.wait(timeout=10)

    assert process_one(service, "worker", handler=handler)
    assert clock[0] - start > timedelta(seconds=1)
    status = service.get_for_owner("owner", "hunt")
    assert status is not None and status["status"] == "completed"
    service.engine.dispose()


def test_expired_lease_cannot_complete_job() -> None:
    service = _service(lease_seconds=1)
    service.enqueue("owner", "hunt", idempotency_key="expired-complete")
    now = datetime.now(timezone.utc)
    lease = service.claim("worker", now=now)
    assert lease is not None

    with pytest.raises(JobConflict, match="no longer owned"):
        service.complete(lease, now=now + timedelta(seconds=2))


def test_active_hunt_cap_blocks_second_claim_in_scope() -> None:
    service = _service(lease_seconds=10)
    service.max_active_hunts = 1
    service.enqueue("owner", "hunt-1", idempotency_key="cap-1")
    service.enqueue("owner", "hunt-2", idempotency_key="cap-2")
    assert service.claim("worker-1") is not None
    assert service.claim("worker-2") is None


def test_heartbeat_database_failure_signals_handler_before_return() -> None:
    service = _service(lease_seconds=1)
    service.enqueue("owner", "hunt", idempotency_key="heartbeat")
    finished = threading.Event()

    def broken_heartbeat(_lease):
        raise SQLAlchemyError("database unavailable")

    service.heartbeat = broken_heartbeat  # type: ignore[method-assign]

    def handler(lease):
        while not lease.cancellation_token.is_cancelled():
            time.sleep(0.01)
        finished.set()

    assert process_one(service, "worker", handler=handler)
    assert finished.is_set()
