"""Durable queue and expiring worker leases for hunt execution."""

from __future__ import annotations

from dataclasses import dataclass, field
import threading
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, MetaData, String, Table, Text, select, update
from sqlalchemy.engine import Engine

metadata = MetaData()
execution_jobs = Table(
    "execution_jobs", metadata,
    Column("job_id", String(36), primary_key=True),
    Column("hunt_id", String(36), nullable=False, index=True),
    Column("owner_id", String(36), nullable=False, index=True),
    Column("deployment_scope_id", String(200), nullable=False, default="default"),
    Column("status", String(32), nullable=False, default="queued"),
    Column("worker_id", String(200), nullable=True),
    Column("lease_expires_at_utc", DateTime(timezone=True), nullable=True),
    Column("heartbeat_at_utc", DateTime(timezone=True), nullable=True),
    Column("attempts", Integer, nullable=False, default=0),
    Column("idempotency_key", String(200), nullable=False, unique=True),
    Column("payload", JSON, nullable=False, default=dict),
    Column("cancel_requested", Boolean, nullable=False, default=False),
    Column("last_error", Text, nullable=True),
    Column("created_at_utc", DateTime(timezone=True), nullable=False),
    Column("updated_at_utc", DateTime(timezone=True), nullable=False),
)


class JobConflict(RuntimeError):
    """A job cannot be claimed or transitioned by the caller."""


class LeaseCancellation:
    """Process-local cooperative signal for a fenced or cancelled handler."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def is_set(self) -> bool:
        return self._event.is_set()


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class JobLease:
    job_id: str
    hunt_id: str
    owner_id: str
    deployment_scope_id: str
    worker_id: str
    generation: int
    expires_at: datetime
    cancellation_token: LeaseCancellation = field(default_factory=LeaseCancellation, compare=False, repr=False)


class JobService:
    """Persist queue state and ensure only one live worker lease owns a job."""

    def __init__(self, engine: Engine, *, lease_seconds: int = 60, deployment_scope_id: str = "default", max_active_hunts: int | None = None) -> None:
        if lease_seconds <= 0:
            raise ValueError("lease_seconds must be positive")
        if not deployment_scope_id or len(deployment_scope_id) > 200:
            raise ValueError("deployment_scope_id must contain 1 to 200 characters")
        if max_active_hunts is not None and max_active_hunts <= 0:
            raise ValueError("max_active_hunts must be positive")
        self.engine = engine
        self.lease_seconds = lease_seconds
        self.deployment_scope_id = deployment_scope_id
        self.max_active_hunts = max_active_hunts

    def enqueue(self, owner_id: str, hunt_id: str, *, idempotency_key: str, payload: dict[str, object] | None = None, deployment_scope_id: str | None = None) -> dict[str, object]:
        now = _now()
        scope = deployment_scope_id or self.deployment_scope_id
        values = {"job_id": str(uuid4()), "hunt_id": hunt_id, "owner_id": owner_id, "deployment_scope_id": scope, "status": "queued", "worker_id": None, "lease_expires_at_utc": None, "heartbeat_at_utc": None, "attempts": 0, "idempotency_key": idempotency_key, "payload": payload or {}, "cancel_requested": False, "last_error": None, "created_at_utc": now, "updated_at_utc": now}
        with self.engine.begin() as connection:
            existing = connection.execute(select(execution_jobs).where(execution_jobs.c.idempotency_key == idempotency_key)).mappings().first()
            if existing is not None:
                return dict(existing)
            connection.execute(execution_jobs.insert().values(**values))
        return values

    def claim(self, worker_id: str, *, deployment_scope_id: str | None = None, now: datetime | None = None) -> JobLease | None:
        now = now or _now()
        expiry = now + timedelta(seconds=self.lease_seconds)
        scope = deployment_scope_id or self.deployment_scope_id
        with self.engine.begin() as connection:
            if self.max_active_hunts is not None:
                active_rows = connection.execute(select(execution_jobs.c.hunt_id).where(execution_jobs.c.status == "claimed", execution_jobs.c.deployment_scope_id == scope).with_for_update()).all()
                if len({str(item[0]) for item in active_rows}) >= self.max_active_hunts:
                    return None
            row = connection.execute(select(execution_jobs).where(execution_jobs.c.status == "queued", execution_jobs.c.cancel_requested.is_(False), execution_jobs.c.deployment_scope_id == scope).order_by(execution_jobs.c.created_at_utc).limit(1).with_for_update(skip_locked=True)).mappings().first()
            if row is None:
                return None
            changed = connection.execute(update(execution_jobs).where(execution_jobs.c.job_id == row["job_id"], execution_jobs.c.deployment_scope_id == scope, execution_jobs.c.status == "queued", execution_jobs.c.cancel_requested.is_(False)).values(status="claimed", worker_id=worker_id, lease_expires_at_utc=expiry, heartbeat_at_utc=now, attempts=int(row["attempts"]) + 1, updated_at_utc=now))
            if changed.rowcount != 1:
                return None
        generation = int(row["attempts"]) + 1
        return JobLease(str(row["job_id"]), str(row["hunt_id"]), str(row["owner_id"]), str(row["deployment_scope_id"]), worker_id, generation, expiry)

    def require_lease(self, job_id: str, worker_id: str, *, generation: int | None = None, deployment_scope_id: str | None = None, now: datetime | None = None) -> dict[str, object]:
        """Require a live claim owned by one worker before mutating hunt state."""
        now = now or _now()
        with self.engine.connect() as connection:
            row = connection.execute(select(execution_jobs).where(execution_jobs.c.job_id == job_id)).mappings().first()
        if row is None or row["status"] != "claimed" or row["worker_id"] != worker_id or row["cancel_requested"]:
            raise JobConflict("job lease is missing or owned by another worker")
        if generation is not None and int(row["attempts"]) != generation:
            raise JobConflict("job lease generation is fenced")
        if deployment_scope_id is not None and row["deployment_scope_id"] != deployment_scope_id:
            raise JobConflict("job deployment scope does not match worker scope")
        expiry = row["lease_expires_at_utc"]
        if expiry is None or (expiry.replace(tzinfo=timezone.utc) if expiry.tzinfo is None else expiry) <= now:
            raise JobConflict("job lease has expired")
        return dict(row)

    def heartbeat(self, lease: JobLease, *, now: datetime | None = None) -> JobLease:
        now = now or _now()
        expiry = now + timedelta(seconds=self.lease_seconds)
        with self.engine.begin() as connection:
            result = connection.execute(update(execution_jobs).where(execution_jobs.c.job_id == lease.job_id, execution_jobs.c.worker_id == lease.worker_id, execution_jobs.c.status == "claimed", execution_jobs.c.cancel_requested.is_(False), execution_jobs.c.attempts == lease.generation, execution_jobs.c.deployment_scope_id == lease.deployment_scope_id, execution_jobs.c.lease_expires_at_utc > now).values(lease_expires_at_utc=expiry, heartbeat_at_utc=now, updated_at_utc=now))
        if result.rowcount != 1:
            raise JobConflict("job lease is missing, expired, or cancelled")
        return JobLease(lease.job_id, lease.hunt_id, lease.owner_id, lease.deployment_scope_id, lease.worker_id, lease.generation, expiry, lease.cancellation_token)

    def complete(self, lease: JobLease, *, status: str = "completed", error: str | None = None, now: datetime | None = None) -> None:
        if status not in {"completed", "failed", "cancelled"}:
            raise ValueError("invalid terminal job status")
        now = now or _now()
        with self.engine.begin() as connection:
            result = connection.execute(update(execution_jobs).where(execution_jobs.c.job_id == lease.job_id, execution_jobs.c.worker_id == lease.worker_id, execution_jobs.c.status == "claimed", execution_jobs.c.attempts == lease.generation, execution_jobs.c.deployment_scope_id == lease.deployment_scope_id).values(status=status, worker_id=None, lease_expires_at_utc=None, heartbeat_at_utc=None, last_error=error, updated_at_utc=now))
        if result.rowcount != 1:
            raise JobConflict("job is no longer owned by this worker")

    def get_for_owner(self, owner_id: str, hunt_id: str) -> dict[str, object] | None:
        """Return the newest owned job for a hunt without exposing other owners."""
        with self.engine.connect() as connection:
            row = connection.execute(select(execution_jobs).where(execution_jobs.c.owner_id == owner_id, execution_jobs.c.hunt_id == hunt_id).order_by(execution_jobs.c.created_at_utc.desc()).limit(1)).mappings().first()
        return None if row is None else dict(row)

    def request_cancel(self, owner_id: str, hunt_id: str, *, now: datetime | None = None) -> int:
        now = now or _now()
        with self.engine.begin() as connection:
            result = connection.execute(update(execution_jobs).where(execution_jobs.c.owner_id == owner_id, execution_jobs.c.hunt_id == hunt_id, execution_jobs.c.status.in_(["queued", "claimed"])).values(cancel_requested=True, status="cancelled", worker_id=None, lease_expires_at_utc=None, heartbeat_at_utc=None, updated_at_utc=now))
        return int(result.rowcount or 0)

    def recover_expired(self, *, now: datetime | None = None) -> int:
        now = now or _now()
        with self.engine.begin() as connection:
            result = connection.execute(update(execution_jobs).where(execution_jobs.c.status == "claimed", execution_jobs.c.lease_expires_at_utc <= now, execution_jobs.c.cancel_requested.is_(False)).values(status="queued", worker_id=None, lease_expires_at_utc=None, heartbeat_at_utc=None, updated_at_utc=now))
        return int(result.rowcount or 0)


__all__ = ["JobConflict", "JobLease", "JobService", "LeaseCancellation", "execution_jobs", "metadata"]
