"""Restartable, owner-safe retention cleanup for all hunt artifacts."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable, Mapping, Protocol
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import text


TERMINAL_STATES = frozenset({"finalized", "cancelled", "failed"})
ARTIFACTS: tuple[str, ...] = (
    "workspace",
    "uploads",
    "intelligence_inputs",
    "evidence",
    "entities",
    "entity_evidence",
    "pivots",
    "findings",
    "notes",
    "query_ledger",
    "reports",
    "snapshots",
    "audit",
    "hunt",
)


class RetentionError(RuntimeError):
    """A cleanup task could not make progress and remains retryable."""


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    hunt_days: int = 90
    abandoned_days: int = 7
    temporary_result_hours: int = 24

    def __post_init__(self) -> None:
        if self.hunt_days <= 0 or self.abandoned_days <= 0 or self.temporary_result_hours <= 0:
            raise ValueError("retention periods must be positive")


@dataclass(frozen=True, slots=True)
class HuntRetentionSnapshot:
    hunt_id: str
    owner_id: str
    state: str
    updated_at: datetime
    active_worker: bool = False
    active_external_job: bool = False

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL_STATES


@dataclass(frozen=True, slots=True)
class CleanupResult:
    hunt_id: str
    task_id: str | None
    status: str
    deleted_artifacts: tuple[str, ...] = ()
    error: str | None = None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("retention timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def retention_due(snapshot: HuntRetentionSnapshot, *, now: datetime, policy: RetentionPolicy) -> bool:
    """Return true only when the exact last-activity rule is satisfied."""

    now = _utc(now)
    last_activity = _utc(snapshot.updated_at)
    if snapshot.terminal:
        return now >= last_activity + timedelta(days=policy.hunt_days)
    return is_abandoned(snapshot, now=now, policy=policy)


def is_abandoned(snapshot: HuntRetentionSnapshot, *, now: datetime, policy: RetentionPolicy | None = None) -> bool:
    """A non-terminal hunt idle seven consecutive days without active work."""

    policy = policy or RetentionPolicy()
    if snapshot.terminal or snapshot.active_worker or snapshot.active_external_job:
        return False
    return _utc(now) >= _utc(snapshot.updated_at) + timedelta(days=policy.abandoned_days)


class RetentionRepository(Protocol):
    def candidate_hunts(self, *, now: datetime, policy: RetentionPolicy) -> Iterable[HuntRetentionSnapshot]: ...
    def claim_task(self, *, hunt_id: str, owner_id: str, now: datetime) -> Mapping[str, Any]: ...
    def lock_hunt(self, *, hunt_id: str, owner_id: str) -> HuntRetentionSnapshot | None: ...
    def artifact_paths(self, *, hunt_id: str, owner_id: str) -> Iterable[str]: ...
    def delete_artifact(self, *, artifact: str, hunt_id: str, owner_id: str) -> None: ...
    def save_task_failure(self, *, task_id: str, cursor: int, error: str, now: datetime) -> None: ...
    def complete_task(self, *, task_id: str, now: datetime) -> None: ...
    def audit_cleanup(self, *, hunt_id: str, owner_id: str, outcome: str, detail: str, now: datetime) -> None: ...


class FileStore:
    """Safely remove one persisted artifact without following path traversal."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def remove(self, relative_path: str) -> None:
        target = (self.root / relative_path).resolve()
        if target != self.root and self.root not in target.parents:
            raise RetentionError("artifact path escapes configured storage")
        try:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                target.unlink(missing_ok=True)
        except OSError as exc:
            raise RetentionError("artifact file could not be deleted") from exc

    def remove_orphan_temp_files(self, *, directory: str = "reports") -> int:
        target = (self.root / directory).resolve()
        if target != self.root and self.root not in target.parents:
            raise RetentionError("temporary directory escapes configured storage")
        if not target.is_dir():
            return 0
        removed = 0
        for path in target.iterdir():
            if path.name.startswith(".") and path.name.endswith(".tmp"):
                try:
                    path.unlink()
                    removed += 1
                except OSError:
                    continue
        return removed


class RetentionService:
    """Process due hunts through a durable cursor, safely across restarts."""

    def __init__(self, repository: RetentionRepository, *, file_store: FileStore, policy: RetentionPolicy | None = None, clock: Any = lambda: datetime.now(timezone.utc)) -> None:
        self.repository = repository
        self.file_store = file_store
        self.policy = policy or RetentionPolicy()
        self.clock = clock

    def cleanup(self) -> tuple[CleanupResult, ...]:
        now = _utc(self.clock())
        results: list[CleanupResult] = []
        for candidate in self.repository.candidate_hunts(now=now, policy=self.policy):
            results.append(self.cleanup_hunt(candidate.hunt_id, candidate.owner_id, now=now))
        return tuple(results)

    def cleanup_hunt(self, hunt_id: str, owner_id: str, *, now: datetime | None = None) -> CleanupResult:
        now = _utc(now or self.clock())
        task = self.repository.claim_task(hunt_id=hunt_id, owner_id=owner_id, now=now)
        task_id = str(task.get("task_id") or uuid4())
        snapshot = self.repository.lock_hunt(hunt_id=hunt_id, owner_id=owner_id)
        if snapshot is None:
            self.repository.complete_task(task_id=task_id, now=now)
            return CleanupResult(hunt_id, task_id, "already_missing")
        # Crucially, this is a second activity/lease check under the hunt lock;
        # the candidate query cannot race a newly resumed hunt into deletion.
        if not retention_due(snapshot, now=now, policy=self.policy):
            self.repository.complete_task(task_id=task_id, now=now)
            return CleanupResult(hunt_id, task_id, "skipped_active")
        paths = tuple(self.repository.artifact_paths(hunt_id=hunt_id, owner_id=owner_id))
        cursor = int(task.get("cursor", 0) or 0)
        deleted: list[str] = []
        try:
            self.repository.audit_cleanup(hunt_id=hunt_id, owner_id=owner_id, outcome="started", detail="retention cleanup claimed", now=now)
            for path in paths:
                self.file_store.remove(path)
            for index, artifact in enumerate(ARTIFACTS[cursor:], start=cursor):
                self.repository.delete_artifact(artifact=artifact, hunt_id=hunt_id, owner_id=owner_id)
                deleted.append(artifact)
                # A task cursor is durable before the next potentially failing
                # deletion.  Replays of already deleted rows are harmless.
                self.repository.save_task_failure(task_id=task_id, cursor=index + 1, error="", now=now)
            self.repository.complete_task(task_id=task_id, now=now)
            self.repository.audit_cleanup(hunt_id=hunt_id, owner_id=owner_id, outcome="success", detail="all hunt artifacts deleted", now=now)
        except Exception as exc:
            next_cursor = cursor + len(deleted)
            self.repository.save_task_failure(task_id=task_id, cursor=next_cursor, error=str(exc)[:500], now=now)
            self.repository.audit_cleanup(hunt_id=hunt_id, owner_id=owner_id, outcome="failed", detail=str(exc)[:500], now=now)
            return CleanupResult(hunt_id, task_id, "retryable_failure", tuple(deleted), str(exc))
        return CleanupResult(hunt_id, task_id, "deleted", tuple(deleted))


class SqlRetentionRepository:
    """PostgreSQL repository using the durable cleanup task table."""

    def __init__(self, engine: Any) -> None:
        self.engine = engine

    def candidate_hunts(self, *, now: datetime, policy: RetentionPolicy) -> Iterable[HuntRetentionSnapshot]:
        terminal_cutoff = _utc(now) - timedelta(days=policy.hunt_days)
        abandoned_cutoff = _utc(now) - timedelta(days=policy.abandoned_days)
        query = text("""SELECT hunt_id, owner_id, state, updated_at,
            COALESCE(lease_expires_at > :now, false) AS active_worker
            FROM hunts
            WHERE (state IN ('finalized','cancelled','failed') AND updated_at <= :terminal_cutoff)
               OR (state NOT IN ('finalized','cancelled','failed') AND updated_at <= :abandoned_cutoff)""")
        with self.engine.connect() as connection:
            rows = connection.execute(query, {"now": now, "terminal_cutoff": terminal_cutoff, "abandoned_cutoff": abandoned_cutoff}).mappings().all()
        for row in rows:
            yield HuntRetentionSnapshot(str(row["hunt_id"]), str(row["owner_id"]), str(row["state"]), _utc(row["updated_at"]), bool(row.get("active_worker")), False)

    def claim_task(self, *, hunt_id: str, owner_id: str, now: datetime) -> Mapping[str, Any]:
        task_id = str(uuid4())
        with self.engine.begin() as connection:
            connection.execute(text("""INSERT INTO retention_cleanup_tasks(task_id, owner_id, hunt_id, state, cursor, attempts, created_at_utc, updated_at_utc)
                VALUES (:task_id,:owner_id,:hunt_id,'running',:cursor,1,:now,:now)
                ON CONFLICT (hunt_id) DO UPDATE SET state='running', attempts=retention_cleanup_tasks.attempts+1, claimed_at_utc=:now, updated_at_utc=:now"""), {"task_id": task_id, "owner_id": owner_id, "hunt_id": hunt_id, "cursor": 0, "now": now})
            row = connection.execute(text("SELECT task_id, cursor FROM retention_cleanup_tasks WHERE hunt_id=:hunt_id AND owner_id=:owner_id"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().one()
        return dict(row)

    def lock_hunt(self, *, hunt_id: str, owner_id: str) -> HuntRetentionSnapshot | None:
        with self.engine.begin() as connection:
            row = connection.execute(text("SELECT hunt_id, owner_id, state, updated_at, COALESCE(lease_expires_at > CURRENT_TIMESTAMP,false) AS active_worker FROM hunts WHERE hunt_id=:hunt_id AND owner_id=:owner_id FOR UPDATE"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().first()
        if row is None:
            return None
        return HuntRetentionSnapshot(str(row["hunt_id"]), str(row["owner_id"]), str(row["state"]), _utc(row["updated_at"]), bool(row.get("active_worker")), False)

    def artifact_paths(self, *, hunt_id: str, owner_id: str) -> Iterable[str]:
        with self.engine.connect() as connection:
            report = connection.execute(text("SELECT pdf_path FROM reports WHERE hunt_id=:hunt_id AND owner_id=:owner_id"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().first()
            if report and report.get("pdf_path"):
                yield str(report["pdf_path"])
            rows = connection.execute(text("SELECT storage_path FROM uploads WHERE hunt_id=:hunt_id AND owner_id=:owner_id"), {"hunt_id": hunt_id, "owner_id": owner_id}).mappings().all()
        yield from (str(row["storage_path"]) for row in rows if row.get("storage_path"))

    def delete_artifact(self, *, artifact: str, hunt_id: str, owner_id: str) -> None:
        table_by_artifact = {
            "workspace": "workspace_artifacts", "uploads": "uploads", "intelligence_inputs": "intelligence_inputs",
            "evidence": "evidence_records", "entities": "entities", "entity_evidence": "entity_evidence",
            "pivots": "pivots", "findings": "findings", "notes": "hunt_notes", "query_ledger": "query_ledger",
            "reports": "reports", "snapshots": "hunt_snapshots", "audit": "audit_records", "hunt": "hunts",
        }
        table = table_by_artifact.get(artifact)
        if table is None:
            raise RetentionError(f"unknown retention artifact {artifact}")
        # Table names are a fixed allowlist above; hunt/owner predicates keep
        # retries scoped to exactly one retained hunt.
        with self.engine.begin() as connection:
            connection.execute(text(f"DELETE FROM {table} WHERE hunt_id=:hunt_id AND owner_id=:owner_id"), {"hunt_id": hunt_id, "owner_id": owner_id})

    def save_task_failure(self, *, task_id: str, cursor: int, error: str, now: datetime) -> None:
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE retention_cleanup_tasks SET cursor=:cursor, error=:error, updated_at_utc=:now WHERE task_id=:task_id"), {"task_id": task_id, "cursor": cursor, "error": {"message": error} if error else None, "now": now})

    def complete_task(self, *, task_id: str, now: datetime) -> None:
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE retention_cleanup_tasks SET state='completed', completed_at_utc=:now, updated_at_utc=:now WHERE task_id=:task_id"), {"task_id": task_id, "now": now})

    def audit_cleanup(self, *, hunt_id: str, owner_id: str, outcome: str, detail: str, now: datetime) -> None:
        with self.engine.begin() as connection:
            connection.execute(text("""INSERT INTO audit_records(audit_id, hunt_id, owner_id, actor_type, action, outcome, detail, timestamp_utc)
                VALUES (:audit_id,:hunt_id,:owner_id,'system','retention_cleanup',:outcome,:detail,:now)"""), {"audit_id": str(uuid4()), "hunt_id": hunt_id, "owner_id": owner_id, "outcome": outcome, "detail": detail, "now": now})


__all__ = ["ARTIFACTS", "CleanupResult", "FileStore", "HuntRetentionSnapshot", "RetentionError", "RetentionPolicy", "RetentionRepository", "RetentionService", "SqlRetentionRepository", "is_abandoned", "retention_due"]
