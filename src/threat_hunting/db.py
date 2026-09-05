"""PostgreSQL connection and migration-readiness checks."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import SecretStr
from sqlalchemy import Engine, create_engine, text
from sqlalchemy.exc import SQLAlchemyError

MIGRATION_HEAD = "0012_security_hardening"
MAX_AUDIT_METADATA_BYTES = 32_768


class DatabaseUnavailable(RuntimeError):
    """Raised when PostgreSQL cannot satisfy a readiness operation."""


def action_digest(action: Mapping[str, Any]) -> str:
    """Return a stable SHA-256 digest for a normalized MCP action envelope.

    Only this digest belongs in the MCP request ledger.  Callers should pass
    the normalized, allow-listed action envelope rather than raw provider
    payloads; this function never returns or stores the envelope itself.
    """

    try:
        encoded = json.dumps(action, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("MCP action must be JSON-serializable") from exc
    return hashlib.sha256(encoded).hexdigest()


def safe_action_digest(action: Mapping[str, Any]) -> str:
    """Alias for :func:`action_digest` used by persistence callers."""

    return action_digest(action)


def deterministic_sid(request_id: str) -> str:
    """Derive a stable opaque SID from the application-assigned request ID."""

    if not request_id or len(request_id) > 128:
        raise ValueError("request_id must contain 1 to 128 characters")
    return hashlib.sha256(f"mcp:sid:{request_id}".encode("utf-8")).hexdigest()


def bounded_audit_metadata(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Validate and normalize nullable audit metadata within its size bound."""

    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("audit metadata must be a JSON object or null")
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("audit metadata must be JSON-serializable") from exc
    if len(encoded) > MAX_AUDIT_METADATA_BYTES:
        raise ValueError("audit metadata exceeds the 32768-byte limit")
    return json.loads(encoded)


@dataclass(slots=True)
class Database:
    """Small owner for the application's SQLAlchemy engine."""

    engine: Engine

    @classmethod
    def connect(cls, url: SecretStr, *, connect_timeout_seconds: int) -> "Database":
        engine = create_engine(
            url.get_secret_value(),
            pool_pre_ping=True,
            connect_args={"connect_timeout": connect_timeout_seconds},
        )
        return cls(engine=engine)

    def ping(self) -> None:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError as exc:
            raise DatabaseUnavailable("PostgreSQL connectivity check failed") from exc

    def current_migration(self) -> str | None:
        try:
            with self.engine.connect() as connection:
                return connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one_or_none()
        except SQLAlchemyError as exc:
            raise DatabaseUnavailable("could not read the database migration revision") from exc

    def require_current_migration(self) -> None:
        current = self.current_migration()
        if current != MIGRATION_HEAD:
            raise DatabaseUnavailable("database migrations are not current")

    def publish_worker_heartbeat(self, worker_id: str) -> None:
        statement = text(
            """
            INSERT INTO worker_heartbeats (worker_id, heartbeat_at)
            VALUES (:worker_id, CURRENT_TIMESTAMP)
            ON CONFLICT (worker_id)
            DO UPDATE SET heartbeat_at = EXCLUDED.heartbeat_at
            """
        )
        try:
            with self.engine.begin() as connection:
                connection.execute(statement, {"worker_id": worker_id})
        except SQLAlchemyError as exc:
            raise DatabaseUnavailable("worker heartbeat write failed") from exc

    def dispose(self) -> None:
        self.engine.dispose()
