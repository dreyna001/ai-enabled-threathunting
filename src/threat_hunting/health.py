"""Application and worker liveness/readiness behavior."""

from __future__ import annotations

import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict

from threat_hunting.config import ConfigurationError, RuntimeSettings, load_database_url
from threat_hunting.db import Database, DatabaseUnavailable


class HealthCheck(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    status: Literal["pass", "fail"]
    detail: str | None = None


class HealthResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["live", "ready", "not_ready"]
    checks: tuple[HealthCheck, ...] = ()


def _storage_check(path: Path, reserve_bytes: int, *, name: str) -> HealthCheck:
    try:
        path.mkdir(parents=True, exist_ok=True)
        if not path.is_dir():
            return HealthCheck(name=name, status="fail", detail="configured path is not a directory")
        with tempfile.NamedTemporaryFile(prefix=".health-", dir=path, delete=True):
            pass
        free_bytes = shutil.disk_usage(path).free
    except OSError:
        return HealthCheck(name=name, status="fail", detail="configured path is not writable")
    if free_bytes < reserve_bytes:
        return HealthCheck(name=name, status="fail", detail="minimum free-space reserve is not available")
    return HealthCheck(name=name, status="pass")


def check_readiness(
    *,
    settings_loader: Callable[[], RuntimeSettings] = RuntimeSettings.load,
    database_factory: Callable[[RuntimeSettings], Database] | None = None,
) -> HealthResponse:
    """Run deterministic local readiness checks without exposing secret values."""

    checks: list[HealthCheck] = []
    try:
        settings = settings_loader()
    except ConfigurationError:
        return HealthResponse(
            status="not_ready",
            checks=(HealthCheck(name="configuration", status="fail", detail="runtime configuration is invalid"),),
        )
    checks.append(HealthCheck(name="configuration", status="pass"))

    checks.extend(
        (
            _storage_check(
                settings.storage.persistent_path,
                settings.storage.persistent_min_free_bytes,
                name="persistent_storage",
            ),
            _storage_check(
                settings.storage.temporary_path,
                settings.storage.temporary_min_free_bytes,
                name="temporary_storage",
            ),
        )
    )

    database: Database | None = None
    try:
        if database_factory is None:
            database = Database.connect(
                load_database_url(),
                connect_timeout_seconds=settings.database.connect_timeout_seconds,
            )
        else:
            database = database_factory(settings)
        database.ping()
        checks.append(HealthCheck(name="postgresql", status="pass"))
        database.require_current_migration()
        checks.append(HealthCheck(name="migrations", status="pass"))
    except (ConfigurationError, DatabaseUnavailable):
        checks.append(HealthCheck(name="postgresql", status="fail", detail="database readiness check failed"))
    finally:
        if database is not None:
            database.dispose()

    status: Literal["ready", "not_ready"] = "ready" if all(item.status == "pass" for item in checks) else "not_ready"
    return HealthResponse(status=status, checks=tuple(checks))


def worker_id_from_environment() -> str:
    """Return a bounded worker identifier suitable for heartbeat records."""

    value = os.environ.get("THREAT_HUNTING_WORKER_ID", "worker-1").strip()
    if not value or len(value) > 200:
        raise ConfigurationError("THREAT_HUNTING_WORKER_ID must contain 1 to 200 characters")
    return value

