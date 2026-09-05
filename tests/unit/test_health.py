from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from threat_hunting.config import RuntimeSettings
from threat_hunting.health import check_readiness
from threat_hunting.main import create_app


class ReadyDatabase:
    disposed = False

    def ping(self) -> None:
        return None

    def require_current_migration(self) -> None:
        return None

    def dispose(self) -> None:
        self.disposed = True


class UnreadyDatabase(ReadyDatabase):
    def ping(self) -> None:
        from threat_hunting.db import DatabaseUnavailable

        raise DatabaseUnavailable("test failure")


def settings(tmp_path: Path) -> RuntimeSettings:
    return RuntimeSettings.model_validate(
        {
            "environment": "test",
            "image_version": "test",
            "storage": {
                "persistent_path": str(tmp_path / "persistent"),
                "temporary_path": str(tmp_path / "temporary"),
                "persistent_min_free_bytes": 1,
                "temporary_min_free_bytes": 1,
            },
            "splunk": {"url": "https://splunk.test:8089"},
            "model": {"provider": "openai", "model_name": "test"},
        }
    )


def test_liveness_does_not_require_dependencies() -> None:
    response = TestClient(create_app()).get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "live", "checks": []}


def test_readiness_passes_when_all_checks_pass(tmp_path: Path) -> None:
    database = ReadyDatabase()
    result = check_readiness(
        settings_loader=lambda: settings(tmp_path),
        database_factory=lambda _: database,  # type: ignore[arg-type]
    )
    assert result.status == "ready"
    assert all(check.status == "pass" for check in result.checks)
    assert database.disposed


def test_readiness_fails_without_database_detail_leak(tmp_path: Path) -> None:
    result = check_readiness(
        settings_loader=lambda: settings(tmp_path),
        database_factory=lambda _: UnreadyDatabase(),  # type: ignore[arg-type]
    )
    assert result.status == "not_ready"
    assert any(check.name == "postgresql" and check.status == "fail" for check in result.checks)
    assert "test failure" not in result.model_dump_json()


def test_readiness_fails_when_free_space_reserve_is_unavailable(tmp_path: Path) -> None:
    value = settings(tmp_path).model_copy(
        update={
            "storage": settings(tmp_path).storage.model_copy(
                update={"persistent_min_free_bytes": 10**30}
            )
        }
    )
    result = check_readiness(
        settings_loader=lambda: value,
        database_factory=lambda _: ReadyDatabase(),  # type: ignore[arg-type]
    )
    assert result.status == "not_ready"
    assert any(check.name == "persistent_storage" and check.status == "fail" for check in result.checks)

