from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from threat_hunting.config import RuntimeSettings
from threat_hunting.db import DatabaseUnavailable
from threat_hunting.mcp import main


def settings_for_mcp(tmp_path: Path) -> RuntimeSettings:
    return RuntimeSettings.model_validate(
        {
            "environment": "test",
            "image_version": "test-image",
            "storage": {
                "persistent_path": str(tmp_path / "persistent"),
                "temporary_path": str(tmp_path / "temporary"),
                "persistent_min_free_bytes": 1,
                "temporary_min_free_bytes": 1,
            },
            "splunk": {"url": "https://splunk.test:8089"},
            "model": {"provider": "openai", "model_name": "test-model"},
            "execution": {
                "mode": "mcp",
                "deployment_scope_id": "customer-a",
                "mcp_url": "https://mcp.internal:8443",
                "mcp_ca_bundle_path": str(tmp_path / "ca.pem"),
                "mcp_client_cert_path": str(tmp_path / "client.pem"),
                "mcp_client_key_path": str(tmp_path / "client-key.pem"),
                "mcp_service_subject": "worker/customer-a",
                "provider_data_handling_approval_ref": "approval-test",
            },
        }
    )


class FakeDatabase:
    def __init__(self, *, migration_error: BaseException | None = None) -> None:
        self.migration_error = migration_error
        self.closed = False

    def require_current_migration(self) -> None:
        if self.migration_error is not None:
            raise self.migration_error

    def dispose(self) -> None:
        self.closed = True


def set_required_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    subject = tmp_path / "subject"
    ca = tmp_path / "ca.pem"
    cert = tmp_path / "client.pem"
    key = tmp_path / "client-key.pem"
    splunk = tmp_path / "splunk-token"
    subject.write_text("worker/customer-a\n", encoding="utf-8")
    for path in (ca, cert, key, splunk):
        path.write_text("test-secret\n", encoding="utf-8")
    monkeypatch.setenv(main.MCP_SERVICE_SUBJECT_FILE_ENV, str(subject))
    monkeypatch.setenv(main.MCP_TLS_CA_FILE_ENV, str(ca))
    monkeypatch.setenv(main.MCP_TLS_CLIENT_CERT_FILE_ENV, str(cert))
    monkeypatch.setenv(main.MCP_TLS_CLIENT_KEY_FILE_ENV, str(key))
    monkeypatch.setenv(main.MCP_SPLUNK_TOKEN_FILE_ENV, str(splunk))


def test_mcp_profile_rejects_direct_mode_before_reading_secrets(tmp_path: Path) -> None:
    settings = RuntimeSettings.model_validate(
        {
            "environment": "test",
            "image_version": "test-image",
            "storage": {
                "persistent_path": str(tmp_path / "persistent"),
                "temporary_path": str(tmp_path / "temporary"),
                "persistent_min_free_bytes": 1,
                "temporary_min_free_bytes": 1,
            },
            "splunk": {"url": "https://splunk.test:8089"},
            "model": {"provider": "openai", "model_name": "test-model"},
            "execution": {"provider_data_handling_approval_ref": "approval-test"},
        }
    )

    with pytest.raises(main.MCPStartupError, match="execution.mode=mcp"):
        main.load_runtime(settings_loader=lambda: settings)


def test_mcp_profile_requires_secret_backed_tls_and_subject(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    settings = settings_for_mcp(tmp_path)

    with pytest.raises(main.MCPStartupError, match="MCP service subject"):
        main.load_runtime(settings_loader=lambda: settings)

    set_required_files(monkeypatch, tmp_path)
    monkeypatch.setenv(main.MCP_TLS_CA_FILE_ENV, "relative-ca.pem")
    with pytest.raises(main.MCPStartupError, match="absolute"):
        main.load_runtime(settings_loader=lambda: settings)

    monkeypatch.setenv(main.MCP_TLS_CA_FILE_ENV, str(tmp_path / "ca.pem"))
    (tmp_path / "subject").write_text("different-subject\n", encoding="utf-8")
    with pytest.raises(main.MCPStartupError, match="does not match"):
        main.load_runtime(settings_loader=lambda: settings)


def test_mcp_profile_validates_dependencies_without_starting_listener(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    settings = settings_for_mcp(tmp_path)
    set_required_files(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_validate_tls_files", lambda *_paths: None)
    database = FakeDatabase()
    monkeypatch.setattr(main, "load_database_url", lambda: SecretStr("postgresql://test"))

    runtime = main.load_runtime(
        settings_loader=lambda: settings,
        database_connector=lambda *_args, **_kwargs: database,  # type: ignore[arg-type]
    )

    assert runtime.service_subject == "worker/customer-a"
    assert runtime.ca_bundle_path == tmp_path / "ca.pem"
    assert not database.closed
    runtime.close()
    assert database.closed


def test_run_refuses_to_start_without_authorized_handlers(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    database = FakeDatabase()
    runtime = main.MCPRuntime(
        settings=settings_for_mcp(tmp_path),
        database=database,  # type: ignore[arg-type]
        service_subject="worker/customer-a",
        ca_bundle_path=tmp_path / "ca.pem",
        client_cert_path=tmp_path / "client.pem",
        client_key_path=tmp_path / "client-key.pem",
    )
    monkeypatch.setattr(main, "load_runtime", lambda: runtime)

    with pytest.raises(main.MCPStartupError, match="handlers are not enabled"):
        main.run()

    assert database.closed


def test_mcp_profile_fails_closed_when_database_migrations_are_stale(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    settings = settings_for_mcp(tmp_path)
    set_required_files(monkeypatch, tmp_path)
    monkeypatch.setattr(main, "_validate_tls_files", lambda *_paths: None)
    monkeypatch.setattr(main, "load_database_url", lambda: SecretStr("postgresql://test"))
    database = FakeDatabase(migration_error=DatabaseUnavailable("stale migration"))

    with pytest.raises(main.MCPStartupError, match="database readiness"):
        main.load_runtime(
            settings_loader=lambda: settings,
            database_connector=lambda *_args, **_kwargs: database,  # type: ignore[arg-type]
        )

    assert database.closed
