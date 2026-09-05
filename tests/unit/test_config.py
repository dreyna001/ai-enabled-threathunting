from __future__ import annotations

from pathlib import Path

import pytest

from threat_hunting.config import ConfigurationError, RuntimeSettings, load_database_url


def valid_config(tmp_path: Path) -> dict[str, object]:
    return {
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
    }


def test_settings_accept_valid_minimal_configuration(tmp_path: Path) -> None:
    settings = RuntimeSettings.model_validate(valid_config(tmp_path))
    assert settings.reports.display_timezone == "UTC"
    assert settings.hunt_limits.query_start_cutoff_utc.hour == 20
    assert settings.hunt_limits.hard_completion_minutes == 12
    assert settings.hunt_limits.agent_cycles == 8
    assert settings.hunt_limits.query_count == 12
    assert settings.hunt_limits.per_hunt_query_concurrency == 2
    assert settings.hunt_limits.active_hunts_per_deployment == 1
    assert settings.hunt_limits.deployment_query_concurrency == 2
    assert settings.hunt_limits.per_query_row_limit == 10_000
    assert settings.hunt_limits.per_query_byte_limit == 250 * 1024 * 1024
    assert settings.hunt_limits.per_hunt_row_limit == 50_000
    assert settings.hunt_limits.per_hunt_byte_limit == 1024 * 1024 * 1024
    assert settings.hunt_limits.representative_event_limit == 100
    assert settings.hunt_limits.targeted_event_limit == 500
    assert settings.hunt_limits.model_calls == 12
    assert settings.hunt_limits.input_tokens == 500_000
    assert settings.hunt_limits.output_tokens == 96_000
    assert settings.execution.mode == "direct"
    assert settings.execution.deployment_scope_id == "default"


def test_settings_reject_unknown_keys(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["unexpected"] = True
    with pytest.raises(ValueError):
        RuntimeSettings.model_validate(value)


def test_settings_reject_insecure_production_tls(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["environment"] = "production"
    value["tls"] = {"verify": False, "lab_only_allow_insecure": True}
    with pytest.raises(ValueError):
        RuntimeSettings.model_validate(value)


def test_settings_reject_invalid_limit_relationship(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["hunt_limits"] = {"per_query_row_limit": 101, "per_hunt_row_limit": 100}
    with pytest.raises(ValueError):
        RuntimeSettings.model_validate(value)


def test_production_mcp_requires_complete_tls_and_provider_binding(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value.update(
        {
            "environment": "production",
            "execution": {
                "mode": "mcp",
                "deployment_scope_id": "customer-a",
                "mcp_url": "https://mcp.internal:8443",
                "mcp_ca_bundle_path": str(tmp_path / "ca.pem"),
                "mcp_client_cert_path": str(tmp_path / "client.pem"),
                "mcp_client_key_path": str(tmp_path / "client-key.pem"),
                "mcp_service_subject": "worker/customer-a",
                "provider_data_handling_approval_ref": "approval-2026-01",
            },
        }
    )
    settings = RuntimeSettings.model_validate(value)
    assert settings.execution.mode == "mcp"
    assert settings.execution.mcp_tls_ca_path == tmp_path / "ca.pem"


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("deployment_scope_id", None),
        ("mcp_url", None),
        ("mcp_ca_bundle_path", None),
        ("mcp_client_cert_path", None),
        ("mcp_client_key_path", None),
        ("mcp_service_subject", None),
        ("provider_data_handling_approval_ref", None),
    ],
)
def test_mcp_rejects_incomplete_configuration(tmp_path: Path, field: str, replacement: object) -> None:
    value = valid_config(tmp_path)
    value["execution"] = {
        "mode": "mcp",
        "deployment_scope_id": "customer-a",
        "mcp_url": "https://mcp.internal:8443",
        "mcp_ca_bundle_path": str(tmp_path / "ca.pem"),
        "mcp_client_cert_path": str(tmp_path / "client.pem"),
        "mcp_client_key_path": str(tmp_path / "client-key.pem"),
        "mcp_service_subject": "worker/customer-a",
        "provider_data_handling_approval_ref": "approval-2026-01",
    }
    value["execution"][field] = replacement  # type: ignore[index]
    with pytest.raises(ValueError):
        RuntimeSettings.model_validate(value)


def test_production_mcp_rejects_insecure_endpoint(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value.update(
        {
            "environment": "production",
            "execution": {
                "mode": "mcp",
                "deployment_scope_id": "customer-a",
                "mcp_url": "http://mcp.internal:8080",
                "mcp_ca_bundle_path": str(tmp_path / "ca.pem"),
                "mcp_client_cert_path": str(tmp_path / "client.pem"),
                "mcp_client_key_path": str(tmp_path / "client-key.pem"),
                "mcp_service_subject": "worker/customer-a",
                "provider_data_handling_approval_ref": "approval-2026-01",
            },
        }
    )
    with pytest.raises(ValueError, match="HTTPS"):
        RuntimeSettings.model_validate(value)


def test_from_yaml_rejects_non_mapping(tmp_path: Path) -> None:
    path = tmp_path / "runtime.yml"
    path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="YAML mapping"):
        RuntimeSettings.from_yaml(path)


def test_database_secret_is_loaded_from_file_without_exposure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_path = tmp_path / "database_url"
    secret_path.write_text("postgresql+psycopg://user:sensitive@example/test\n", encoding="utf-8")
    monkeypatch.setenv("THREAT_HUNTING_DATABASE_URL_FILE", str(secret_path))
    value = load_database_url()
    assert value.get_secret_value().endswith("/test")
    assert "sensitive" not in str(value)


def test_empty_database_secret_fails_without_secret_content(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    secret_path = tmp_path / "database_url"
    secret_path.write_text("\n", encoding="utf-8")
    monkeypatch.setenv("THREAT_HUNTING_DATABASE_URL_FILE", str(secret_path))
    with pytest.raises(ConfigurationError, match="empty"):
        load_database_url()
