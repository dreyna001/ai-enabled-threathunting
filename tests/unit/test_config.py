from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import create_engine

from threat_hunting.config import ConfigurationError, RuntimeSettings, load_database_url
from threat_hunting.domain.common import is_absolute_config_path
from threat_hunting.services import runtime


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
        "execution": {"provider_data_handling_approval_ref": "approval-test"},
    }


def test_settings_accept_valid_minimal_configuration(tmp_path: Path) -> None:
    settings = RuntimeSettings.model_validate(valid_config(tmp_path))
    assert settings.reports.display_timezone == "UTC"
    assert settings.hunt_limits.query_start_cutoff_utc.hour == 20
    assert settings.hunt_limits.hard_completion_minutes == 20
    assert settings.hunt_limits.agent_cycles == 8
    assert settings.hunt_limits.query_count == 50
    assert settings.hunt_limits.per_hunt_query_concurrency == 2
    assert settings.hunt_limits.active_hunts_per_deployment == 1
    assert settings.hunt_limits.deployment_query_concurrency == 2
    assert settings.hunt_limits.per_query_row_limit == 10_000
    assert settings.hunt_limits.per_query_byte_limit == 250 * 1024 * 1024
    assert settings.hunt_limits.per_hunt_row_limit == 50_000
    assert settings.hunt_limits.per_hunt_byte_limit == 1024 * 1024 * 1024
    assert settings.hunt_limits.representative_event_limit == 500
    assert settings.hunt_limits.targeted_event_limit == 500
    assert settings.hunt_limits.model_calls == 12
    assert settings.hunt_limits.input_tokens == 500_000
    assert settings.hunt_limits.output_tokens == 96_000
    assert settings.hunt_limits.output_tokens_per_call == 8_000
    assert settings.execution.mode == "direct"
    assert settings.execution.deployment_scope_id == "default"


def test_settings_reject_unknown_keys(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["unexpected"] = True
    with pytest.raises(ValueError):
        RuntimeSettings.model_validate(value)


@pytest.mark.parametrize("minutes,model_seconds,expected", [
    (20, 300, (1200, 780, 120, 300)),
    (20, 120, (1200, 960, 120, 120)),
    (12, 300, (720, 300, 120, 300)),
    (1, 300, (60, 1, 1, 58)),
])
def test_hunt_time_reserves_follow_runtime_settings(tmp_path: Path, minutes: int, model_seconds: int, expected: tuple[int, ...]) -> None:
    value = valid_config(tmp_path)
    value["hunt_limits"] = {"hard_completion_minutes": minutes, "model_call_timeout_seconds": model_seconds}
    limits = runtime.budget_limits_from_settings(RuntimeSettings.model_validate(value))
    assert (limits.hard_hunt_seconds, limits.query_start_cutoff_seconds,
            limits.max_inflight_query_seconds_after_cutoff, limits.synthesis_allowance_seconds) == expected
    assert limits.max_model_call_timeout_seconds == model_seconds
    assert limits.max_model_calls == 12


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/var/lib/threat-hunting", True),
        ("/tmp/missing-ca.pem", True),
        ("tmp/missing-ca.pem", False),
        ("./secrets/ca.pem", False),
    ],
)
def test_absolute_config_path_accepts_posix_and_rejects_relative(path: str, expected: bool) -> None:
    assert is_absolute_config_path(Path(path)) is expected
    if expected:
        assert is_absolute_config_path(path) is True


def test_settings_reject_relative_storage_paths(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["storage"]["persistent_path"] = "relative/persistent"
    with pytest.raises(ValueError, match="storage paths must be absolute"):
        RuntimeSettings.model_validate(value)


def test_shipped_runtime_uses_twenty_minutes_and_five_minute_model_calls() -> None:
    settings = RuntimeSettings.from_yaml(Path("deploy/docker/config/runtime.yml"))
    limits = runtime.budget_limits_from_settings(settings)
    assert limits.hard_hunt_seconds == 1200
    assert limits.query_start_cutoff_seconds == 780
    assert limits.max_splunk_queries == 50
    assert limits.max_model_call_timeout_seconds == limits.synthesis_allowance_seconds == 300


def test_configured_per_call_model_budget_reaches_runtime(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["hunt_limits"] = {"output_tokens_per_call": 24000}
    settings = RuntimeSettings.model_validate(value)
    limits = runtime.budget_limits_from_settings(settings)
    assert limits.max_model_output_tokens_per_call == 24000
    assert limits.max_model_output_tokens == 96000


@pytest.mark.parametrize("limit", [0, -1, 96001])
def test_invalid_per_call_model_budget_is_rejected(tmp_path: Path, limit: int) -> None:
    value = valid_config(tmp_path)
    value["hunt_limits"] = {"output_tokens_per_call": limit}
    with pytest.raises(ValueError):
        RuntimeSettings.model_validate(value)


def test_external_provider_requires_data_handling_approval(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["execution"] = {}

    with pytest.raises(ValueError, match="provider_data_handling_approval_ref"):
        RuntimeSettings.model_validate(value)


def test_explicit_local_litellm_provider_does_not_require_external_approval(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["model"] = {
        "provider": "litellm",
        "model_name": "local-model",
        "endpoint": "https://model.internal/v1",
        "data_boundary": "local",
    }
    value["execution"] = {}

    settings = RuntimeSettings.model_validate(value)

    assert settings.model.data_boundary == "local"
    assert settings.execution.provider_data_handling_approval_ref is None


def test_local_boundary_rejects_external_provider_kind(tmp_path: Path) -> None:
    value = valid_config(tmp_path)
    value["model"] = {
        "provider": "openai",
        "model_name": "test-model",
        "data_boundary": "local",
    }

    with pytest.raises(ValueError, match="local model data boundary"):
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


def test_production_service_uses_configured_upload_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    value = valid_config(tmp_path)
    value["uploads"] = {"per_file_bytes": 10, "file_count": 2, "total_bytes": 20, "extracted_text_characters": 30}
    settings = RuntimeSettings.model_validate(value)
    monkeypatch.setattr(
        runtime,
        "build_production_adapters",
        lambda _settings: (object(), object()),
    )
    service = runtime.build_production_service(create_engine("sqlite+pysqlite://"), settings)

    assert service.upload_limits.per_file_bytes == 10
    assert service.upload_limits.file_count == 2
    assert service.upload_limits.total_bytes == 20
    assert service.upload_limits.extracted_text_characters == 30
    assert service.execution_config["provider_data_boundary"] == "external"
    assert service.execution_config["provider_data_handling_approval_ref"] == "approval-test"
