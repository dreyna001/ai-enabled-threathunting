"""Typed runtime configuration loaded from YAML and separate secret files."""

from __future__ import annotations

import os
from datetime import time
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, PositiveInt, SecretStr, field_validator, model_validator


CONFIG_ENV = "THREAT_HUNTING_CONFIG"
DATABASE_URL_FILE_ENV = "THREAT_HUNTING_DATABASE_URL_FILE"


class ConfigurationError(RuntimeError):
    """Raised when runtime configuration or a required secret is invalid."""


class StrictModel(BaseModel):
    """Base for configuration sections that reject misspelled or unknown keys."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class StorageSettings(StrictModel):
    persistent_path: Path
    temporary_path: Path
    persistent_min_free_bytes: PositiveInt = 1_073_741_824
    temporary_min_free_bytes: PositiveInt = 2_147_483_648

    @field_validator("persistent_path", "temporary_path")
    @classmethod
    def path_must_be_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            raise ValueError("storage paths must be absolute")
        return value

    @model_validator(mode="after")
    def paths_must_differ(self) -> "StorageSettings":
        if self.persistent_path == self.temporary_path:
            raise ValueError("persistent and temporary storage paths must differ")
        return self


class DatabaseSettings(StrictModel):
    connect_timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 5


class TlsSettings(StrictModel):
    verify: bool = True
    ca_bundle_path: Path | None = None
    lab_only_allow_insecure: bool = False

    @model_validator(mode="after")
    def insecure_mode_requires_explicit_lab_flag(self) -> "TlsSettings":
        if not self.verify and not self.lab_only_allow_insecure:
            raise ValueError("TLS verification can be disabled only with lab_only_allow_insecure=true")
        if self.ca_bundle_path is not None and not self.ca_bundle_path.is_absolute():
            raise ValueError("ca_bundle_path must be absolute")
        return self


class ModelSettings(StrictModel):
    provider: Literal["openai", "bedrock", "litellm"]
    model_name: str = Field(min_length=1, max_length=200)
    endpoint: str | None = None


class SplunkSettings(StrictModel):
    url: str = Field(min_length=1)
    app_namespace: str = Field(default="search", min_length=1, max_length=100)


class HuntLimitSettings(StrictModel):
    query_start_cutoff_utc: time = time(hour=20)
    hard_completion_minutes: PositiveInt = 12
    agent_cycles: PositiveInt = 8
    query_count: PositiveInt = 12
    per_hunt_query_concurrency: PositiveInt = 2
    search_job_timeout_seconds: PositiveInt = 120
    splunk_transport_timeout_seconds: PositiveInt = 30
    active_hunts_per_deployment: PositiveInt = 1
    deployment_query_concurrency: PositiveInt = 2
    per_query_row_limit: PositiveInt = 10_000
    per_query_byte_limit: PositiveInt = 262_144_000
    per_hunt_row_limit: PositiveInt = 50_000
    per_hunt_byte_limit: PositiveInt = 1_073_741_824
    representative_event_limit: PositiveInt = 100
    targeted_event_limit: PositiveInt = 500
    model_calls: PositiveInt = 12
    model_call_timeout_seconds: PositiveInt = 120
    context_characters: PositiveInt = 500_000
    input_tokens: PositiveInt = 500_000
    output_tokens: PositiveInt = 96_000

    @model_validator(mode="after")
    def validate_limit_relationships(self) -> "HuntLimitSettings":
        if self.per_hunt_query_concurrency > self.deployment_query_concurrency:
            raise ValueError("per-hunt query concurrency cannot exceed deployment concurrency")
        if self.per_query_row_limit > self.per_hunt_row_limit:
            raise ValueError("per-query row limit cannot exceed per-hunt row limit")
        if self.per_query_byte_limit > self.per_hunt_byte_limit:
            raise ValueError("per-query byte limit cannot exceed per-hunt byte limit")
        if self.representative_event_limit > self.per_query_row_limit:
            raise ValueError("representative event limit cannot exceed per-query row limit")
        if self.targeted_event_limit > self.per_query_row_limit:
            raise ValueError("targeted event limit cannot exceed per-query row limit")
        return self


class RetentionSettings(StrictModel):
    hunt_days: PositiveInt = 90
    temporary_result_hours: PositiveInt = 24


class UploadSettings(StrictModel):
    file_count: PositiveInt = 10
    per_file_bytes: PositiveInt = 26_214_400
    total_bytes: PositiveInt = 104_857_600
    extracted_text_characters: PositiveInt = 500_000

    @model_validator(mode="after")
    def total_must_fit_one_file(self) -> "UploadSettings":
        if self.total_bytes < self.per_file_bytes:
            raise ValueError("total upload limit cannot be smaller than the per-file limit")
        return self


class ReportSettings(StrictModel):
    display_timezone: str = "UTC"
    input_characters: PositiveInt = 750_000
    evidence_excerpt_characters: PositiveInt = 4_000
    page_count: PositiveInt = 100
    render_timeout_seconds: PositiveInt = 120

    @field_validator("display_timezone")
    @classmethod
    def timezone_must_exist(cls, value: str) -> str:
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("display_timezone must be a valid IANA timezone") from exc
        return value


class ExecutionSettings(StrictModel):
    """Non-secret settings that bind execution to one deployment scope.

    Direct execution remains the default for the Phase 6A rollout.  MCP
    settings are deliberately kept in the same immutable configuration object
    so switching modes cannot silently select a different scope or provider.
    """

    mode: Literal["direct", "mcp"] = "direct"
    deployment_scope_id: str = Field(default="default", min_length=1, max_length=200)
    mcp_url: str | None = None
    mcp_ca_bundle_path: Path | None = None
    mcp_client_cert_path: Path | None = None
    mcp_client_key_path: Path | None = None
    mcp_service_subject: str | None = Field(default=None, min_length=1, max_length=200)
    provider_data_handling_approval_ref: str | None = Field(default=None, min_length=1, max_length=500)

    @model_validator(mode="before")
    @classmethod
    def normalize_mcp_settings(cls, value: object) -> object:
        """Accept the flat deployment format and its equivalent ``mcp`` block.

        Runtime YAML has historically used small top-level sections.  The
        normal form remains flat, while accepting a nested MCP block keeps
        operator configuration readable without weakening unknown-key checks.
        """

        if not isinstance(value, dict):
            return value
        normalized = dict(value)
        flat_aliases = {
            "mcp_tls_ca_path": "mcp_ca_bundle_path",
            "mcp_tls_client_cert_path": "mcp_client_cert_path",
            "mcp_tls_client_key_path": "mcp_client_key_path",
            "mcp_ca_path": "mcp_ca_bundle_path",
            "mcp_service_identity": "mcp_service_subject",
            "provider_approval_ref": "provider_data_handling_approval_ref",
        }
        for source, target in flat_aliases.items():
            if source in normalized:
                if target in normalized and normalized[target] != normalized[source]:
                    raise ValueError(f"conflicting execution MCP setting: {target}")
                normalized[target] = normalized.pop(source)
        nested = normalized.pop("mcp", None)
        if nested is None:
            return normalized
        if not isinstance(nested, dict):
            raise ValueError("execution.mcp must be a YAML mapping")
        aliases = {
            "url": "mcp_url",
            "ca_bundle_path": "mcp_ca_bundle_path",
            "tls_ca_path": "mcp_ca_bundle_path",
            "client_cert_path": "mcp_client_cert_path",
            "tls_client_cert_path": "mcp_client_cert_path",
            "client_key_path": "mcp_client_key_path",
            "tls_client_key_path": "mcp_client_key_path",
            "service_subject": "mcp_service_subject",
        }
        for key, nested_value in nested.items():
            target = aliases.get(key, key)
            if target in normalized and normalized[target] != nested_value:
                raise ValueError(f"conflicting execution MCP setting: {target}")
            normalized[target] = nested_value
        return normalized

    @field_validator("mcp_url")
    @classmethod
    def mcp_url_must_be_absolute(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("mcp_url must be an absolute HTTP(S) URL")
        return value

    @field_validator("deployment_scope_id", "mcp_service_subject", "provider_data_handling_approval_ref")
    @classmethod
    def mcp_binding_strings_must_not_be_blank(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("MCP binding values must not be blank")
        return value

    @field_validator("mcp_ca_bundle_path", "mcp_client_cert_path", "mcp_client_key_path")
    @classmethod
    def mcp_tls_paths_must_be_absolute(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("MCP TLS certificate paths must be absolute")
        return value

    @model_validator(mode="after")
    def mcp_settings_must_be_complete(self) -> "ExecutionSettings":
        if self.mode != "mcp":
            return self
        required = {
            "mcp_url": self.mcp_url,
            "mcp_ca_bundle_path": self.mcp_ca_bundle_path,
            "mcp_client_cert_path": self.mcp_client_cert_path,
            "mcp_client_key_path": self.mcp_client_key_path,
            "mcp_service_subject": self.mcp_service_subject,
            "provider_data_handling_approval_ref": self.provider_data_handling_approval_ref,
        }
        missing = ", ".join(name for name, item in required.items() if item in (None, ""))
        if missing:
            raise ValueError(f"MCP execution configuration is incomplete: {missing}")
        return self

    @property
    def mcp_tls_ca_path(self) -> Path | None:
        """Compatibility name for the MCP CA bundle path."""

        return self.mcp_ca_bundle_path

    @property
    def mcp_tls_client_cert_path(self) -> Path | None:
        """Compatibility name for the MCP client certificate path."""

        return self.mcp_client_cert_path

    @property
    def mcp_tls_client_key_path(self) -> Path | None:
        """Compatibility name for the MCP client key path."""

        return self.mcp_client_key_path


class RuntimeSettings(StrictModel):
    environment: Literal["development", "test", "lab", "production"] = "production"
    image_version: str = Field(min_length=1, max_length=200)
    execution: ExecutionSettings = Field(default_factory=ExecutionSettings)
    database: DatabaseSettings = DatabaseSettings()
    storage: StorageSettings
    tls: TlsSettings = TlsSettings()
    splunk: SplunkSettings
    model: ModelSettings
    hunt_limits: HuntLimitSettings = HuntLimitSettings()
    retention: RetentionSettings = RetentionSettings()
    uploads: UploadSettings = UploadSettings()
    reports: ReportSettings = ReportSettings()

    @model_validator(mode="before")
    @classmethod
    def normalize_top_level_mcp_settings(cls, value: object) -> object:
        """Fold a legacy top-level MCP block into the execution contract."""

        if not isinstance(value, dict) or "mcp" not in value:
            return value
        normalized = dict(value)
        top_level_mcp = normalized.pop("mcp")
        execution = normalized.get("execution", {})
        if execution is None:
            execution = {}
        if not isinstance(execution, dict):
            raise ValueError("execution must be a YAML mapping")
        execution = dict(execution)
        if "mcp" in execution and execution["mcp"] != top_level_mcp:
            raise ValueError("conflicting top-level and execution MCP settings")
        execution["mcp"] = top_level_mcp
        normalized["execution"] = execution
        return normalized

    @model_validator(mode="after")
    def production_cannot_disable_tls(self) -> "RuntimeSettings":
        if self.environment == "production" and not self.tls.verify:
            raise ValueError("TLS verification cannot be disabled in production")
        if self.environment == "production" and self.execution.mode == "mcp":
            if self.execution.mcp_url is None or not self.execution.mcp_url.startswith("https://"):
                raise ValueError("production MCP execution requires an HTTPS mcp_url")
            if not self.tls.verify:
                raise ValueError("production MCP execution requires TLS verification")
        return self

    @classmethod
    def from_yaml(cls, path: Path) -> "RuntimeSettings":
        """Load strict non-secret settings from a YAML file."""

        if not path.is_file():
            raise ConfigurationError(f"runtime configuration file does not exist: {path}")
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, yaml.YAMLError) as exc:
            raise ConfigurationError(f"could not read runtime configuration: {path}") from exc
        if not isinstance(raw, dict):
            raise ConfigurationError("runtime configuration must be a YAML mapping")
        try:
            return cls.model_validate(raw)
        except ValueError as exc:
            raise ConfigurationError("runtime configuration failed validation") from exc

    @classmethod
    def load(cls) -> "RuntimeSettings":
        """Load settings using the required configuration path environment contract."""

        raw_path = os.environ.get(CONFIG_ENV)
        if not raw_path:
            raise ConfigurationError(f"{CONFIG_ENV} must name the runtime YAML file")
        return cls.from_yaml(Path(raw_path))


def read_secret_file(path: Path, *, label: str) -> SecretStr:
    """Read one non-empty secret without returning its content in errors."""

    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise ConfigurationError(f"could not read required secret file for {label}") from exc
    if not value:
        raise ConfigurationError(f"required secret file for {label} is empty")
    return SecretStr(value)


def load_database_url() -> SecretStr:
    """Load the database URL from the configured secret file."""

    raw_path = os.environ.get(DATABASE_URL_FILE_ENV)
    if not raw_path:
        raise ConfigurationError(f"{DATABASE_URL_FILE_ENV} must name the database URL secret file")
    return read_secret_file(Path(raw_path), label="database URL")
