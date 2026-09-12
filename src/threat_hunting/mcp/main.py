"""Fail-closed entrypoint for the optional MCP container profile.

The MCP service contract is not enabled by the direct worker path yet.  This
module therefore performs the complete startup gate and refuses to run when
the service implementation is not available.  In particular, it does not
open a socket or provide an unauthenticated fallback that could be mistaken
for an MCP service.
"""

from __future__ import annotations

import logging
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from sqlalchemy.exc import SQLAlchemyError

from threat_hunting.config import ConfigurationError, RuntimeSettings, load_database_url, read_secret_file
from threat_hunting.db import Database, DatabaseUnavailable
from threat_hunting.domain.common import is_absolute_config_path


LOGGER = logging.getLogger(__name__)

MCP_SERVICE_SUBJECT_FILE_ENV = "THREAT_HUNTING_MCP_SERVICE_SUBJECT_FILE"
MCP_TLS_CA_FILE_ENV = "THREAT_HUNTING_MCP_TLS_CA_FILE"
MCP_TLS_CLIENT_CERT_FILE_ENV = "THREAT_HUNTING_MCP_TLS_CLIENT_CERT_FILE"
MCP_TLS_CLIENT_KEY_FILE_ENV = "THREAT_HUNTING_MCP_TLS_CLIENT_KEY_FILE"
MCP_SPLUNK_TOKEN_FILE_ENV = "THREAT_HUNTING_SPLUNK_TOKEN_FILE"


class MCPStartupError(RuntimeError):
    """Raised when the optional MCP profile cannot start safely."""


@dataclass(frozen=True, slots=True)
class MCPRuntime:
    """Validated, dependency-bound MCP startup state.

    The state contains paths and the authenticated service subject only.  No
    secret value is retained after startup validation, and no listener is
    created by this object.
    """

    settings: RuntimeSettings
    database: Database
    service_subject: str
    ca_bundle_path: Path
    client_cert_path: Path
    client_key_path: Path

    def close(self) -> None:
        """Release the database connection pool owned by the runtime."""

        self.database.dispose()


def _required_path(env_name: str, *, label: str, configured: Path | None = None) -> Path:
    """Resolve and validate one file-backed secret without exposing its value."""

    raw_path = os.environ.get(env_name)
    if not raw_path:
        raise MCPStartupError(f"{env_name} must name the {label} secret file")
    path = Path(raw_path)
    if not is_absolute_config_path(path):
        raise MCPStartupError(f"{env_name} must use an absolute {label} path")
    if configured is not None and path != configured:
        raise MCPStartupError(f"{env_name} does not match the configured {label} path")
    try:
        if not path.is_file() or not path.read_bytes().strip():
            raise MCPStartupError(f"the {label} secret file is missing or empty")
    except OSError as exc:
        raise MCPStartupError(f"could not read the {label} secret file") from exc
    return path


def _validate_tls_files(ca_path: Path, cert_path: Path, key_path: Path) -> None:
    """Prove that the configured CA and client certificate can build TLS state."""

    try:
        context = ssl.create_default_context(cafile=str(ca_path))
        context.load_cert_chain(str(cert_path), str(key_path))
    except (OSError, ssl.SSLError) as exc:
        raise MCPStartupError("MCP TLS certificate configuration is invalid") from exc


def load_runtime(
    *,
    settings_loader: Callable[[], RuntimeSettings] = RuntimeSettings.load,
    database_connector: Callable[..., Database] = Database.connect,
) -> MCPRuntime:
    """Validate MCP configuration, TLS material, and current DB migrations.

    This function deliberately stops before any network listener or tool
    dispatch is created.  It is the only startup path used by :func:`run`.
    """

    try:
        settings = settings_loader()
    except ConfigurationError as exc:
        raise MCPStartupError("MCP runtime configuration is invalid") from exc

    execution = settings.execution
    if execution.mode != "mcp":
        raise MCPStartupError("MCP profile requires execution.mode=mcp")
    if not settings.tls.verify or execution.mcp_url is None or not execution.mcp_url.startswith("https://"):
        raise MCPStartupError("MCP profile requires verified HTTPS transport")
    if execution.mcp_service_subject is None:
        raise MCPStartupError("MCP profile requires a configured service subject")

    subject_path = _required_path(MCP_SERVICE_SUBJECT_FILE_ENV, label="MCP service subject")
    try:
        configured_subject = read_secret_file(subject_path, label="MCP service subject").get_secret_value()
    except ConfigurationError as exc:
        raise MCPStartupError("MCP service subject secret is invalid") from exc
    if configured_subject != execution.mcp_service_subject:
        raise MCPStartupError("MCP service subject does not match runtime configuration")

    ca_path = _required_path(MCP_TLS_CA_FILE_ENV, label="MCP TLS CA", configured=execution.mcp_ca_bundle_path)
    cert_path = _required_path(MCP_TLS_CLIENT_CERT_FILE_ENV, label="MCP TLS client certificate", configured=execution.mcp_client_cert_path)
    key_path = _required_path(MCP_TLS_CLIENT_KEY_FILE_ENV, label="MCP TLS client key", configured=execution.mcp_client_key_path)
    _validate_tls_files(ca_path, cert_path, key_path)
    _required_path(MCP_SPLUNK_TOKEN_FILE_ENV, label="Splunk token")

    database: Database | None = None
    try:
        database = database_connector(
            load_database_url(),
            connect_timeout_seconds=settings.database.connect_timeout_seconds,
        )
        database.require_current_migration()
    except (ConfigurationError, DatabaseUnavailable, SQLAlchemyError) as exc:
        if database is not None:
            database.dispose()
        raise MCPStartupError("MCP database readiness check failed") from exc

    return MCPRuntime(
        settings=settings,
        database=database,
        service_subject=configured_subject,
        ca_bundle_path=ca_path,
        client_cert_path=cert_path,
        client_key_path=key_path,
    )


def run() -> None:
    """Run the MCP profile startup gate and refuse unsafe service startup."""

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    runtime = load_runtime()
    try:
        raise MCPStartupError(
            "MCP service handlers are not enabled in this image; refusing to start without authorization enforcement"
        )
    finally:
        runtime.close()


if __name__ == "__main__":
    run()


__all__ = ["MCPRuntime", "MCPStartupError", "load_runtime", "run"]
