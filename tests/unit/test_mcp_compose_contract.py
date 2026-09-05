from __future__ import annotations

from pathlib import Path

import yaml


COMPOSE_PATH = Path(__file__).parents[2] / "deploy" / "docker" / "compose.yml"


def compose_document() -> dict[str, object]:
    with COMPOSE_PATH.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    assert isinstance(value, dict)
    return value


def test_mcp_service_is_private_hardened_and_secret_backed() -> None:
    document = compose_document()
    services = document["services"]
    assert isinstance(services, dict)
    mcp = services["mcp"]
    assert isinstance(mcp, dict)
    assert mcp["profiles"] == ["mcp"]
    assert "ports" not in mcp
    assert mcp["user"] == "10001:10001"
    assert mcp["read_only"] is True
    assert mcp["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in mcp["security_opt"]
    assert set(mcp["secrets"]) >= {
        "database_url",
        "mcp_service_subject",
        "mcp_tls_ca",
        "mcp_tls_client_cert",
        "mcp_tls_client_key",
        "splunk_token",
    }

    networks = document["networks"]
    assert isinstance(networks, dict)
    assert networks["mcp_internal"]["internal"] is True
    assert "mcp_internal" in mcp["networks"]


def test_worker_keeps_direct_phase_6a_path() -> None:
    document = compose_document()
    services = document["services"]
    assert isinstance(services, dict)
    worker = services["worker"]
    assert isinstance(worker, dict)
    assert worker["command"] == ["python", "-m", "threat_hunting.worker.main"]
    assert "database_url" in worker["secrets"]
    assert "splunk_token" in worker["secrets"]


def test_default_compose_keeps_backend_private_and_persists_uploads() -> None:
    document = compose_document()
    services = document["services"]
    assert isinstance(services, dict)
    backend = services["backend"]
    worker = services["worker"]
    assert isinstance(backend, dict) and isinstance(worker, dict)
    assert "ports" not in backend
    assert backend["environment"]["THREAT_HUNTING_UPLOAD_ROOT"] == "/var/lib/threat-hunting/uploads"
    assert worker["environment"]["THREAT_HUNTING_UPLOAD_ROOT"] == "/var/lib/threat-hunting/uploads"
    assert "mcp" in services and services["mcp"]["profiles"] == ["mcp"]
