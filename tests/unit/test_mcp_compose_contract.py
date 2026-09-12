from __future__ import annotations

import re
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).parents[2]
COMPOSE_PATH = REPO_ROOT / "deploy" / "docker" / "compose.yml"
NGINX_PATH = REPO_ROOT / "deploy" / "docker" / "nginx.conf"
ENV_EXAMPLE_PATH = REPO_ROOT / ".env.example"
BACKEND_DOCKERFILE_PATH = REPO_ROOT / "deploy" / "docker" / "Dockerfile.backend"
FRONTEND_DOCKERFILE_PATH = REPO_ROOT / "deploy" / "docker" / "Dockerfile.frontend"
VERIFY_WORKFLOW_PATH = REPO_ROOT / ".github" / "workflows" / "verify.yml"

PINNED_IMAGE_REFS = {
    "node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32",
    "python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254",
    "nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0",
    "ghcr.io/astral-sh/uv:0.12.10@sha256:2bb3ebca0a796a155094a27773d290c4b074572e6107f171d88d086682fd2500",
    "postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685",
}

FROM_IMAGE_PATTERN = re.compile(r"^FROM (?P<image>[^\s]+)")
COPY_FROM_IMAGE_PATTERN = re.compile(r"^COPY --from=(?P<image>[^\s]+)")
VERIFY_POSTGRES_IMAGE_PATTERN = re.compile(
    r"^\s+image:\s+(?P<image>postgres:[^\s]+)\s*$"
)


def compose_document() -> dict[str, object]:
    with COMPOSE_PATH.open(encoding="utf-8") as stream:
        value = yaml.safe_load(stream)
    assert isinstance(value, dict)
    return value


def env_example() -> dict[str, str]:
    return {
        key: value
        for line in ENV_EXAMPLE_PATH.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
        for key, value in [line.split("=", 1)]
    }


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
    assert backend["environment"]["THREAT_HUNTING_SPLUNK_TOKEN_FILE"] == "/run/secrets/splunk_token"
    assert backend["environment"]["THREAT_HUNTING_MODEL_API_KEY_FILE"] == "/run/secrets/model_api_key"
    assert worker["environment"]["THREAT_HUNTING_MODEL_API_KEY_FILE"] == "/run/secrets/model_api_key"
    assert {"database_url", "splunk_token", "model_api_key"} <= set(backend["secrets"])
    assert {"database_url", "splunk_token", "model_api_key"} <= set(worker["secrets"])
    assert "mcp" in services and services["mcp"]["profiles"] == ["mcp"]


def test_frontend_defaults_to_loopback_and_accepts_allowed_upload_size() -> None:
    document = compose_document()
    services = document["services"]
    assert isinstance(services, dict)
    frontend = services["frontend"]
    assert isinstance(frontend, dict)
    assert frontend["ports"] == [
        "${THREAT_HUNTING_FRONTEND_BIND:-127.0.0.1}:${THREAT_HUNTING_FRONTEND_PORT:-8080}:8080"
    ]
    assert "client_max_body_size 25m;" in NGINX_PATH.read_text(encoding="utf-8")


def test_root_env_example_paths_resolve_from_compose_directory() -> None:
    values = env_example()
    assert values["THREAT_HUNTING_CONFIG_FILE"] == "./config/runtime.yml"
    assert values["THREAT_HUNTING_DATABASE_URL_FILE"] == "../../runtime/secrets/database_url"
    assert values["THREAT_HUNTING_POSTGRES_PASSWORD_FILE"] == "../../runtime/secrets/postgres_password"
    assert values["THREAT_HUNTING_SPLUNK_TOKEN_FILE"] == "../../runtime/secrets/splunk_token"
    assert values["THREAT_HUNTING_MODEL_API_KEY_FILE"] == "../../runtime/secrets/model_api_key"


def _dockerfile_image_refs(path: Path) -> list[str]:
    refs: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if match := FROM_IMAGE_PATTERN.match(line):
            refs.append(match.group("image"))
        elif match := COPY_FROM_IMAGE_PATTERN.match(line):
            image = match.group("image")
            if "@sha256:" in image:
                refs.append(image)
    return refs


def test_container_base_images_are_digest_pinned() -> None:
    expected_backend_refs = [
        "node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32",
        "python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254",
        "ghcr.io/astral-sh/uv:0.12.10@sha256:2bb3ebca0a796a155094a27773d290c4b074572e6107f171d88d086682fd2500",
        "python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254",
    ]
    expected_frontend_refs = [
        "node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32",
        "nginxinc/nginx-unprivileged:1.27-alpine@sha256:65e3e85dbaed8ba248841d9d58a899b6197106c23cb0ff1a132b7bfe0547e4c0",
    ]
    assert _dockerfile_image_refs(BACKEND_DOCKERFILE_PATH) == expected_backend_refs
    assert _dockerfile_image_refs(FRONTEND_DOCKERFILE_PATH) == expected_frontend_refs

    compose_postgres = compose_document()["services"]["postgres"]["image"]
    assert isinstance(compose_postgres, str)
    assert compose_postgres == "postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"

    verify_postgres = next(
        match.group("image")
        for line in VERIFY_WORKFLOW_PATH.read_text(encoding="utf-8").splitlines()
        if (match := VERIFY_POSTGRES_IMAGE_PATTERN.match(line))
    )
    assert verify_postgres == "postgres:16-alpine@sha256:cf78e76683b9ca8c5733cbbdce6c9262b45b6767934dd0a95e671f9a0fc20685"

    for ref in expected_backend_refs + expected_frontend_refs + [compose_postgres, verify_postgres]:
        assert ref in PINNED_IMAGE_REFS
        assert "@sha256:" in ref
