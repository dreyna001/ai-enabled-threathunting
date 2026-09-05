# AI-Enabled Threat Hunting MVP

This repository implements the bounded threat-hunting workspace defined in the [MVP specification](docs/threat-hunting-mvp-spec.md). The [implementation plan](docs/implementation-plan.md) is the build and acceptance tracker.

## Current status

A thin, persisted vertical slice is implemented for login, hunt creation, deterministic local Splunk discovery, plan revision and approval, bounded execution, evidence review, editable reporting, and PDF finalization. Production Splunk and model-provider qualification remain integration work.

## Requirements

- Python 3.12
- Node.js 22 and npm
- Docker Engine with Docker Compose

## Local Python setup

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
python -m pytest
```

## Local vertical-slice demo

The local demo uses deterministic synthetic Splunk and planning data. Every such response is labeled `deterministic_local_demo`; it verifies workflow and UI behavior only and is not production evidence or model-accuracy validation.

```bash
cd frontend && npm run build
cd ..
THREAT_HUNTING_DATABASE_URL=sqlite+pysqlite:///runtime/local-demo.db \
THREAT_HUNTING_LOCAL_DEMO=1 \
THREAT_HUNTING_DEMO_PASSWORD='<choose-a-local-secret>' \
.venv/bin/uvicorn threat_hunting.main:app --host 127.0.0.1 --port 8000
```

Sign in with the local-only demo account `analyst` and the password you supplied in `THREAT_HUNTING_DEMO_PASSWORD`. Demo mode fails closed when that value is absent. Do not enable demo mode for production deployments. Verify the complete HTTP workflow with `.venv/bin/python -m pytest tests/e2e/test_vertical_slice.py -q`.

## Runtime configuration and secrets

Non-secret settings live in a read-only YAML file. Start with `deploy/docker/config/runtime.yml`.

Secrets are separate files. Never put secret values in the YAML file, `.env`, command-line arguments, images, or Git. For local Docker development, create the paths named in `.env.example` and place only the corresponding secret value in each file.

The database URL secret uses a SQLAlchemy-compatible PostgreSQL URL, for example:

```text
postgresql+psycopg://threat_hunting:<password>@postgres:5432/threat_hunting
```

## Database migration

```bash
THREAT_HUNTING_CONFIG=/path/to/runtime.yml \
THREAT_HUNTING_DATABASE_URL_FILE=/path/to/database_url \
python -m alembic upgrade head
```

Migrations run as an explicit deployment step. The API and worker never apply migrations themselves.

## Health endpoints

- `GET /health/live` checks that the API process can answer.
- `GET /health/ready` checks configuration, PostgreSQL, migration revision, writable storage, and minimum free space.

The containerized API serves the built frontend on the same origin. Docker Compose
publishes that service on both the configured frontend and API host ports so browser
requests to `/health/*` do not require cross-origin configuration.

The worker publishes a heartbeat to PostgreSQL. Its container health check uses the same configuration, migration, storage, and database checks.

## Docker development deployment

Copy `.env.example` to `.env`, create the local secret files, then validate and build:

```bash
docker compose -f deploy/docker/compose.yml config
docker compose -f deploy/docker/compose.yml build
```

Do not run this deployment with placeholder secrets or production data.
