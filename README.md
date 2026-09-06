# AI-Enabled Threat Hunting

This repository provides a bounded threat-hunting workspace: an analyst supplies a hypothesis and scoped inputs, reviews a generated plan, explicitly approves it, and receives grounded findings and an editable report. The application does not provide autonomous production access, cross-tenant collaboration, detection export, or unbounded search.

The operator journey is deliberately three paths. Complete one path in order and stop at its validation command.

## Path A — local deterministic verification

Use this path to verify the workflow and UI without Docker, Splunk, or an external model. It is synthetic data only and must not receive production evidence.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
THREAT_HUNTING_DATABASE_URL=sqlite+pysqlite:///runtime/local-demo.db \
THREAT_HUNTING_LOCAL_DEMO=1 \
THREAT_HUNTING_DEMO_PASSWORD="<choose-a-local-secret>" \
.venv/bin/uvicorn threat_hunting.main:app --host 127.0.0.1 --port 8000
```

In a second terminal, run the workflow contract and frontend checks:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/run_known_answer_hunts.py --mode synthetic --json
npm --prefix frontend run test:unit
npm --prefix frontend run typecheck
npm --prefix frontend run build
```

Open `http://127.0.0.1:8000`, sign in as `analyst` with the password supplied above, create a hunt, run discovery, review and approve the plan, execute it, and finalize the report. The UI labels deterministic responses as non-production evidence.

## Path B — on-prem Docker Compose

Use this path for a customer-controlled host with PostgreSQL and file-backed secrets. Copy `.env.example` to `.env`, create the four default secret files described in [`deploy/docker/secrets/README.md`](deploy/docker/secrets/README.md) (`postgres_password`, `database_url`, `splunk_token`, and `model_api_key`), then validate and build:

```bash
cp .env.example .env
mkdir -p runtime/secrets
chmod 700 runtime/secrets
# Write postgres_password and database_url with permissions 0600.
docker compose --env-file .env -f deploy/docker/compose.yml config
docker compose --env-file .env -f deploy/docker/compose.yml build
docker compose --env-file .env -f deploy/docker/compose.yml up -d
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/live
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/ready
```

The frontend is the sole published browser origin on port 8080 and proxies `/api` and `/health` to the private backend. It binds to loopback by default; put that origin behind an approved HTTPS reverse proxy before interactive use, and set `THREAT_HUNTING_FRONTEND_BIND` only when the approved edge topology requires another host address. Production session cookies are Secure, so plain HTTP is suitable only for health/build checks. The API, worker, migration job, and PostgreSQL use private service wiring; uploads persist under `/var/lib/threat-hunting/uploads`; containers run read-only, without added capabilities, and as non-root users. Browser authentication uses an HttpOnly session cookie and CSRF header; no bearer token is stored in browser storage.

Path B is complete when the two health checks pass, the migration job exits successfully, and the frontend loads. Rollback means pinning the previous immutable image tag and running the documented migration rollback procedure; `docker compose down -v` is teardown and destroys persistent data, so it is not a rollback.

## Path C — live Splunk/OpenAI qualification

Use this path only after Path B passes and an operator has approved a non-production pilot. Mount the approved Splunk token and model-provider secret through protected files; never place credentials in YAML, `.env`, command arguments, images, or Git. Configure `splunk.url`, `model.provider`, `model.model_name`, the provider endpoint, and `model.data_boundary` in a customer-owned runtime file. External providers also require `execution.provider_data_handling_approval_ref`; only an explicitly local `litellm` endpoint may omit it.

```bash
docker compose --env-file .env -f deploy/docker/compose.yml up -d
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/ready
docker compose --env-file .env -f deploy/docker/compose.yml logs --no-log-prefix --tail=100 backend worker
```

Then run a synthetic-data hunt against the approved Splunk instance, verify the query ledger, cancellation, budget enforcement, evidence grounding, and PDF output, and retain the run identifiers for the pilot record. The twelve-scenario live qualification command is opt-in and requires a dedicated non-production fixture plus an application-owned workflow adapter; it never falls back to the deterministic suite:

```bash
THREAT_HUNTING_SPLUNK_URL="https://splunk-fixture.example:8089" \
THREAT_HUNTING_SPLUNK_TOKEN_FILE="/protected/splunk_token" \
THREAT_HUNTING_MODEL_PROVIDER="openai" \
THREAT_HUNTING_MODEL_NAME="<approved-model>" \
THREAT_HUNTING_MODEL_API_KEY_FILE="/protected/model_api_key" \
THREAT_HUNTING_KNOWN_ANSWER_FIXTURE_ID="<fixture-id>" \
THREAT_HUNTING_KNOWN_ANSWER_LIVE_ADAPTER="<module>:<function>" \
.venv/bin/python scripts/run_known_answer_hunts.py --mode live --json
```

If the adapter or fixture is not configured, the command exits with an explicit blocker and produces no live result.

If Docker is unavailable, Path B is blocked by the host runtime. If Splunk is unavailable or its TLS/token setup is not approved, Path C is blocked at live discovery/execution; Path A remains valid. If the application-specific model secret is absent or the provider is not qualified, Path C is blocked at plan generation/synthesis; Codex or another interactive connection does not supply an application credential.

## Configuration and safety boundaries

Non-secret settings live in [`deploy/docker/config/runtime.yml`](deploy/docker/config/runtime.yml). Secret-file names and permissions are documented in [`deploy/docker/secrets/README.md`](deploy/docker/secrets/README.md). Health endpoints are `/health/live` and `/health/ready`. Migrations run as an explicit deployment step; the API and worker do not apply migrations on startup.

The threat-hunting MVP contract is [`docs/threat-hunting-mvp-spec.md`](docs/threat-hunting-mvp-spec.md). The implementation tracker is [`docs/implementation-plan.md`](docs/implementation-plan.md). Deployment, rollback, live smoke, and blocker handling are in [`docs/operator-runbook.md`](docs/operator-runbook.md). The complete documentation map is [`docs/README.md`](docs/README.md).
