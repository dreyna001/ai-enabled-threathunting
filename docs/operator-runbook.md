# On-prem operator runbook

This runbook owns one concern: deploying and validating the Docker Compose stack on a customer-controlled host. Start at [`README.md`](../README.md), choose Path B, and return here for the deployment checks.

## Prepare

Install Docker Engine with Compose v2, copy `.env.example` to `.env`, and create the protected files listed in [`../deploy/docker/secrets/README.md`](../deploy/docker/secrets/README.md). The database URL must resolve the Compose service name `postgres`. Use an immutable `THREAT_HUNTING_IMAGE` and `THREAT_HUNTING_FRONTEND_IMAGE` tag for every release.

```bash
chmod 700 runtime/secrets
chmod 600 runtime/secrets/*
docker compose --env-file .env -f deploy/docker/compose.yml config
docker compose --env-file .env -f deploy/docker/compose.yml build
docker compose --env-file .env -f deploy/docker/compose.yml up -d
```

## Validate

```bash
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/live
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/ready
docker compose --env-file .env -f deploy/docker/compose.yml ps
docker compose --env-file .env -f deploy/docker/compose.yml logs --no-log-prefix --tail=100 migrate backend worker frontend
```

Readiness must report the database, migration revision, storage, and configuration checks as passing. The migration job must have completed successfully before the API and worker are admitted. The frontend service is the only published browser origin; it proxies same-origin cookies and CSRF-protected API calls to the backend.

## Live smoke gate

Run this only with written approval for a non-production pilot and a synthetic dataset.

1. Confirm Splunk TLS verification, least-privilege token, URL, namespace, and network reachability.
2. Confirm the model provider secret is mounted through the approved secret-file boundary and the configured model is qualified.
3. Sign in, create a synthetic hunt, run discovery, approve the generated plan, and execute it.
4. Confirm the query ledger contains only approved bounded searches, then exercise cancellation and budget exhaustion.
5. Confirm findings cite retained evidence and the finalized report downloads as a PDF.

```bash
docker compose --env-file .env -f deploy/docker/compose.yml logs --no-log-prefix --tail=200 backend worker
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/ready
```

These commands cannot qualify provider credentials by themselves. A Docker engine outage blocks the container checks; Splunk URL/TLS/token failure blocks discovery and execution; a missing or unqualified model secret blocks plan generation or synthesis. Record the blocker and use Path A for deterministic workflow verification.

## Rollback and teardown

Rollback is a controlled release change: stop admission, pin the previously verified image tags, deploy, and verify readiness and migration compatibility. Preserve PostgreSQL and application volumes.

```bash
docker compose --env-file .env -f deploy/docker/compose.yml down
```

This stops services but preserves named volumes. `docker compose down -v` removes persistent database and application data and is teardown, not rollback; use it only with an explicit destructive-data approval.

## Next

After health and synthetic live smoke pass, complete analyst acceptance and the security review before admitting customer evidence. Keep the exact image tags, migration revision, provider qualification, and smoke run identifiers with the release record.
