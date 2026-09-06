# On-prem operator runbook

This runbook owns one concern: deploying and validating the Docker Compose stack on a customer-controlled host. Start at [`README.md`](../README.md), choose Path B, and return here for the deployment checks.

## Prepare

Install Docker Engine with Compose v2, copy `.env.example` to `.env`, and create the four default protected files listed in [`../deploy/docker/secrets/README.md`](../deploy/docker/secrets/README.md): `postgres_password`, `database_url`, `splunk_token`, and `model_api_key`. The database URL must resolve the Compose service name `postgres`. Use an immutable `THREAT_HUNTING_IMAGE` and `THREAT_HUNTING_FRONTEND_IMAGE` tag for every release.

```bash
chmod 700 runtime/secrets
chmod 600 runtime/secrets/*
docker compose --env-file .env -f deploy/docker/compose.yml config
docker compose --env-file .env -f deploy/docker/compose.yml build
docker compose --env-file .env -f deploy/docker/compose.yml up -d
```

## Production configuration gate

Before admitting customer evidence, use a customer-owned runtime file and verify all of the following:

- Set `environment: production`, an immutable `image_version`, and a deployment-specific `execution.deployment_scope_id`. Keep `execution.mode: direct` until the optional MCP runtime is implemented and separately qualified.
- Keep `tls.verify: true`. Configure a trusted `tls.ca_bundle_path` when private CAs are used; do not use the lab-only insecure override in production.
- Replace the placeholder Splunk URL, namespace, model provider, model name, and endpoint. Use a least-privilege search token and record `execution.provider_data_handling_approval_ref` whenever `model.data_boundary` is `external`.
- Supply all secrets through the configured host files or a customer secret manager. Enforce host ACLs equivalent to operator-only access and verify the effective permissions on the actual production filesystem; POSIX mode output on a Windows-mounted development workspace is not sufficient evidence.
- Keep the browser origin on loopback unless an approved edge listener is required. Terminate HTTPS at that edge, preserve the private backend network, and do not expose PostgreSQL, the backend API, worker, or Splunk management ports publicly.
- Pin backend and frontend images by immutable tag or digest, verify database backup and migration compatibility, and keep the previous qualified images available for rollback.

## Validate

```bash
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/live
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/ready
docker compose --env-file .env -f deploy/docker/compose.yml ps
docker compose --env-file .env -f deploy/docker/compose.yml logs --no-log-prefix --tail=100 migrate backend worker frontend
```

Readiness must report the database, migration revision, storage, and configuration checks as passing. Terminate HTTPS at the approved ingress before interactive use; production session cookies are Secure and the direct HTTP port is for health/build checks only. The migration job must have completed successfully before the API and worker are admitted. The frontend service is the only published browser origin; the backend has no host port and receives same-origin cookies and CSRF-protected API calls through the frontend proxy. Uploads persist under `/var/lib/threat-hunting/uploads`.

## Live smoke gate

Run this only with written approval for a non-production pilot and a synthetic dataset.

1. Confirm Splunk TLS verification, least-privilege token, URL, namespace, and network reachability.
2. Confirm the model provider secret is mounted through the approved secret-file boundary and the configured model is qualified. Set `model.data_boundary: external` and record `execution.provider_data_handling_approval_ref` for an external provider; use `local` only for a deployment-owned LiteLLM-compatible endpoint.
3. Sign in, create a synthetic hunt, run discovery, approve the generated plan, and execute it.
4. Confirm the query ledger contains only approved bounded searches, then exercise cancellation and budget exhaustion.
5. Confirm findings cite retained evidence and the finalized report downloads as a PDF.

```bash
docker compose --env-file .env -f deploy/docker/compose.yml logs --no-log-prefix --tail=200 backend worker
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/ready
```

These commands cannot qualify provider credentials by themselves. A Docker engine outage blocks the container checks; Splunk URL/TLS/token failure blocks discovery and execution; a missing or unqualified model secret blocks plan generation or synthesis. Record the blocker and use Path A for deterministic workflow verification.

## Monitoring checklist

- Alert when `/health/ready` is not ready, a service is unhealthy or repeatedly restarting, or the migration job exits nonzero. Liveness alone does not admit work.
- Monitor PostgreSQL connectivity, persistent and temporary free space, worker lease age, queued/failed jobs, and retention-cleanup failures.
- Track hunt completion time, query and model-call counts, row/byte/token budgets, timeouts, retries, cancellations, and provider error categories. Investigate sustained growth before raising a hard limit.
- Review failed and rate-limited logins, rejected SPL policy decisions, approval/cancellation/finalization events, and pre-submit execution records. Treat a missing expected audit record as a release blocker, not as a successful action.
- Keep logs free of session cookies, CSRF values, Splunk/model credentials, raw authorization headers, uploaded content, and unnecessary event payloads. Retain correlation and run identifiers needed for diagnosis.

## Privacy and data-handling checklist

- Use synthetic data until the live smoke and analyst-acceptance gates pass. Confirm the Splunk indexes and time range contain no customer data before a qualification run.
- Record the approved provider, model, data boundary, purpose, and `provider_data_handling_approval_ref` before any data leaves the deployment. Do not relabel an external provider as local.
- Send only the bounded context required for the approved hunt. Do not include credentials, answer keys, unrelated uploads, or unrestricted raw Splunk results in model prompts.
- Treat uploads, selected evidence, reports, query text, and audit metadata as sensitive. Verify owner scoping, protected storage, backup handling, and the configured 90-day default retention before admitting customer evidence.
- Preserve non-secret run metadata for reproducibility. Delete test artifacts through retention or an explicitly approved, test-specific teardown; do not use teardown as rollback.

## Analyst acceptance checklist

- Record the exact application image, migration revision, fixture hashes, Splunk scope, policy version, provider/model configuration, prompt contract, and run identifiers.
- Run all 12 known-answer scenarios against verified non-production Splunk fixtures. The deterministic rehearsal is required but does not qualify model accuracy.
- Require at least 90% expected-evidence recovery, no fabricated evidence, complete positive and negative/coverage citations, and no forbidden SPL reaching Splunk.
- Confirm cutoff, timeout, retry, interruption/resume, cancellation, truncation, and hard-budget behavior, including no duplicate queries or evidence after replay.
- Have an analyst review the approved plan, query ledger, limitations, evidence, findings, final PDF, and expected audit trail. Record each item as pass, fail, or deferred with an owner; any safety-contract failure blocks acceptance.

## Rollback and teardown

Rollback is a controlled release change: stop admission, pin the previously verified image tags, deploy, and verify readiness and migration compatibility. Preserve PostgreSQL and application volumes.

```bash
docker compose --env-file .env -f deploy/docker/compose.yml down
```

This stops services but preserves named volumes. `docker compose down -v` removes persistent database and application data and is teardown, not rollback; use it only with an explicit destructive-data approval.

## Next

After health and synthetic live smoke pass, complete analyst acceptance and the security review before admitting customer evidence. Keep the exact image tags, migration revision, provider qualification, and smoke run identifiers with the release record.
