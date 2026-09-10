# AI-Enabled Threat Hunting

This repository provides a bounded threat-hunting workspace: an analyst supplies a hypothesis and scoped inputs, reviews a generated plan, explicitly approves it, and receives grounded findings and an editable report. The application does not provide autonomous production access, cross-tenant collaboration, detection export, or unbounded search.

Model calls use API-enforced structured response schemas. Assessment and synthesis prompts use request-local evidence/query labels; application code restores durable IDs and derives query relationships for evidence-backed findings. Final synthesis uses query/source-balanced records within the 500-record batch limit, prioritizing exact advisory literal matches within each query. Earlier assessment conclusions, their citation-group priorities, and model-authored skip reasons are excluded from final synthesis; they remain available in the investigation/audit history. Query and sample omissions remain explicit. This prevents earlier conclusions from controlling the final handoff; it does not prove the resulting prose is factually correct. Deploy API and worker together and generate/approve a fresh plan: the execution binding now uses prompt contract `1.23`. Discovery samples the proposed hunt sources and dates before final plan review and refreshes when an analyst edits that scope. Field samples remain bounded and nonexhaustive. Application code skips exact duplicate follow-up searches without consuming a model repair, preserving approved-question priority and recording the skipped work. Exact advisory hashes are supplied without presumed telemetry algorithm labels. Assessment and synthesis receive application-computed comparisons of observed scalar literals against the extracted advisory values, keeping filename matches, hash matches, and missing hash literals distinct. These comparisons do not establish full STIX pattern satisfaction, file identity, or maliciousness. Apply migration `0013_hunt_listing_index` before starting the new API and worker. Each configured provider/model must support native structured outputs; unsupported schemas fail explicitly without a JSON-mode fallback.

The local prompt-1.23 candidate requires a concise answer and supported findings or explicit limitations for every approved question. Application code owns question/finding identities and references. All generated findings remain in hunt results; the report selects detailed examples separately and never uses its presentation target to restrict investigation memory. The app provides expandable findings by question and navigation to its complete retained results (not a link to a Splunk search job). PDF question answers show summaries and counts instead of every internal reference. These source changes are not deployed; see [remaining work](docs/remaining-work.md) for current qualification gaps.

The local prompt-1.23 candidate spreads selected raw evidence across early, late and interior times and supplies application-computed retained-query field inventories. The model can request bounded retained pages by query, exact typed field values, and optional UTC time windows. Completed answers and pages are checkpointed, and requests preserve original coverage and citation origins. Complete-request context checks include schema/system/repair size; synthesis fits evidence to the remaining allowance. Adaptive work and retrieval reserve a final call and tokens. UTF-8 byte estimation is conservative, not measured provider token usage; analytical coverage remains unqualified. Start with the [resume checkpoint](docs/resume-checkpoint.md).

Execution results include per-attempt contract and grounding checks in `usage.model_output_checks`. The known-answer command's `synthetic` mode verifies scripted scorer fixtures only. Its `observed` mode scores actual result exports plus independent analyst judgments; instructions and metric definitions are in the operator runbook. Passing tests or successful repairs do not establish first-pass model quality.

Hunt lists now return owner-scoped summary pages (default 50, maximum 100, with a 500-character hypothesis excerpt). Pass the last displayed `hunt_id` as `cursor`; use `GET /api/hunts/{hunt_id}` for complete details. The dashboard pages through summaries and fetches a selected hunt separately. Queue state, publication, and audit records commit together; PostgreSQL admission serializes the deployment's active-hunt cap. Model SDK retries are disabled, calls receive transport deadlines, and timed-out work retains its capacity until it finishes.

Observed timestamps are computed by the app and supplied to assessment, synthesis, findings, and reports. Point events—even events at both interval endpoints—do not establish continuous telemetry or activity throughout the approved search window. A bounded live regression passed, but representative analyst-reviewed quality remains a separate acceptance requirement.

The application derives retained row kind from the executed SPL pipeline, independently of the model's requested result mode. Source-coverage checks use this same distinction. This adds no customer mappings, normalization steps, or prompt configuration.

Backend runtime and development dependencies are recorded in `uv.lock`; the Docker build uses that lock and a pinned build backend. `.github/workflows/verify.yml` runs type checking, backend tests with a disposable PostgreSQL database, frontend tests/build, and an application image build. For the same PostgreSQL checks locally, set `THREAT_HUNTING_TEST_DATABASE_URL_FILE` to a secret file naming an explicitly disposable database ending in `_test`, then run the commands below. Each test creates and drops only its own temporary schema. Without that setting, PostgreSQL tests are explicitly skipped.

## Threat-hunt framework alignment

The workflow is aligned to the investigation outcomes in [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final): correlate related telemetry (DE.AE-03), assess scope and impact (DE.AE-04), preserve investigation evidence and records (RS.AN-06/07), and examine affected assets and potential targets to establish magnitude (RS.AN-08). Its adaptive pivots also follow the backward and forward investigation pattern in [MITRE TTP-Based Hunting, section 2.4.3.6](https://www.mitre.org/sites/default/files/2021-11/prs-19-3892-ttp-based-hunting.pdf).

These are alignment references, not a certification claim. Evidence sampling, query and model budgets, stopping rules, and concise report limits are application implementation choices; reports state when unanswered questions, missing telemetry, truncation, or budget limits prevent a complete scope assessment. The default search ceiling is 50 per hunt, within the existing 20-minute execution limit. This is a maximum, not a target; model-call, token, evidence, and concurrency limits remain independent.

Every generated follow-up question requires either a validated query or a recorded reason it cannot proceed. Pivots may use exact values from that question's cited evidence, including JSON raw events, rather than only the entities selected by the assessment. Skipped questions and their reasons remain visible in the results and report limitations.

Production discovery supplements configured sourcetypes with a bounded indexed-source catalog, so correctly indexed HEC labels do not require a saved sourcetype definition to be discoverable. Raw-event schema sampling stays within the proposed sources and dates. The separately versioned [normalized telemetry fixture](tests/known_answer/fixtures/normalized-v1/README.md) defines coherent event semantics and private expectations without changing the original regression dataset.

Unsearched approved questions take priority over adaptive pivots. Skipping a question preserves the remaining search capacity for other pending questions; hard limits still reserve a model call for synthesis. Reports derive counts, classifications, and searched sources from execution records, preserve source identifiers and synthetic provenance, and disclose unexecuted questions. Valid references do not establish that a finding's claims are supported; that remains part of analytical evaluation. See the [live-trial procedure](docs/operator-runbook.md#repeatable-live-trials) for separate retrieval, citation, coverage, and repeated-trial measurements.

Assessment evidence is grouped by completed search. Citations are checked against the exact sample supplied for that search, not all stored records. A grounding repair receives only failed assessments and their original evidence groups; valid assessments are preserved. Repairs remain bounded and are rejected if citations are still invalid. Cross-search correlation remains available for follow-up planning and report synthesis. This requires an updated backend/worker image; the hardening release also includes the hunt-list index migration described above.

The application assigns initial question IDs (`q1`, `q2`, ...) before plan review; models supply question content, not identity. Edits preserve valid IDs, and duplicate, blank, or `unknown` IDs are rejected before approval or execution. Previously approved plans are never silently renumbered.

If a model response reaches its token limit, persisted usage and model-call diagnostics identify the contract and token usage. Job errors expose safe categories and error types without copying exception text or response content. The configured limit is a ceiling, not a guarantee that high reasoning will finish; inspect the failing step before increasing budgets or repeating a full hunt.

The operator journey is deliberately three paths. Complete one path in order and stop at its validation command.

Query-result ceilings are 500 summary (aggregate) rows and 10,000 raw representative or targeted rows per search, bounded by the configured 50,000-row hunt limit and query/hunt byte limits. The executor fetches fixed pages of at most 500 rows, preserves ordering, and records the server output count when available, retained count, pages received, and any retrieval stop reason. A result exactly at its requested cap is complete only when the server total confirms completeness; an unknown total leaves that boundary conservatively truncated. Earlier pages survive a later timeout or byte limit. These limits do not bound the number of events Splunk may scan. The separate model evidence sample now defaults to 500 rows per batch. Assessment uses `representative_event_limit`; pivot planning and synthesis use `targeted_event_limit`. Additional retrieval and improved timeline selection remain pending. Generate and approve a fresh plan after deploying this policy change. This policy applies equally to local and production deployments.

## Path A — local deterministic verification

The Docker runtime defaults to OpenAI `gpt-5.1` with `model.reasoning_effort: none` in `deploy/docker/config/runtime.yml`. This disables the extra reasoning phase for all model calls, including repairs and report synthesis. Reasoning is included in execution approval settings; generate and approve a fresh plan after changing it. Production deployments must set these same values in their runtime configuration to use GPT-5.1 without reasoning. No automatic model fallback is enabled. The per-call output ceiling remains `hunt_limits.output_tokens_per_call: 24000`, and the timeout remains `hunt_limits.model_call_timeout_seconds: 300`; configurations omitting these settings retain the 8,000-token and 120-second defaults. The total hunt deadline is now 20 minutes. With the shipped 300-second call timeout, new queries and adaptive work stop at minute 13; in-flight queries have at most two more minutes, leaving five minutes for synthesis. The 96,000-token total output budget, 12-call limit, and prompts remain unchanged. Custom YAML files must set `hunt_limits.hard_completion_minutes: 20` to adopt the longer limit; omitted values now default to 20. Execution settings are bound to plan approval, so finish active jobs before rollout and obtain a fresh plan approval for changed settings. If reasoning is enabled later, reasoning and visible answers share the output allowance. Token-limit cutoffs fail with an explicit budget error instead of triggering an ineffective JSON repair at the same limit.

Use this path to verify the workflow and UI without Docker, Splunk, or an external model. It is synthetic data only and must not receive production evidence.

```bash
python3.12 -m pip install uv==0.12.10
uv sync --locked --extra dev --python 3.12
. .venv/bin/activate
THREAT_HUNTING_DATABASE_URL=sqlite+pysqlite:///runtime/local-demo.db \
THREAT_HUNTING_LOCAL_DEMO=1 \
THREAT_HUNTING_DEMO_PASSWORD="<choose-a-local-secret>" \
.venv/bin/uvicorn threat_hunting.main:app --host 127.0.0.1 --port 8000
```

In a second terminal, run the workflow contract and frontend checks:

```bash
uv run --locked --extra dev mypy
uv run --locked --extra dev pytest -q
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

The frontend is the sole published browser origin on port 8080 and proxies `/api` and `/health` to the private backend. It binds to loopback by default; put that origin behind an approved HTTPS reverse proxy before interactive use, and set `THREAT_HUNTING_FRONTEND_BIND` only when the approved edge topology requires another host address. Production session cookies are Secure and require HTTPS. A development-only HTTP LAN workspace must explicitly set `THREAT_HUNTING_COOKIE_SECURE=false`; never use that override in production. The API, worker, migration job, and PostgreSQL use private service wiring; uploads persist under `/var/lib/threat-hunting/uploads`; containers run read-only, without added capabilities, and as non-root users. Browser authentication uses an HttpOnly session cookie and CSRF header; no bearer token is stored in browser storage.

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
