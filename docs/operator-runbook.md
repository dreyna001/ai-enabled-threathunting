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
6. Run the twelve-scenario qualification command only after the dedicated fixture workflow adapter is installed; a missing adapter is a hard stop, not a pass.

```bash
docker compose --env-file .env -f deploy/docker/compose.yml logs --no-log-prefix --tail=200 backend worker
curl --fail http://127.0.0.1:${THREAT_HUNTING_FRONTEND_PORT:-8080}/health/ready
.venv/bin/python scripts/run_known_answer_hunts.py --mode synthetic --json
```

These commands cannot qualify provider credentials by themselves. The live known-answer runner additionally requires `THREAT_HUNTING_KNOWN_ANSWER_FIXTURE_ID` and `THREAT_HUNTING_KNOWN_ANSWER_LIVE_ADAPTER=module:function`; without an application-owned fixture workflow it exits with a blocker and does not claim qualification. A Docker engine outage blocks the container checks; Splunk URL/TLS/token failure blocks discovery and execution; a missing or unqualified model secret blocks plan generation or synthesis. Record the blocker and use Path A for deterministic workflow verification.

## Model output evaluation

After deploying prompt contract `1.18`, generate and approve a fresh plan. Update API and worker images together and set the runtime `image_version` to the immutable release tag. OpenAI-compatible endpoints must accept strict `json_schema` response formats; Bedrock models must support Converse `outputConfig.textFormat`. There is no automatic downgrade to JSON mode. These shapes follow the [OpenAI structured-output contract](https://developers.openai.com/api/docs/guides/structured-outputs) and [Bedrock structured-output contract](https://docs.aws.amazon.com/bedrock/latest/userguide/structured-output.html).

For follow-up repairs, check the per-proposal rejection reasons and preserved accepted proposals. Repairs address only rejected decisions. After validation, application code suppresses searches with identical normalized SPL, UTC bounds, result mode and limits, within the same execution configuration. It preserves approved-question order and records `decision_source: application_duplicate_suppression`; the skipped question is not claimed as separately searched. Changed windows or limits remain new work. An exact duplicate does not consume a model repair.

Query context supplies literal advisory hashes in `advisory_iocs.file_hashes`. For a shared hash field, query guidance compares those values directly without an unnecessary algorithm/type predicate. Other categorical filters need supplied or observed values; bounded discovery samples do not establish an exhaustive enum.

For entity-grounding repair failures, inspect the recorded `new_entities` positions. An entity must match a complete scalar field value or list element in cited evidence. The application rejects parsed command-line substrings as structured entity values; use observed fields such as `file_name` or `process`, while retaining useful command-line interpretations in grounded summary text. Do not relax this boundary or repeatedly resume a failed hunt to obtain a passing result.

Since prompt 1.10, the model is asked for entity type and value only. Entity citations are application-derived exact matches within the selected query's supplied evidence. Wrong-query values and substrings remain invalid; do not treat the existence of a matching value as proof of an entity classification or narrative claim.

Prompt 1.11 supplies application-computed per-source retained and model-sample counts. When a truncated raw query omits an identified source, the application checkpoints a source-specific check using the original question, filters, pipeline, dates and limits. It adds an exact source constraint before the first pipe, validates the search, and reserves assessment/synthesis capacity within the existing budgets. These entries use `phase: source_coverage` and retain `source_query_id` and `source_pair`; a completed or pending check is not regenerated. Budget stops leave explicit unresolved source coverage in the report. Combined aggregates do not automatically trigger raw-event checks. A completed check establishes search coverage, not a factual answer.

Retained evidence uses the source fields returned by Splunk when they identify one possible source pair. Omitted fields can be derived only from unambiguous effective query scope; otherwise source identity remains `unknown`. Historical evidence is preserved, including earlier incorrect first-source labels; coverage calculations use its selected result and actual SPL.

Prompt 1.12 records the completed query IDs considered for each model follow-up decision. Skipped questions return for consideration only after additional queries complete; unchanged evidence does not cause repeated planning. Exact duplicate suppression remains explicit, and historical decisions without a recorded basis retain their original behavior.

Execution submits the approved UTC range as Splunk `earliest_time` and `latest_time` strings. Earlier releases sent unsupported `earliest` and `latest` parameters that Splunk ignored. Recorded proposal windows in those runs therefore do not prove enforced search bounds; preserve the runs and audit job request metadata before drawing scoped absence conclusions. Deploy API/worker together and approve a fresh plan before retesting. Repeated identical source-field values identify one source; conflicting values remain unknown.

Prompt 1.13 removes `intelligence_refs` from the model-facing plan. Application code attaches a reference to the actual nonempty analyst-supplied advisory field. Its source descriptor is stored in discovery `input_context.intelligence_sources`, identifies the content field and its SHA-256, and is scoped to the hunt and exact text. This identifies supplied context; it does not claim to verify an external document or turn advisory text into observed evidence. Empty input produces no source. Explicit canonical references and plan edits must resolve to those supplied sources, and approval/execution reject unknown references. Historical empty reference lists remain valid.

Prompt 1.14 corrects synthesis evidence selection without increasing the 100-record limit. It first reserves one retained row per observed source/query where capacity permits, then includes complete assessment support groups in approved-question order before adaptive groups. Groups that cannot fit or refer to unavailable/wrong-query rows receive no partial priority allocation; remaining capacity is filled by balanced sampling. An assessment is supplied only when all of its supporting records are present, and omitted assessments and evidence remain explicit. This selection does not rank maliciousness, use fixture expectations, or establish claim correctness.

Prompt 1.15 adds claim boundaries to assessment and synthesis guidance and to the provider-facing field descriptions: distinguish observed actions from intent/authorization, scope any supplied baseline comparison, and distinguish shared host/account context from process/session relationships. Positive observations must not imply a broad absence of malicious behavior. The native schema and existing repair preserve these instructions, but they do not constitute a semantic fact checker; schema-valid prose can still fail factual review. No prose blacklist, automatic rewriting, or additional model-review call is introduced.

Prompt 1.16 adds application-computed IOC literal comparisons to each sampled assessment/synthesis row and supplies the same bounded extracted advisory IOC lists used for query generation. Complete hexadecimal hash values compare case-insensitively; names and domains use exact whole-value equality. An empty hash comparison list means no comparable literal was supplied, not a negative hash result. Comparisons include scalar values in retained JSON and preserve conflicting raw/projected values. They do not infer field semantics, parse command-line substrings, evaluate complete STIX patterns, or establish file identity or maliciousness. Source records and historical findings remain unchanged; model prose still requires factual review.

With prompt contract 1.17, retained row kind comes from the executed SPL, independently of requested result mode: supported `stats`/`timechart` pipelines produce aggregate rows; supported event-preserving pipelines produce raw-event rows. Source-coverage scheduling uses this same distinction, so a raw query requested in aggregate mode no longer bypasses omitted-source checks. Requested retrieval caps remain unchanged. Historical records are preserved. This adds no customer configuration, services, or dependencies and does not make schema-valid prose automatically factual.

Prompt contract 1.18 supersedes the 1.14 synthesis-priority behavior above. Final synthesis excludes earlier assessment summaries/limitations and model-authored skip reasons, and no longer prioritizes their citation groups. Query/source-balanced sampling retains the 100-record cap; exact extracted advisory hash/name/domain literals are prioritized within their own query. The investigation retains its assessments for pivots and audit. This is a bounded handoff correction, not a completed per-question retrieval design or a factual-accuracy guarantee. The candidate requires live qualification before promotion.

Provider HTTP 429 errors with structured `insufficient_quota` or `credit_balance_exhausted` codes are recorded as `provider_quota_exhausted`, with no automatic retry/repair. Restore API account capacity before retrying. Other 429 errors remain `rate_limited` and retain their existing bounded retry classification. Classification never copies provider billing messages, account identifiers, or request bodies into diagnostics.

The pending v19 retrieval change permits 10,000 raw rows per representative/targeted query and keeps aggregate results at 500. Fixed pages contain at most 500 rows; the final retained page also respects the remaining query/hunt storage budget. Inspect query records for `available_result_count` (server output count, nullable), `result_count` (retained rows), `result_pages`, and `retrieval_stop_reason`. Reasons distinguish query/hunt row or byte limits, query timeouts, and incomplete pages. A known total makes an exact-cap result complete; an unknown total leaves it conservatively truncated. Earlier pages survive a later timeout or byte-limit failure. Zero retained rows after incomplete retrieval do not establish zero matches. A `skipped_budget` ledger entry records an unstarted search when search or storage capacity is exhausted. Completed query checkpoints remain idempotent on recovery. Prompt 1.19 raises model evidence batches to 500 records by default and uses the existing representative/targeted configuration limits at context construction. Assessment repair keeps its original evidence set. Deployed v18 still uses the earlier retrieval and 100-record context behavior until a verified rollout of the current candidate.

The local prompt-1.24 candidate also requires every approved question to have a concise summary plus supported findings or explicit limitations. The application assigns question/finding identities. All generated findings stay in retained hunt results. The report draft defaults to ten selected finding details across questions, favoring hunt leads within each question, while preserving every question summary and full finding references; analysts may include more within the existing 1 MiB report input limit. This default does not restrict investigation memory, evidence retrieval, or model output. PDF/HTML question answers print summaries, limitations, and reference counts. The app expands complete findings for each question and links to its own retained results, not the Splunk search UI. No new customer configuration is required. Missing support must remain explicit, and valid answer slots do not establish complete or correct analysis. This candidate remains undeployed.

Prompt 1.24 retains time-spread evidence selection and application-computed query inventories with explicit missing/multivalue counts. It adds bounded retained-page requests by completed query, exact field values and optional UTC time windows. A question either returns a final answer or requests up to three pages, each at most 500 representation groups. Identical raw representations retain all citation origins; differing fields remain separate. Completed answers/pages are checkpointed, repeated requests stop retrieval, and original query coverage remains distinct from local page/sample coverage. The application reserves a final call and tokens during adaptive/retrieval work. Complete-request preflight enforces `context_characters` and uses UTF-8 bytes plus framing as a conservative input-token estimate; synthesis adjusts the evidence sample while rebuilding coverage. Repairs retain their original evidence mapping and must also fit. Budget exhaustion leaves explicit unanswered slots. This candidate remains undeployed and unqualified; see the [resume checkpoint](resume-checkpoint.md) for measured fitting limits and remaining checks.

The candidate excludes failed, truncated, partial or incompletely retrieved queries from negative-finding choices and validates the same condition after model output and before persistence. A positive observation may still cite an actually retained row from a truncated search. Invalid negative claims and out-of-scope retained lookup windows use the existing single repair attempt, preserving the original context and budgets. Requests for fields never observed in the retained raw records report that limitation explicitly; zero local matches do not establish absence in the source.

Plan review must check the requested hunt dates against the snapshot's `schema_requested_scope` and `schema_sampling_scope`. Discovery samples at most 100 events per source pair and eight pairs; windows over seven days sample their final seven days. Missing sample fields are a coverage limitation, not proof that the telemetry cannot provide them. Changing a plan's sources or dates refreshes discovery before the edit is saved.

Production discovery combines configured sourcetypes with one bounded `tstats` query of indexed source names across catalog indexes (or the proposed indexes during scoped refresh). It returns no raw events and uses existing transport, item, and byte limits. `saved/sourcetypes` alone is not an inventory of indexed data: HEC can carry labels with no saved source configuration. A failed or capped indexed-catalog query is reported as partial discovery. A successful indexed-source probe sets `tstats_available` to true, including when it returns no rows; this proves that scoped probe worked, not data-model acceleration or every possible `tstats` query. A failed or unexecuted probe does not establish availability. Source membership does not establish an index/source pairing or activity in the hunt window; the scoped sample and analyst review remain required.

Discovery also reads the account's current roles and effective allowed/disallowed index patterns before admitting indexes or submitting discovery searches. The Splunk integration account must be able to read its current context and role metadata. Missing or malformed permissions yield a partial catalog with no authorized indexes. Explicit and inherited denies override allows; `*` excludes internal indexes unless an underscore-prefixed pattern allows them. See [Splunk's index permission rules](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authorize.conf). Differing field lists for one sourcetype are retained as an observed union with a limitation; they do not establish an exhaustive schema. Live least-privilege qualification remains required.

The separate [normalized v1 fixture](../tests/known_answer/fixtures/normalized-v1/README.md) defines process/session/event semantics and private expectations before model execution. Its loader accepts only loopback lab endpoints, exact frozen files and isolated `th_real_v1_*` indexes. Provision those four indexes and a HEC token restricted to them; the reader's allowed-index list and any search filter must include them. Load one variant only, using `python -m scripts.load_realistic_fixture load --fixture tests/known_answer/fixtures/normalized-v1/events.jsonl --output runtime/normalized-load --search-token-file PATH --hec-token-file PATH`. Use the same command with `verify` and without the HEC token to inspect ingestion after an uncertain response. Never repost an uncertain request or load the outage variant into the complete variant's indexes. The loader checks index totals as well as search results so a role-filtered empty search cannot silently authorize an append. Keep the original `th_test_*` fixture unchanged.

Use an approved non-production fixture and retain the owned `/api/hunts/{hunt_id}/results` response as `hunt-results.json`. Keep the execution's actual model/provider/reasoning settings with that export. Do not provide the evaluator's answer key or judgments to the model. This command evaluates existing outputs and makes no model or Splunk calls:

```bash
.venv/bin/python scripts/run_known_answer_hunts.py --mode observed --observations observations.json --json
```

`observations.json` contains a `runs` array. Each entry has `scenario_id`, `model_provider`, `model_name`, optional `reasoning_effort`, and `results` holding the actual results response. To package an export for initial validation metrics:

```python
import json
from pathlib import Path

run = {
    "scenario_id": "approved-fixture-1",
    "model_provider": "openai",  # Use the actual execution settings.
    "model_name": "gpt-5.1",
    "reasoning_effort": "none",
    "results": json.loads(Path("hunt-results.json").read_text()),
}
Path("observations.json").write_text(json.dumps({"runs": [run]}))
```

For analytical scoring, add `expected_finding_ids` containing the fixture's independently defined expected findings, plus `judgments` with exactly one entry per actual finding. Each judgment contains the returned `finding_id`, boolean `supported`, and the `expected_finding_ids` it satisfies. A supported incidental finding can match no expected finding; an unsupported finding cannot satisfy an expectation. For a correctly empty result, supply both arrays as empty. Keep missing judgments omitted rather than inventing them. `measured_cost_usd` is optional; missing cost stays unknown.

When projected results omit the configured fixture identity, retained/cited match counts include identified records only. Recall and missed-event lists remain `null` when unidentified rows could change the result. A zero requires measurable absence; the scorer never guesses an identity from the answer key.

SPL policy 1.3 normalizes grouped initial expressions to an explicit `search` command before API submission. Source-branch, exact-scope, time, and command restrictions still apply.

Metrics distinguish:

- Safe validation diagnostics: `usage.model_output_checks[].validation_error_code` retains a fixed schema, JSON, reference-label, citation-relationship, or structure code even when a subsequent repair cannot start. It contains no model text or validation input.
- First-pass contract validity: initial outputs accepted after structural validation and citation-label resolution, including failures in the denominator.
- First-pass grounded output: initial assessment/synthesis calls passing both contract and downstream citation/entity checks. These checks do not prove claim truth.
- Repair-call percentage: repair calls divided by all recorded model calls.
- Finding precision/recall and unsupported findings: independent analyst judgments compared with the expected findings. The existing `unsupported_claim_count` field counts findings judged unsupported, not individual unsupported sentences or claims.
- Citation failures: unavailable evidence, unfinished/unknown queries, or incorrect evidence/query relationships in the exported findings.
- Retrieval and citation recall: supply evaluator-only `expected_event_ids`. Set `fixture_event_id_field` to the selected-result field holding the fixture identity (for example, `event_id` or `synthetic_event_id`). If omitted, historical exports use `source_event_ref`. Splunk may populate that reference with `_cd`, which is not a fixture ID. The scorer reports its identity field and unidentified-record count, rejects ambiguous multivalue identities, and never silently falls back to another field. Missing expectations stay unknown. Do not add irrelevant citations to improve recall.
- Approved-question execution coverage: supply `approved_question_ids` from the approved plan. This measures completed searches and does not establish that the questions were answered.
- Retained and distinct cited records, classification totals, and duplicate citation counts come from actual results.
- Provider-reported token usage and optional measured cost. Old exports without a complete validation trace report unknown first-pass metrics.

The JSON reports `answer_key_matched` separately from these metrics and explicitly does not establish production qualification. Exit codes are `0` for complete matching results, `1` for an answer-key or citation mismatch, and `2` for unassessed analytical quality or malformed input. The input is bounded to 32 MiB and 100 runs. Compare first-pass metrics and independently reviewed quality across the same fixtures and model settings before claiming an improvement. Synthetic mode remains a scorer regression test; full live Splunk qualification still requires the separate fixture workflow described above.

### Repeatable live trials

`scripts/run_live_hunt_trial.py` prepares, approves/enqueues, and captures a trial through the normal application APIs. It does not load Splunk fixtures or implement the twelve-scenario callback. Verify the isolated synthetic indexes and their contents before preparing a trial.

Create a scenario JSON file containing `scenario_id`, `variant_id`, `trial_id`, the verified fixture's `fixture_sha256`, the exact `scope` (`earliest_utc`, `latest_utc`, `indexes`, `sourcetypes`), a normal `hunt_input` object (`title`, `hypothesis`, `objective`, optional `threat_intelligence` and `synthetic_data`), and evaluator-only `expected_event_ids`. State the intended scope in the hunt input as well; the generated plan must match the declared scope before this runner permits approval. Only `hunt_input` is sent to the application. Keep answer keys and judgments outside that object.

Use a dedicated existing test account, with `username` and `password` in a protected credentials JSON file. Each trial requires a new output directory and hunt. HTTP is allowed only for loopback; other deployments require HTTPS.

```bash
.venv/bin/python scripts/run_live_hunt_trial.py prepare --credentials-file /protected/trial-account.json --scenario scenario.json --output runtime/qualification/trial-1
# Review runtime/qualification/trial-1/discovered-hunt.json before using its printed plan hash.
.venv/bin/python scripts/run_live_hunt_trial.py execute --credentials-file /protected/trial-account.json --output runtime/qualification/trial-1 --reviewed-plan-sha256 REVIEWED_PLAN_SHA256
.venv/bin/python scripts/run_live_hunt_trial.py capture --credentials-file /protected/trial-account.json --output runtime/qualification/trial-1
```

Capture returns the current state; a successful capture command does not mean the hunt completed. Recheck the existing hunt/job while it is queued or running. Mutations are never automatically retried. After an interrupted approval or enqueue request, inspect the saved hunt in the app before taking another action. The runner rejects reused execution attempts. Report finalization remains an explicit app action.

All terminal trials, including failed and cancelled hunts, export `observations.json` with `terminal_state`, the approved runtime settings, actual results, and no invented analytical judgments. Put `fixture_event_id_field` in the scenario when fixture IDs differ from Splunk record IDs; this field and the answer key remain outside application requests. Add independently reviewed judgments before claiming analytical acceptance. Combine the `runs` arrays from multiple exports for comparison. Each `(scenario_id, variant_id, trial_id)` and supplied hunt ID must be unique; trials within one variant must use identical fixture hashes, model settings, versions, identity fields, and expectations. Use a different `variant_id` for a candidate release or model configuration. The scorer includes failed/cancelled trials in the report-completion denominator; unknown historical states remain unknown. Observed ranges do not predict future reliability. Repeated success on one fixture does not replace representative positive, negative, incomplete-telemetry, and behavioral hunts.

## Hunt timing and evaluation parity

The default total execution ceiling is **20 minutes**. The shipped Docker settings retain **300 seconds per model call**, **120 seconds per search**, and **12 model calls**. New searches and adaptive model work stop at minute **13**; outstanding searches stop by minute **15**, leaving one five-minute model-call allowance for synthesis. A shorter remaining hunt deadline further caps every model call. Counts and token limits may stop a hunt sooner.

The default per-hunt search ceiling is **50**, configured by `hunt_limits.query_count`. It is a maximum, not a required search count. Model-call, token, evidence, time, and concurrency limits remain independent and may stop investigation first. A larger search budget does not establish better report accuracy or ensure every retrieved event reaches synthesis.

The query cutoff is derived automatically from `hunt_limits.hard_completion_minutes`, `model_call_timeout_seconds`, and `search_job_timeout_seconds`. A configuration omitting the model-call setting retains its 120-second default and therefore a minute-16 cutoff. The legacy `query_start_cutoff_utc` setting is accepted for compatibility but does not schedule execution. No customer timing calculations or new configuration switches are required.

Before changing a deployed configuration, finish active jobs, preserve the database and prior image/configuration, and update both API and worker. Existing approval snapshots remain immutable; new settings require fresh discovery/approval. For explicit existing YAML configurations, set `hard_completion_minutes: 20` and `query_count: 50`.

Run qualification through the deployed application with the captured approval configuration. A diagnostic using a separate short cutoff is a latency smoke test, not equivalent to the deployed runtime. Derive diagnostic model timeouts from the runtime configuration, record any other deliberate deviations, and keep old 90-second results as historical observations. Those results cannot establish failure under a five-minute limit. The API trial runner enqueues execution asynchronously; its individual HTTP timeout is not the hunt deadline. Offline evaluator tests use no live model and do not measure hunt latency.

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

Observed evaluation exports should set `judgment_source` to `analyst` or `assistant`; omitted provenance is reported as `unspecified`. Assistant review does not satisfy independent analyst acceptance.

## Hardening release verification

- Deploy the frontend, API, and worker from the same verified working tree. The backend uses `uv.lock`; refresh dependencies deliberately with `uv lock`, then run `uv sync --locked --extra dev`, `uv run --locked --extra dev mypy`, and `uv run --locked --extra dev pytest -q`.
- Set `THREAT_HUNTING_TEST_DATABASE_URL_FILE` (or the CI-only `THREAT_HUNTING_TEST_DATABASE_URL`) for PostgreSQL verification. The database name must end in `_test`; do not point these checks at application data. Tests cover migration upgrade/downgrade, queue visibility/rollback, duplicate execution, concurrent admission, lease fencing, and summary pagination. SQLite alone does not qualify PostgreSQL concurrency.
- Apply migration `0013_hunt_listing_index` with admission stopped. It adds only an owner/creation-time/hunt-ID index. Verify `/health/ready` and worker health, then reopen admission. Existing reports remain historical outputs; new findings require a new hunt and an approved prompt-contract `1.2` plan.
- HTTP responses include server-generated `X-Request-ID`; logs record template routes, status, and duration. Model logs record contract, repair status, latency, and token counts. Worker failures record hunt/job IDs, category, and error type. Raw prompts, exception text, queries, auth headers, and credentials are not copied into these diagnostics.
- Cancellation returns promptly to the caller. An already-running provider request may continue until its transport deadline; its adapter capacity stays occupied until it finishes, and shutdown releases the client afterward. This bounds outstanding work and does not claim remote inference was forcibly terminated.
- Time-bound metadata is computed from retained raw-event timestamps, excluding unknown times and aggregate rows. Sample completeness, the query window, and continuous telemetry coverage are distinct. A valid citation or one successful live case cannot establish general factual accuracy.

## Rollback and teardown

Rollback is a controlled release change: stop admission and workers, pin the previously verified image tags, deploy, and verify readiness and migration compatibility. Preserve PostgreSQL and application volumes. To roll back this index-only release to a runtime expecting `0012_security_hardening`, use the **new** image's migration command before starting the old services:

```bash
docker compose --env-file .env -f deploy/docker/compose.yml stop frontend backend worker
docker compose --env-file .env -f deploy/docker/compose.yml run --rm --no-deps migrate python -m alembic downgrade 0012_security_hardening
# Set the previously recorded backend and frontend image tags in .env.
docker compose --env-file .env -f deploy/docker/compose.yml up -d --no-deps --wait backend worker frontend
```

This downgrade removes the new index only. Upgrade/downgrade data preservation is covered on disposable PostgreSQL; an actual application rollback must still verify health and preserved records. Other future migrations require their own compatibility review.

```bash
docker compose --env-file .env -f deploy/docker/compose.yml down
```

This stops services but preserves named volumes. `docker compose down -v` removes persistent database and application data and is teardown, not rollback; use it only with an explicit destructive-data approval.

## Next

After health and synthetic live smoke pass, complete analyst acceptance and the security review before admitting customer evidence. Keep the exact image tags, migration revision, provider qualification, and smoke run identifiers with the release record.
