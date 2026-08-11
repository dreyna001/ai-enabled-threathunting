# Threat Hunting MVP Implementation Plan

Status: Ready for implementation  
Source of truth: [Threat Hunting MVP Specification](./threat-hunting-mvp-spec.md)  
Plan purpose: Tell Codex what to build, in what order, and how to prove each part works.

## 1. How to use this plan

The MVP specification defines the product. This plan only defines the build order. If this plan and the specification disagree, follow the specification.

When implementing:

1. Read the full MVP specification and the applicable `AGENTS.md` instructions before changing code.
2. Work on one implementation block at a time, in the order shown below.
3. Keep every change inside the approved MVP scope. Do not add features because they may be useful later.
4. Complete the code, tests, documentation, configuration, and database migration for the current block together.
5. Run the listed checks and meet every acceptance check before starting the next block.
6. Record the completion date, commands run, and any approved deviation in the progress log at the end of this document.
7. If a requirement is unclear, stop and resolve it against the specification. Do not invent product behavior.

## 2. Fixed scope and decisions

These decisions are already made and must not be reopened during implementation:

- The workflow is create, discover, draft, approve, execute, synthesize, review, and finalize.
- An analyst cannot edit an approved or running hunt. They must cancel it and start a new hunt.
- Only the state changes listed in specification section 5 are allowed. Invalid state changes fail without changing stored data.
- All model output uses the JSON contracts in specification section 7. Missing information is represented as `unknown`; invented evidence is forbidden.
- Splunk access is read-only and every SPL query must pass deterministic validation before execution.
- Per-query, per-hunt, and deployment-wide limits are enforced outside the model.
- Failed model calls and repair attempts count against model limits.
- Retryable failures and stop-the-hunt failures follow specification section 11.
- Evidence, reports, and audit records use the same configurable retention period, with a default of 90 days.
- All stored timestamps are UTC. Reports display both UTC and the configured report timezone.
- OpenAI API and Amazon Bedrock model paths are part of MVP validation. A real local Gemma deployment test is deferred, but the local-model interface and tests using a fake implementation are still required.
- The twelve known-answer hunts use synthetic data and must cover the cases listed in specification section 19.
- Authentication remains intentionally simple for this MVP. More advanced identity and CUI controls are documented future work, not this build.

## 3. Working architecture and repository layout

Use the simplest layout that keeps web requests, background work, integrations, model calls, and business rules separate:

```text
.
├── docs/
│   ├── threat-hunting-mvp-spec.md
│   └── implementation-plan.md
├── src/threat_hunting/
│   ├── api/                 # FastAPI routes and request/response models
│   ├── auth/                # Local login and hunt ownership checks
│   ├── domain/              # Hunt states, policies, limits, and contracts
│   ├── integrations/        # Splunk and model-provider adapters
│   ├── services/            # Application workflow and report services
│   ├── worker/              # Background job execution and recovery
│   ├── config.py
│   ├── db.py
│   └── main.py
├── frontend/                # React application
├── migrations/              # Alembic migrations
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── e2e/
│   ├── fixtures/
│   └── known_answer/
├── deploy/docker/
├── scripts/
├── pyproject.toml
└── README.md
```

The first implementation block may make small naming changes if the framework requires them. After that, keep paths stable unless a change is needed to meet the specification.

## 4. Implementation rules that apply to every block

- Validate external input before saving, displaying, or executing it.
- Treat uploaded files, Splunk fields, Splunk events, and model responses as untrusted data.
- Keep secrets out of source code, logs, reports, tests, and browser responses.
- Keep the Splunk adapter, model-provider adapters, file storage, and database access behind small interfaces so tests can replace them with fakes.
- Enforce security and budget decisions in deterministic application code, never only in an LLM prompt.
- Make retries safe. A retry must not duplicate evidence, audit records, queries, or reports.
- Use stable identifiers and database constraints for deduplication.
- Log failures with hunt and operation identifiers, but never raw secrets or unnecessary customer data.
- Use database transactions for state changes that must succeed or fail together.
- Add a migration for every database change. Do not edit an old migration after it has been used.
- Do not use production or customer data in automated tests.
- Keep each pull request or review unit limited to one block or a clearly separable part of one block.

## 5. Implementation blocks

### Block 1 — Application foundation and enforceable contracts

Status: Not started

Objective: Create a runnable development system and implement the deterministic rules that all later work depends on.

Specification coverage: sections 3, 5, 7, 9, 11, 12, 16, 17, and 20.

Main work:

- Create the Python 3.12 backend, React frontend, test structure, README, and Docker Compose development setup.
- Add typed runtime configuration with startup validation. Separate ordinary settings from secrets.
- Add PostgreSQL access, Alembic, and the initial database migration.
- Define hunt, query, model-call, evidence, report, audit, upload, and snapshot identifiers.
- Implement the hunt state machine and its exact allowed state changes.
- Implement the canonical JSON contracts from specification section 7 as strict Pydantic models. Reject unknown fields where the specification does not allow them.
- Implement shared limit and budget objects, UTC timestamp handling, error categories, and retry classifications.
- Add application and worker health endpoints. Health checks must distinguish process health from dependency readiness.
- Run containers as non-root and verify TLS certificates for outbound connections by default.

Expected files:

- `pyproject.toml`, `README.md`, `.env.example`
- `src/threat_hunting/config.py`, `db.py`, `main.py`
- `src/threat_hunting/domain/`
- `migrations/`
- `frontend/`
- `deploy/docker/`
- `tests/unit/`, `tests/integration/`

Required tests:

- Every allowed state change succeeds; every other state change fails without altering the hunt.
- Each canonical JSON example validates, and malformed, incomplete, or extra-field examples fail as intended.
- Budget counters include failed calls and repair attempts.
- Configuration rejects missing required settings, invalid limits, and unsafe combinations.
- UTC serialization and report-timezone conversion are deterministic.
- Database migration upgrades a blank database successfully.
- Application and worker health checks report healthy, not ready, and dependency-failure states correctly.

Verification commands:

```bash
python -m pytest tests/unit tests/integration
python -m alembic upgrade head
docker compose -f deploy/docker/compose.yml config
docker compose -f deploy/docker/compose.yml build
npm --prefix frontend run build
```

Acceptance checks:

- A clean checkout can be configured from `.env.example`, built, migrated, and started without undocumented steps.
- The backend, worker, frontend, PostgreSQL, and persistent storage locations are present in the deployment definition.
- No secret value is committed or returned by a health endpoint.
- Contracts and state rules match the specification exactly.

Rollback note: This block creates the base system. Before shared deployment, rollback means reverting the block and removing only the new local development database and containers. Once a shared database exists, use Alembic downgrade or a documented forward-fix; never delete shared data.

### Block 2 — Login, private hunts, input handling, and the hunt shell

Status: Not started

Objective: Let an analyst sign in, create a private hunt, add bounded inputs, and see the hunt in the UI without running Splunk or a model yet.

Specification coverage: sections 3, 4, 5 phases 1 and 4, 12, 13, 15, 16, and 18.

Main work:

- Implement the simple local username/password login, secure password hashing, session handling, logout, and login rate limiting.
- Enforce hunt ownership on every API operation and storage lookup. Do not rely only on hidden UI controls.
- Add create, list, view, and cancel hunt APIs and their matching React screens.
- Implement safe upload handling for the supported file types and enforce the file-count, per-file, and total-size limits before full processing.
- Validate filenames, MIME/type expectations, parser results, and manual JSON/YAML/text inputs.
- Store uploads outside the web root using generated identifiers. Preserve hashes and the metadata required by the specification.
- Treat content extracted from files as data, not instructions to the model.
- Write append-only audit records for login and hunt actions.
- Show clear empty, loading, validation, authorization, cancellation, and failure states in the UI.

Expected files:

- `src/threat_hunting/auth/`
- `src/threat_hunting/api/auth.py`, `hunts.py`, `uploads.py`
- `src/threat_hunting/services/hunts.py`, `uploads.py`, `audit.py`
- new Alembic migration files
- `frontend/src/`
- `tests/unit/`, `tests/integration/`, `tests/e2e/`

Required tests:

- Successful login, bad credentials, rate limiting, logout, and expired session.
- One analyst cannot list, read, download, cancel, or guess another analyst's hunt or files.
- Valid uploads work; unsupported types, false extensions, oversized files, too many files, path traversal names, malformed documents, and decompression hazards fail safely.
- Cancelling a draft hunt follows the state rules and is idempotent.
- Stored content is not served as executable HTML or from a public file path.
- Audit records are created without passwords, session values, or raw authorization headers.
- Browser tests cover login, create hunt, upload/manual entry, validation errors, hunt list, and cancellation.

Verification commands:

```bash
python -m pytest tests/unit tests/integration
npm --prefix frontend run build
npm --prefix frontend run test:e2e
```

Acceptance checks:

- An analyst can complete the create-hunt flow using each supported input method.
- Hunt and file access stays private even when identifiers are manually changed in API requests.
- Invalid input never creates a partly valid hunt or an orphaned stored file.
- A cancelled hunt cannot be edited or restarted.

Rollback note: Roll back application code and the block's migration together. Preserve uploaded files until their database records are safely migrated or removed by the normal cleanup process.

### Block 3 — Splunk discovery, plan drafting, and mandatory approval

Status: Not started

Objective: Connect to Splunk safely, capture the exact environment seen by the hunt, draft a bounded plan, and require analyst approval before execution.

Specification coverage: sections 4, 5 phases 2 through 4, 6, 7, 8, 9, 10, 12, and 13.

Main work:

- Implement the thin, read-only Splunk adapter with TLS verification, timeouts, cancellation, normalized errors, and no leaked credentials.
- Implement bounded discovery and save the immutable discovery snapshot defined in specification section 4.
- Save the immutable execution-configuration snapshot before approval.
- Build the canonical model context from analyst inputs and snapshots.
- Implement OpenAI API and Amazon Bedrock adapters plus fake adapters for deterministic tests. Define the local-model adapter interface without claiming a real Gemma deployment works.
- Add structured model calls, JSON validation, the single permitted repair attempt, and usage accounting.
- Generate a plan draft using the exact contract in specification section 7.
- Add plan review and approval UI. Display the discovery time and the settings that will control execution.
- Hash and version the approved plan. Approval changes the state exactly once and makes the hunt immutable.
- Require cancellation and a new hunt for any post-approval change.

Expected files:

- `src/threat_hunting/integrations/splunk.py`
- `src/threat_hunting/integrations/models/`
- `src/threat_hunting/services/discovery.py`, `planning.py`, `snapshots.py`
- `src/threat_hunting/api/discovery.py`, `plans.py`
- new Alembic migration files
- plan and discovery screens under `frontend/src/`
- provider fakes and fixtures under `tests/fixtures/`

Required tests:

- Discovery is bounded, normalized, reproducible from its snapshot, and never searches event data beyond the approved discovery behavior.
- TLS, authentication, timeout, unavailable-Splunk, permission, and cancellation failures map to the correct safe error.
- Model adapters produce the same internal response type and preserve provider/model metadata without secrets.
- Valid structured output passes; invalid output gets at most one repair attempt; failed and repaired calls count toward limits.
- Missing facts remain `unknown`; prompt-injection text in analyst input, file content, or Splunk metadata cannot override system rules.
- Approval creates immutable plan/configuration/discovery versions and the correct audit record.
- Concurrent or repeated approval requests cannot approve twice or create conflicting versions.
- Browser tests cover discovery progress/failure, plan review, approval, and the rule that approved hunts cannot be edited.

Verification commands:

```bash
python -m pytest tests/unit tests/integration
npm --prefix frontend run build
npm --prefix frontend run test:e2e
```

Acceptance checks:

- A hunt cannot execute before explicit approval.
- The approved plan can always be tied to one discovery snapshot and one execution-configuration snapshot.
- Changing live operator settings after approval does not silently change that hunt.
- Automated tests work without real Splunk or model credentials; optional non-production smoke tests are separately marked and skipped when credentials are absent.

Rollback note: Retain snapshots and audit history when rolling back. If a provider adapter must be disabled, fail affected new calls clearly; do not silently switch an already approved hunt to another provider or model.

### Block 4 — Safe query execution, budgets, retries, cancellation, and recovery

Status: Not started

Objective: Execute approved hunts in the background while keeping every query and model call inside the approved safety, time, and cost limits.

Specification coverage: sections 5 phase 5, 6 through 12, and 17.

Main work:

- Implement the database-backed background job queue and worker claim/lease behavior.
- Make job start and resume idempotent so duplicate delivery cannot duplicate work.
- Implement the deterministic SPL parser/validator and reject commands, macros, subsearches, indexes, time ranges, and result sizes outside policy.
- Revalidate all generated SPL immediately before Splunk execution.
- Implement progressive queries, duplicate-query cache rules, per-query limits, per-hunt limits, deployment limits, and the daily 8:00 PM cutoff behavior.
- Use a database-safe deployment counter or lease so multiple workers cannot exceed shared concurrency or daily limits.
- Implement the retry matrix, backoff, model repair limit, paused states, and terminal failure rules from specification section 11.
- Implement cooperative cancellation for queued jobs, active Splunk searches, and model calls where supported. Ignore late results after cancellation.
- Implement heartbeat, stale-lease recovery, and abandoned-hunt handling from specification section 12.
- Add running-hunt API and UI views showing progress, consumed limits, recoverable pauses, failures, and cancellation.

Expected files:

- `src/threat_hunting/worker/`
- `src/threat_hunting/domain/spl_policy.py`, `budgets.py`, `retries.py`
- `src/threat_hunting/services/execution.py`, `recovery.py`, `query_cache.py`
- `src/threat_hunting/api/execution.py`
- new Alembic migration files
- running and paused hunt screens under `frontend/src/`
- concurrency and recovery tests under `tests/integration/`

Required tests:

- Every forbidden SPL construct is rejected before Splunk receives it; allowed SPL is not changed silently.
- Model-supplied index names, time bounds, and result limits cannot exceed the approved policy.
- Query, hunt, model, token, time, and deployment limits stop new work at the correct boundary.
- A hunt started before 8:00 PM may finish within its configured ceiling, while new work after cutoff is handled exactly as specified.
- Cache hits require compatible successful results; failed, cancelled, stale, or incompatible results are never reused.
- Retryable failures retry only to the configured limit. Non-retryable failures stop or pause the hunt as specified.
- Duplicate worker delivery, worker crash, application restart, and stale lease recovery do not duplicate queries or evidence.
- Cancellation wins races with late provider responses and leaves a consistent final state.
- Two or more workers cannot exceed deployment-wide limits under concurrent tests.
- Browser tests cover running, paused, limit-reached, failed, recovered, and cancelled states.

Verification commands:

```bash
python -m pytest tests/unit tests/integration
npm --prefix frontend run build
npm --prefix frontend run test:e2e
```

Acceptance checks:

- No SPL reaches Splunk without deterministic validation and an audit trail.
- No model or worker can bypass the approved budgets.
- Restarting a worker during a synthetic hunt resumes safely from stored state.
- The UI never claims a cancelled or failed hunt is still running.

Rollback note: Stop workers before rolling back execution code. Let leases expire or release them safely, keep persisted job history, and never delete in-flight records to force a clean state.

### Block 5 — Evidence, findings, reports, editing, finalization, and retention

Status: Not started

Objective: Turn completed hunt work into traceable evidence and an analyst-reviewed PDF, then remove all retained hunt data on the configured schedule.

Specification coverage: sections 5 phase 6 and sections 7, 12 through 16, 18, and 20.

Main work:

- Store normalized evidence with immutable source metadata, integrity hashes, query links, timestamps, and truncation information.
- Implement extracted entities, pivots, finding drafts, confidence, limitations, and citation validation using the canonical contracts.
- Keep direct evidence, context, and inference visibly separate. A finding cannot cite missing or unrelated evidence.
- Produce no-evidence and incomplete-hunt reports honestly, without invented conclusions.
- Build the report draft, analyst editing experience, save behavior, finalization state change, and PDF generation.
- Escape or sanitize all report content before HTML/PDF rendering and prevent local-file or network access from the renderer.
- Include a query appendix that remains understandable through the full retention period.
- Implement authorized report and evidence downloads with safe filenames and content types.
- Implement configurable retention cleanup for evidence, uploads, reports, snapshots, audit records, and related hunt data, defaulting to 90 days.
- Define and enforce `last activity` and `abandoned hunt` exactly as stated in the specification.
- Make cleanup restartable, idempotent, audited, and safe when files or database rows are already missing.

Expected files:

- `src/threat_hunting/services/evidence.py`, `findings.py`, `reports.py`, `retention.py`
- `src/threat_hunting/services/citations.py`
- `src/threat_hunting/api/reports.py`, `evidence.py`
- report templates and renderer configuration
- new Alembic migration files
- report workspace screens under `frontend/src/`
- retention and PDF fixtures under `tests/fixtures/`

Required tests:

- Evidence hashes and source links are stable and detect later modification.
- Each citation resolves to retained evidence and supports the claim it is attached to.
- Missing evidence, truncated results, unavailable data, and model uncertainty appear as limitations, not facts.
- No-evidence hunts produce a valid no-evidence report.
- Concurrent report saves do not silently overwrite analyst work.
- Only allowed states can be edited or finalized; finalization is idempotent and locks the report.
- Malicious HTML, links, file paths, and oversized content cannot escape the renderer or retrieve local/network resources.
- Another analyst cannot access report previews, PDFs, or evidence downloads.
- Cleanup honors the configured age, skips active hunts, handles abandoned hunts correctly, and deletes all covered artifacts together.
- Cleanup can rerun after partial failure without deleting newer or unrelated data.
- Browser tests cover evidence review, finding citations, report editing, finalization, PDF download, no-evidence, and incomplete-hunt reports.

Verification commands:

```bash
python -m pytest tests/unit tests/integration
npm --prefix frontend run build
npm --prefix frontend run test:e2e
```

Acceptance checks:

- Every report statement is either supported by a visible citation or clearly labeled context, inference, uncertainty, or limitation.
- The generated PDF contains the required sections and displays both UTC and the configured report timezone.
- Finalized reports are immutable.
- Retention applies one configurable period to evidence, PDFs, audit records, and the other hunt artifacts named in the specification.

Rollback note: Do not roll back a retention change by restoring already deleted data unless a tested backup is available. Pause cleanup before rollback, preserve reports and evidence, then use a forward migration if schema reversal could lose records.

### Block 6 — Known-answer validation, model qualification, and deployment handoff

Status: Not started

Objective: Prove the complete MVP behaves correctly, safely, and consistently in the supported deployment shape.

Specification coverage: sections 17 through 20, plus end-to-end validation of sections 1 through 16.

Main work:

- Build the twelve synthetic known-answer hunts and expected-evidence manifests defined in specification section 19.
- Cover successful hunts, no-evidence hunts, missing data, timeouts, truncation, retryable failure, terminal failure, cancellation, restart recovery, and citation checks across the twelve hunts.
- Implement the evidence-recovery scorer exactly as specified: expected evidence items recovered and correctly cited divided by the expected evidence items available to that hunt.
- Run all twelve hunts against deterministic fake Splunk and model services on every automated test run.
- Qualify OpenAI API and Bedrock configurations against the same known-answer hunts when non-production credentials are available. Keep these tests opt-in and record provider/model/version/settings.
- Test the local-model adapter contract with a fake provider. Mark real local Gemma deployment qualification as deferred work, without weakening the other acceptance checks.
- Run a non-production Splunk smoke test using only synthetic data.
- Verify fresh installation, migration ownership, startup order, health checks, non-root containers, TLS verification, persistent volumes, restart recovery, logs, backups, and operator configuration.
- Complete operator documentation for installation, configuration, model selection, Splunk permissions, backups, updates, recovery, retention, and known limitations.
- Record the final acceptance results and any deferred item already permitted by the specification.

Expected files:

- `tests/known_answer/`
- `tests/e2e/`
- `scripts/run_known_answer_hunts.*`
- `docs/operator-guide.md`
- `docs/acceptance-results.md`
- final deployment and README updates

Required tests:

- All deterministic unit, integration, browser, recovery, security-boundary, and known-answer tests from earlier blocks.
- Twelve-hunt allocation and case coverage match specification section 19 exactly.
- Evidence-recovery calculation has tests for full, partial, zero-expected, missing, duplicate, and wrongly cited evidence.
- The configured pass threshold is met without counting invented, duplicate, or incorrectly cited evidence.
- Fresh install and upgrade tests work from documented commands.
- Container restart during an active hunt preserves safe recovery behavior.
- Unsupported or unqualified model configurations fail clearly instead of appearing approved.

Verification commands:

```bash
python -m pytest
npm --prefix frontend run build
npm --prefix frontend run test:e2e
docker compose -f deploy/docker/compose.yml config
docker compose -f deploy/docker/compose.yml build
```

Run provider and non-production Splunk tests only through clearly named opt-in commands documented in `README.md`; they must skip safely when credentials are absent.

Acceptance checks:

- All deterministic tests pass from a clean checkout.
- The known-answer suite meets the accuracy requirement in specification section 19.
- OpenAI API and Bedrock qualification results identify the exact provider, model, version, and settings used.
- Real local Gemma qualification is clearly listed as deferred and is not presented as tested.
- A new operator can install, configure, run, back up, update, and recover the MVP using the documentation.
- No unresolved issue violates an in-scope acceptance requirement.

Rollback note: Keep the previously qualified image and migration instructions available. Application rollback must not use an older image against an incompatible newer schema. Restore from a tested backup only when a forward fix is not safe.

## 6. Dependency order and review gates

```text
Block 1: Foundation and contracts
  └── Block 2: Login, hunts, and inputs
        └── Block 3: Discovery, planning, and approval
              └── Block 4: Execution and recovery
                    └── Block 5: Evidence and reports
                          └── Block 6: Acceptance and handoff
```

At the end of each block:

- Review the change against the named specification sections.
- Run the block's verification commands from a clean test environment.
- Check database migration behavior in both the normal and failure paths.
- Confirm secrets and sensitive content are absent from logs and test artifacts.
- Confirm error, empty, loading, cancelled, paused, and success states exist where relevant.
- Update the progress log only after all acceptance checks pass.

Do not start a later block to hide a failure in an earlier one.

## 7. Traceability map

| Specification area | Primary implementation block | Final proof |
|---|---:|---|
| Objective and scope | All | Scope review in every block |
| User and authorization | 2 | Ownership and browser tests |
| Inputs and discovery | 2–3 | Parser, limit, and discovery tests |
| Workflow and state changes | 1–5 | State-transition and end-to-end tests |
| Agent and model architecture | 1, 3–5 | Contract, repair, grounding, and provider tests |
| Splunk connector and SPL policy | 3–4 | Adapter and deterministic validator tests |
| Limits, cost control, retries, and stopping | 1, 4 | Boundary and concurrent-worker tests |
| Persistence, audit, and recovery | 1–5 | Migration, idempotency, restart, and audit tests |
| Evidence and reports | 5 | Citation, PDF, and no-evidence tests |
| Retention | 5 | Cleanup age, activity, and partial-failure tests |
| Stack and deployment | 1, 6 | Clean build, health, restart, and handoff tests |
| Data handling | 2–6 | Input, logging, access, and synthetic-data tests |
| Validation and adjustable settings | 1–6 | Known-answer and configuration tests |

## 8. Definition of MVP complete

The MVP is complete only when:

- All six blocks meet their acceptance checks.
- All in-scope behavior in the specification is implemented.
- All deterministic automated tests pass from a clean checkout.
- The twelve synthetic known-answer hunts meet the required evidence-recovery threshold.
- OpenAI API and Bedrock qualification results are recorded for the configurations actually tested.
- Real local Gemma testing is clearly deferred and no claim says it was qualified.
- The deployment starts with documented commands, runs non-root, validates TLS, preserves required data, and reports useful health status.
- The operator guide and acceptance results match the shipped code and configuration.
- No critical or high-severity defect remains open.
- No feature outside the approved MVP scope was added.

## 9. Progress log

Update this table during implementation. Do not mark a block complete until its tests and acceptance checks pass.

| Block | Status | Completion date | Verification evidence | Approved deviations |
|---:|---|---|---|---|
| 1 | Not started | — | — | None |
| 2 | Not started | — | — | None |
| 3 | Not started | — | — | None |
| 4 | Not started | — | — | None |
| 5 | Not started | — | — | None |
| 6 | Not started | — | — | None |
