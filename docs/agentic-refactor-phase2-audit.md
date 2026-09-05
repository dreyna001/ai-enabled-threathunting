# Agentic Refactor Phase 2 Audit

Status: Phase 2 audit and contained hardening complete; Phase 3 blocked on baseline mismatch  
Audit date: 2026-09-02  
Authorities: [MVP specification](./threat-hunting-mvp-spec.md), [MVP implementation plan](./implementation-plan.md), and [agentic refactor plan](./agentic-threat-hunting-refactor-plan.md)

## Scope match

The checked-out repository is not the implementation baseline described by the external refactor handoff.

- The handoff describes a completed planning and execution application with phase skills, `worker/runner.py`, `services/execution.py`, `services/planning.py`, `services/materialization.py`, `domain/spl_policy.py`, PostgreSQL hunt execution state, and a known-answer harness.
- Those components do not exist in this checkout.
- [README.md](../README.md) identifies Implementation Block 1 as still in progress.
- The only worker behavior in `src/threat_hunting/worker/main.py` is a heartbeat loop.
- The only committed repository documents before this refactor were the MVP plans. The application, deployment, migrations, frontend, and tests are currently untracked working-tree content and were preserved as user work.
- The checkout is `main` at `982ba34`; it is not the handoff's reported `dc9c42f` baseline.

Implementing Phases 3, 4, and 6 from this state would require silently implementing substantial portions of MVP Blocks 2 through 4 first. That is a material scope expansion and violates the refactor plan's instruction to preserve the existing investigation loop rather than restart it.

## Critical findings

### C-1 — Deterministic SPL policy and safe execution boundary are absent

Evidence:

- `src/threat_hunting/domain/spl_policy.py` is absent.
- `SplunkConnector.validate_query()` only checks that a string is non-empty.
- `SplunkConnector.submit()` sends that string to Splunk without an approved-plan, discovery, absolute-time, index, field, command, or budget policy decision.
- There is no runner that could supply or persist the required validation result and audit decision.

Impact: arbitrary mutating or otherwise prohibited SPL can reach the adapter if `submit()` is called directly. The current heartbeat-only worker does not expose this as a complete hunt path, but execution must remain disabled until the deterministic policy and execution service exist.

Rules: MVP specification sections 6, 8, 9, and 12; `cybersecurity-approval-policy-gates`; `llm-deterministic-guardrails`; refactor DB-5 and DB-6.

Minimum resolution: implement the MVP Block 4 query-policy and execution boundary before enabling any direct or MCP execution. Bind every validation to the immutable approval, plan scope, discovery snapshot, policy version, and remaining budgets. Add allow/deny tests that prove rejected SPL never reaches the fake connector.

### C-2 — Planning, approval-bound execution, recovery, and audit persistence are absent

Evidence:

- `src/threat_hunting/agent/`, planning services, execution services, and `worker/runner.py` are absent.
- Migration `0001_foundation` creates only `worker_heartbeats`.
- There is no durable hunt queue, approval record, execution record, query ledger, model-call ledger, Splunk job recovery state, or append-only audit table.

Impact: threat-skill selection cannot be placed before final approval or pinned into an execution snapshot because neither the planning/approval workflow nor execution snapshot persistence exists. MCP cannot validate an approved execution context that has not been implemented.

Rules: MVP specification sections 4 through 7 and 12; refactor DB-2, DB-5, and DB-7.

Minimum resolution: complete the relevant MVP Blocks 2 through 4 or switch to the repository/branch described by the handoff before starting refactor Phase 3.

### C-3 — Structured model output has no workflow-level validation and repair boundary

Evidence:

- Provider adapters can parse a JSON-shaped `structured` value, but no planning or investigation service validates it against the step-specific Pydantic contract.
- There is no parse, validate, bounded repair, usage-accounting, or explicit-failure orchestration.
- Provider adapters now reject caller-supplied `system` messages and snapshot nested message content after validation, but no workflow exists to delimit telemetry and skill content or validate step-specific output contracts.

Impact: DB-1 through DB-4 cannot safely consume threat skills or telemetry until trusted prompt construction and strict per-step validation exist.

Rules: MVP specification sections 6 and 7; `cybersecurity-workflow-design`; `security-evidence-discipline`; refactor DB-3, DB-4, and DB-8.

Minimum resolution: implement one trusted system-instruction path, labeled and delimited untrusted context, strict output models, a maximum of two budgeted repairs per the MVP specification, and explicit failure after repair exhaustion.

### C-4 — Evidence lineage and report finalization can be bypassed by current service callers

Evidence:

- `build_evidence()` accepts caller-provided query, job, source-row, index, and selected-result values without resolving them against a completed query result.
- Evidence persistence validates owner presence and the evidence hash but not source-row existence, query ownership, query completion, or hunt association.
- Finding persistence accepts references without resolving them transactionally.
- Report citation checks depend on optional repository methods, and the SQL report repository does not provide the complete citation lookup contract.
- The current artifact tables are created from service code rather than represented by Alembic migrations with relational constraints.

Impact: a future model or compromised service caller could materialize fabricated or cross-hunt lineage despite otherwise strong evidence hashing.

Rules: MVP specification sections 7, 12, 13, and 14; `security-evidence-discipline`; refactor DB-3 and DB-8.

Minimum resolution: materialize only adapter-issued result-row references from completed, owner-scoped queries; enforce foreign keys or equivalent transactional resolution; make citation validation mandatory before persistence and finalization; add forged, missing, nested, and cross-hunt reference tests.

### C-5 — Runtime model transport configuration does not fully propagate the documented TLS boundary

Evidence:

- Runtime TLS settings are not consistently propagated into model-adapter construction.
- Runtime `ModelSettings` coercion currently drops TLS, CA bundle, and credential fields even though direct adapter configuration now requires HTTPS, rejects embedded credentials/query/fragment material, masks API keys, and emits only endpoint origin metadata.

Impact: runtime-created adapters can ignore the configured CA/trust settings or omit configured credentials, causing a secure deployment to fail or use provider/environment defaults instead of the reviewed runtime contract. Directly configured adapters fail closed on non-HTTPS or credential-bearing endpoint URLs.

Rules: MVP specification sections 17 and 18; `security`; refactor DB-7.

Minimum resolution: propagate the approved TLS/CA and secret configuration through the runtime model factory without introducing a permissive fallback.

## High-ROI should-fix findings

The following contained fixes were completed in Phase 2 without inventing the missing workflow:

1. Align in-code hunt-limit defaults with the MVP/runtime YAML values so omitted YAML sections cannot silently grant larger budgets.
2. Make discovery and retained-evidence snapshots mutation-proof after construction so approved scope and hashed evidence cannot change in memory.
3. Classify certificate failures before generic `OSError` handling so they remain non-retryable.
4. Allow best-effort Splunk cancellation cleanup after the hunt cancellation signal is set.
5. Derive evidence replay deduplication from immutable source identity rather than collection time while retaining collection time in the integrity hash.
6. Reject incoherent stop reason/disposition combinations and require coverage or limitations for non-positive conclusions.
7. Reject caller-supplied model system roles and freeze validated nested messages against post-validation mutation.
8. Require HTTPS model endpoints, reject URL credentials/query/fragment material, mask API keys, and retain only safe origin metadata.
9. Normalize blank evidence source references and derive persisted replay deduplication keys from immutable source identity.
10. Thread cancellation through Splunk discovery calls, propagate cancellation instead of degrading it into a partial result, and bound SDK collection/endpoint iteration and streamed response bytes.

Additional should-fix work that depends on the missing execution boundary:

- reconcile the documentation conflict between the MVP specification's two allowed repair retries and the implementation plan's single repair attempt; the specification is authoritative;
- reconcile the unused `query_start_cutoff_utc: 20:00` configuration with the MVP specification's relative eight-minute query-start cutoff before implementing execution;
- reconcile unknown Splunk submit outcomes before retrying; a thread timeout does not stop an underlying SDK call;
- apply equivalent byte accounting to executed result decoding when the missing execution boundary is implemented;
- wire Splunk and model credentials exclusively from secret files with redacted configuration objects;
- project only the minimum relevant result fields into model requests;
- replace runtime table creation with forward Alembic migrations and relational ownership/lineage constraints.

## Nice to have

- Add static type checking and linting only after the existing repository chooses and documents those tools.
- Add richer discovery freshness and ambiguity metadata with the threat-skill capability map in Phase 3.
- Add Pydantic Evals for probabilistic skill-selection quality after the deterministic selection contract exists.

## Explicitly deferred or out of scope

- FastMCP service, MCP network exposure tests, and worker MCP migration remain Phases 6A and 6B.
- Mid-hunt skill expansion remains deferred from selection v1.
- Real local Gemma qualification and production CUI responsibility documentation remain deferred by the MVP specification.
- Live OpenAI or Splunk qualification was not attempted without approved non-production credentials.

## Verification evidence

- Python unit and integration tests: `80 passed` using `TMPDIR=/tmp .venv/bin/python -m pytest -q` (one upstream Starlette/httpx deprecation warning).
- Python bytecode compilation: passed using `.venv/bin/python -m compileall -q src tests`.
- Frontend unit tests: `7 passed` using `npm --prefix frontend run test:unit`.
- Frontend production build: passed using `npm --prefix frontend run build`.
- Docker Compose validation: attempted but unavailable because the `docker` command is not installed in this WSL distro.
- The refactor plan's known-answer scripts are absent from this checkout, so those gates could not be run.
- Daybreak Blue performed separate workflow/evidence and Splunk/policy reviews. Both independently identified the missing execution baseline as a critical prerequisite blocker.

## Phase gate

Do not start Phase 3 in this checkout until one of these is true:

1. the intended repository/branch containing the completed investigation loop is provided; or
2. the user explicitly expands scope to complete the prerequisite MVP Blocks 2 through 4 in this repository before resuming the refactor.

This gate prevents threat skills and MCP from being built against placeholder execution paths that cannot enforce approval, evidence, replay, or SPL policy contracts.
