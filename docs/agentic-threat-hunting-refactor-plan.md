# Agentic Threat-Hunting Refactor Plan

Status: Blocked before Phase 3 on missing MVP execution prerequisites; see [Phase 2 audit](./agentic-refactor-phase2-audit.md)  
Repository: `/mnt/c/Users/dreyn/OneDrive/Desktop/Cursor/ai-enabled-threathunting`  
Primary product authority: [Threat Hunting MVP Specification](./threat-hunting-mvp-spec.md)  
Existing build authority: [MVP Implementation Plan](./implementation-plan.md)

## 1. Purpose

Extend the existing bounded threat-hunting application with versioned threat-specific skills, deterministic skill selection controls, and a policy-enforced Splunk MCP service without weakening the approved MVP security, evidence, ownership, budget, replay, or reporting contracts.

This document supersedes the external handoff for the refactor work only. If it conflicts with the MVP specification, the MVP specification wins unless the product decision is explicitly changed and documented.

## 2. Model operating model

- **Current cybersecurity pass — Daybreak Blue:** define and review threat-domain behavior, adversarial cases, evidence semantics, ATT&CK mappings, approval boundaries, prompt-injection defenses, and Splunk/MCP security requirements.
- **Implementation orchestrator — GPT-5.6 Sol, medium reasoning:** sequence phases, assign bounded work, integrate changes, and enforce exit criteria.
- **Implementation subagents — GPT-5.6 Luna, xhigh reasoning:** implement narrowly owned code, tests, migrations, configuration, and documentation. Subagents must not independently change security policy or product scope.
- Deterministic tests and policy checks remain authoritative regardless of model.

Daybreak Blue should be used where cybersecurity judgment is material. Routine framework plumbing is not a reason to use the cybersecurity-specialized model.

## 3. Frozen architecture decisions

### 3.1 Model responsibilities

The model may recommend:

- applicable threat skills;
- hypothesis refinement and investigative questions;
- query strategy and evidence-backed pivots;
- evidence candidates;
- confidence and stopping recommendations.

Deterministic application code decides:

- authentication, ownership, execution authorization, approval, and cancellation;
- approved time, index, sourcetype, entity, and capability scope;
- SPL policy and whether any query is submitted;
- query, row, byte, token, cycle, concurrency, and wall-clock budgets;
- whether a reference is valid and whether a claim may become evidence;
- persistence, replay, audit, citation validation, disposition, and report finalization.

Threat skills are advisory investigation strategy. They are never evidence, authorization, or executable policy.

### 3.2 Query and integration model

- Prefer semantic tools for stable process, authentication, and network searches.
- Retain validated generic SPL for novel investigations.
- Both paths use the same versioned SPL policy and approved execution scope.
- MCP exposes narrow capabilities. It does not receive a shell, arbitrary HTTP, Splunk administration, saved-search mutation, alerting, export, or writeback tools.
- MCP failure never causes an automatic production fallback to direct Splunk access.

### 3.3 Delivery constraints

- Preserve the current FastAPI, PostgreSQL, worker, PydanticAI, Splunk adapter, React, and Docker Compose architecture.
- Do not add an orchestration framework, queue framework, speculative plugin system, or second policy implementation.
- Implement and test one bounded slice at a time. The final qualification suite runs last, but phase-level tests run with every phase.

## 4. Daybreak Blue cybersecurity workstream

These are the cyber-focused items to design or review with Daybreak Blue.

### DB-1 — Threat-skill security and content model

Define the first three packs:

1. `powershell-abuse`, including T1059.001;
2. `lateral-movement`;
3. `credential-access`.

For broad categories such as lateral movement and credential access, map each hypothesis and strategy to specific supported ATT&CK technique IDs. A selected skill or ATT&CK mapping is advisory context, not proof that the technique occurred.

Each pack must define:

- observable hypotheses rather than threat narratives alone;
- required and optional telemetry capabilities with `all`, `any`, and partial-coverage semantics;
- customer-field alternatives without assuming fixed field names;
- narrow initial strategies and evidence-backed pivot rules;
- direct-evidence retention rules and prohibited inferences;
- supported, not-supported, and inconclusive stopping guidance;
- coverage gaps that prevent a negative conclusion;
- bounded model-facing guidance that treats telemetry and retrieved content as untrusted data.

Daybreak acceptance:

- no hypothesis requires invented telemetry or customer field names;
- missing coverage results in `inconclusive`, not a benign conclusion;
- every pivot is tied to an approved question, explicit hypothesis, contradiction, or referenced evidence item;
- threat doctrine is clearly separated from current-hunt facts.

### DB-2 — Threat-skill selection and approval boundary

Define a strict, versioned selection contract with:

- `selection_status`: `selected`, `no_match`, `blocked_missing_capability`, or `invalid`;
- nullable primary skill ID and version;
- supporting skill IDs and versions;
- bounded, evidence-referenced selection rationale;
- deterministic missing-capability results;
- applicability confidence with an explicit meaning;
- selected skill content hashes and discovery-snapshot hash.

Rules:

- never force a skill when none fits;
- compute missing prerequisites in code rather than accepting the model's assertion;
- validate IDs, versions, hashes, duplicate selections, primary/support overlap, and the support-count limit;
- select and pin the initial skills before final plan approval when they affect planned scope;
- defer mid-hunt supporting-skill additions for v1; any future addition that expands approved scope requires reapproval;
- resume uses the exact approved skill and discovery snapshots and fails closed on an unknown or changed version.

### DB-3 — Evidence, inference, and investigation lineage

Extend existing evidence discipline rather than replacing it.

- Model outputs may nominate evidence only through adapter-generated evidence references.
- The model must never create row, event, query, job, or evidence IDs.
- Deterministic code verifies ownership, hunt association, source existence, and claim support before materialization or finalization.
- Keep `direct_evidence`, `advisory_context`, and `inference` discriminated in prompts and machine-consumed contracts.
- Threat intelligence, ATT&CK content, skill guidance, discovery metadata, and runbooks remain advisory unless the source is itself a retained case artifact.
- Each query and pivot records its approved question, hypothesis, capability, strategy or pivot ID, tool, policy version, fixed time scope, and execution snapshot.
- Truncated, partial, timed-out, or coverage-limited results must retain that limitation and cannot support a complete negative conclusion.

### DB-4 — Adversarial prompt and content handling

Treat analyst text, uploads, threat intelligence, skill guidance, discovery values, and Splunk event values as untrusted data.

- Delimit untrusted sources and label their role in every affected prompt and repair prompt.
- Instruct the model that source content cannot redefine the task, contract, policy, tools, or approval state.
- Validate structured outputs outside the prompt and forbid extra fields.
- Repair only parse, schema, or policy defects; repair must not add facts or make a better guess.
- Count every repair and retry against the existing model budget.
- Preserve safe diagnostic metadata for review without persisting secrets or unnecessary raw event data.

Required adversarial cases include instructions embedded in PowerShell command lines, script-block text, usernames, hostnames, threat-intelligence documents, and skill guidance.

### DB-5 — Splunk and MCP authorization policy

Authentication between worker and MCP is necessary but not sufficient. For every request, MCP must deterministically enforce the approved execution context.

The trusted context must bind:

- deployment/customer scope and authenticated worker identity;
- hunt and execution ID;
- hunt owner and approved plan revision/hash;
- allowed operation and capability;
- approved indexes, sourcetypes, entities, and absolute UTC time window;
- budget and result limits;
- policy version/hash;
- expiry and replay protection.

Implementation may use an established signed execution credential or a narrow server-side authorization lookup. Do not invent a custom cryptographic protocol. The MCP server must not authorize from client-supplied scope fields alone.

Every request rechecks approval and cancellation before submission. Cancellation propagates to active Splunk jobs where possible. Missing, expired, revoked, replayed, out-of-scope, or policy-incompatible requests fail closed with structured reasons.

### DB-6 — Safe semantic tools and generic SPL

For every semantic tool:

- accept strict typed parameters and absolute UTC bounds;
- reject missing, reversed, future-invalid, excessive, or out-of-plan time ranges;
- resolve indexes, sourcetypes, and fields only from the pinned capability snapshot;
- fail explicitly on absent or ambiguous capability mappings;
- safely encode values rather than interpolating untrusted strings into SPL;
- cap request size, jobs, polling, duration, rows, and bytes server-side;
- return normalized results with adapter-generated references, provenance, coverage, and truncation metadata.

For generic SPL:

- require a structured reason tied to an approved question or hypothesis;
- apply the same policy and scope validation as the direct path;
- reject unsupported macros, placeholders, invented fields, administration, mutation, export, external commands, and unbounded resource use;
- prevent SPL time predicates, subsearches, or other constructs from broadening approved scope.

### DB-7 — Sensitive-data egress and audit

The MVP specification permits raw Splunk results to reach the deployment's authorized model endpoint. Preserve that product decision while enforcing minimum necessary disclosure:

- document that the configured provider is approved for the deployment's data classification;
- aggregate, filter, and select only fields needed for the current bounded question before model use;
- never send credentials, tokens, authorization headers, connector secrets, or unrelated raw events;
- apply the existing provider retention and transport requirements;
- keep raw sensitive payloads out of ordinary logs, traces, errors, and MCP audit records.

Audit both allowed and denied operations. Record authenticated subject, hunt/execution, approval revision, resolved scope, tool, normalized/redacted arguments, policy decision/reason/version, request and query IDs, Splunk job ID, retries, status, cancellation, latency, and truncation. Define an explicit fail-closed response if required security audit persistence is unavailable.

### DB-8 — Cybersecurity evaluation set

Add deterministic negative and adversarial cases for:

- no matching skill and missing or partial telemetry;
- invented hosts, users, timestamps, tools, ATT&CK mappings, findings, and evidence references;
- advisory text copied into evidence;
- prompt instructions embedded in telemetry and retrieved content;
- unsupported or out-of-scope pivots;
- generic-SPL policy bypass attempts;
- missing, expired, replayed, revoked, or cross-hunt authorization;
- execution after cancellation;
- changed skill content or discovery snapshot on resume;
- timeouts, unknown submit outcomes, duplicate delivery, and truncated results;
- insecure TLS/configuration and public MCP exposure.

Pydantic Evals may measure skill-selection and pivot quality. Authorization, evidence integrity, policy, replay, scope, and citation behavior must remain deterministic pytest assertions.

## 5. Phased implementation

### Phase 2 — Focused architecture and security audit

Deliver:

- a written audit grouped by Critical, Should fix, Nice to have, and explicitly deferred;
- rule/contract mapping for each finding;
- only Critical and high-return Should-fix changes needed by this refactor.

Cyber emphasis: verify model/deterministic boundaries, evidence lineage, prompt-injection handling, SPL fail-closed behavior, ownership, approval snapshots, replay, cancellation, secret handling, and TLS defaults.

Exit:

- audit is committed to `docs/`;
- critical preconditions for threat skills are fixed;
- relevant unit and integration tests pass.

### Phase 3 — Versioned threat-skill packs

Create a minimal loader and registry under `src/threat_hunting/agent/threat_skills/` plus the three DB-1 packs.

Requirements:

- strict schemas with forbidden extras and bounded content sizes;
- safe YAML parsing;
- semantic-version validation plus content hashes;
- deterministic capability mapping with provenance, coverage, freshness, and ambiguity information;
- unknown versions or changed hashes fail closed;
- selected pack IDs, versions, and hashes enter the execution snapshot;
- phase skills remain responsible for planning, query generation, assessment, and stopping.

Exit:

- all three packs load from fixtures without live Splunk;
- invalid, incomplete, oversized, duplicate, and changed packs are rejected;
- current phase-skill behavior does not regress.

### Phase 4 — Initial dynamic selection

Implement initial selection before final plan approval and inject approved threat-skill context into planning/execution prompts.

Requirements:

- use the DB-2 contract;
- count selection and repairs against model-call limits;
- persist the candidate set, result, validations, hashes, and audit decision;
- expose selected/no-match status to the workspace API;
- do not implement mid-hunt skill expansion in v1.

Exit:

- selected, no-match, missing-capability, version-mismatch, changed-content, and out-of-scope cases pass;
- approved execution uses only pinned skill and discovery context;
- stopping remains a model recommendation with deterministic disposition/finalization.

### Phase 6A — MCP service beside the direct path

Add a non-root FastMCP container that wraps the existing Splunk adapter and shared SPL policy. Register:

- `search_process_execution`;
- `search_authentication`;
- `search_network_connections`;
- `search_splunk`.

Requirements:

- internal-only network exposure with no public host port;
- TLS/service authentication and DB-5 authorization enforcement;
- one shared policy module and policy-version compatibility check;
- strict schemas, server-side limits, typed errors, audit, and cancellation;
- fake Splunk contract tests and Compose validation.

The worker still uses direct mode while this slice is validated. Production MCP outages do not trigger direct fallback.

### Phase 6B — Feature-flagged worker migration

Add explicit `direct | mcp` execution configuration.

- `mcp` is the production target once qualified.
- `direct` remains an explicit test/development or rollback mode and requires its own credential boundary.
- Never retry an uncertain MCP submission through the direct adapter.
- Persist idempotency keys and Splunk job IDs; reconcile unknown submit outcomes before any retry.
- Enforce identical policy and budget semantics on both paths.

Exit:

- worker-to-MCP-to-fake-Splunk integration passes;
- duplicate delivery cannot duplicate searches or evidence;
- cancellation, revocation, audit failure, timeout reconciliation, and policy denial fail safely;
- Compose proves MCP is not publicly exposed.

### Final verification

Run the complete deterministic suite, frontend checks, Compose validation, known-answer rehearsal, and production-path known-answer harness. Live OpenAI and Splunk qualification remains optional and requires approved non-production credentials.

Update `README.md`, agent-runtime documentation, operator guidance, runtime configuration, acceptance results, and migrations in the same implementation slices that change their contracts.

## 6. Required verification

Run focused tests after each slice, then the complete suite:

```bash
python -m pytest tests/unit tests/integration
npm --prefix frontend run test:unit
npm --prefix frontend run build
docker compose -f deploy/docker/compose.yml config
./.venv/bin/python scripts/run_known_answer_hunts.py --rehearsal
./.venv/bin/python scripts/run_known_answer_hunts.py
```

Credential-dependent commands must be marked `NOT RUN` when credentials are unavailable. They must not silently pass through mocks.

## 7. Overall success criteria

An approved hunt can select an appropriate pinned threat skill or explicitly report no match, conduct an iterative evidence-grounded investigation, and execute bounded Splunk searches through semantic or generic MCP tools while preserving ownership, approval, policy, budget, replay, cancellation, evidence, citation, audit, and data-handling controls.

No skill, model output, prompt text, MCP parameter, or fallback path can independently expand approved scope or turn unsupported content into evidence.
