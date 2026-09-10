# Agentic Threat Hunting Workspace — MVP Specification

## 1. Objective

Build a focused, production-ready threat-hunting capability for government customers that can be deployed and operationalized with minimal customer-specific development or manual configuration.

Customer setup must be limited to normal deployment, integration access/permissions, and hunt inputs and scope. Manual log normalization, customer-authored correlation scripts, prompt maintenance, and bespoke baseline authoring must not be prerequisites for reliable operation. Discovery, supported source interpretation, IOC comparisons, query handling, and routine evidence validation are application responsibilities. Existing environment documentation and organization context remain optional aids. Missing or inconsistent telemetry must produce actionable diagnostics and appropriately limited conclusions; mandatory analyst plan review does not transfer responsibility for application correctness to the customer.

The MVP is an ad hoc threat-hunting workspace in which an AI agent:

1. Discovers the customer's available Splunk data.
2. Uses threat intelligence and customer context to draft a formal hunt plan.
3. Waits for mandatory analyst review and approval of that plan.
4. Executes the approved hunt autonomously within fixed limits.
5. Produces an editable report and one finalized PDF report.

Threat emulation is not part of the capability.

## 2. MVP Scope

### Included

- Splunk as the only hunt system.
- One configured Splunk connection per customer deployment.
- Ad hoc hunts.
- One bounded threat-hunting agent.
- Mandatory human review of the hunt plan.
- Autonomous execution after plan approval.
- OpenAI API models.
- Amazon Bedrock models.
- On-premises models served by vLLM through LiteLLM.
- Local user accounts.
- One user type: `threat hunter`.
- Private hunts visible only to their owning user.
- CUI support.
- Editable workspace report followed by a finalized PDF.
- On-premises deployment first using Docker Compose.

### Explicitly excluded

- Threat emulation.
- CrowdStrike connectors.
- Data-lake connectors.
- Multi-system hunts.
- Detection export.
- Case creation.
- Collaboration.
- Multiple user roles.
- Automatic model-provider failover.
- LangGraph, CrewAI, AutoGen, Celery, Redis, Next.js, Tiptap, or another agent-orchestration framework.

## 3. User and Authorization Model

- The MVP has multiple local accounts.
- The only application role is `threat hunter`.
- Hunts are private to the user who created them.
- Accounts are created locally.
- The initial and additional accounts are created with an operator-run application CLI command inside the deployment; an account-administration web screen is not required.
- The CLI accepts the password through an interactive hidden prompt or protected standard input, never as a command-line argument, normal environment variable, or log entry.
- Usernames are normalized, required to be unique, and cannot be changed during the MVP.
- Passwords are hashed with Argon2id using `argon2-cffi`.
- Every hunt, plan, query, evidence item, workspace artifact, report, and download is checked against the authenticated owning user before it is returned or changed.
- Worker processes use the same ownership checks when loading or updating hunt data.
- The MVP uses a simple authenticated session after login and does not include self-registration, MFA, SSO, password recovery, an account-administration UI, or advanced account-security features.
- Broader login and account hardening is deferred because the MVP is focused on proving threat-hunting accuracy and workflow behavior.
- Everything accessible through the configured Splunk service account is already approved for hunting.
- The agent does not request approval before accessing an index, sourcetype, field, or other Splunk data that the service account can access.
- The only mandatory human approval is the hunt-plan review.

## 4. Hunt Inputs and Data Discovery

### Hunt inputs

The workspace accepts threat-hunt context such as:

- Open-source threat intelligence.
- CISA information or feeds.
- Subscription threat-intelligence information.
- Customer-provided intelligence.
- Customer-provided data dictionaries, index documentation, sourcetype documentation, or similar environment documentation.

For the MVP, analysts provide this material by pasting text or uploading files. The application does not connect to, poll, or automatically download from CISA, subscription feeds, websites, or other threat-intelligence services. A reference to a feed means analyst-supplied content from that feed.

### Customer data shape

- Customers are not required to transform documentation into a prescribed input shape.
- A customer may provide a document in any layout or schema; the customer does not have to reshape its content for the application.
- Supported MVP upload formats are PDF, DOCX, XLSX, CSV, TSV, TXT, Markdown, JSON, YAML, and YML.
- The application extracts relevant information from the document into its internal catalog.
- Uploaded documentation is optional; the agent must be able to discover the environment directly from Splunk.
- Default upload limits are 25 MB per file, 10 files per hunt, 100 MB total per hunt, and 2,000,000 extracted text characters per hunt. Operators may change these limits without rebuilding the image.
- File extension, detected content type, and parser must agree. Corrupt, encrypted, password-protected, unsupported, or non-extractable files fail with a clear error and are not sent to a model.
- Parsing uses bounded CPU, memory, decompressed-size, worksheet, row, and page limits. Nested archives, archive bombs, active content, macros, external entity resolution, and parser network access are rejected or disabled.
- The MVP does not promise OCR for image-only or scanned documents.
- Uploaded filenames are treated as display metadata only. Storage uses application-assigned IDs and never uses an uploaded filename as a filesystem path.
- Each upload records its application ID, original filename, detected type, byte size, SHA-256 hash, uploader, upload time in UTC, parser version, extraction status, and extraction errors.

### Splunk discovery

The agent can discover:

- Accessible indexes.
- Accessible sourcetypes.
- Available fields and representative schemas.
- Time coverage and retention information that Splunk exposes.
- Accelerated data models and `tstats` availability.
- Data quality and coverage limitations observed during discovery.

Prompt contract 1.6 starts with catalog metadata, drafts the hunt scope, then samples that scope before the final plan is reviewed. It samples up to 100 events for each exact index/sourcetype pair, with at most eight pair searches. Sampling stays within the proposed dates; ranges longer than seven days use their final seven days. The snapshot records both the requested scope and actual sampling bounds. When field context changes, one bounded model revision uses the refreshed snapshot and must preserve the sampled scope. Sampled field absence does not establish that a source lacks that capability.

The production catalog includes configured sourcetypes and a bounded indexed-field `tstats` query for observed sourcetypes; saved source configuration is not treated as an exhaustive inventory of indexed data. The query uses exact validated catalog/proposed indexes and existing discovery transport, item and byte limits, returns no raw events, and marks failure or truncation as partial discovery. The catalog does not prove source pairing, hunt-window activity, or continuous coverage.

Analyst edits to the source pairs or dates refresh discovery and its snapshot binding without a model rewriting the edited plan. A failed refresh leaves the previous plan intact. Approval checks that the reviewed scope matches its discovery snapshot.

Discovery results are persisted and used to draft the hunt plan. Customer-provided documentation supplements discovery but does not replace it.

### Splunk discovery snapshot

Each planning run saves a discovery snapshot. In plain terms, this is a dated picture of what the application knew about Splunk when it created the plan.

The snapshot contains:

- A unique snapshot ID.
- The hunt ID and configured Splunk connection identifier.
- The UTC time when discovery completed.
- Accessible indexes, sourcetypes, fields, representative schemas, time coverage, accelerated data models, and `tstats` availability.
- Known coverage gaps, discovery errors, incomplete results, and truncation information.
- References to customer-provided documentation that supplemented discovery.

The hunt plan records the snapshot ID it used. The snapshot is not overwritten later. A later discovery creates a new snapshot so the application can always explain what information was available when a plan was written and approved.

### Execution configuration snapshot

Before a plan is presented for approval, the application saves the exact non-secret settings that would govern execution. This immutable snapshot contains:

- Model provider, model name, logical endpoint configuration ID, and model parameters.
- Prompt and structured-contract versions.
- SPL query-policy version.
- All resolved per-hunt query, result, time, concurrency, model-call, and token limits, plus the deployment-wide caps in effect when approval occurred.
- Report-template version and application image version.

The snapshot has an application-assigned ID and SHA-256 hash and contains no credentials or secret values. The plan and approval record reference it. Later operator configuration changes do not raise or otherwise change the approved hunt's per-hunt limits. A lower current deployment-wide safety cap may still reduce concurrency or delay the queued hunt; it never grants the hunt more authority or budget.

## 5. Hunt Workflow

### Phase 1: Create hunt

The analyst creates an ad hoc hunt and supplies available threat intelligence, context, and optional customer documentation.

### Phase 2: Discover Splunk

The agent uses the configured Splunk connection to learn what data is available. It does not require a customer-specific schema.

### Phase 3: Draft plan

The agent creates a formal, structured hunt plan. The plan is persisted as canonical structured JSON. Narrative plan fields are editable in the Lexical workspace editor.

### Phase 4: Mandatory plan review

The analyst must choose one of the following:

- Approve the plan.
- Revise the plan.
- Ask the agent to revise the plan.

The hunt cannot execute until the analyst approves the plan.

Approval applies to one exact version of the plan:

- Every saved plan has a version number and a SHA-256 hash of its canonical JSON.
- Approval stores the plan ID, version, plan hash, execution-configuration snapshot ID and hash, approving user, approval time in UTC, and optional analyst note.
- The approved plan version is not overwritten.
- Execution is tied to that exact approved version and hash.
- Any change to the plan's content creates a new plan version, clears the prior approval, and returns the hunt to plan review. Display-only formatting changes do not create a new version.
- Asking the agent to revise the plan also creates a new version that must be approved.
- Editing the report after execution does not change the approved hunt plan.
- Once execution enters `running`, the hunt inputs, threat intelligence, customer documentation, discovery snapshot, plan, scope, model choice, and hunt limits are locked.
- After execution starts, the analyst may let the hunt finish or cancel it. The analyst cannot change the hunt and continue the same execution.
- If the analyst wants different inputs, scope, plan content, model selection, or limits after execution has started, the analyst must cancel the original hunt and create a new hunt with a new hunt ID and a new approval.

### Phase 5: Execute hunt

After approval, a new bounded execution run begins. The agent:

- Executes Splunk searches through the Splunk connector.
- Starts with narrow, high-confidence searches.
- Uses results to decide whether a broader or more detailed search is justified.
- Tracks open questions, coverage, entities, findings, evidence, queries, and remaining budgets.
- Operates autonomously within the approved environment and fixed limits.
- Does not request additional access approvals.

### Phase 6: Synthesize and report

The agent synthesizes the hunt state and selected evidence into one editable report. The analyst may edit the report before finalizing it as a PDF.

### Hunt workflow states

Workflow state and final hunt disposition are separate. Workflow state says where the hunt is in the process. Disposition says what the hunt concluded.

The allowed workflow moves are:

- `created` -> `discovering`
- `discovering` -> `plan_draft`
- `plan_draft` -> `awaiting_plan_review`
- `awaiting_plan_review` -> `approved` when the analyst approves the exact plan version
- `awaiting_plan_review` -> `plan_draft` when the analyst or agent revises the plan
- `approved` -> `queued`
- `approved` -> `plan_draft` if the plan is changed before it is queued
- `queued` -> `plan_draft` if the plan is changed before a worker starts execution
- `queued` -> `running` for a new execution or a resumed investigation
- `queued` -> `synthesizing` only when resuming a hunt that was interrupted during synthesis
- `running` -> `synthesizing` when investigation stops normally or reaches a limit
- `running` -> `paused` when a recoverable interruption prevents immediate continuation
- `paused` -> `queued` only when the unchanged hunt is safely resumed after a recoverable system interruption
- `synthesizing` -> `report_draft`
- `synthesizing` -> `paused` when report creation is recoverably interrupted
- `report_draft` -> `finalized` when the analyst finalizes the report
- Any non-terminal state -> `cancelled` when the analyst cancels the hunt

The `paused` record stores whether the safe resume target is `running` or `synthesizing`. An approved plan cannot be edited after execution enters `running`. Pausing and resuming never unlocks the hunt or permits changes. An unrecoverable error may move an active state to `failed`. The application must not skip from a draft or review state directly to execution. `finalized`, `cancelled`, and `failed` are terminal workflow states. Every state change is persisted and audited.

### Cancellation behavior

- Only the authenticated owning analyst may cancel the hunt.
- Cancellation immediately stops new model calls and new Splunk query submissions.
- Cancellation is idempotent. Repeating the same cancellation request leaves the hunt in `cancelled` and does not create duplicate work or audit side effects beyond recording the repeated request outcome.
- Cancellation and worker claiming use atomic state checks. A worker verifies that the hunt is not cancelled immediately before every external model or Splunk action.
- The application makes a best-effort request to cancel any active Splunk jobs and records the result.
- Already persisted queries, results, evidence, usage, errors, and audit records remain available until the normal retention date.
- A cancelled hunt does not continue to synthesis and cannot produce or finalize a report.
- A cancelled hunt cannot be edited, approved again, resumed, or restarted.
- Starting over always creates a new hunt with a new hunt ID, discovery snapshot, plan version, and approval.
- Report editing remains allowed after a hunt finishes normally and reaches `report_draft`; this does not change the completed investigation.

## 6. Agent Architecture

Use one bounded agent implemented with PydanticAI and a small deterministic Python state machine.

### PydanticAI responsibilities

- Model interaction.
- Tool registration and invocation.
- Typed and validated structured output.
- Output-validation retries.
- Request and token usage limits.
- Model-specific capability handling.

### Application responsibilities

- Mandatory plan-review boundary.
- Hunt phase transitions.
- PostgreSQL persistence and recovery.
- Splunk query validation and execution.
- Hunt, query, time, result, and token budgets.
- Context construction and reduction.
- Stopping logic.
- Evidence storage.
- Report generation.
- Audit records.

### Framework decision

- Use PydanticAI as the single agent library.
- Do not use LangGraph, CrewAI, AutoGen, or another orchestration framework.
- The workflow is sufficiently bounded for a deterministic state machine.

## 7. Model Architecture

### Supported model paths

A `ModelFactory` selects one of these configurations without changing agent logic:

- OpenAI through the OpenAI API.
- Amazon Bedrock through its native PydanticAI model support.
- On-premises models served by vLLM and exposed through LiteLLM's OpenAI-compatible endpoint.

The planned initial on-premises model option is Gemma 4 31B. The LiteLLM/vLLM path remains part of the MVP design and testable interface, but running and accuracy-testing a real local Gemma deployment is deferred until suitable local model infrastructure is available.

Initial end-to-end domain-accuracy validation may use either an OpenAI API model or an Amazon Bedrock model. The first external provider that passes the known-answer suite is sufficient to prove the initial threat-hunting workflow. The other external provider can be qualified afterward using the same suite.

Until a real local model is available, automated tests for the LiteLLM/vLLM path use a mocked OpenAI-compatible endpoint to verify request formatting, authentication and configuration handling, structured outputs, tool calls, usage accounting, timeouts, retries, and failures. These tests validate the application integration but do not claim that a real Gemma deployment or its hunt accuracy has been validated.

### Model selection

- Each deployment has a default model configuration.
- A model may optionally be selected when starting a hunt.
- The model provider does not switch automatically during a hunt.

### Model state and sessions

- PostgreSQL is the authoritative source of hunt state.
- Provider-hosted conversation sessions are not authoritative.
- Planning and execution are separate bounded model runs.
- Model calls receive only the context required for the current phase and question.
- Raw Splunk results and the full historical transcript are not repeatedly placed in model context.
- Provider-specific response chaining or compaction may be used as an optimization, but the workflow must remain portable across OpenAI, Bedrock, and LiteLLM.

### Canonical model context

The application maintains and selectively supplies:

- Approved plan or relevant plan section.
- Current hunt summary.
- Open questions.
- Entities.
- Findings and confidence.
- Selected evidence references.
- Query ledger.
- Coverage and limitations.
- Remaining budgets.
- Relevant Splunk discovery information.

### Context limits

- Maximum model input per call: the smaller of 64,000 tokens or 60% of the configured model's context window.
- Maximum model output per call: 8,000 tokens.
- Maximum model-call duration: 120 seconds by default.
- Maximum total hunt input: 500,000 tokens.
- Maximum total hunt output: 96,000 tokens.
- Maximum model calls per hunt: 12.
- Structured outputs are validated with Pydantic.
- A failed structured output receives at most two repair retries.
- After two failed repair attempts, the step fails with a resumable error.
- Every model request counts against the model-call limit, including requests that return an error, an invalid response, or a response that requires repair.
- Tokens used by failed responses and repair attempts count against the input-token and output-token limits when the provider reports that usage.
- The application never hides a failed model call or repair attempt from the usage ledger.
- During timed execution, the effective model-call timeout is the smaller of the configured model-call timeout or the time remaining before the hard hunt ceiling.
- If the analyst cancels while a model request is in flight, the application requests cancellation when supported, ignores any late response, records any reported usage, and never applies that response to hunt state.

### Model output rules

- Machine-consumed model responses return valid JSON only and must match the applicable Pydantic contract.
- Missing factual text uses `"unknown"` when the contract permits it.
- A missing collection uses an empty list.
- The model must not invent IDs. It may only reference IDs supplied by the application; new record IDs are assigned by the application after validation.
- The model must not invent hosts, users, IP addresses, timestamps, tools, processes, indexes, sourcetypes, fields, events, findings, severities, telemetry, ATT&CK mappings, IOCs, or source evidence.
- Customer documentation, threat intelligence, Splunk field values, and retrieved context are untrusted content. Instructions inside that content cannot change system instructions, approval requirements, budgets, query policy, tool permissions, or evidence rules.
- Direct Splunk evidence, advisory intelligence or documentation, and model inference remain separate fields.

Follow-up validation attributes semantic errors to individual proposals. Prompt contract 1.8 repairs only rejected decisions, preserves accepted proposals unchanged, and revalidates the merged batch before execution. After validation, application code suppresses exact duplicate searches using the policy cache identity and result mode. Normalized SPL, UTC bounds, limits and execution configuration must match; changed windows or limits are new work. Approved questions retain their application-defined priority even when model output is reordered. Duplicate skips record `decision_source: application_duplicate_suppression` and explicitly state that the question was not separately searched. They consume no model repair and do not prevent distinct approved work from running. Repaired proposals that remain invalid fail explicitly.

Query context provides advisory hashes as literal `advisory_iocs.file_hashes`, without algorithm-key names that could be mistaken for telemetry enum values. Query guidance matches these values directly in shared hash fields without an additional type predicate; algorithm-specific fields require discovered schema support. Other categorical values must come from supplied context or observed telemetry, or be explored with a bounded aggregate. This guidance does not establish query correctness by itself.

SPL policy 1.3 normalizes a grouped initial search expression to the explicit `search` command required by the transport API, using the same source-scope proof as an explicitly named search.

### Model transport projection (prompt contract 1.18)

The canonical contracts below describe application and stored data. The model transport derives a closed JSON schema from those contracts and sends it through the provider API. Its shared schema enforces types, required fields, supported string formats, enum choices, and allowed citation labels; application validators retain length, range, timestamp, policy, and cross-field checks. Refusals and truncated responses fail explicitly. Finding wire schema variants require evidence with empty query citations for positive observations and hunt leads, and completed-query citations with empty evidence citations for scoped negative findings. Application code derives positive findings' query relationships from their evidence; canonical stored contracts remain unchanged. The wire schema and application validators share the same classification-to-grounding rules.

Assessment and synthesis use request-local `E1`, `E2`, ... evidence labels and `Q1`, `Q2`, ... completed-query labels. Only records actually supplied to that call can be resolved. The application restores durable IDs before semantic validation or persistence. Assessment wire output selects only a query label; application code supplies its already-known question ID. Canonical stored assessments retain question_id. Findings select evidence labels and normally return `query_ids: []`; the application derives the related queries. Findings without evidence can select completed-query labels, including searches with zero results.

Prompt contract 1.9 makes entity selection explicit: each `AssessmentEntity.value` must equal a complete scalar field value or list element in cited evidence, including parsed JSON containers. A path appearing only within a longer command line is not an exact scalar entity; command-line interpretations may be described in grounded summary text. Invalid-entity repair feedback identifies every failing zero-based `new_entities` position without echoing source values. The validator does not normalize, invent, or silently discard entities.

Prompt contract 1.10 removes `result_row_refs` from the model-facing entity shape. The model selects `entity_type` and an exact observed `value`; application code derives all matching references from that selected query's supplied evidence, using the same scalar extraction as semantic validation. Values found only in another query, an omitted row, or a substring remain rejected. Canonical stored entities retain their references, and historical explicit references still undergo semantic validation. Entity classification and narrative claim support remain subject to analytical review.

Prompt contract 1.11 adds per-source evidence coverage to assessment, adaptive planning, and synthesis. Bounded samples balance both queries and identified sources within each query. For a truncated representative/targeted raw query with an unrepresented source, application code schedules a policy-validated source-specific check, preserving the original question, predicates, pipeline, time bounds, and result cap. Check lineage is checkpointed; existing query/model/cycle budgets remain enforced and unresolved gaps are reported. Combined aggregates are excluded. Source identity derives from observed projection fields and satisfiable exact source pairs, with `unknown` for ambiguous or contradictory projections. Neither retained-source counts nor a completed check establish an answered investigation question.

Prompt contract 1.12 binds model follow-up skips to the application-recorded completed-query set; new query results reopen skipped questions, while unchanged context and exact duplicate suppression cannot create unbounded retries. Execution uses the documented Splunk search job `earliest_time`/`latest_time` parameters rather than unsupported aliases, which were silently ignored in earlier releases. Repeated identical source metadata is resolved to one possible pair; genuinely conflicting source values remain unknown.

Prompt contract 1.13 removes `intelligence_refs` from the model plan shape. Application code derives references to actual supplied advisory content, with hunt/content-bound IDs and content digests retained in `discovery_snapshot.input_context.intelligence_sources`. Empty advisory input creates no source. Canonical explicit references, user plan edits, approval and execution are validated against the supplied source set. Advisory provenance remains separate from direct telemetry evidence and external-document authenticity.

Prompt contract 1.14 reserves one row per observed query/source within the existing 100-record synthesis sample, then prioritizes whole assessment support groups in approved-question order before adaptive groups. Unavailable/wrong-query support and groups exceeding remaining capacity receive no partial priority allocation; remaining capacity uses query/source-balanced sampling. Synthesis receives prior assessments labeled as interpretations only when their full supporting records are supplied. Omitted assessments have an explicit count; shortened summary/limitation text is marked. The selection uses query scope and validated support, never an evaluation answer key or presumed maliciousness. Prior model interpretations do not become observed facts.

Prompt contract 1.15 makes observation/inference boundaries explicit in assessment and synthesis rules and model-facing field descriptions, which are preserved in both the native response schema and repair requests. Familiar names, ports, or successful events do not establish benignness, authorization, intent, or a normal baseline. Supported baseline comparisons remain scoped to their supplied evidence. Shared hosts/accounts are distinct from stable process/session relationships; positive observations cannot establish broad absence of malicious behavior. These descriptions guide the model; structural validation neither rejects every unsupported claim nor rewrites prose. Analytical review remains required.

Prompt contract 1.16 supplies the bounded extracted advisory IOC lists and application-computed literal comparisons beside each sampled evidence row in assessment and synthesis. It distinguishes a filename match from a hash match and missing hash literals from observed values absent from the extracted list. Hash equality ignores hexadecimal case; filename/domain equality uses complete literal values without normalization. Comparisons do not interpret STIX conjunctions, field semantics, file identity, or maliciousness, and do not modify retained evidence. Prior model assessments remain interpretations to be checked against the comparisons and source rows.

With prompt contract 1.17, evidence classification uses the executed supported SPL pipeline rather than the model's requested result mode: `stats` and `timechart` produce aggregate rows, while supported event-preserving pipelines produce raw-event rows. The same distinction controls omitted-source checks for truncated results. Retrieval caps remain tied to the existing query contract; historical evidence is not rewritten. No customer configuration or data normalization is required.

Prompt contract 1.18 replaces the synthesis support-group priority described for 1.14. Final writing receives query/source-balanced records, exact application-computed IOC comparisons, completed query scope and operational coverage. It excludes earlier assessment prose, assessment-based sample priority, and model-authored skip explanations; the investigation retains those records for pivots and audit. Exact advisory literal matches receive priority within each query, without increasing the 100-record total or using fixture answer keys. Queries and samples retain explicit omission metadata. This removes a path for earlier interpretation errors to reach final writing; semantic accuracy still requires qualification. Per-question/claim evidence retrieval remains a separate unfinished requirement.

`usage.model_output_checks` records contract validity after reference resolution and downstream grounding validity separately for initial and repair calls. Neither metric establishes the truth of a claim. Analytical precision, recall, and unsupported claims require independent judgments on actual workflow output.

Application code deduplicates citation references and computes retained/cited counts, classification totals, and searched sources. Query truncation and omission from the bounded model sample are separate metadata fields. Synthesis must support each material claim with relevant evidence, including each source involved in a claimed correlation; references alone do not prove that support. Source names and synthetic-data provenance are preserved without semantic rewriting.

The investigation revisits unsearched approved questions before adaptive pivots. An explicit skip closes only that question, leaving search capacity available for other pending questions. Pending question IDs and reasons remain in the execution record when budgets prevent further work. A completed query establishes search execution, not that the investigation question has been answered.

Prompt contract 1.5 exposes each completed query's actual UTC search bounds to assessment and synthesis, separately from evidence timestamps and the approved range. Initial coverage guidance surveys the approved range before narrowing to a lead; absence claims remain limited to the selected window and filters. Reports explicitly disclose searches that cover only a subset of the approved time range.

SPL policy 1.2 checks source conditions with `search`'s OR-before-AND precedence. Each possible branch must constrain both index and sourcetype, and contradictory source conditions are rejected. Compound alternatives require their own parentheses, such as `((index=one sourcetype=first) OR (index=two sourcetype=second))`, using actual approved values. The bounded source proof does not validate all SPL semantics or prove that an otherwise valid search answers its question. Runtime execution snapshots record the policy version from the implementation constant.

### Canonical JSON contracts

These are the required MVP structures. Exact field constraints and enums are implemented as versioned Pydantic models.

#### Hunt plan

```json
{
  "schema_version": "1.0",
  "plan_id": "application-assigned UUID",
  "plan_version": 1,
  "hunt_id": "application-assigned UUID",
  "discovery_snapshot_id": "application-assigned UUID",
  "execution_config_snapshot_id": "application-assigned UUID",
  "hypothesis": "string",
  "objective": "string",
  "scope": {
    "earliest_utc": "RFC 3339 UTC timestamp",
    "latest_utc": "RFC 3339 UTC timestamp",
    "indexes": ["string"],
    "sourcetypes": ["string"]
  },
  "intelligence_refs": ["application-provided source ID"],
  "data_sources": [
    {
      "index": "string",
      "sourcetypes": ["string"],
      "purpose": "string"
    }
  ],
  "questions": [
    {
      "question_id": "application-assigned ID",
      "question": "string",
      "rationale": "string",
      "expected_information_gain": "string"
    }
  ],
  "query_strategy": ["string"],
  "coverage_limitations": ["string"],
  "created_at_utc": "RFC 3339 UTC timestamp"
}
```

#### Plan approval

Plan approval is created by deterministic application code after the authenticated owner approves the displayed plan.

```json
{
  "schema_version": "1.0",
  "approval_id": "application-assigned UUID",
  "hunt_id": "application-assigned UUID",
  "plan_id": "application-assigned UUID",
  "plan_version": 1,
  "plan_sha256": "lowercase SHA-256 hex digest",
  "execution_config_snapshot_id": "application-assigned UUID",
  "execution_config_sha256": "lowercase SHA-256 hex digest",
  "approved_by_user_id": "application-assigned UUID",
  "approved_at_utc": "RFC 3339 UTC timestamp",
  "analyst_note": "string or unknown"
}
```

#### Query proposal

```json
{
  "schema_version": "1.0",
  "question_id": "existing plan question ID",
  "purpose": "string",
  "expected_information_gain": "string",
  "spl": "string",
  "earliest_utc": "RFC 3339 UTC timestamp",
  "latest_utc": "RFC 3339 UTC timestamp",
  "indexes": ["string"],
  "sourcetypes": ["string"],
  "requested_fields": ["string"],
  "result_mode": "aggregate | representative | targeted",
  "max_results": 100
}
```

`max_results` is the total requested retention ceiling: up to 10,000 raw representative/targeted rows or 500 aggregate rows. Retrieval uses fixed pages of at most 500 rows and also enforces the configured per-query/per-hunt row and byte limits. The requested ceiling may be smaller than the policy ceiling; neither changes the separate model context limit. The application records `available_result_count` from completed job metadata when available, `result_count` for retained rows, `result_pages`, and `retrieval_stop_reason`. Row/byte/time limits and incomplete pages are explicit truncation causes. A known server total distinguishes an exactly complete result from a capped result; unknown totals remain conservatively truncated at the cap. Prior pages survive a later timeout/byte-limit failure. Searches skipped for budget exhaustion are checkpointed and reported without discarding earlier evidence. The model cannot raise deployment limits.

#### Query validation result

This record is created by deterministic application code. The model cannot mark its own query as allowed.

```json
{
  "schema_version": "1.0",
  "query_id": "application-assigned UUID",
  "allowed": true,
  "normalized_spl": "string",
  "earliest_utc": "RFC 3339 UTC timestamp",
  "latest_utc": "RFC 3339 UTC timestamp",
  "cache_key": "lowercase SHA-256 hex digest",
  "reason_codes": [],
  "enforced_limits": {
    "max_results": 100,
    "max_bytes": 262144000,
    "timeout_seconds": 120
  },
  "query_policy_version": "string"
}
```

For a rejected query, `allowed` is `false`, `reason_codes` is non-empty, and fields that exist only for execution such as `cache_key` are `null`.

#### Query assessment

```json
{
  "schema_version": "1.0",
  "query_id": "application-provided query ID",
  "question_id": "existing plan question ID",
  "answered_question": true,
  "material_progress": true,
  "summary": "string",
  "new_entities": [
    {
      "entity_type": "host | user | ip | process | file | domain | other",
      "value": "string",
      "result_row_refs": ["application-provided result row ID"]
    }
  ],
  "evidence_candidate_row_refs": ["application-provided result row ID"],
  "coverage_changes": ["string"],
  "limitations": ["string"],
  "proposed_next_question": {
    "question": "string",
    "rationale": "string",
    "expected_information_gain": "string"
  }
}
```

`proposed_next_question` is `null` when no follow-up is justified. When it is present and valid, the application assigns its ID before it can be used by a later query proposal.

#### Evidence record

Evidence records are created by deterministic application code from selected non-empty Splunk result rows, not invented by the model. A retained result may be a raw event or a bounded aggregate row such as a count, distribution, or timeline bucket.

```json
{
  "schema_version": "1.0",
  "evidence_id": "application-assigned UUID",
  "hunt_id": "application-assigned UUID",
  "query_id": "application-assigned UUID",
  "splunk_job_id": "Splunk job ID",
  "evidence_kind": "raw_event | aggregate_row",
  "index": "string",
  "sourcetype": "string or unknown",
  "event_time_utc": "RFC 3339 UTC timestamp or unknown",
  "collected_at_utc": "RFC 3339 UTC timestamp",
  "source_event_ref": "source identifier or unknown",
  "selected_result": {},
  "sha256": "lowercase SHA-256 hex digest"
}
```

#### Finding

```json
{
  "schema_version": "1.0",
  "finding_id": "application-assigned UUID",
  "title": "string",
  "classification": "hunt_lead | supported_observation | not_supported_within_scope",
  "statement": "string",
  "confidence": "low | medium | high",
  "evidence_ids": ["existing evidence ID"],
  "query_ids": ["existing completed query ID"],
  "inference": "string or unknown",
  "limitations": ["string"]
}
```

`hunt_lead` and `supported_observation` findings require at least one retained `evidence_id`. A `not_supported_within_scope` finding may instead cite one or more completed `query_ids` that demonstrate the searched scope and result. Empty evidence is never presented as proof of absence beyond that documented scope.

#### Stop decision

```json
{
  "schema_version": "1.0",
  "disposition": "supported | not_supported_within_scope | inconclusive | budget_exhausted | failed",
  "reason_code": "hypothesis_disposed | plan_exhausted | low_yield | budget_reached | unrecoverable_error",
  "summary": "string",
  "evidence_ids": ["existing evidence ID"],
  "query_ids": ["existing completed query ID"],
  "coverage": ["string"],
  "limitations": ["string"],
  "open_questions": ["string"]
}
```

`cancelled` is assigned only by deterministic application code after an authenticated analyst cancellation request. The model cannot select or trigger cancellation.

#### Report content

```json
{
  "schema_version": "1.0",
  "hunt_id": "application-assigned UUID",
  "approved_plan_id": "application-assigned UUID",
  "approved_plan_version": 1,
  "approved_plan_sha256": "lowercase SHA-256 hex digest",
  "execution_config_snapshot_id": "application-assigned UUID",
  "execution_config_sha256": "lowercase SHA-256 hex digest",
  "hypothesis": "string",
  "objective_and_scope": "string",
  "data_sources_used": ["string"],
  "finding_ids": ["existing finding ID"],
  "evidence_ids": ["existing evidence ID"],
  "query_ids": ["existing completed query ID"],
  "entities": [
    {
      "entity_type": "host | user | ip | process | file | domain | other",
      "value": "string",
      "evidence_ids": ["existing evidence ID"]
    }
  ],
  "timeline": [
    {
      "time_utc": "RFC 3339 UTC timestamp or unknown",
      "description": "string",
      "evidence_ids": ["existing evidence ID"]
    }
  ],
  "coverage": ["string"],
  "limitations": ["string"],
  "conclusion": {
    "text": "string",
    "finding_ids": ["existing finding ID"],
    "evidence_ids": ["existing evidence ID"],
    "query_ids": ["existing completed query ID"]
  },
  "disposition": "supported | not_supported_within_scope | inconclusive | budget_exhausted | failed"
}
```

## 8. Splunk Connector

The MVP implements only `SplunkConnector`, backed by the official `splunk-sdk` library.

The connector is wrapped behind an application-owned interface so other hunt systems can be added later without changing the orchestrator.

### Connector interface

```python
class HuntConnector:
    def healthcheck(self): ...
    def discover(self): ...
    def validate_query(self, query): ...
    def submit(self, query): ...
    def status(self, job_id): ...
    def fetch_results(self, job_id, page, limit): ...
    def cancel(self, job_id): ...
    def job_metadata(self, job_id): ...
```

### Splunk connection behavior

- One Splunk deployment or search head is configured per customer deployment.
- The application does not create multiple application connections merely to run sequential or concurrent searches.
- Splunk search jobs manage query execution through the single configured connection.
- Searches normally execute sequentially, with at most two Splunk jobs running concurrently.
- Splunk SDK connection and read operations use a configurable 30-second transport timeout by default. This is separate from the 120-second maximum runtime of a submitted Splunk search job.
- Discovery and health-check calls use the same bounded transport behavior and return explicit partial-discovery or unavailable errors rather than hanging indefinitely.

### SPL validation and safety policy

Every agent-generated query is parsed and checked by deterministic application code before it is sent to Splunk. Prompt instructions alone are not a security control.

A query is allowed only when:

- It is read-only.
- Its indexes and sourcetypes are present in the hunt's discovery snapshot or are revalidated against the configured Splunk connection.
- Source fields must be present in discovery or revalidated. New fields created inside the same query by an allowed `eval`, `rename`, aggregation, or extraction may be used only after their definition and are tracked separately from discovered source fields.
- It uses explicit absolute UTC start and end times within the approved plan scope.
- It is tied to a plan question, unresolved question, contradiction, or coverage gap.
- It states its purpose and expected information gain.
- It requests only needed fields and applies application-enforced row, byte, and runtime limits.
- Every SPL command, function, field, and data model is allowed by the versioned application query policy.

The application rejects:

- Commands that write, delete, export, alert, send, or otherwise change data or system state, including commands such as `collect`, `delete`, `outputlookup`, `outputcsv`, `sendalert`, and `sendemail`.
- Commands that can invoke scripts, operating-system actions, external network access, REST actions, uncontrolled nested searches, or other unbounded work.
- Unknown or customer-defined commands and all Splunk macros. Macro execution is not supported in the MVP query policy.
- Placeholders, fake field names, invented indexes, invented sourcetypes, moving time windows, or missing time bounds.
- Queries whose estimated or configured limits exceed the remaining hunt budget.

The local policy 1.5 candidate enforces source-field discovery against actual query text in the existing command subset, independently of `requested_fields`. Static eval assignments are validated left-to-right, and rename/aggregate outputs become available only after their definitions. Quoted names and literal values retain their command-specific meanings. Dynamic eval names and unsupported field syntax fail closed with `field_syntax_not_supported`; wildcard rename patterns are bounded to 32 wildcards. The candidate preserves source/time/result guards and requires a fresh execution approval after rollout. Eval/where and aggregation functions must also belong to the policy allowlists exposed to query generation; `lookup`, `searchmatch` and customer functions fail closed with `function_not_allowed`. The operator runbook describes the supported boundary. The implementation follows the installed Splunk 10.4 [search comparison semantics](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.4/search-commands/search), [eval ordering and quotation rules](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.4/search-commands/eval), [aggregate field syntax](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.4/search-commands/stats), [evaluation functions](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.4/evaluation-functions/evaluation-functions), and [rename semantics](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.4/search-commands/rename).

Validation returns a structured allow or reject result with reason codes. A rejected query is never submitted. If budget remains, the agent may produce one corrected proposal based on the rejection reasons. The corrected proposal must pass the same validation. Query-policy enforcement does not add another human approval step.

MVP rejection reason codes include `spl_parse_error`, `unsafe_command`, `unknown_command`, `macro_not_allowed`, `index_not_discovered`, `sourcetype_not_discovered`, `field_not_discovered`, `invalid_time_range`, `outside_approved_scope`, `missing_purpose`, `placeholder_detected`, and `budget_exceeded`. Multiple codes may be returned for one proposal.

The configured Splunk service account remains a second safety boundary and should have search-only, least-privilege access to the data approved for the deployment.

## 9. Hunt and Query Budgets

All values are deployment-configurable. These are the MVP defaults.

| Setting | Default |
| --- | ---: |
| Hard hunt completion ceiling | 20 minutes |
| Stop starting new Splunk queries | At 13 minutes with the shipped five-minute model-call limit |
| Maximum in-flight query time after cutoff | 2 minutes, subject to the per-query timeout |
| Synthesis/report allowance after investigation closes | Reserve 5 minutes within the hard ceiling |
| Agent investigation cycles | 8 |
| Splunk queries per hunt | 50 |
| Concurrent Splunk jobs per hunt | 2 |
| Active hunts per deployment | 1 |
| Concurrent Splunk jobs per deployment | 2 |
| Hard timeout per Splunk query | 120 seconds |
| Model calls per hunt | 12 |
| Model input tokens per hunt | 500,000 |
| Model output tokens per hunt | 96,000 |
| Model output tokens per call | 24,000 in the shipped Docker configuration; 8,000 if omitted |
| Hard timeout per model call | 300 seconds in the shipped Docker configuration; 120 seconds if omitted |
| Cached raw rows per query | 10,000 |
| Cached raw bytes per query | 250 MB |
| Cached raw rows per hunt | 50,000 |
| Cached raw bytes per hunt | 1 GB |
| Initial representative events supplied to model | 500 |
| Targeted event expansion supplied to model | 500 |

The 50-search budget is a per-hunt ceiling, not a target. The agent stops when useful leads are exhausted or another limit is reached. Raising it does not increase model calls, tokens, concurrent jobs, or model-visible evidence; measure useful additional coverage before raising those separate limits.

Prompt contract 1.19 raises the default assessment, pivot-planning, and final-synthesis evidence batches to 500 records. Assessment uses the existing representative-event limit; pivot planning and synthesis use the targeted-event limit. Stored-result limits are separate. Repairs retain the original supplied evidence set, and omitted records remain explicit. Larger batches do not establish factual correctness or complete question coverage.

Prompt contract 1.21 requires one application-generated answer slot per approved question. Each slot contains a concise summary, findings, and limitations, with at least one finding or limitation. Native schemas and application validation enforce question coverage and supplied evidence/query references; application code supplies durable IDs and derives relationships. Summaries must cover material findings and their uncertainty without inventing claims. This is structural coverage, not proof that each question was fully answered.

All generated findings remain stored independently of report presentation. The draft selects ten detailed findings by default across questions and favors hunt leads within each question, while retaining every question summary and its complete finding references. Analysts may add more detailed findings within the existing report input-size boundary. Neither this selection nor summary length limits retained investigation state. PDF/HTML question answers avoid printing full reference arrays; PDF finding details show a few references with total counts. The app exposes expandable per-question findings and its full retained findings/evidence. Report edits cannot drop or reassign question finding references. Earlier assessment prose is excluded from new question-answer report limitations.

Prompt contract 1.26 retains time-spread sampling and inventories computed over complete retained raw subsets, independently of the model sample. Counts disclose missing/multivalue fields and do not establish affected entities or unique process instances. Exact typed field filters, optional timezone-aware half-open windows within approved scope, and pages of at most 500 representation groups are available through bounded model requests. Each question may finish or request up to three pages; completed answers and page metadata are persisted before another call. Identical representations retain all original evidence/query references, and differing fields remain separate. Requested pages take priority in the next bounded context; any remaining omission is explicit. Repeated pages stop retrieval. Negative findings cannot cite failed, truncated or partial query results; the native choices and post-response/persistence checks enforce that boundary. Out-of-scope lookup windows use the bounded repair path, and unobserved filter fields remain explicit limitations. This remains a local, analytically unqualified candidate.

Complete-request preflight now enforces `context_characters` and estimates input tokens conservatively using UTF-8 bytes plus framing, including decoded schema/system/repair content and tools without double-counting HTTP transport escaping. This is not measured provider usage. Each submitted call records its request characters and input estimate in `usage.model_output_checks`; returned responses also record actual input/output tokens, including invalid outputs and repairs. Missing historical or transport-failure usage remains unknown. Synthesis searches for a fitting evidence sample and rebuilds original-versus-supplied coverage. Repairs preserve their original references. Adaptive assessment/follow-ups and retrieval each reserve a final call and half their starting remaining token allowance; actual provider usage still counts against the shared hunt totals. Synthesis budget exhaustion preserves completed answers and creates explicit unanswered slots. Large-input behavior, analytical completeness, and live qualification remain open as described in the [resume checkpoint](resume-checkpoint.md).

### Time-limit behavior

- The execution clock starts when an approved hunt enters `running`. Discovery and plan review happen before this clock starts.
- With the shipped configuration, at minute 13 the application stops starting new Splunk queries and further adaptive model work. Unstarted searches remain recorded as skipped, not as completed zero-result searches.
- A query that is already running may finish, fail, or reach its existing query timeout, with a latest investigation deadline at minute 15. Recovery uses its original submission time rather than restarting the per-query clock. Timed-out searches remain disclosed as coverage gaps.
- When the investigation closes because of its time cutoff, the agent synthesizes the retained state after in-flight queries finish or are cancelled. An analyst-cancelled hunt does not run synthesis or create a report draft.
- The full execution has a 20-minute hard ceiling. Each model call is limited to the smaller of its configured timeout and remaining phase time. Late model responses are accounted for but rejected. Failure at the hard deadline preserves persisted state and records `hard_timeout`; it does not create an accepted report.
- The cutoff is derived from the hard ceiling, reserving one configured model-call timeout for synthesis and up to 120 seconds for an in-flight query. With the omitted-setting 120-second model default, the query cutoff is minute 16 and synthesis reserve is two minutes. Short custom ceilings clamp these reserves to fit. The legacy `query_start_cutoff_utc` field is accepted for old configurations but has no scheduling effect; these limits use elapsed time, not time of day.
- Query, cycle, model-call, token and result-size limits still apply independently. Twenty minutes is a ceiling, not a target runtime or a guarantee that other budgets will last that long. Discovery and plan review, queue waiting, and later analyst PDF finalization are outside this execution clock.

### Per-hunt and deployment limits

Per-hunt limits control one investigation. They include that hunt's query count, concurrent query count, cycles, query timeout, cached rows and bytes, model calls, tokens, and execution time.

Deployment limits protect the shared Splunk system and application. For the MVP:

- One hunt runs at a time by default.
- No more than two Splunk jobs run across the entire deployment at once.
- Additional approved hunts remain in `queued` state and start in first-in, first-out order.
- Operators may change these deployment limits without rebuilding the image.

### Budget accounting

- Every request actually sent to a model counts as a model call, including failed and repair requests.
- Provider-reported tokens from failed and repair requests count toward token budgets.
- Every search submitted to Splunk counts against the execution query limit, including searches that later fail, time out, or are cancelled.
- A query rejected before submission does not count as a Splunk query, but any model call used to create or correct it still counts.
- A valid cache hit does not count as a new Splunk query because no new search is submitted.
- Splunk metadata and discovery operations before approval are recorded but do not count against the post-approval execution query limit.
- Planning, execution, and report-generation model calls all count against the per-hunt model-call and token limits.
- Raw-result row and byte counters use the data actually accepted into the temporary cache. The application stops fetching before either the per-query or per-hunt cap is exceeded and records truncation metadata.
- Reaching the per-hunt raw-result cap stops new investigation queries and moves the hunt to synthesis with `budget_exhausted`.

## 10. Query Strategy and Cost Control

### Progressive querying

- Start with the narrowest time range, indexes, fields, and high-confidence analytics that can answer the current question.
- Broaden a query only when the current result creates a specific unresolved question or coverage gap.
- Every follow-up query must have a stated purpose and expected information gain.
- Use explicit time ranges.
- Target relevant indexes and sourcetypes.
- Request only required fields.
- Aggregate and deduplicate in Splunk before sending information to the model.
- Use `tstats` and accelerated data models when available and appropriate.
- Apply row, byte, runtime, hunt, and model limits.

### Information supplied to the agent

Prefer:

- Counts.
- Distributions.
- Anomalies.
- Representative samples.
- Entities.
- Timelines.
- Coverage information.
- Truncation metadata.
- Query and job metadata.

The agent requests detailed events only for selected entities, findings, or unresolved questions.

### Duplicate-query cache

- Cache exact duplicate queries only within the same hunt.
- Build the cache key from the normalized SPL, configured Splunk connection, execution-configuration snapshot, query-policy version, query parameters, and fixed time range.
- Before executing a query, check the completed-query ledger for the same key.
- Reuse the prior completed result instead of submitting the same query again.
- Do not share query caches across customers or users.
- Do not reuse cached results for moving or live time windows.
- Resolve all time ranges to fixed UTC timestamps before creating the cache key.
- Query normalization must preserve quoted strings, regular expressions, case-sensitive values, and every other value that can change the result.
- Include every execution-affecting parameter, the approved Splunk connection identifier, and the fixed time range in the key.
- Reuse only a completed, successful, unexpired, untruncated result created earlier in the same hunt.
- Do not reuse failed, cancelled, timed-out, stale, truncated, partially fetched, or policy-incompatible results.
- Record every cache hit in the query ledger and report appendix as reused work rather than a new Splunk job.

Duplicate queries can occur because of agent replanning, retries, overlapping reasoning branches, or a user rerunning a hunt step.

## 11. Low-Yield and Stopping Decisions

### Low-yield definition

A completed query or investigation step is low-yield when its resource cost is not matched by useful progress, such as when it:

- Repeats previously collected evidence.
- Adds no new entities, evidence, or coverage.
- Does not answer its stated hunt question.
- Exceeds its runtime, result, or hunt budget.

Zero results are not automatically low-yield. A zero-result search can answer a hunt question or help disposition a branch.

### Who decides

- Deterministic application code measures runtime, duplication, result volume, budgets, and repeated coverage.
- The agent evaluates whether results answered an open question or materially changed the investigation.
- Only hard budget or timeout violations automatically cancel a running query.

### Retry and failure behavior

The component that talks to an external system owns transport retries. The state machine decides whether the overall hunt can continue.

The application may retry:

- A temporary network failure, HTTP `429`, or provider/server `5xx` response once when time and budgets remain.
- Polling or fetching an existing Splunk job after reconnecting. The application must use the persisted Splunk job ID before considering a new submission.
- A model response that fails parsing or Pydantic validation through the existing maximum of two repair attempts.
- Report rendering once when the failure is temporary and the report input has not changed.

Every retry is recorded. Model retries count against model-call and token limits. A newly submitted Splunk search counts against the query limit. Retries use short bounded backoff and never run past the hunt's hard ceiling.

Retries stay with the model provider and model selected for the hunt. They never trigger automatic provider or model failover.

The application does not automatically retry:

- Invalid credentials or permission errors.
- Invalid or missing required configuration.
- TLS certificate-validation failures.
- Database persistence or migration failures.
- An SPL query rejected by policy. The agent may create one corrected proposal, but the rejected query is never executed.
- A query that reached its hard timeout. The agent may choose a narrower new query if time and query budget remain.
- A hard hunt, query, result, cycle, model-call, or token limit.

Zero results, incomplete data coverage, and an unsupported hypothesis are not system failures. They are recorded as hunt results or limitations.

If a temporary failure remains after its allowed retry, the hunt moves to `paused` when its saved state permits safe resumption. If safe resumption is not possible, it moves to `failed`. Reaching a hard budget produces `budget_exhausted`, not a silent partial success.

### Hunt stop conditions

Stop the hunt when any applicable condition is reached:

- The hypothesis has a supported disposition.
- The hypothesis is not supported within the observed scope.
- The approved plan and available data have been exhausted.
- The hunt reaches a hard query, time, iteration, result, or token budget.
- Two consecutive follow-ups produce no material new evidence or coverage and there is no distinct next question with expected information gain.
- The analyst cancels the hunt.
- An unrecoverable failure prevents continuation.

### Final hunt statuses

- `supported`
- `not_supported_within_scope`
- `inconclusive`
- `budget_exhausted`
- `cancelled`
- `failed`

Absence of evidence is not reported as proof that compromise did not occur. Coverage and limitations must accompany the disposition.

## 12. Persistence and Recovery

- Persist hunt state in PostgreSQL.
- Persist before and after every Splunk query action.
- Persist before and after every model action.
- Persist Splunk job IDs and execution metadata.
- Persist every state transition.
- Use the query ledger and persisted job state to avoid rerunning completed work after an interruption.
- A paused or interrupted hunt is resumable only without changing its locked inputs, approved plan, model, scope, or limits. Hunts in terminal workflow state `cancelled` or `failed` are not resumed.
- A worker claims one queued hunt in a single atomic database operation and records a lease owner, lease expiration, and heartbeat.
- Another worker cannot run the same hunt while that lease is valid.
- If a lease expires, a replacement worker loads the saved state, checks persisted Splunk job IDs, and continues from the last completed action.
- Before resubmitting any external action, the replacement worker checks whether the prior action already completed.
- State changes, query submissions, evidence creation, report creation, and finalization use idempotency keys or database uniqueness constraints so replay does not create duplicates.

### Audit records

Audit records are append-only through the application. Analysts cannot edit or delete individual audit entries; they are removed only by the configured hunt-retention cleanup.

Each audit record contains:

- Audit ID, hunt ID, UTC timestamp, and request or correlation ID.
- Actor type (`analyst`, `worker`, or `system`) and actor ID when applicable.
- Action name, affected object type and ID, prior workflow state, and resulting workflow state when applicable.
- Outcome (`success`, `rejected`, `cancelled`, or `failed`) and a structured reason or error code.
- Application image version, prompt version, structured-contract version, query-policy version, model provider and model name when relevant.
- Model-call and token usage, Splunk job ID, query ID, and retry number when relevant.

Audit records never contain passwords, API keys, session cookies, raw authorization headers, secret-file contents, or full temporary raw-result batches.

## 13. Evidence and Workspace Outputs

### Retained evidence

- Exact SPL queries.
- Query purpose.
- Splunk indexes and time ranges used.
- Query execution timestamps.
- Splunk job IDs.
- Result counts and status.
- Errors and truncation metadata.
- Selected raw events and aggregate result rows that support findings.
- Extracted entities.
- Timeline entries.
- Finding-to-evidence citations.
- Analyst notes.
- Source intelligence and provenance.
- Evidence hashes and audit information.

Full raw result batches are temporary cache data. Only selected raw events needed to support findings are retained as evidence.

### Evidence integrity

- The application assigns every retained evidence item a stable UUID.
- The retained selected result is stored as an immutable snapshot. Later display or report formatting does not change it.
- The application calculates a SHA-256 hash over a documented canonical representation of the selected result and its source metadata.
- Each evidence item records the hunt ID, query ID, Splunk job ID, index, sourcetype when available, source event reference when available, event time in UTC when available, and collection time in UTC.
- Positive observed-activity findings and report claims cite evidence IDs. Negative and coverage claims cite completed query IDs. Citations never use row positions or temporary cache locations.
- The application prevents references to missing evidence IDs or evidence owned by another hunt or user.
- Direct Splunk evidence, advisory threat intelligence or customer documentation, and model or analyst inference are labeled separately.
- Unsupported factual values use `unknown`; they are not guessed.

### Workspace outputs

- Threat-intelligence input and provenance.
- Discovered Splunk catalog.
- Structured hunt plan.
- Plan-review status.
- Hunt progress and phase status.
- Query ledger.
- Splunk job metadata.
- Findings.
- Selected evidence excerpts.
- Entities.
- Timeline.
- Coverage and limitations.
- Analyst notes.
- Editable report draft.
- Final PDF report.
- Query appendix.
- Audit trail.

## 14. Final Report

Produce one best report format for the MVP.

### Report workflow

1. The agent generates an editable report preview in the Lexical workspace.
2. The analyst may edit the report.
3. The application finalizes the report as a PDF.

Finalization works as follows:

- The analyst may edit the report only before finalization.
- Finalization freezes the exact report content version used to create the PDF.
- The application records the report version, approved plan version and hash, execution-configuration snapshot, finalizing user, finalization time in UTC, PDF SHA-256 hash, finding IDs, evidence IDs, and completed query IDs used as citations.
- The application retains the original agent-generated draft and the final analyst-edited version so the two can be distinguished; full edit-by-edit version history is not required.
- Required sections and every referenced finding, evidence, and query ID are validated before PDF generation.
- For finalization, a material factual claim means a statement about observed host, user, process, file, domain, network, or other environment activity. Positive observed-activity claims must cite retained evidence IDs. Negative or coverage claims may cite completed query IDs that show exactly what was searched. Hypotheses, objectives, stated scope, and clearly labeled limitations are not treated as observed-activity claims.
- If an analyst adds or changes a material factual claim without a valid evidence or query citation, finalization is blocked until the claim is cited or clearly rewritten as an analyst hypothesis or note.
- Analyst and model text is escaped when rendered into HTML. Untrusted report content cannot supply raw HTML, scripts, styles, file paths, or resource URLs.
- PDF rendering uses only bundled report templates and approved local static assets. WeasyPrint is not allowed to fetch remote URLs or read arbitrary host files.
- Report input size, evidence-excerpt size, page count, and render time are bounded by deployment configuration. MVP defaults are 5 MB of structured report input, 64 KB per evidence excerpt, 5 MB of evidence excerpts in total, 100 PDF pages, and 60 seconds of render time. Exceeding a limit produces a clear resumable report error rather than a partial PDF.
- The finalized PDF and its metadata are immutable. The MVP produces one finalized PDF per hunt.
- A failed PDF render does not rerun the hunt. It remains a resumable report-generation error using the same frozen report input.

### Report contents

- Hunt hypothesis.
- Objective and scope.
- Data sources used.
- Findings.
- Selected evidence excerpts and counts.
- Entities.
- Timeline.
- Coverage and limitations.
- Conclusion and disposition.
- Query appendix.

The report must not contain the full raw Splunk result set.

All stored execution, evidence, approval, audit, query-range, and finalization times use UTC. The report may display times in a deployment-configured timezone, but every displayed timestamp must include its timezone label. The query appendix retains the exact UTC search bounds used for execution.

### Query appendix

For every executed query, include:

- Exact SPL.
- Query purpose.
- Indexes and time range.
- Execution timestamp.
- Splunk job ID.
- Result count and status.
- Errors or truncation information.

Operational audit metadata that is not part of the analyst report remains separate from the report.

## 15. Retention

All retention values are deployment-configurable.

| Data | Default retention |
| --- | ---: |
| Temporary raw query results after hunt completion | 24 hours |
| Temporary raw results for abandoned hunts | 7 days |
| Workspace, uploaded inputs, selected evidence, notes, and query ledger | 90 days after last activity |
| Final PDF, query appendix, and audit trail | 90 days after last activity |

For retention purposes:

- `last activity` means the last user or hunt-worker action that changed the hunt, including editing inputs, saving a plan, approving a plan, executing a query, adding evidence or notes, cancelling the hunt, editing the report, or finalizing the report.
- Viewing or downloading a hunt does not extend retention.
- Automated cleanup, health checks, and other maintenance do not extend retention.
- An `abandoned hunt` is a non-terminal hunt with no active worker or external job and no user change or worker progress for seven consecutive days.
- When a hunt reaches its configured retention date, the application deletes its workspace, uploaded documents and intelligence inputs, selected evidence, notes, query ledger, final PDF, query appendix, and hunt-specific audit trail together.
- Temporary raw results continue to use their shorter retention periods.
- All retention values remain operator-configurable without rebuilding the image.

## 16. Application Stack

### Frontend

- React.
- Vite.
- Lexical editor.
- No Next.js.
- No Tiptap.

Minimum MVP screens and states:

- Login.
- Private hunt list showing only the authenticated user's hunts and their workflow states.
- Create-hunt screen for pasted context, supported uploads, optional model selection, and submission.
- Discovery and plan-review workspace showing the discovery snapshot, editable plan draft, approval, analyst revision, and agent-revision request.
- Running-hunt workspace showing locked inputs and plan, current phase, open questions, budget use, query ledger, evidence progress, errors, and a cancel action with confirmation.
- Paused-hunt state showing the interruption reason and allowing only unchanged resume or cancellation.
- Cancelled-hunt read-only state showing what stopped and confirming that a new hunt is required to start again.
- Report workspace for normally completed hunts, including report editing, citation validation, finalization, and final PDF download.
- Explicit loading, empty, validation-error, unavailable, budget-exhausted, failed, and read-only states; errors are not represented only by transient notifications.

### Backend

- Python.
- FastAPI.
- PydanticAI.
- Pydantic models for validated application and agent data.

### Database

- PostgreSQL.
- SQLAlchemy 2.
- Alembic migrations.

### Background execution

- Run hunts in a separate worker process rather than inside a FastAPI request or `BackgroundTasks`.
- Use a PostgreSQL-backed job table.
- Use the same application image for the API and worker, with different container commands.
- Do not add Celery, Redis, or RabbitMQ for the MVP.

### Splunk

- Official `splunk-sdk` Python library.
- Application-owned `SplunkConnector` wrapper.

### Authentication

- Local accounts.
- `argon2-cffi` for Argon2id password hashing.

### Reports

- HTML report templates.
- WeasyPrint PDF generation.

### Testing

- Pytest.
- Playwright.
- Mocked model interfaces.
- Mocked Splunk connector.

## 17. Docker and Deployment

### Deployment model

- On-premises Docker Compose is the first deployment target.
- The same immutable application image must be deployable on-premises, in AWS, or in Azure.
- Do not maintain different application codebases or different application builds for each environment.

### Inside the application image

- Backend code.
- Frontend build.
- Agent logic.
- Prompts.
- Default configuration.
- Report templates.
- Database migrations.
- Static assets.
- Required runtime libraries.

### Outside the application image

- Docker Compose deployment manifest.
- Environment-specific, read-only runtime configuration.
- Secrets.
- Persistent PostgreSQL data.
- Persistent application data.

### Runtime configuration

Use a read-only mounted YAML file for non-secret environment-specific settings such as:

- Splunk URL and connection settings.
- Selected model provider and model name.
- OpenAI, Bedrock, or LiteLLM endpoint configuration.
- Hunt budgets.
- Context limits.
- Retention settings.
- Active-hunt and deployment-wide Splunk concurrency limits.
- Upload size, count, and extracted-text limits.
- Report input, evidence-excerpt, page-count, and render-time limits.
- Minimum free-space reserves for persistent and temporary data volumes.
- Report display timezone.
- Customer CA bundle paths and the explicit lab-only TLS-verification override.

### Secrets

- Mount secrets as Docker secrets or files under `/run/secrets`.
- Do not bake secrets into the image.
- Do not store secrets in the normal runtime YAML.
- Do not use ordinary environment variables for secret values.

Secrets include:

- Splunk credentials or token.
- OpenAI API key.
- AWS credentials when required by the deployment.
- LiteLLM credentials when configured.
- Application authentication secrets.

### Persistent data

Use Docker volumes or customer-provided persistent storage for PostgreSQL and retained application data.

- PostgreSQL stores accounts, ownership, hunt and workflow state, discovery and execution-configuration snapshots, plans and approvals, the job queue, query ledger, budgets, findings, entities, selected-evidence records, report content and metadata, retention dates, and audit records.
- The persistent application-data volume stores uploaded source documents and finalized PDF files.
- Temporary raw Splunk result batches use a separate temporary-data volume so their shorter retention and storage limits can be enforced independently.
- PostgreSQL stores the application-assigned file ID, storage location, size, content type, SHA-256 hash, retention date, and status for every file or temporary result object.
- File writes use a temporary name followed by an atomic move after hashing. A database record is marked complete only after the final file exists and its hash matches.
- Cleanup retries incomplete deletions and removes orphaned temporary files without deleting a file referenced by a live database record.

### Updates

- Publish versioned immutable application images.
- Upgrade by changing the configured image version.
- Perform an explicit backup of PostgreSQL and the persistent application-data volume before migrations or upgrades.
- Verify that both backups completed before applying the migration.

### Health, startup, and container behavior

- The API liveness check reports whether the API process is running.
- The API readiness check reports ready only when required configuration is valid, PostgreSQL is reachable, required migrations are applied, and required persistent paths are writable.
- The worker writes a heartbeat to PostgreSQL. Worker readiness reports ready only when configuration is valid, PostgreSQL is reachable, migrations are current, and the worker can claim work.
- Readiness checks the configured minimum free-space reserve on persistent and temporary data volumes. MVP defaults are 1 GB reserved on the persistent volume and 2 GB reserved on the temporary volume. Uploads and result caching fail clearly before a write would cross that reserve.
- Splunk and model connectivity are checked during startup preflight and are exposed separately from process liveness so a temporary external outage does not cause an endless container restart loop.
- Database migrations run once as an explicit upgrade or startup step. The API and worker do not race each other to apply migrations.
- The API and worker run as a dedicated non-root user inside the container.
- The container filesystem is read-only except for explicitly mounted temporary and persistent-data paths that require writes.
- Runtime configuration and secret files are read-only to the application user.
- TLS certificate verification is enabled by default for Splunk, model endpoints, PostgreSQL when TLS is configured, and external provider connections.
- A deployment may mount a customer CA bundle. Disabling TLS verification requires an explicit lab-only setting, produces a visible warning, and is not an accepted production default.

## 18. Data Handling

- Assume the configured LLM endpoint is authorized to ingest raw Splunk results for the deployment.
- Raw Splunk results may be sent to the configured OpenAI, Bedrock, or LiteLLM-backed model.
- Minimize what is sent for cost, context quality, and performance rather than because raw ingestion is prohibited.
- Retain full raw query batches only as temporary cache data.
- Retain selected evidence required to support findings and citations.
- Treat uploaded documents, threat-intelligence text, retrieved context, and Splunk event values as untrusted data rather than application or agent instructions.

### Deferred CUI documentation TODO

Before a production deployment is represented as ready for CUI, document which protections are provided by the application, deployment operator, customer infrastructure, storage platform, backup process, and configured model endpoint. Cover transport, storage, logs, reports, exports, administrative access, backup, and deletion responsibilities.

This documentation task is deferred from the current domain-accuracy MVP work and does not add a new product capability or certification effort.

## 19. Validation

Validate the MVP with at least 12 representative, known-answer hunts using synthetic or purpose-built controlled Splunk test data. Customer production data is not required for this acceptance test.

A known-answer hunt uses a fixed test dataset and a written answer key created before the test run. Because the test data is controlled, the team knows exactly which events and evidence exist before the agent runs. The answer key lists the evidence items in the test data, the acceptable disposition, and the important limitations the report should identify.

Unit and component tests use the mocked Splunk connector. The 12 end-to-end known-answer hunts use a real non-production Splunk deployment loaded with the versioned synthetic fixtures so SPL correctness, job behavior, fields, time ranges, truncation, and workload are tested against Splunk itself. Test indexes are isolated from customer production data.

Synthetic fixtures, expected-evidence answer keys, hunt inputs, approved plans, and evaluation code are versioned together. A test result records those versions, the application image version, and the execution-configuration snapshot so the run can be reproduced.

The answer key is available only to the evaluation harness after the hunt. It is never included in the model prompt, uploaded hunt context, Splunk discovery catalog, or analyst-approved plan.

The 90% expected-evidence recovery requirement is an MVP testing metric for this controlled dataset. It is not a promise that every production hunt will find 90% of all real-world malicious activity.

Use the 12 hunts to test different behavior rather than repeating only successful examples:

- Three hunts with a supported hypothesis and known evidence.
- Two hunts where the hypothesis is not supported and no matching evidence should be invented.
- One hunt with missing or incomplete data coverage.
- One hunt that reaches a result-row or byte limit and must handle truncation correctly.
- One hunt with a Splunk query timeout.
- One hunt with an invalid model response that requires repair.
- One hunt interrupted during execution and safely resumed without duplicate work.
- One hunt that reaches a hard budget and stops cleanly.
- One hunt cancelled during execution that stops new work, cancels active Splunk jobs when possible, remains terminal, and requires a new hunt to start again.

Measure:

- Expected-evidence recovery.
- Unsupported or fabricated findings.
- Finding-to-evidence citation completeness.
- Hunt completion and disposition time.
- Splunk query count and workload.
- Duplicate-query rate.
- Model-call and token usage.
- Compliance with all hard budgets.

Initial acceptance requirements:

- At least 90% of expected evidence is recovered.
- No fabricated evidence.
- Every positive material report claim cites retained evidence, and every negative or coverage claim cites the completed queries that support its stated scope.
- Every hunt stops starting new queries at its configured cutoff and completes, pauses, is cancelled, or fails explicitly by the configured hard completion ceiling.
- No hard budget is exceeded without the hunt receiving `budget_exhausted` or `failed`, as applicable.

Calculate expected-evidence recovery as follows:

1. Before running a positive known-answer hunt, list each distinct evidence item that the test dataset contains and that the approved hunt scope makes available.
2. Count an item as recovered only when the hunt retains the correct evidence record and a finding or material report claim cites that evidence ID correctly.
3. Add the recovered-item counts across all positive known-answer hunts.
4. Divide by the total expected-evidence-item count across those hunts and multiply by 100.

Hunts with no expected evidence are not included in that percentage's denominator. They are evaluated on correct disposition, coverage statements, and the absence of invented evidence. Report both the overall recovery percentage and each hunt's individual result so a weak hunt is visible.

### Required deterministic tests

The 12 known-answer hunts test end-to-end domain behavior. The normal automated test suite separately covers:

- Owner checks on every hunt, artifact, report, and worker lookup.
- Plan version and hash approval, execution-configuration binding, invalid state moves, locked running hunts, and idempotent cancellation.
- Supported and rejected upload types, size and extraction limits, corrupt files, archive bombs, and path-safe storage.
- SPL allow and deny cases, fixed UTC ranges, discovered fields, policy reason codes, cache keys, and rejection before submission.
- Query, row, byte, cycle, model-call, token, timeout, cutoff, and hard-ceiling boundary behavior.
- Retry classification, persisted Splunk job recovery, lease expiration, and replay without duplicate work.
- JSON parsing, Pydantic validation, `unknown` handling, invalid IDs, repair limits, and explicit model-call failures.
- Evidence hashing, cross-hunt citation rejection, report citation validation, HTML escaping, blocked remote PDF resources, and stored PDF hash verification.
- Retention dates, abandoned-hunt detection, file and database cleanup, incomplete-deletion retries, and orphan cleanup.
- Configuration validation, health and readiness behavior, migration ownership, backup preconditions, and TLS verification defaults.
- Playwright coverage for login, private hunt visibility, plan revision and approval, locked running hunts, cancellation confirmation, paused unchanged resume, report editing, citation errors, finalization, and PDF download.

### Model-configuration qualification

For initial MVP accuracy validation, run the 12 known-answer hunts against one available external provider-and-model configuration: either OpenAI API or Amazon Bedrock. Passing the suite with either one is sufficient for the first domain-accuracy milestone.

Run the same suite later against any additional provider-and-model configuration before describing that exact configuration as accuracy-validated. This does not mean testing every model a provider offers.

The LiteLLM/vLLM integration is tested initially with a mocked OpenAI-compatible endpoint. Those automated tests must cover request and response compatibility, structured-output validation, tool calls, token and call accounting, timeouts, retries, and failure handling. They do not require local Gemma weights, GPUs, a working local inference deployment, or real local-model accuracy testing.

After the external-provider workflow is proven and local model infrastructure is available, run the same known-answer suite against the real Gemma 4 31B deployment before describing that local configuration as deployed or accuracy-validated.

Each configuration that runs the real known-answer suite must satisfy the same no-fabrication, citation, stopping, and hard-budget requirements. Record accuracy, query workload, completion time, model calls, token use, repair attempts, and failures separately for each configuration.

Compare the progressive, narrow-to-broad search strategy against a broad-search baseline using accuracy, time-to-disposition, Splunk workload, and model-token consumption. The baseline uses the same synthetic data, hypothesis, approved time range, read-only SPL policy, service account, hard safety limits, and model configuration. It is "broad" because it starts with a broad search rather than progressive narrowing; it is not exempt from security or resource controls.

## 20. Adjustable Settings Summary

The following must be configurable without rebuilding the image:

- Splunk endpoint and credentials.
- Model provider, endpoint, model name, and credentials.
- Query-start cutoff.
- Hard hunt completion ceiling.
- Agent-cycle limit.
- Query count, concurrency, search-job timeout, and Splunk transport timeout.
- Active hunts per deployment and deployment-wide Splunk job concurrency.
- Per-query and per-hunt result row and byte limits.
- Representative and targeted event limits.
- Model call, model-call timeout, context, input-token, and output-token limits.
- Evidence and report retention periods.
- Temporary raw-result retention periods.
- Upload size, count, and extracted-text limits.
- Report input, evidence-excerpt, page-count, and render-time limits.
- Minimum free-space reserves for persistent and temporary data volumes.
- Report display timezone.
- Customer CA bundle paths and the explicit lab-only TLS-verification override.
