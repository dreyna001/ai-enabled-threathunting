# Post-Implementation Local Splunk Validation Plan

Status: Planned post-implementation validation  
Run after: Implementation Blocks 1 through 5 are complete  
Required before: Final MVP acceptance in Implementation Block 6  
Source of truth: [Threat Hunting MVP Specification](./threat-hunting-mvp-spec.md), especially section 19

## 1. Purpose

Prove that the completed application can load controlled security logs into a real local Splunk deployment, discover the available data, generate safe SPL, execute that SPL through the Splunk API, retain the correct evidence, and produce an evidence-backed report.

This is a validation environment. It does not add another production deployment option or change the MVP product scope.

## 2. What this test proves

The test must prove that:

- Splunk actually executes the application's approved SPL queries.
- The application does not treat a generated query as successful unless Splunk returns a successful job result.
- Generated SPL is rejected before submission when it violates policy.
- The agent discovers and uses only indexes, source types, and fields that exist in the test environment.
- Evidence retained by the application can be traced back to a specific Splunk result and query.
- Expected evidence is found and cited at the required rate.
- No evidence, event, host, user, timestamp, or finding is invented.
- Timeouts, truncation, retries, interruption, budgets, and cancellation behave as specified.
- The same test can be repeated from a clean environment with the same fixtures and settings.

## 3. Test environment

Use a standalone Splunk Enterprise container from the official Splunk image. Pin the exact image version or digest; do not use `latest` for an acceptance run.

The local test stack contains:

```text
Versioned synthetic fixtures
        |
        v
Test-only fixture loader --HEC--> Local Splunk container
                                      |
                                      | HTTPS search API
                                      v
Threat hunting application --> SPL validator --> Splunk adapter
        |
        v
Evidence, findings, report, and evaluation results
```

Required local services:

- The completed threat hunting application and worker.
- PostgreSQL and the application's normal persistent storage.
- One standalone Splunk Enterprise container.
- The normal deterministic test model for harness checks.
- One approved external model configuration, either OpenAI API or Amazon Bedrock, for the domain-accuracy acceptance run.

Use a dedicated Compose file and project name so the test environment cannot affect unrelated containers or volumes.

Proposed implementation paths:

```text
deploy/docker/compose.splunk-test.yml
deploy/docker/splunk-test/
tests/known_answer/
scripts/local_splunk_test.py
docs/acceptance-results.md
```

## 4. Security boundaries

- Use only synthetic test data. Never load customer or production data.
- Bind Splunk Web, HEC, and the management/search API to loopback unless the test environment explicitly requires otherwise.
- Keep the Splunk administrator password, HEC token, and application search credentials out of Git, images, logs, reports, and browser responses.
- Use the Splunk administrator only during bootstrap.
- Give the application a separate search-only account limited to the test indexes.
- Give the fixture loader a separate HEC token that can write only to the test indexes.
- Do not give the model Splunk credentials, container access, a shell, or direct API access.
- Every agent-generated query must pass the normal deterministic SPL validator immediately before submission.
- Enforce the normal index, time-range, row, byte, query-count, timeout, and hunt-budget limits.
- Configure and trust a local test certificate or test certificate authority. Do not make disabled TLS verification the normal test path.
- Keep answer keys outside the model prompt, uploaded hunt context, Splunk discovery results, and approved plan.

## 5. Synthetic data design

Each event must have a stable synthetic identifier so the evaluation harness can identify it without relying on row position. All event timestamps and hunt ranges use fixed UTC values.

Use realistic but fictional values for:

- Users and service accounts.
- Workstations and servers.
- IP addresses and domains reserved for documentation or testing.
- Process names and command lines.
- Authentication, endpoint, DNS, network, and cloud activity.
- Benign background activity.
- Evidence that supports the hunt hypothesis.
- Events that look interesting but should not become a confirmed finding.

Suggested test indexes:

```text
th_test_auth
th_test_endpoint
th_test_dns
th_test_network
th_test_cloud
```

Each known-answer hunt directory should contain:

```text
tests/known_answer/KH-01/
├── hunt-input.json
├── approved-plan.json
├── fixture-manifest.json
├── expected-evidence.json
└── events/
    ├── auth.jsonl
    ├── endpoint.jsonl
    ├── dns.jsonl
    ├── network.jsonl
    └── cloud.jsonl
```

The fixture manifest records:

- Fixture version and content hashes.
- Expected event count by file, index, and source type.
- Fixed earliest and latest UTC event times.
- Required fields.
- Synthetic run identifier.
- Application configuration expected by the hunt.

The loader must fail if a fixture is malformed, has a duplicate synthetic event ID, targets an unapproved index, or does not match its manifest.

After loading, verify event counts, unique event IDs, fields, earliest/latest timestamps, and fixture hashes through Splunk queries before starting a hunt.

## 6. The twelve known-answer hunts

Use the exact allocation required by specification section 19:

| Hunt | Scenario | Expected behavior |
|---|---|---|
| KH-01 | Supported hypothesis 1 | Recover and cite the known evidence |
| KH-02 | Supported hypothesis 2 | Recover and cite the known evidence |
| KH-03 | Supported hypothesis 3 | Recover and cite the known evidence |
| KH-04 | Unsupported hypothesis 1 | Report no supporting evidence without invention |
| KH-05 | Unsupported hypothesis 2 | Report no supporting evidence without invention |
| KH-06 | Missing data coverage | State the coverage gap and limit the conclusion |
| KH-07 | Result-row or byte limit | Mark truncation and avoid claiming complete coverage |
| KH-08 | Splunk query timeout | Apply the permitted failure behavior and stop or pause correctly |
| KH-09 | Invalid model response | Use no more than the allowed repair attempt and count all calls |
| KH-10 | Interrupted execution | Resume safely without duplicate queries or evidence |
| KH-11 | Hard budget reached | Stop cleanly with the correct final status |
| KH-12 | Cancelled execution | Stop new work, cancel active work when possible, and remain terminal |

Use controlled fault injection for timeout, invalid-response, interruption, and cancellation cases. The fault must be introduced at a documented boundary and must not use an unbounded or intentionally dangerous SPL query.

## 7. Execution sequence

### Phase 1 — Clean bootstrap

1. Record the application commit, application image digest, Splunk image digest, fixture version, test-plan version, and execution-configuration snapshot.
2. Validate the dedicated Compose file.
3. Start a clean local Splunk test project with its own named volumes.
4. Wait for Splunk health and readiness checks to pass.
5. Create only the required test indexes, source types, HEC input, search-only role, and search account.
6. Verify that invalid credentials and an untrusted TLS certificate fail closed.

Do not destroy or reset any volume unless its exact test project name and volume names have been verified first.

### Phase 2 — Load and verify fixtures

1. Load the versioned JSON Lines fixtures through the test-only HEC token.
2. Wait for indexing to complete using a bounded readiness check.
3. Query Splunk for the expected event counts, unique synthetic event IDs, fields, source types, and timestamp ranges.
4. Compare the results with the fixture manifest.
5. Stop the run immediately if any count, hash, ID, field, or timestamp check fails.

### Phase 3 — Connector and policy smoke tests

Before the twelve hunts, verify:

- Splunk authentication with the search-only account.
- Discovery of only the allowed test indexes, source types, and fields.
- One allowed bounded SPL query executes successfully.
- A forbidden command is rejected before Splunk receives it.
- An unapproved index is rejected before Splunk receives it.
- Excessive time ranges and result limits are rejected.
- Splunk job status, result retrieval, cancellation, timeout, and normalized errors work.
- Credentials and raw authorization headers do not appear in logs.

### Phase 4 — Deterministic rehearsal

Run the behavioral suite with deterministic model responses before spending external-model calls. This rehearsal checks orchestration, state changes, validator behavior, fault injection, evidence storage, citation checks, scoring, recovery, and cleanup.

The rehearsal does not count as model-accuracy qualification.

### Phase 5 — Real end-to-end acceptance run

1. Select one approved external provider and exact model configuration: OpenAI API or Amazon Bedrock.
2. Start each hunt from a clean application state while retaining the verified Splunk fixtures.
3. Complete the normal discovery and analyst plan-approval flow.
4. Let the application submit only policy-approved SPL through its Splunk adapter.
5. Preserve Splunk job IDs, normalized query records, evidence IDs, findings, citations, reports, budgets, and audit records.
6. Evaluate the result only after the hunt is terminal.
7. Keep the answer key hidden until evaluation.
8. Record every model call, repair attempt, query, cache hit, timeout, retry, state change, and final disposition.

### Phase 6 — Progressive versus broad baseline

Run the comparison required by specification section 19 using the same:

- Synthetic data.
- Hypothesis and approved time range.
- Search-only account.
- SPL safety policy.
- Hard resource limits.
- Provider and model settings.

The only intended difference is that the baseline starts with a broad search rather than the normal progressive narrow-to-broad strategy.

Compare accuracy, time to disposition, Splunk workload, query count, result volume, model calls, and token use.

### Phase 7 — Results and controlled teardown

1. Write the results to `docs/acceptance-results.md` using no secrets or raw sensitive payloads.
2. Retain the exact fixture, answer-key, application, image, configuration, and model identifiers required to reproduce the run.
3. Confirm the application retained and deleted test artifacts according to the configured retention behavior.
4. Stop the dedicated test stack.
5. Remove test volumes only through the test-specific cleanup command and only after their exact names are displayed and verified.

## 8. Measurements and pass conditions

Calculate expected-evidence recovery exactly as defined in specification section 19:

```text
recovered and correctly cited expected evidence
------------------------------------------------ x 100
all expected evidence available to positive hunts
```

No-evidence hunts are excluded from the percentage denominator. They are evaluated on correct disposition, accurate coverage statements, and absence of invented evidence.

The run passes only when:

- At least 90% of expected evidence is retained and correctly cited across the positive hunts.
- No fabricated evidence exists.
- Every material positive claim cites retained evidence.
- Every material negative or coverage claim cites the completed queries supporting its stated scope.
- No cross-hunt, missing, duplicate, or incorrect citation receives credit.
- Every forbidden SPL test is blocked before submission.
- No hard budget is silently exceeded.
- Timeout, truncation, repair, interruption, budget, and cancellation hunts reach the required explicit states.
- Interrupted execution does not duplicate a Splunk job, query record, evidence record, or report.
- The application search account cannot write data, change Splunk configuration, or search outside the test indexes.
- The progressive-versus-broad comparison is recorded.

Report both the overall recovery percentage and each hunt's individual result.

## 9. Model qualification boundaries

- Passing with deterministic model responses proves the harness, not model accuracy.
- Passing with one exact OpenAI API or Bedrock configuration satisfies the initial domain-accuracy milestone.
- Record provider, model name, model/version identifier when available, parameters, prompt/contract version, and execution settings.
- A different model or materially different configuration must run the same known-answer suite before being called accuracy-validated.
- Test the local OpenAI-compatible adapter with a fake endpoint as part of normal automated tests.
- Do not claim that Gemma 4 31B or any real local model is deployed or accuracy-validated until the same suite is run against that real deployment.

## 10. Planned implementation slices

### Slice 1 — Local Splunk container and bootstrap

Objective: Start a pinned, isolated Splunk instance with trusted TLS, test indexes, HEC loading, and a search-only application account.

Files to add or update:

- `deploy/docker/compose.splunk-test.yml`
- `deploy/docker/splunk-test/`
- `.env.example`
- operator documentation

Tests and checks:

- Compose validation, health/readiness, credential separation, index restrictions, TLS success/failure, and persistent-volume behavior.

Acceptance: A clean machine can start the isolated test deployment using documented commands, and the application account cannot administer Splunk or access non-test indexes.

Rollback: Stop only the named test project. Preserve its volume for diagnosis unless an explicit test-specific cleanup is requested.

### Slice 2 — Versioned fixtures and idempotent loader

Objective: Load controlled synthetic events and prove that Splunk contains exactly the declared dataset.

Files to add or update:

- `tests/known_answer/`
- `scripts/local_splunk_test.py`
- fixture schema and validation tests

Tests and checks:

- Schema, duplicate-ID, hash, count, index allowlist, source type, timestamp, partial-load, and replay behavior.

Acceptance: The loader either produces a fully verified dataset or fails explicitly without presenting a partial load as valid.

Rollback: Discard only the dedicated test run or rebuild the dedicated Splunk test volume from the versioned fixtures.

### Slice 3 — Real Splunk connector and policy checks

Objective: Prove discovery, real SPL execution, job handling, and pre-execution policy rejection.

Files to add or update:

- Splunk integration tests
- policy test cases
- local test runner and documentation

Tests and checks:

- Allowed and denied SPL, index and field discovery, time limits, row limits, timeout, job cancellation, error normalization, and audit records.

Acceptance: Real SPL reaches Splunk only after approval and deterministic validation; denied SPL never reaches Splunk.

Rollback: Disable the local integration-test profile without changing the production connector contract.

### Slice 4 — Twelve-hunt runner and evaluator

Objective: Execute the complete known-answer suite and calculate evidence recovery without exposing the answer key to the agent.

Files to add or update:

- known-answer runner
- evidence and citation evaluator
- result schema
- deterministic fault controls

Tests and checks:

- Full, partial, zero-expected, duplicate, missing, cross-hunt, and incorrectly cited evidence; all twelve required scenarios.

Acceptance: The suite generates a reproducible result for every hunt and applies the section 19 formula exactly.

Rollback: Keep the runner opt-in so ordinary unit tests remain fast; remove only generated test results when rerunning.

### Slice 5 — External-model qualification and acceptance report

Objective: Run the real suite with one approved external model configuration and record the final decision.

Files to add or update:

- opt-in provider test configuration
- `docs/acceptance-results.md`
- operator runbook

Tests and checks:

- Missing credentials skip safely, credentials stay out of output, provider/model metadata is recorded, and the progressive-versus-broad comparison uses matching controls.

Acceptance: All pass conditions in this plan are met and the report clearly separates passed, failed, and deferred items.

Rollback: Revoke test credentials if necessary, preserve non-secret result metadata, and do not label a failed or incomplete configuration as qualified.

## 11. Explicitly out of scope

- Production Splunk validation.
- Customer data.
- Splunk clustering, search-head clustering, or indexer clustering.
- Splunk Enterprise Security content or notable-event workflows unless separately approved.
- Load, scale, or performance certification beyond the MVP's configured hard limits.
- Direct model access to Splunk.
- Automatic response, containment, or writeback actions.
- Real Gemma 4 31B deployment or accuracy qualification.
- Certification of every OpenAI or Bedrock model.

## 12. Hard stops

Stop the validation run if:

- The environment is not clearly isolated from production.
- Any fixture contains real customer or production data.
- The Splunk or model credential scope is broader than intended.
- TLS verification is silently disabled.
- Fixture verification fails.
- The answer key becomes visible to the agent or model.
- A query bypasses approval or deterministic policy validation.
- A forbidden query reaches Splunk.
- Test cleanup cannot identify its exact project and volume targets.
- Results cannot be tied to exact fixture, application, model, and configuration versions.

