# Pause and resume checkpoint

## Active desktop work after resumption

**The user resumed work on September 10 and set an active goal to finish all checkpoint fixes and qualification gates. This section supersedes the historical pauses below.**

- The authoritative source is this desktop project on local `main`, base `d0af9378fbfec8a8b2a7574e760e345a431a3ede`, with all restored v22 changes and current fixes kept together. Continue from the current `main` HEAD; the user has authorized periodic verified checkpoint commits and pushes to remote `main`. The redundant local feature branch pointed to the same commit and was removed. Local `main` is the only branch in this repository.
- The saved v22 patch and all ten base/candidate file hashes were verified before applying the patch here. Frozen fixture hashes still match. Prompt binding is now **1.23**, policy **1.4**. The candidate is not deployed or analytically qualified.
- Restored PostgreSQL and the existing v18 API/worker/frontend by recreating missing mount bindings against the same named volumes. The database again reports migration 0013, 42 hunts, zero queued/claimed jobs, and the historical hunt/job fingerprints unchanged. Existing Splunk was started against its original volumes and is healthy. No fixtures were loaded and no new hunts or provider diagnostics were run.
- Fixed lookup metadata citation-label encoding, requested-page priority during context sampling, and one-sided time filters escaping the approved window. Regression tests failed before each fix and passed afterward. Corrected the saved integration test's incomplete fake follow-up responses; both page/checkpoint recovery cases now pass.
- Improved request fitting to use the space between the original halving steps, and reserved a final model call plus half the remaining tokens before adaptive assessment/follow-ups. An oversized assessment now preserves retained evidence and proceeds to final synthesis with an explicit budget limitation. Its regression failed before the fix.
- Verification artifacts are under `runtime/qualification/quality-fixes-20260910/v22-resumed/`. The first full run had 600 passes and eight setup errors caused by the disposable database's SQL_ASCII encoding. With `PGCLIENTENCODING=UTF8`, **608 tests passed, no skips**, before the last fitting/reservation changes. After the fitting/reservation fixes and prompt binding update, the full backend suite passed **610 tests, no skips**, with the same two upstream warnings; mypy passed on **55 source files**. Related checks also passed **48 tests**, including the 25-test focused file. See `verification.json`, `backend-tests-second.log`, and `mypy-second.log`. Any further edits require appropriate fresh verification.
- Offline frozen-evidence fitting now supplies 411 of 447 representations with an unused budget, compared with 250 before the fitting correction. Using the recorded trial-13 **total** usage leaves capacity for 75 representations; the retrieval step's half-budget allocation cannot fit its minimum request and falls back to final-only synthesis without a provider call. This stress case includes the old synthesis usage and is **not measured pre-synthesis capacity**. Byte-based estimation remains conservative and needs further review before live qualification.
- GitHub sign-in completed on September 10 using the GitHub CLI credential store, connected to this repository for Git access. Fetch and a non-mutating push dry run passed. The user explicitly authorized updating remote `main` and periodically pushing verified checkpoints throughout this goal. At authorization, the remote had only the older feature branch at `e825367`, already an ancestor of desktop `main`; the first authorized checkpoint push creates remote `main`. Check current Git refs for publication status.
- The clean `/home/dreyna/ai-enabled-threathunting` checkout is an older ancestor. `/tmp/threat-hunting-resume-work` matches the original saved candidate and is no longer used. `/home/dreyna/src/ai-enabled-threathunting` contains a different, older refactor plus uncommitted changes. Its changed-file inventory is saved in `older-checkout-reconciliation.json`; applicable fixes must be reconciled before retiring it. The user clarified: inspect code to establish which behavior is newer and keep the newer implementation. Do not blindly merge the older refactor. Preserve any still-needed older fixes in desktop main before retiring the duplicate. The older tracked uncommitted patch is also preserved as `older-refactor-uncommitted.patch`; new/untracked older files remain in that checkout and must not be discarded.


- Latest pre-publication verification: **630 backend tests passed, no skips**, two existing dependency warnings; mypy passed on **55 source files**. See `backend-tests-prepush.log` and `mypy-third.log`. The preceding full run had 629 passes and one new cancellation-test expectation failure: cancellation correctly revoked the worker lease. The corrected test verifies rejection, unchanged checkpointed findings and zero additional model calls.
- Reconciled older fixes for effective Splunk index permissions and source-query citation validation. Discovery now filters explicit/inherited allows and denies, fails closed on unavailable permissions, and preserves differing field observations with a limitation. The generic citation validator resolves source-query lineage and rejects failed or incomplete query coverage for negative claims. Review the active synthesis/materialization boundary for equivalent negative-claim enforcement before analytical qualification; fixing the generic validator alone does not prove the live path.
- Fixed newer retained pages being starved by older requests. Pages from the latest model round get priority; repeated pages terminate retrieval and remain prioritized for the final answer. Regressions cover checkpoint recovery, repeat termination and cancellation. Partially identified sources already remain ungrouped across queries; that additional regression passes without a source change.
- Preserved all 370 tracked and untracked older source files in `older-checkout-source-and-untracked.tar.gz`, with its SHA-256 in `older-checkout-archive.json`. The old checkout is not retired yet. Its comparison-field SPL validation still needs evaluation against the newer parser before reconciliation is complete; do not import its entire architecture.
- Read-only live checks found a deployment mismatch: the existing Splunk container publishes management port **28089**, while the saved v18 application configuration points to **18089**. The saved Splunk token is rejected at 28089 (`invalid_credentials`). Resolve the correct existing instance/credentials and endpoint before any provider replay or fresh hunt. No search or fixture reload was submitted; container health alone does not establish usable integration access.

Current test tooling: `/tmp/threat-hunting-desktop-v22-env/bin/python`, installed from this desktop project's frozen lockfile. Disposable test DSN remains `postgresql+psycopg:///threat_hunting_quality_test?host=/tmp&port=55439`; set `PGCLIENTENCODING=UTF8`. Never run tests against the application database.

Next: finish retained-page/repeat/cancellation/resource-reservation review, improve large-input handling where needed, reconcile applicable older-checkout fixes, run final deterministic checks, and then perform the new labeled provider replay and claim-level review. All deployment, fresh-plan/full-hunt, repeated-case/matrix/fixture-adapter, independent analyst, and release gates in the ordered checklist below remain required. Preserve trial 14, all historical artifacts and application volumes. Keep working from desktop `main` only.

## Historical September 10 pause

**Paused at the user's request on September 10, 2026. Restart from the desktop project, not the remote-control task. No work should resume until the user asks.**

## Current desktop restart point

- Use `/mnt/c/Users/dreyn/OneDrive/Desktop/Cursor/ai-enabled-threathunting` (Windows: `C:\Users\dreyn\OneDrive\Desktop\Cursor\ai-enabled-threathunting`), local `main`, base commit `d0af9378fbfec8a8b2a7574e760e345a431a3ede`. The remote task's `/home/dreyna/ai-enabled-threathunting` checkout is older and lacks this checkpoint.
- The project's actual application source remains **v21, prompt 1.22 / policy 1.4**. New **v22 work is an unfinished, unqualified candidate saved as a patch and source snapshot; it has NOT been applied to this project's source, built, deployed, committed or pushed**. The temporary implementation checkout is `/tmp/threat-hunting-resume-work`; do not rely on `/tmp` surviving a restart.
- Durable handoff: [`runtime/qualification/quality-fixes-20260910/v22-paused/manifest.json`](../runtime/qualification/quality-fixes-20260910/v22-paused/manifest.json), [`candidate.patch`](../runtime/qualification/quality-fixes-20260910/v22-paused/candidate.patch), and [`source/`](../runtime/qualification/quality-fixes-20260910/v22-paused/source/). Ten changed/new files are preserved with base and candidate SHA-256 hashes. The patch passed `git apply --check` against this desktop project; that was a handoff-integrity check, not an implementation test.
- The full backend/typing run was queued but **did not start** before the stop. Read-only pause capture found no verification process and no full-run logs. No new model calls, Splunk searches, fixture reloads, hunts, or deployments occurred in this resumption. No scheduled continuation exists.

## What was completed during this resumption

1. Located the correct desktop project and verified the v21 source and frozen fixture hashes. The substantive v21 files match the previous checkpoint; its document had since been edited. The earlier broad dirty tree was already committed in `d0af937`; it was not discarded.
2. Completed an assistant claim-level review of the saved four-call focused diagnostic. It remains **not accepted**: broader lead chronology and requested entity counts are missing, and a communications-to-process relationship lacks its process endpoint citation. See [quality review](../runtime/qualification/quality-fixes-20260910/v22-paused/focused-quality-review.json) and its saved claim/coverage evidence. The four calls used 308,952 input tokens, about 62% of the entire hunt budget before investigation costs. Do not rerun that completed diagnostic or mistake this assistant review for independent analyst acceptance.
3. Identified conflicting synthesis instructions: scoped entity counts were requested while numeric counts in findings were forbidden. The candidate removes that conflict, without claiming it explains every analytical error.
4. Implemented in the temporary candidate: complete-request context/input-budget preflight; remaining output allowance; synthesis sampling that rebuilds coverage while fitting; repair-size checks without changing original references; conservative identical-representation grouping that retains citation origins and preserves differing fields; bounded retained query/entity/time/page requests; completed-answer and page checkpoints; final-answer call/token/time reservation; and explicit unanswered slots when synthesis resources cannot support an answer. This keeps the existing all-question call when enough evidence is supplied, rather than unconditionally adopting the four-call prototype.
5. Added query guidance to preserve general process lifecycle chronology and avoid losing authentication events through nullable `stats BY` fields. This is unqualified guidance, not proof that fresh generated searches are correct.

## Verification status of the saved candidate

- Initial context-fitting slice: 87 focused tests passed before subsequent changes.
- Intermediate combined run: 107 passed and one new fitting test failed because its limit was smaller than the complete schema/rules/request. The test limit was corrected; the latest run of the new focused file passed **21 tests**.
- Intermediate mypy passed on **55 source files** before the last small changes.
- Three new end-to-end cases for page retrieval, recovery after a persisted answer, and exhausted-context reporting were added but **have not run**. The full backend suite and final mypy **have not run**. Do not combine the earlier counts into a claimed final pass.
- Frontend is unchanged from the previous v20 UI candidate; no frontend checks were rerun. No real-provider diagnostic or end-to-end hunt validates v22 yet.

## Environment at this pause

Docker Desktop was reachable (native client reported server 29.7.2), but the last inspected application containers were unhealthy after restart: backend/worker/PostgreSQL exited with missing WSL bind-mount errors, frontend was restarting, and Splunk was stopped. No container restoration was performed. **Current application database fingerprints and queued/claimed job counts were not rechecked** because PostgreSQL was down. The 42-hunt / zero-active-job figures below are historical, not a new verification.

A disposable PostgreSQL test cluster was started at `/tmp/threat-hunting-resume-pg`, Unix socket `/tmp`, port `55439`, database `threat_hunting_quality_test`. Test DSN: `postgresql+psycopg:///threat_hunting_quality_test?host=/tmp&port=55439`. Never point pytest at the application database. Locked dependencies were restored with `uv sync --frozen --extra dev` into `/tmp/threat-hunting-resume-work/.venv`; uv is `/tmp/threat-hunting-resume-tools/bin/uv`. These paths may disappear on restart. No secrets were copied into the handoff.

## Next work on desktop, in order

1. Read this section, the manifest and saved quality review. Preserve trial 14, historical trials, fixture hashes and all application volumes. Inspect current Git/Docker/job state; restore missing mount bindings without deleting volumes or admitting jobs before checking the database.
2. Review and restore the saved patch into the correct desktop source or a new isolated checkout. Compare manifest base hashes first; use the source snapshot to resolve any intervening changes. The current temporary candidate still carries prompt binding **1.22**; bump and synchronize the binding/docs only when a coherent candidate is ready. Do not approve a fresh plan against a stale binding.
3. Finish code review and focused tests. In particular, verify encoding of `returned_evidence_ids` / `supplied_evidence_ids` in lookup metadata into request-local reference labels; those new field names were not added to the reference-field allowlist. Check unknown-field/time handling, repeat-page termination, resource reservation, cancellation, checkpoint recovery and original coverage preservation. This is an identified follow-up, not a completed fix.
4. Run the newly added recovery/budget cases, the full backend suite on isolated PostgreSQL and mypy. Check candidate context fitting against the frozen trial-13 evidence with actual remaining hunt budgets: the UTF-8-byte estimate is conservative and may over-reduce context; it is not measured token usage. Initial evidence fitting currently targets synthesis; other model steps have preflight checks and need review for large-input behavior.
5. Complete claim-level chronology and both-endpoint relationship support, scoped counts and conservative duplicate handling. Validate new query generation for lifecycle ends and nullable auth fields. Passing structural checks does not establish analytical completeness.
6. After deterministic verification, run a new, clearly labeled real-provider replay; do not restart the completed v21 diagnostic. Compare quality, actual tokens/time, omitted records, retained-page use and failure categories. Promote no candidate solely because it returns more findings or valid references.
7. Only then build/deploy backend and worker together plus the v20 frontend, verify installed versions/settings, health/state preservation and rollback availability, generate/review a fresh plan on unchanged fixtures, preserve unapproved trial 14, and run fresh full hunts.
8. The repeated positive/negative/incomplete/outage cases, twelve-scenario matrix, fixture adapter, independent analyst acceptance and other release gates below remain open. No commit/push or external messages are authorized by this handoff.

---

## Historical September 9 checkpoint

**Everything below describes the prior pause. Use the current restart section above for today's candidate, verification and environment state.**

**Paused at the user's request on September 9, 2026, approximately 20:29 EDT / September 10, 00:29 UTC. Work is unfinished. Read this first, then the historical record in [remaining-work.md](remaining-work.md).**

## Where we stopped

**Branch to continue from:** continue work on local `main` (current head). Local `feature/2026-09-05-threat-hunt-vertical-slice` is intentionally aligned to `main` at commit `d0af9378fbfec8a8b2a7574e760e345a431a3ede`; remote `origin/feature/2026-09-05-threat-hunt-vertical-slice` still points to an older commit until the next authenticated push.

Local source is **v21, prompt contract 1.22 / SPL policy 1.4**, including the v19 retrieval and v20 report/UI changes. None of v19–v21 has been deployed. Backend and worker still run **v18, prompt 1.18 / policy 1.3**; the frontend predates the question-summary UI. Deterministic checks pass, but analytical completeness and claim support remain unresolved.

The final diagnostic was already running when the user requested this pause. It finished with four structurally valid answers; factual review is pending. Session `36795` returned exit code 0. No new tests, model calls, Splunk searches, implementation or deployment were started after the pause request. Subsequent work only documented the handoff, captured existing artifacts and checked state read-only. No diagnostic calls remain in flight; the app has **zero queued/claimed execution jobs**. Docker/services were left running. No scheduled continuation, commit, or push was created.

| Item | State at pause |
| --- | --- |
| Workspace | `/mnt/c/users/dreyn/onedrive/desktop/cursor/ai-enabled-threathunting` |
| API / worker | `threat-hunting:local-20260909-quality-v18-231548`, both healthy |
| Frontend | `threat-hunting-frontend:local-20260908-hardening`, healthy |
| Deployed config | `runtime/config/local-20260909-quality-v18-231548.yml`, selected by existing `.env` |
| Model | OpenAI `gpt-5.6-terra`, reasoning `medium` |
| Time budgets | 20-minute hunt; minute-13 query/adaptive cutoff; up to 120 seconds for in-flight query; 300-second synthesis reserve; model calls limited to 300 seconds or remaining phase time |
| Independent budgets | 50 searches, 12 model calls, 8 cycles, 500,000 input tokens, 96,000 output tokens; deployed config permits 24,000 output tokens per call |
| Concurrency | 2 queries per hunt/deployment; 1 active hunt |
| Retention ceilings | 10,000 rows / 262,144,000 bytes per query; 50,000 rows / 1,073,741,824 bytes per hunt |
| Deployed retrieval/model sampling | Earlier single-page retrieval / 100 model records; v19 paging / 500-record batches remain local |
| Database | PostgreSQL 16, migration `0013_hunt_listing_index`, 42 hunts, 0 active jobs |
| Hunt fingerprint | `48be2e4f095418eec5d4dd7784f65a29`, unchanged from v20 |
| Job fingerprint | `0dd9c1ddabe0e024e1bf9adabc6ad123`, unchanged from v20 |
| Splunk | `splunk/splunk:10.4-rhel9`, healthy; `https://127.0.0.1:18089` |
| Latest full hunt | Trial 13, `e98ad766-9dc8-4ab6-a727-ec6a3cf6b72a`, report draft; completeness review failed |
| Prepared but unexecuted | Trial 14, `c62147d0-68f9-4161-a835-16cfcf8218ac`, unapproved; preserve it |
| Working tree | Extensive tracked and untracked edits from multiple increments; preserve all |

Trial 14's old plan hash is `0336a0bea436508225ba1d0d2d3c2b361fc5019fb2785e82b62c9fe0f3344b98`. Scenario: `runtime/qualification/quality-fixes-20260909/v18/trial-14-scenario.json`. Generate and review a fresh plan after a coherent candidate is deployed; do not reuse its old approval binding with changed prompt/configuration.

## Completed local changes

### V19: retrieving and supplying more evidence

- Raw representative/targeted searches can retain 10,000 rows; aggregates remain 500. Splunk retrieval uses fixed pages of at most 500, respecting remaining query/hunt row, byte and time budgets.
- Query metadata separates server output count, retained count, pages and retrieval stop reason. Earlier pages survive later timeout/byte failures. Incomplete empty retrieval does not establish zero matches. Unstarted budget-limited queries are checkpointed as skipped.
- Raw projections preserve native source/time/event identity; executed normalized SPL is stored. Body reads occur inside the bounded adapter call. Errors do not become empty successful results.
- Assessment, pivot and synthesis evidence batches default to 500. Repairs keep the original sample. Citation schema definitions share enums to support that evidence count.
- Verified 555 backend tests/no skips and mypy 55 files. Read-only live Splunk checks retained all 390 results of the old q4 search and all 594 frozen DNS/network events across two pages. No deployment occurred.

### V20: answering every question and keeping reports concise

- Required question slots contain a concise summary, findings and limitations, with findings or limitations required. App code assigns durable question/finding identities and resolves request citation labels. A populated slot establishes structure, not semantic completeness.
- All generated findings remain stored. Report drafts default to ten selected details across questions, favoring hunt leads within each question; analysts may include more within the existing 1 MiB report-input boundary. Every question keeps its summary and all finding references. Report editing cannot silently drop a question or reassign/drop those references.
- PDF/HTML show summaries, limitations and counts instead of printing every reference ID. Full references remain stored. Evidence selection considers the whole retained hunt, including cited rows after row 10,000. Earlier assessment interpretations do not reappear in new question-report limitations.
- UI shows question summaries and expandable complete findings. The new link navigates to retained results **inside this app**, not the Splunk search UI. This UI is local source only.
- Verified 565 backend tests/no skips, mypy 55 files, 16 frontend tests, production build, browser checks on the built frontend using intercepted saved responses, and PDF inspection. Regression retains 2,000 findings while keeping report presentation compact. Browser verification did not modify application data.

### V21: time selection and retained-evidence lookup

Files changed in this increment:

- [evidence.py](../src/threat_hunting/services/evidence.py): `raw_event_time` and `lookup_retained_evidence` read already owner-scoped retained results using validated completed query IDs, exact typed field filters, optional timezone-aware half-open time windows, stable ordering and pages of at most 500 rows. Original query totals/truncation remain separate from matching subset/page counts. Returned containers are copied; no search or persistence is performed.
- The lookup computes distinct literal and unambiguous field counts over the entire matching retained raw subset, including missing/multivalue counts. Aggregates are excluded. Unknown times are excluded and counted when a time filter requires them. Repeated values do not inflate distinct counts. Raw record counts still include repeated representations of the same event; process names are not process-instance counts, and observed values are not confirmed affected entities.
- [investigation.py](../src/threat_hunting/services/investigation.py): `_spread_evidence_in_time` selects early, late and interior observations before existing source/query balance, preserving advisory-match priority and explicit omissions. Storage order is unchanged. `_synthesis_context` adds each completed query's retained field inventories with scope and missing-data guidance. Do not sum overlapping query counts or apply whole-query counts to a narrower lead.
- [runtime.py](../src/threat_hunting/services/runtime.py): candidate prompt binding is 1.22. Workflow source still performs **one final model call for all questions**. Per-question calls exist only in a diagnostic script.
- [Lookup regression tests](../tests/unit/services/test_retained_evidence_lookup.py): typed filters, query scope, time windows, paging, missing timestamps, aggregates, duplicates, source/query balance, time spread and counts independent of the model sample.

**Boundary:** synthesis automatically receives whole-query inventories. The model cannot yet request additional retained evidence by entity/time/page. The tested lookup helper is groundwork, not a completed agent retrieval loop. No new dependency, migration, customer configuration or service was added.

Before the pause: **581 backend tests passed, no skips**, on isolated PostgreSQL; **65 focused tests passed**; mypy passed across **55 source files**. Two existing Starlette deprecation warnings remain. Frontend source was unchanged in v21; v20 is its last applicable test/build/browser verification. [V21 verification](../runtime/qualification/quality-fixes-20260909/v21/verification.json).

The deterministic replay shows a specific sampling improvement: the old 100-row context included 10 related communications and **zero after the lead**; the new 100-row context includes 10 and **four after the lead**; the 500-row context supplies all 447 saved rows, including all 52 related communications and all 20 after the lead. A session/time lookup found **54 raw representations**, not 54 unique events: one host, one user, one source IP, three destination IPs, three process GUIDs/names and one session, with missing fields counted separately. No model/Splunk calls were needed for this replay. [Replay](../runtime/qualification/quality-fixes-20260909/v21/evidence-replay/verification.json).

## Model diagnostics and unresolved analytical errors

These are real-provider replays of saved trial-13 evidence, not fresh hunts/searches. No hunt or fixture was modified. Usage is measured tokens, not monetary cost or a general success rate.

| Diagnostic | Calls / repairs | Input / output tokens | Elapsed | Outcome |
| --- | --- | --- | --- | --- |
| V20 prompt 1.21, all questions / 447 rows | 1 / 0 | 168,789 / 2,669 | 28.49 s | 4 answer slots / 6 findings; coverage review failed |
| V21 prompt 1.22, all questions / 447 rows | 1 / 0 | 176,721 / 2,600 | 29.14 s | 4 answer slots / 6 findings; coverage/citation review failed |
| V21 focused question prototype | 4 / 0 | 308,952 / 6,853 | 83.33 s | 4 answer slots / 10 findings; factual review pending |

The v21 single-call output improved before/after communications coverage and included authentication for the second lead. Remaining defects:

- q2 omits other lead timelines beyond the exact-hash lead.
- q4 omits requested distinct entity counts despite receiving retained-query inventories.
- q4's relationship finding cites only DNS/network rows and omits the process endpoint needed to support its link to the exact-hash execution.
- q2 says the parent executable was not provided even though the source names `cmd.exe`; missing full path/parent instance identity must not be conflated with a missing executable name.
- It avoids the previous HTTPS inference from TCP/443, but that does not make the whole output acceptable. Time-order and inventory changes were tested together, so their individual effects are not isolated.

This is **not accepted**. [Saved output](../runtime/qualification/quality-fixes-20260909/v21/retained-inventory-live/materialized.json), [assistant review](../runtime/qualification/quality-fixes-20260909/v21/retained-inventory-live/quality-review.json). Assistant review is not independent analyst acceptance.

The completed focused prototype selects **whole queries** sharing actual source pairs with each question, plus whole queries containing literal advisory matches. It keeps all selected rows before ordinary sampling: q1 69 rows / 2 findings; q2 69 / 3; q3 95 / 3; q4 421 / 2. Original query retrieval counts remain intact; no artificial retention gap was introduced. The older v19 prototype filtered rows while retaining full counts and is an invalid comparison; preserve its failure. The newer source-pair selection heuristic is not proven sufficient for general investigations.

**First analytical task tomorrow:** read the focused prototype's four answers and verify every lead timeline, auth relationship, before/after communications, scoped entity counts and both endpoints of relationship claims against the supplied records. Do not restart the completed diagnostic. [Verification](../runtime/qualification/quality-fixes-20260909/v21/focused-synthesis-live/verification.json), [combined answers](../runtime/qualification/quality-fixes-20260909/v21/focused-synthesis-live/materialized.json).

Four focused calls consumed about **62% of the 500,000-input-token hunt budget** in isolation. Production investigation consumes those same budgets. Adopting this approach requires remaining-call/token/time reservation and per-answer checkpoint/recovery; do not simply replace the final call with a loop. More findings or valid citation references do not prove better accuracy.

## Newly confirmed configuration gap

`HuntLimitSettings.context_characters` is set to 500,000, but its only occurrence in runtime source is its declaration in [config.py](../src/threat_hunting/config.py). `budget_limits_from_settings` does not map it into execution and context construction does not enforce it. Current budget checks account for consumed usage rather than fitting the upcoming complete request. **The context-character setting is inert.** Character count is not token count.

This was diagnosed but not fixed. V20's encoded context was 428,129 characters, below that nominal ceiling, so this is not proven to have caused that output's omissions. Implement coherent context fitting that accounts for rows, schema/system text, repair growth and remaining token capacity while preserving provenance/coverage. A hard rejection alone would create another failure mode. No tokenizer dependency was added.

## Remaining work, in execution order

1. Read this checkpoint and v21 artifacts. Recheck Docker, active jobs, source/fixture identity and the saved diagnostic completion. Preserve all historical trials and the dirty tree; do not reload fixtures or restart completed trials.
2. Finish claim-level review of the completed focused diagnostic and save explicit quality/coverage findings. Compare its quality and budget use with the failed single-call versions before selecting a production design.
3. Complete bounded retained-evidence retrieval by question/entity/time/page. Existing pure lookup and automatic whole-query inventories do not implement the model-directed retrieval loop. Preserve application-owned bookkeeping, supplied citation references, original query coverage, ownership and checkpoint/recovery.
4. Resolve lead-specific chronology and relationship coverage: all material leads; same process vs same session vs same host/account; both endpoints for relationship claims. Do not restore earlier assessment prose as source facts or insert fixture-specific answer rules.
5. Deduplicate event representations without discarding differing fields, conflicting values or provenance. Distinct-value counting alone does not fix duplicated evidence rows.
6. Wire context/token fitting into execution. If focused synthesis is chosen, explicitly reserve calls/tokens/time and checkpoint each completed answer. Keep 50 searches as a ceiling, not a target; more searches alone cannot repair a bad evidence handoff.
7. Fix restrictive query generation: general endpoint chronology can omit `process_end` through `process_start OR image_load`; auth `stats BY` nullable fields can drop legitimate logoffs. Preserve intentionally targeted searches. Sampling improvements do not repair server-side omissions.
8. Run relevant regressions and required backend/typing/frontend checks for actual new changes. Build/deploy backend and worker together, plus the v20 frontend. Verify installed source, prompt/policy/settings, state preservation, health and rollback availability with no active jobs.
9. Generate/review a fresh plan on the unchanged normalized fixture; preserve unapproved trial 14. Execute fresh full hunts and review material claims and question coverage. Current model diagnostics are not end-to-end qualification.
10. Complete repeated positive, negative, incomplete-telemetry and outage cases, the full twelve-scenario live matrix, and independent analyst acceptance. The matrix still needs an application-owned fixture adapter. Track first-pass validity, factual accuracy, coverage, cost/usage and failure categories separately; no reliable general hunt success rate is established.
11. Finish outstanding release gates in [remaining-work.md](remaining-work.md#other-acceptancerelease-work-still-open): production TLS/HTTPS, least-privilege external accounts, approval-reference validation, pinned base images, remote CI after authorized commit/push, rollback qualification for future schema changes, warning maintenance and the frontend E2E placeholder. The separate MCP/refactor plan is not this immediate quality block.

## User decisions to preserve

- Customer operation must stay light. The application owns discovery, evidence selection, bookkeeping and retrieval; customers should not curate every query or supply an answer key.
- Evaluate architecture, AI behavior and synthetic data objectively. Keep failed trials. Correct impossible/unrealistic fixture states only for independently justified realism reasons, never to make the app pass. Current frozen fixtures remain unchanged.
- Keep all generated findings and retained evidence within investigation budgets. Reports summarize each approved question and select details separately. Ten default report details is not a cap on investigation memory or findings.
- The new UI navigation is inside the app, not a Splunk job link, and is not deployed.
- Application code owns durable evidence/query/finding IDs and maps short request labels and question slots. Earlier assessments remain investigation/audit history, but their prose and citation priorities are excluded from final synthesis.
- API funding was restored; the earlier funding hold is lifted. This pause authorizes no further paid work until resumption. No commit/push or external messages have been authorized.

## Artifacts, frozen data and tools

- Latest directory: `runtime/qualification/quality-fixes-20260909/v21/`. Read `verification.json`, `evidence-replay/verification.json`, `retained-inventory-live/quality-review.json`, then `focused-synthesis-live/verification.json`. Live directories preserve context/schema/system text, raw responses and materialized answers. Runtime artifacts are Git-ignored and must remain with the workspace.
- `before-edit.json` preserves v20 text/hashes for the v21 edit set. `candidate.diff` records the incremental v21 delta including the new test. `pause-git-status.txt` inventories the wider dirty tree; it is not a full backup. Earlier v19/v20 logs, diffs, UI screenshots and PDFs remain in their directories.
- Normalized fixture: `tests/known_answer/fixtures/normalized-v1/events.jsonl`, 689 events: 70 endpoint, 25 auth, 297 DNS, 297 network. SHA-256 `3705fc2a00f7b1c89ef984c73fee474a23846f1ecfdd5c069a2715f1cb46d31c`.
- Original snapshot: `runtime/qualification/live-e2e-20260908/current-lab-events.json`, 2,088 events. SHA-256 `c08babff1a54c08a550cc533f8a65eebbf60b074d12305d4dc98a311f30400aa`. Outage variant has not been loaded/run. Original Splunk jobs may have expired; replays cannot reconstruct missing historical server metadata.
- Trial 13: 447 retained representations, 439 raw + 8 aggregate, 258 distinct raw fixture events; 12 queries, 8 model calls, no repairs, 329,019 input / 16,012 output tokens. Approved-hunt SHA-256 `08358d28059a9a7234c045ca0cd82f088a1b13e0f81a19bd45324af442dcb3e3`; results SHA-256 `e2b655b3dce5ad1b1ad8ef6e4db54bccc3f8ad5224e7d34f300d77d2edb5a745`.
- Locked Python: `/tmp/threat-hunting-locked-env/bin/python`; uv: `/tmp/threat-hunting-build-tools/bin/uv`. Temporary tooling/PG may disappear across restarts. Isolated test cluster: `/tmp/threat-hunting-quality-pg`. Test DSN only: `postgresql+psycopg:///threat_hunting_quality_test?host=/tmp&port=55439`. Never run pytest against the app database or another checkout's port 5432.
- Model/Splunk secrets remain under `runtime/secrets/`; protected test credentials/session files are under `/tmp`. Do not print or copy their values into documentation. Playwright tooling is available at `/home/dreyna/src/ai-enabled-threathunting/frontend/node_modules/playwright`; that other checkout is not this source/deployment.
- V20 UI preview session was stopped; the final v21 diagnostic session is terminal. Existing tests/logs are saved; no rerun is needed just to establish what already passed.

Useful evidence anchors for factual review, not instructions/answers to give the model:

- Exact-hash lead: `ws-17.corp.example`, `CORP\j.smith`, HRsword GUID `7b0a41a9-acc0-5565-8176-81b3ca99829a`, session `3cc97923-2cf1-5465-be13-735f603e5311`; start January 6 13:07:43Z, end 13:19:09Z; auth 08:06:12Z / 16:32:12Z. Parent field names `cmd.exe`.
- Browser GUID `498f3bd6-f95e-560f-b33a-07c625e50049` shares that recorded session but is a different process. TCP/443 does not prove HTTPS, destination ownership, benignness or causality.
- Filename-only lead: `ops-03.corp.example`, `CORP\m.rivera`, `C:\AdminTools\HRsword.exe`, four daily lifetimes January 5–8, different hash. Reused PID 4308 across those distinct lifetimes is realistic.

## Read-only checks when resuming

From this workspace:

```bash
git status --short
docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'
curl --fail --silent --show-error http://127.0.0.1:8080/health/ready
docker exec -i threat-hunting-postgres-1 sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At' < runtime/qualification/quality-fixes-20260909/v6/database-state.sql
```

Expected at pause: healthy v18 services; readiness HTTP 200 when checked; 42 hunts, zero `queued`/`claimed` jobs, migration 0013 and the fingerprints above. Revalidate overnight state. Do not execute a hunt as a health check. Follow the [operator runbook](operator-runbook.md) for deployment/rollback and preserve volumes. Resume work only after the user continues the session.
