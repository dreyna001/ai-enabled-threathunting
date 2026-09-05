import { useState } from "react";
import {
  BudgetMetric,
  ExecutionResponse,
  QueryLedgerEntry,
  WorkflowState,
} from "../api/execution";
import { HuntExecutionViewState, useHuntExecution } from "../state/useHuntExecution";

interface HuntWorkspaceProps {
  huntId: string;
}

const STATE_LABELS: Record<WorkflowState, string> = {
  created: "Created",
  discovering: "Discovering",
  plan_draft: "Plan draft",
  awaiting_plan_review: "Awaiting plan approval",
  approved: "Approved",
  queued: "Queued",
  running: "Running",
  paused: "Paused — safe resume available",
  synthesizing: "Synthesizing",
  report_draft: "Report draft",
  finalized: "Finalized",
  cancelled: "Cancelled",
  failed: "Failed",
  budget_exhausted: "Budget exhausted",
};

function formatCount(value: number): string {
  return new Intl.NumberFormat().format(value);
}

function formatMetric(metric: BudgetMetric): string {
  return metric.limit === null
    ? formatCount(metric.used)
    : `${formatCount(metric.used)} / ${formatCount(metric.limit)}`;
}

function metricPercent(metric: BudgetMetric): number | null {
  if (metric.limit === null || metric.limit <= 0) {
    return null;
  }
  return Math.min(100, Math.round((metric.used / metric.limit) * 100));
}

function stateTone(execution: ExecutionResponse): "success" | "warning" | "error" | "neutral" {
  if (execution.state === "cancelled") return "warning";
  if (execution.state === "failed") return "error";
  if (execution.state === "budget_exhausted" || execution.final_disposition === "budget_exhausted") return "warning";
  if (execution.state === "running" || execution.state === "queued" || execution.state === "synthesizing") return "success";
  return "neutral";
}

function isReadOnly(execution: ExecutionResponse): boolean {
  return execution.state === "cancelled"
    || execution.state === "failed"
    || execution.state === "finalized"
    || execution.state === "budget_exhausted";
}

function isPreRun(execution: ExecutionResponse): boolean {
  return ["created", "discovering", "plan_draft", "awaiting_plan_review", "approved"].includes(execution.state);
}

function BudgetCard({ label, metric }: { label: string; metric: BudgetMetric }) {
  const percent = metricPercent(metric);
  return (
    <div className="budget-card">
      <dt>{label}</dt>
      <dd>{formatMetric(metric)}</dd>
      {percent !== null ? (
        <div className="budget-meter" aria-label={`${label} budget ${percent}% used`}>
          <span style={{ width: `${percent}%` }} />
        </div>
      ) : <span className="muted budget-unbounded">No configured limit</span>}
    </div>
  );
}

function BudgetSection({ execution }: { execution: ExecutionResponse }) {
  const budget = execution.budget;
  return (
    <section className="workspace-section" aria-labelledby="budget-heading">
      <div className="section-heading">
        <h2 id="budget-heading">Budget use</h2>
        <span className="muted">Counters include failed calls and retries</span>
      </div>
      <dl className="budget-grid">
        <BudgetCard label="Splunk queries" metric={budget.queries} />
        <BudgetCard label="Model calls" metric={budget.model_calls} />
        <BudgetCard label="Input tokens" metric={budget.input_tokens} />
        <BudgetCard label="Output tokens" metric={budget.output_tokens} />
        <BudgetCard label="Cached rows" metric={budget.cached_rows} />
        <BudgetCard label="Cached bytes" metric={budget.cached_bytes} />
        <BudgetCard label="Agent cycles" metric={budget.cycles} />
      </dl>
    </section>
  );
}

function QueryLedger({ entries }: { entries: QueryLedgerEntry[] }) {
  return (
    <section className="workspace-section" aria-labelledby="query-ledger-heading">
      <div className="section-heading">
        <h2 id="query-ledger-heading">Query ledger</h2>
        <span className="muted">Persisted query activity</span>
      </div>
      {entries.length === 0 ? (
        <p className="empty-state">No query activity has been recorded yet.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <caption className="visually-hidden">Executed Splunk queries</caption>
            <thead>
              <tr><th scope="col">Query</th><th scope="col">Purpose</th><th scope="col">Status</th><th scope="col">Rows</th></tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id}>
                  <th scope="row">{entry.id}</th>
                  <td>{entry.purpose ?? "unknown"}</td>
                  <td>{entry.status}</td>
                  <td>{entry.result_count === null || entry.result_count === undefined ? "unknown" : formatCount(entry.result_count)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function ErrorSection({ execution }: { execution: ExecutionResponse }) {
  if (execution.errors.length === 0) {
    return null;
  }
  return (
    <section className="workspace-section execution-errors" aria-labelledby="execution-errors-heading">
      <div className="section-heading">
        <h2 id="execution-errors-heading">Errors and interruptions</h2>
      </div>
      <ul>
        {execution.errors.map((error, index) => (
          <li key={`${error.code ?? "error"}-${index}`}>
            <strong>{error.code ?? "Execution error"}</strong>
            <span>{error.message}</span>
            {error.recoverable ? <span className="muted">Recoverable</span> : null}
          </li>
        ))}
      </ul>
    </section>
  );
}

function CancellationDialog({
  pending,
  onConfirm,
  onClose,
}: {
  pending: boolean;
  onConfirm: () => void;
  onClose: () => void;
}) {
  return (
    <div className="dialog-backdrop" role="presentation">
      <section className="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="cancel-dialog-heading">
        <h2 id="cancel-dialog-heading">Cancel this hunt?</h2>
        <p>Cancellation stops new model calls and Splunk searches. Persisted queries, evidence, and errors remain available, but this hunt cannot be resumed or restarted.</p>
        <div className="dialog-actions">
          <button type="button" className="button-secondary" onClick={onClose} disabled={pending}>Keep running</button>
          <button type="button" className="button-danger" onClick={onConfirm} disabled={pending}>
            {pending ? "Cancelling…" : "Cancel hunt"}
          </button>
        </div>
      </section>
    </div>
  );
}

function ActionError({ message }: { message: string | null }) {
  return message ? <p className="inline-error" role="alert">{message}</p> : null;
}

function WorkspaceDetails({
  execution,
  actionPending,
  actionError,
  onEnqueue,
  onResume,
  onRequestCancel,
}: {
  execution: ExecutionResponse;
  actionPending: boolean;
  actionError: string | null;
  onEnqueue: () => void;
  onResume: () => void;
  onRequestCancel: () => void;
}) {
  const [confirmingCancel, setConfirmingCancel] = useState(false);
  const readOnly = isReadOnly(execution);
  const paused = execution.state === "paused";
  const budgetExhausted = execution.state === "budget_exhausted" || execution.final_disposition === "budget_exhausted";
  const tone = stateTone(execution);

  return (
    <>
      <section className={`workspace-card workspace-tone-${tone}`} aria-labelledby="execution-heading" aria-busy={actionPending}>
        <div className="workspace-header">
          <div>
            <p className="eyebrow">Hunt execution</p>
            <h2 id="execution-heading">{STATE_LABELS[execution.state]}</h2>
            <p className="muted">Hunt <code>{execution.hunt_id}</code></p>
          </div>
          <span className={`state-badge state-${execution.state}`}>{STATE_LABELS[execution.state]}</span>
        </div>

        {execution.recovered ? <p className="recovery-banner" role="status">Recovered execution state loaded. Work continues from the persisted ledger.</p> : null}
        {execution.locked.inputs || execution.locked.plan ? (
          <p className="lock-banner" role="status"><strong>Locked after approval:</strong> hunt inputs and approved plan cannot be edited during execution or pause.</p>
        ) : null}

        {paused ? (
          <div className="pause-banner" role="status">
            <h3>Execution paused safely</h3>
            <p>{execution.interruption_reason ?? execution.paused_reason_code ?? "A recoverable interruption paused this hunt."}</p>
            <p className="muted">Resume uses the unchanged approved plan and locked limits. Editing is unavailable.</p>
            <div className="action-row">
              <button type="button" onClick={onResume} disabled={actionPending || !execution.can_resume}>
                {actionPending ? "Resuming…" : "Resume unchanged hunt"}
              </button>
              {execution.can_cancel ? <button type="button" className="button-secondary" onClick={() => setConfirmingCancel(true)} disabled={actionPending}>Cancel hunt</button> : null}
            </div>
          </div>
        ) : null}

        {isPreRun(execution) ? (
          <div className="empty-state pre-run-state">
            <h3>Execution has not started</h3>
            <p>{execution.state === "approved" ? "The approved plan is ready. Start a bounded execution when you are ready." : "Execution details will appear after the plan is approved and queued."}</p>
            {execution.state === "approved" ? <button type="button" onClick={onEnqueue} disabled={actionPending}>{actionPending ? "Queueing…" : "Start execution"}</button> : null}
          </div>
        ) : null}

        {!isPreRun(execution) && !paused ? (
          <div className="execution-overview">
            <div>
              <span className="detail-label">Current phase</span>
              <strong>{execution.phase ?? "unknown"}</strong>
            </div>
            <div>
              <span className="detail-label">Progress</span>
              <strong>{execution.progress.percent === null ? `${formatCount(execution.progress.completed)} completed` : `${execution.progress.percent}%`}</strong>
              {execution.progress.percent !== null ? <div className="progress-meter" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={execution.progress.percent}><span style={{ width: `${execution.progress.percent}%` }} /></div> : null}
            </div>
            <div>
              <span className="detail-label">Evidence selected</span>
              <strong>{formatCount(execution.evidence.selected)}{execution.evidence.available === null ? "" : ` / ${formatCount(execution.evidence.available)}`}</strong>
            </div>
          </div>
        ) : null}

        {budgetExhausted ? <p className="limit-banner" role="status"><strong>Limit reached:</strong> no additional investigation work will be started. The persisted state is available for review.</p> : null}
        {execution.state === "failed" ? <p className="failure-banner" role="alert"><strong>Execution failed:</strong> this hunt is terminal and cannot be resumed.</p> : null}
        {execution.state === "cancelled" ? <p className="cancelled-banner" role="status"><strong>Cancelled:</strong> this hunt is read-only. Start a new hunt to investigate different inputs.</p> : null}

        {execution.can_cancel && !paused && !readOnly ? <div className="action-row action-row-end"><button type="button" className="button-secondary" onClick={() => setConfirmingCancel(true)} disabled={actionPending}>Cancel hunt</button></div> : null}
        <ActionError message={actionError} />
      </section>

      {!isPreRun(execution) ? (
        <>
          {execution.open_questions.length > 0 ? (
            <section className="workspace-section" aria-labelledby="open-questions-heading">
              <div className="section-heading"><h2 id="open-questions-heading">Open questions</h2></div>
              <ul className="question-list">{execution.open_questions.map((question, index) => <li key={`${question}-${index}`}>{question}</li>)}</ul>
            </section>
          ) : <section className="workspace-section"><h2>Open questions</h2><p className="empty-state">No open questions are recorded.</p></section>}
          <BudgetSection execution={execution} />
          <QueryLedger entries={execution.query_ledger} />
          <ErrorSection execution={execution} />
        </>
      ) : null}

      {confirmingCancel ? <CancellationDialog pending={actionPending} onClose={() => setConfirmingCancel(false)} onConfirm={() => { setConfirmingCancel(false); onRequestCancel(); }} /> : null}
    </>
  );
}

function StateView({ state, onRetry }: { state: HuntExecutionViewState; onRetry: () => void }) {
  switch (state.kind) {
    case "empty":
      return <section className="workspace-card" aria-labelledby="empty-execution-heading"><h2 id="empty-execution-heading">No hunt selected</h2><p className="empty-state">Open a hunt to view its execution workspace.</p></section>;
    case "loading":
      return <section className="workspace-card" aria-labelledby="loading-execution-heading" aria-busy="true"><p className="eyebrow">Loading</p><h2 id="loading-execution-heading">Loading execution state</h2><p className="muted" role="status">Reading persisted progress, budgets, and query activity…</p></section>;
    case "error":
      return <section className="workspace-card workspace-tone-error" aria-labelledby="execution-error-heading" role="alert"><p className="eyebrow">Unavailable</p><h2 id="execution-error-heading">Execution status could not be loaded</h2><p>{state.message}</p><button type="button" onClick={onRetry}>Try again</button></section>;
    case "ready":
      return null;
  }
}

export function HuntWorkspace({ huntId }: HuntWorkspaceProps) {
  const { state, actions, actionPending, actionError } = useHuntExecution(huntId);
  const [cancelError, setCancelError] = useState<string | null>(null);

  if (state.kind !== "ready") {
    return <StateView state={state} onRetry={actions.refresh} />;
  }

  return (
    <div className="hunt-workspace">
      <WorkspaceDetails
        execution={state.execution}
        actionPending={actionPending}
        actionError={actionError ?? cancelError}
        onEnqueue={() => { void actions.enqueue(); }}
        onResume={() => { void actions.resume(); }}
        onRequestCancel={() => {
          setCancelError(null);
          void actions.cancel().catch(() => setCancelError("Cancellation could not be completed."));
        }}
      />
    </div>
  );
}
