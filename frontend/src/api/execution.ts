/**
 * Browser-facing contract for an approved hunt execution.
 *
 * The execution service may omit progress details until a hunt is queued.  The
 * parser deliberately normalizes those optional sections to empty values so a
 * pre-run hunt can still be rendered without inventing execution activity.
 */

export const WORKFLOW_STATES = [
  "created",
  "discovering",
  "plan_draft",
  "awaiting_plan_review",
  "approved",
  "queued",
  "running",
  "paused",
  "synthesizing",
  "report_draft",
  "finalized",
  "cancelled",
  "failed",
  // A few deployments expose the final disposition as the top-level status.
  // It is rendered as read-only even though the persisted workflow state is
  // normally ``synthesizing`` or ``report_draft``.
  "budget_exhausted",
] as const;

export type WorkflowState = (typeof WORKFLOW_STATES)[number];
export type ResumeTarget = "running" | "synthesizing";

export interface ProgressInfo {
  completed: number;
  total: number | null;
  percent: number | null;
}

export interface BudgetMetric {
  used: number;
  limit: number | null;
}

export interface BudgetUse {
  queries: BudgetMetric;
  model_calls: BudgetMetric;
  input_tokens: BudgetMetric;
  output_tokens: BudgetMetric;
  cached_rows: BudgetMetric;
  cached_bytes: BudgetMetric;
  cycles: BudgetMetric;
}

export interface QueryLedgerEntry {
  id: string;
  status: string;
  purpose?: string;
  query?: string;
  result_count?: number | null;
  error?: string | null;
}

export interface EvidenceProgress {
  selected: number;
  available: number | null;
}

export interface ExecutionError {
  code?: string;
  message: string;
  recoverable?: boolean;
  occurred_at?: string;
}

export interface LockedArtifacts {
  inputs: boolean;
  plan: boolean;
}

export interface ExecutionResponse {
  hunt_id: string;
  state: WorkflowState;
  phase: string | null;
  progress: ProgressInfo;
  open_questions: string[];
  budget: BudgetUse;
  query_ledger: QueryLedgerEntry[];
  evidence: EvidenceProgress;
  errors: ExecutionError[];
  resume_target: ResumeTarget | null;
  locked: LockedArtifacts;
  interruption_reason: string | null;
  final_disposition: string | null;
  paused_reason_code: string | null;
  started_at: string | null;
  query_cutoff_at: string | null;
  hard_ceiling_at: string | null;
  can_cancel: boolean;
  can_resume: boolean;
  recovered: boolean;
}

export type ExecutionApiErrorCode = "network" | "invalid_response" | "http_error";

export class ExecutionApiError extends Error {
  readonly code: ExecutionApiErrorCode;
  readonly status: number | null;

  constructor(
    message: string,
    code: ExecutionApiErrorCode,
    status: number | null = null,
  ) {
    super(message);
    this.name = "ExecutionApiError";
    this.code = code;
    this.status = status;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function nonNegativeNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

function numberOrNull(value: unknown): number | null {
  return value === null || value === undefined ? null : nonNegativeNumber(value);
}

function readFirst(source: Record<string, unknown>, ...keys: string[]): unknown {
  for (const key of keys) {
    if (source[key] !== undefined) {
      return source[key];
    }
  }
  return undefined;
}

function parseWorkflowState(value: unknown): WorkflowState | null {
  return typeof value === "string" && (WORKFLOW_STATES as readonly string[]).includes(value)
    ? (value as WorkflowState)
    : null;
}

function parseMetric(value: unknown): BudgetMetric {
  if (typeof value === "number") {
    return { used: nonNegativeNumber(value) ?? 0, limit: null };
  }

  if (!isRecord(value)) {
    return { used: 0, limit: null };
  }

  const used = nonNegativeNumber(readFirst(value, "used", "consumed", "value", "count")) ?? 0;
  const limit = numberOrNull(readFirst(value, "limit", "max", "maximum", "budget"));
  return { used, limit };
}

function parseBudget(value: unknown): BudgetUse {
  const source = isRecord(value) ? value : {};
  const consumed = isRecord(source.consumed) ? source.consumed : source;
  const limits = isRecord(source.limits) ? source.limits : {};
  const metric = (...keys: string[]) => {
    const usage = parseMetric(readFirst(consumed, ...keys));
    const limit = numberOrNull(readFirst(limits, ...keys));
    return { used: usage.used, limit: limit ?? usage.limit };
  };
  return {
    queries: metric("queries", "splunk_queries", "query_count"),
    model_calls: metric("model_calls", "model_call_count"),
    input_tokens: metric("input_tokens", "model_input_tokens"),
    output_tokens: metric("output_tokens", "model_output_tokens"),
    cached_rows: metric("cached_rows", "rows"),
    cached_bytes: metric("cached_bytes", "bytes"),
    cycles: metric("cycles", "agent_cycles"),
  };
}

function parseProgress(value: unknown): ProgressInfo {
  if (typeof value === "number") {
    const percent = Math.min(100, Math.max(0, value));
    return { completed: 0, total: null, percent };
  }

  if (!isRecord(value)) {
    return { completed: 0, total: null, percent: null };
  }

  const completed = nonNegativeNumber(readFirst(value, "completed", "complete", "done")) ?? 0;
  const total = numberOrNull(readFirst(value, "total", "target"));
  const suppliedPercent = numberOrNull(readFirst(value, "percent", "percentage"));
  const percent = suppliedPercent === null && total && total > 0
    ? Math.min(100, Math.round((completed / total) * 100))
    : suppliedPercent === null
      ? null
      : Math.min(100, Math.max(0, suppliedPercent));
  return { completed, total, percent };
}

function parseStringList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string");
}

function parseQueryLedger(value: unknown): QueryLedgerEntry[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((item, index) => {
    if (!isRecord(item)) {
      return [];
    }
    const id = stringValue(readFirst(item, "id", "query_id"));
    const status = stringValue(readFirst(item, "status", "state", "outcome"));
    if (!id || !status) {
      return [];
    }
    const purpose = stringValue(item.purpose);
    const query = stringValue(readFirst(item, "query", "spl"));
    const resultCount = numberOrNull(readFirst(item, "result_count", "resultCount", "rows", "result_rows"));
    const error = stringValue(readFirst(item, "error", "error_code"));
    return [{
      id: id || `query-${index}`,
      status,
      ...(purpose ? { purpose } : {}),
      ...(query ? { query } : {}),
      result_count: resultCount,
      error,
    }];
  });
}

function parseEvidence(value: unknown): EvidenceProgress {
  if (typeof value === "number") {
    return { selected: nonNegativeNumber(value) ?? 0, available: null };
  }
  if (!isRecord(value)) {
    return { selected: 0, available: null };
  }
  return {
    selected: nonNegativeNumber(readFirst(value, "selected", "count", "selected_count")) ?? 0,
    available: numberOrNull(readFirst(value, "available", "total", "available_count", "query_count")),
  };
}

function parseErrors(value: unknown): ExecutionError[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.flatMap((item) => {
    if (typeof item === "string") {
      return [{ message: item }];
    }
    if (!isRecord(item)) {
      return [];
    }
    const message = stringValue(readFirst(item, "message", "detail", "error"));
    if (!message) {
      return [];
    }
    const code = stringValue(item.code);
    const occurredAt = stringValue(readFirst(item, "occurred_at", "occurredAt"));
    return [{
      message,
      ...(code ? { code } : {}),
      ...(typeof item.recoverable === "boolean" ? { recoverable: item.recoverable } : {}),
      ...(occurredAt ? { occurred_at: occurredAt } : {}),
    }];
  });
}

/** Parse the API response without exposing backend-specific naming to views. */
export function parseExecutionResponse(value: unknown): ExecutionResponse | null {
  if (!isRecord(value)) {
    return null;
  }

  const huntId = stringValue(readFirst(value, "hunt_id", "huntId", "id"));
  const state = parseWorkflowState(readFirst(value, "state", "workflow_state", "workflowState", "status"));
  if (!huntId || !state) {
    return null;
  }

  const budgetSource = readFirst(value, "budget", "budgets", "budget_use", "budgetUse", "usage");
  const progressSource = readFirst(value, "progress", "execution_progress", "executionProgress");
  const queriesSource = readFirst(value, "query_ledger", "queryLedger", "queries");
  const evidenceSource = readFirst(value, "evidence", "evidence_progress", "evidenceProgress");
  const errorsSource = readFirst(value, "errors", "execution_errors", "executionErrors");
  const resume = stringValue(readFirst(value, "resume_target", "resumeTarget"));
  const lockedSource = readFirst(value, "locked", "locks", "artifacts_locked");
  const lockedRecord = isRecord(lockedSource) ? lockedSource : {};
  const lockedValue = typeof lockedSource === "boolean"
    ? lockedSource
    : ["queued", "running", "paused", "synthesizing", "report_draft", "finalized", "cancelled", "failed", "budget_exhausted"].includes(state);
  const recoveredValue = readFirst(value, "recovered", "was_recovered");
  const deliveryAttempts = nonNegativeNumber(readFirst(value, "delivery_attempt", "deliveryAttempt")) ?? 0;

  return {
    hunt_id: huntId,
    state,
    phase: stringValue(readFirst(value, "phase", "current_phase", "currentPhase")),
    progress: parseProgress(progressSource),
    open_questions: parseStringList(readFirst(value, "open_questions", "openQuestions")),
    budget: parseBudget(budgetSource),
    query_ledger: parseQueryLedger(queriesSource),
    evidence: parseEvidence(evidenceSource),
    errors: parseErrors(errorsSource),
    resume_target: resume === "running" || resume === "synthesizing" ? resume : null,
    locked: {
      inputs: typeof lockedRecord.inputs === "boolean" ? lockedRecord.inputs : lockedValue,
      plan: typeof lockedRecord.plan === "boolean" ? lockedRecord.plan : lockedValue,
    },
    interruption_reason: stringValue(readFirst(value, "interruption_reason", "interruptionReason", "reason")),
    final_disposition: stringValue(readFirst(value, "final_disposition", "finalDisposition", "disposition")),
    paused_reason_code: stringValue(readFirst(value, "paused_reason_code", "pausedReasonCode")),
    started_at: stringValue(readFirst(value, "started_at", "startedAt")),
    query_cutoff_at: stringValue(readFirst(value, "query_cutoff_at", "queryCutoffAt")),
    hard_ceiling_at: stringValue(readFirst(value, "hard_ceiling_at", "hardCeilingAt")),
    can_cancel: typeof value.can_cancel === "boolean"
      ? value.can_cancel
      : !["cancelled", "failed", "finalized", "budget_exhausted"].includes(state),
    can_resume: typeof value.can_resume === "boolean" ? value.can_resume : state === "paused",
    recovered: recoveredValue === true || deliveryAttempts > 1,
  };
}

function apiBaseUrl(): string {
  const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL;
  return typeof configuredBaseUrl === "string" ? configuredBaseUrl.replace(/\/$/, "") : "";
}

function executionUrl(huntId: string, suffix = ""): string {
  return `${apiBaseUrl()}/api/hunts/${encodeURIComponent(huntId)}/execution${suffix}`;
}

function cancelUrl(huntId: string): string {
  return `${apiBaseUrl()}/api/hunts/${encodeURIComponent(huntId)}/cancel`;
}

async function parseResponse(response: Response, operation: string): Promise<ExecutionResponse> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new ExecutionApiError(
      `The ${operation} service returned an invalid response.`,
      "invalid_response",
      response.status,
    );
  }

  if (!response.ok) {
    const detail = isRecord(body) ? stringValue(readFirst(body, "detail", "message", "error")) : null;
    throw new ExecutionApiError(
      detail ?? `The ${operation} request failed.`,
      "http_error",
      response.status,
    );
  }

  const execution = parseExecutionResponse(body);
  if (!execution) {
    throw new ExecutionApiError(
      `The ${operation} service returned an invalid response.`,
      "invalid_response",
      response.status,
    );
  }
  return execution;
}

async function requestExecution(
  url: string,
  method: "GET" | "POST",
  operation: string,
  signal?: AbortSignal,
): Promise<ExecutionResponse> {
  let response: Response;
  try {
    response = await fetch(url, {
      method,
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }
    throw new ExecutionApiError(`The ${operation} service could not be reached.`, "network");
  }
  return parseResponse(response, operation);
}

export function getExecution(huntId: string, signal?: AbortSignal): Promise<ExecutionResponse> {
  return requestExecution(executionUrl(huntId), "GET", "execution", signal);
}

export function enqueueExecution(huntId: string, signal?: AbortSignal): Promise<ExecutionResponse> {
  return requestExecution(executionUrl(huntId), "POST", "execution", signal);
}

export function resumeExecution(huntId: string, signal?: AbortSignal): Promise<ExecutionResponse> {
  return requestExecution(executionUrl(huntId, "/resume"), "POST", "resume", signal);
}

export function cancelHunt(huntId: string, signal?: AbortSignal): Promise<ExecutionResponse> {
  return requestExecution(cancelUrl(huntId), "POST", "cancellation", signal);
}
