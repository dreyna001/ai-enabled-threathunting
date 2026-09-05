import { afterEach, describe, expect, it, vi } from "vitest";
import {
  cancelHunt,
  getExecution,
  parseExecutionResponse,
  resumeExecution,
} from "./execution";

describe("parseExecutionResponse", () => {
  it("normalizes the running execution contract and nested budget counters", () => {
    const execution = parseExecutionResponse({
      hunt_id: "hunt-1",
      workflow_state: "running",
      phase: "investigate",
      locked: { inputs: true, plan: true },
      budget: {
        limits: { splunk_queries: 12, model_calls: 8 },
        consumed: { splunk_queries: 3, model_calls: 2 },
      },
      open_questions: ["Which account launched the process?"],
      query_ledger: [{ id: "q-1", state: "completed", purpose: "Initial search", result_rows: 4 }],
      evidence_progress: { selected_count: 2, query_count: 1 },
      errors: [],
      can_cancel: true,
      can_resume: false,
      delivery_attempt: 2,
    });

    expect(execution).not.toBeNull();
    expect(execution?.state).toBe("running");
    expect(execution?.budget.queries).toEqual({ used: 3, limit: 12 });
    expect(execution?.budget.model_calls).toEqual({ used: 2, limit: 8 });
    expect(execution?.query_ledger[0]).toMatchObject({ id: "q-1", status: "completed", result_count: 4 });
    expect(execution?.evidence).toEqual({ selected: 2, available: 1 });
    expect(execution?.recovered).toBe(true);
  });

  it("accepts pre-run hunts without execution details and does not invent activity", () => {
    const execution = parseExecutionResponse({ hunt_id: "hunt-2", workflow_state: "approved" });

    expect(execution).toMatchObject({
      hunt_id: "hunt-2",
      state: "approved",
      phase: null,
      open_questions: [],
      query_ledger: [],
      errors: [],
      locked: { inputs: false, plan: false },
    });
    expect(execution?.budget.queries).toEqual({ used: 0, limit: null });
  });

  it("rejects responses missing an owner-safe hunt id or valid workflow state", () => {
    expect(parseExecutionResponse({ workflow_state: "running" })).toBeNull();
    expect(parseExecutionResponse({ hunt_id: "hunt-1", workflow_state: "unknown" })).toBeNull();
    expect(parseExecutionResponse(null)).toBeNull();
  });
});

describe("execution API transport", () => {
  afterEach(() => vi.restoreAllMocks());

  it("uses encoded hunt ids for status and resume calls", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(async () =>
      new Response(JSON.stringify({ hunt_id: "hunt/a", workflow_state: "paused" }), { status: 200 }));

    await getExecution("hunt/a");
    await resumeExecution("hunt/a");
    await cancelHunt("hunt/a");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "/api/hunts/hunt%2Fa/execution",
      expect.objectContaining({ method: "GET" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "/api/hunts/hunt%2Fa/execution/resume",
      expect.objectContaining({ method: "POST" }),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      3,
      "/api/hunts/hunt%2Fa/cancel",
      expect.objectContaining({ method: "POST" }),
    );
  });

  it("defaults budget-exhausted responses to non-cancellable", () => {
    const execution = parseExecutionResponse({ hunt_id: "hunt-1", workflow_state: "budget_exhausted" });

    expect(execution?.can_cancel).toBe(false);
    expect(execution?.can_resume).toBe(false);
  });

  it("normalizes network, malformed, and HTTP execution failures", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");

    fetchMock.mockRejectedValueOnce(new TypeError("offline"));
    await expect(getExecution("hunt-1")).rejects.toMatchObject({ code: "network" });

    fetchMock.mockResolvedValueOnce(new Response("not-json", { status: 200 }));
    await expect(getExecution("hunt-1")).rejects.toMatchObject({ code: "invalid_response", status: 200 });

    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ detail: "execution unavailable" }), { status: 503 }));
    await expect(getExecution("hunt-1")).rejects.toMatchObject({ code: "http_error", status: 503, message: "execution unavailable" });
  });
});
