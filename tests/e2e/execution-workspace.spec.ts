import { expect, Page, test } from "@playwright/test";

const baseExecution = {
  hunt_id: "hunt-1",
  workflow_state: "running",
  phase: "investigate",
  progress: { completed: 2, total: 4, percent: 50 },
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
};

async function mockHealth(page: Page) {
  await page.route("**/health/ready", async (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ status: "ready", checks: [] }),
  }));
}

async function mockExecution(page: Page, response: Record<string, unknown>) {
  await page.route("**/api/hunts/hunt-1/execution", async (route) => {
    if (route.request().method() === "GET") {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
      return;
    }
    await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(response) });
  });
}

test.describe("execution workspace with mocked API", () => {
  test("renders locked running progress and confirms cancellation", async ({ page }) => {
    await mockHealth(page);
    let cancelled = false;
    await mockExecution(page, baseExecution);
    await page.route("**/api/hunts/hunt-1/cancel", async (route) => {
      cancelled = true;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ...baseExecution, workflow_state: "cancelled", can_cancel: false }),
      });
    });

    await page.goto("/hunts/hunt-1");
    await expect(page.getByRole("heading", { name: "Running" })).toBeVisible();
    await expect(page.getByText("Locked after approval:")).toBeVisible();
    await expect(page.getByText("Which account launched the process?")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Query ledger" })).toBeVisible();

    await page.getByRole("button", { name: "Cancel hunt" }).click();
    await expect(page.getByRole("dialog")).toBeVisible();
    await page.getByRole("dialog").getByRole("button", { name: "Cancel hunt" }).click();
    await expect.poll(() => cancelled).toBe(true);
    await expect(page.getByText("this hunt is read-only")).toBeVisible();
  });

  test("allows only unchanged resume or cancellation while paused", async ({ page }) => {
    await mockHealth(page);
    await mockExecution(page, {
      ...baseExecution,
      workflow_state: "paused",
      paused_reason_code: "provider_timeout",
      interruption_reason: "The provider did not recover after one retry.",
      can_cancel: true,
      can_resume: true,
      resume_target: "running",
    });
    await page.route("**/api/hunts/hunt-1/execution/resume", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ ...baseExecution, recovered: true, delivery_attempt: 2 }),
      });
    });

    await page.goto("/hunts/hunt-1");
    await expect(page.getByRole("heading", { name: /Paused/ })).toBeVisible();
    await expect(page.getByText("The provider did not recover after one retry.")).toBeVisible();
    await expect(page.getByRole("button", { name: "Resume unchanged hunt" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Start execution" })).toHaveCount(0);

    await page.getByRole("button", { name: "Resume unchanged hunt" }).click();
    await expect(page.getByText("Recovered execution state loaded.")).toBeVisible();
  });

  test("keeps budget-exhausted, failed, and cancelled states explicit and read-only", async ({ page }) => {
    await mockHealth(page);
    for (const [state, expected] of [
      ["budget_exhausted", "Limit reached:"],
      ["failed", "Execution failed:"],
      ["cancelled", "this hunt is read-only"],
    ] as const) {
      await page.unrouteAll({ behavior: "ignoreErrors" });
      await mockHealth(page);
      await mockExecution(page, {
        ...baseExecution,
        workflow_state: state,
        final_disposition: state === "budget_exhausted" ? "budget_exhausted" : null,
        can_cancel: false,
        can_resume: false,
      });
      await page.goto(`/hunts/hunt-1?state=${state}`);
      await expect(page.getByText(expected)).toBeVisible();
      await expect(page.getByRole("button", { name: "Cancel hunt" })).toHaveCount(0);
      await expect(page.getByRole("button", { name: "Resume unchanged hunt" })).toHaveCount(0);
    }
  });
});
