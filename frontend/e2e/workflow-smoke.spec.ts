import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const HUNT_ID = "11111111-1111-4111-8111-111111111111";
const RUNNING_HUNT_ID = "22222222-2222-4222-8222-222222222222";

const user = {
  user_id: "analyst-1",
  username: "analyst",
  display_name: "SOC Analyst",
};

const huntSummaries = [
  {
    hunt_id: RUNNING_HUNT_ID,
    title: "Credential pivot investigation",
    hypothesis: "A service account was reused across hosts.",
    state: "running",
    created_at_utc: "2026-01-01T12:00:00Z",
    updated_at_utc: "2026-01-02T08:30:00Z",
  },
  {
    hunt_id: HUNT_ID,
    title: "Lateral movement review",
    hypothesis: "Stolen credentials were used for pivoting.",
    state: "report_draft",
    created_at_utc: "2026-01-01T00:00:00Z",
    updated_at_utc: "2026-01-02T00:00:00Z",
  },
];

const huntDetails: Record<string, Record<string, unknown>> = {
  [RUNNING_HUNT_ID]: {
    hunt_id: RUNNING_HUNT_ID,
    title: "Credential pivot investigation",
    hypothesis: "A service account was reused across hosts.",
    objective: "Confirm or rule out lateral movement.",
    state: "running",
    plan_version: 2,
    plan: {
      hypothesis: "A service account was reused across hosts.",
      objective: "Confirm or rule out lateral movement.",
      scope: {
        earliest_utc: "2026-01-01T00:00:00Z",
        latest_utc: "2026-01-02T00:00:00Z",
        indexes: ["th_real_v1_auth"],
        sourcetypes: ["lab:normalized:auth"],
      },
      questions: [],
      query_strategy: {},
      coverage_limitations: [],
    },
    discovery_snapshot: { indexes: ["th_real_v1_auth"] },
  },
  [HUNT_ID]: {
    hunt_id: HUNT_ID,
    title: "Lateral movement review",
    hypothesis: "Stolen credentials were used for pivoting.",
    objective: "Confirm or rule out lateral movement.",
    state: "report_draft",
    plan_version: 1,
    plan: {
      hypothesis: "Stolen credentials were used for pivoting.",
      objective: "Confirm or rule out lateral movement.",
      scope: {
        earliest_utc: "2026-01-01T00:00:00Z",
        latest_utc: "2026-01-02T00:00:00Z",
        indexes: ["th_real_v1_auth"],
        sourcetypes: ["lab:normalized:auth"],
      },
      questions: [
        {
          question_id: "q-1",
          question: "Which hosts accepted the reused credential?",
          rationale: "Pivot points indicate scope.",
          expected_information_gain: "high",
        },
      ],
      query_strategy: {},
      coverage_limitations: ["Lab fixture only."],
    },
    discovery_snapshot: { indexes: ["th_real_v1_auth"], sourcetypes: ["lab:normalized:auth"] },
  },
};

const reportPreview = {
  hunt_id: HUNT_ID,
  report_id: "report-1",
  version: 1,
  state: "draft",
  content: {
    summary: "No confirmed malicious activity in the retained lab records.",
    findings: [],
  },
};

const huntResults = {
  findings: [],
  evidence: [],
  entities: [],
  timeline: [],
  question_answers: [
    {
      question_id: "q-1",
      question: "Which hosts accepted the reused credential?",
      summary: "Only the lab workstation retained matching auth events.",
      finding_ids: [],
      limitations: ["Fixture coverage is bounded."],
    },
  ],
};

function json(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return {
    status,
    contentType: "application/json",
    headers,
    body: JSON.stringify(body),
  };
}

async function mockWorkflowApi(page: Page) {
  let authenticated = false;

  await page.route("**/api/**", async (route) => {
    const { pathname } = new URL(route.request().url());
    const method = route.request().method();

    if (pathname === "/api/auth/me") {
      if (!authenticated) {
        await route.fulfill(json({ detail: "authentication required" }, 401));
        return;
      }
      await route.fulfill(json({ ...user, csrf_token: "csrf-test" }));
      return;
    }

    if (pathname === "/api/auth/login" && method === "POST") {
      authenticated = true;
      await route.fulfill(json({
        user,
        csrf_token: "csrf-test",
        expires_at: "2026-12-31T23:59:59Z",
      }, 200, {
        "Set-Cookie": "threat_hunting_session=sess-test; Path=/; HttpOnly, threat_hunting_csrf=csrf-test; Path=/",
      }));
      return;
    }

    if (pathname === "/api/hunts" && method === "GET") {
      await route.fulfill(json(huntSummaries));
      return;
    }

    if (pathname === `/api/hunts/${HUNT_ID}` && method === "GET") {
      await route.fulfill(json(huntDetails[HUNT_ID]));
      return;
    }

    if (pathname === `/api/hunts/${RUNNING_HUNT_ID}` && method === "GET") {
      await route.fulfill(json(huntDetails[RUNNING_HUNT_ID]));
      return;
    }

    if (pathname === `/api/hunts/${RUNNING_HUNT_ID}/job` && method === "GET") {
      await route.fulfill(json({
        job_id: "job-running-1",
        hunt_id: RUNNING_HUNT_ID,
        status: "claimed",
        attempts: 1,
        last_error: null,
        updated_at_utc: "2026-01-02T08:31:00Z",
      }));
      return;
    }

    if (pathname === `/api/hunts/${HUNT_ID}/results` && method === "GET") {
      await route.fulfill(json(huntResults));
      return;
    }

    if (pathname === `/api/hunts/${HUNT_ID}/report` && method === "GET") {
      await route.fulfill(json(reportPreview));
      return;
    }

    await route.fulfill(json({ detail: `unmocked ${method} ${pathname}` }, 404));
  });
}

test.describe("Threat Hunt Console workflow smoke", () => {
  test("signs in, lists hunts, and renders execution and report states", async ({ page }) => {
    await mockWorkflowApi(page);
    await page.goto("/");
    await expect(page.getByLabel("Username")).toBeVisible({ timeout: 15_000 });
    await page.getByLabel("Username").fill("analyst");
    await page.getByLabel("Password").fill("secret");
    await page.getByRole("button", { name: "Sign in" }).click();

    await expect(page.getByRole("heading", { name: "Threat hunts" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("SOC Analyst")).toBeVisible();
    await expect(page.getByRole("button", { name: /Credential pivot investigation/ })).toBeVisible();
    await expect(page.getByRole("button", { name: /Lateral movement review/ })).toBeVisible();

    await page.getByRole("button", { name: /Credential pivot investigation/ }).click();
    await expect(page.getByRole("heading", { name: "Credential pivot investigation" })).toBeVisible();
    await expect(page.locator(".vs-badge").filter({ hasText: "running" })).toBeVisible();
    await expect(page.getByText(/Job .*claimed/)).toBeVisible();
    await expect(page.getByRole("button", { name: "Cancel hunt" })).toBeVisible();

    await page.getByRole("button", { name: "Back to hunts" }).click();
    await page.getByRole("button", { name: /Lateral movement review/ }).click();
    await expect(page.getByRole("heading", { name: "Lateral movement review" })).toBeVisible();
    await expect(page.locator(".vs-badge").filter({ hasText: "report draft" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Editable report" })).toBeVisible();
    await expect(page.getByText("No confirmed malicious activity in the retained lab records.")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Approved question answers" })).toBeVisible();
  });
});
