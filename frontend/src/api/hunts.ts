export type JsonObject = Record<string, unknown>;

export interface User {
  user_id: string;
  username: string;
  display_name: string;
}

export interface Session {
  /** Browser authentication uses an HttpOnly same-origin session cookie. */
  access_token?: string;
  token_type?: string;
  csrf_token?: string;
  user: User;
}

export interface HuntPlan {
  hypothesis: string;
  objective: string;
  scope: {
    earliest_utc: string;
    latest_utc: string;
    indexes: string[];
    sourcetypes: string[];
  };
  questions: Array<{
    question_id: string;
    question: string;
    rationale: string;
    expected_information_gain: string;
  }>;
  query_strategy: unknown;
  coverage_limitations: string[];
}

export interface CreateHuntInput {
  title: string;
  hypothesis: string;
  objective: string;
  threat_intelligence: string;
  synthetic_data: string;
}

export interface Hunt {
  hunt_id: string;
  title: string;
  hypothesis: string;
  objective: string;
  state: string;
  threat_intelligence?: string;
  synthetic_data?: string;
  plan_version?: number;
  plan?: HuntPlan | null;
  discovery_snapshot?: JsonObject | null;
  mode?: string | null;
  [key: string]: unknown;
}

export interface HuntSummary {
  hunt_id: string;
  title: string;
  hypothesis: string;
  state: string;
  created_at_utc: string;
  updated_at_utc: string;
}

export interface HuntResults {
  findings: JsonObject[];
  evidence: JsonObject[];
  entities: JsonObject[];
  timeline: JsonObject[];
  question_answers?: Array<{
    question_id: string;
    question: string;
    summary: string;
    finding_ids: string[];
    limitations: string[];
  }>;
  mode?: string | null;
}

export interface ReportPreview {
  hunt_id: string;
  report_id: string;
  version: number;
  state: string;
  content: JsonObject;
  html?: string;
}

export interface JobStatus {
  job_id: string;
  hunt_id: string;
  status: "queued" | "claimed" | "completed" | "failed" | "cancelled" | string;
  attempts?: number;
  last_error?: string | null;
  updated_at_utc?: string;
}

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

function errorDetail(body: unknown, fallback: string): string {
  if (typeof body !== "object" || body === null || !("detail" in body)) {
    return fallback;
  }
  const value = (body as { detail: unknown }).detail;
  return typeof value === "string" ? value : JSON.stringify(value);
}

let csrfToken: string | null = null;

function readCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const prefix = `${encodeURIComponent(name)}=`;
  const value = document.cookie.split(";").map((cookie) => cookie.trim()).find((cookie) => cookie.startsWith(prefix));
  return value ? decodeURIComponent(value.slice(prefix.length)) : null;
}

function rememberCsrf(response: Response, body: unknown): void {
  const header = response.headers.get("X-CSRF-Token") ?? response.headers.get("X-CSRFToken");
  const bodyToken = typeof body === "object" && body !== null && "csrf_token" in body
    ? (body as { csrf_token?: unknown }).csrf_token
    : undefined;
  const token = header ?? (typeof bodyToken === "string" ? bodyToken : null) ?? readCookie("threat_hunting_csrf") ?? readCookie("csrf_token");
  if (token) csrfToken = token;
}

function isMutation(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

async function request<T>(path: string, _legacyToken?: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  const method = init.method ?? "GET";
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  const token = csrfToken ?? readCookie("threat_hunting_csrf") ?? readCookie("csrf_token");
  if (isMutation(method) && token) headers.set("X-CSRF-Token", token);
  try {
    response = await fetch(path, { ...init, credentials: "include", headers });
  } catch {
    throw new ApiError(
      "The API could not be reached. Confirm the backend is running and try again.",
      0,
    );
  }

  if (!response.ok) {
    if (response.status === 401 && typeof window !== "undefined") {
      window.dispatchEvent(new Event("threat-hunt-auth-expired"));
    }
    const body = await response.json().catch(() => null);
    rememberCsrf(response, body);
    throw new ApiError(errorDetail(body, `Request failed (${response.status}).`), response.status);
  }
  if (response.status === 204) return undefined as T;
  const body = await response.json();
  rememberCsrf(response, body);
  return body as T;
}

export const workflowApi = {
  login: async (username: string, password: string) => {
    csrfToken = null;
    const session = await request<Session>("/api/auth/login", undefined, {
      method: "POST",
      body: JSON.stringify({ username, password }),
    });
    csrfToken = session.csrf_token ?? csrfToken ?? readCookie("threat_hunting_csrf") ?? readCookie("csrf_token");
    return session;
  },
  me: async () => {
    const identity = await request<User & { csrf_token?: string }>("/api/auth/me");
    const { csrf_token, ...user } = identity;
    csrfToken = csrf_token ?? csrfToken ?? readCookie("threat_hunting_csrf") ?? readCookie("csrf_token");
    return { user, csrf_token } satisfies Session;
  },
  logout: () => request<void>("/api/auth/logout", undefined, { method: "POST" }),
  listHunts: (token: string | undefined, page: { limit?: number; cursor?: string } = {}) => {
    const params = new URLSearchParams({ limit: String(page.limit ?? 50) });
    if (page.cursor) params.set("cursor", page.cursor);
    return request<HuntSummary[]>(`/api/hunts?${params}`, token);
  },
  getHunt: (token: string | undefined, id: string) =>
    request<Hunt>(`/api/hunts/${id}`, token),
  jobStatus: (token: string | undefined, id: string) =>
    request<JobStatus>(`/api/hunts/${id}/job`, token),
  createHunt: (token: string | undefined, body: CreateHuntInput) =>
    request<Hunt>("/api/hunts", token, { method: "POST", body: JSON.stringify(body) }),
  discover: (token: string | undefined, id: string) =>
    request<Hunt>(`/api/hunts/${id}/discover`, token, { method: "POST" }),
  savePlan: (token: string | undefined, id: string, expectedVersion: number, plan: HuntPlan) =>
    request<Hunt>(`/api/hunts/${id}/plan`, token, {
      method: "PUT",
      body: JSON.stringify({ expected_version: expectedVersion, plan }),
    }),
  revisePlan: (token: string | undefined, id: string, instruction: string) =>
    request<Hunt>(`/api/hunts/${id}/plan/revise`, token, {
      method: "POST",
      body: JSON.stringify({ instruction }),
    }),
  approvePlan: (token: string | undefined, id: string, analystNote?: string) =>
    request<Hunt>(`/api/hunts/${id}/plan/approve`, token, {
      method: "POST",
      body: JSON.stringify({ analyst_note: analystNote || null }),
    }),
  rejectPlan: (token: string | undefined, id: string, analystNote: string) =>
    request<Hunt>(`/api/hunts/${id}/plan/reject`, token, {
      method: "POST",
      body: JSON.stringify({ analyst_note: analystNote }),
    }),
  execute: (token: string | undefined, id: string) =>
    request<Hunt>(`/api/hunts/${id}/execute`, token, { method: "POST" }),
  cancel: (token: string | undefined, id: string) =>
    request<Hunt>(`/api/hunts/${id}/cancel`, token, { method: "POST" }),
  results: (token: string | undefined, id: string) =>
    request<HuntResults>(`/api/hunts/${id}/results`, token),
  report: (token: string | undefined, id: string) =>
    request<ReportPreview>(`/api/hunts/${id}/report`, token),
  saveReport: (token: string | undefined, id: string, expectedVersion: number, content: JsonObject) =>
    request<ReportPreview>(`/api/hunts/${id}/report`, token, {
      method: "PUT",
      body: JSON.stringify({ expected_version: expectedVersion, content }),
    }),
  finalizeReport: (token: string | undefined, id: string, expectedVersion: number) =>
    request<ReportPreview>(`/api/hunts/${id}/report/finalize`, token, {
      method: "POST",
      body: JSON.stringify({ expected_version: expectedVersion }),
    }),
  downloadPdf: async (token: string | undefined, id: string) => {
    const response = await fetch(`/api/hunts/${id}/report/pdf`, {
      credentials: "include",
    });
    if (!response.ok) {
      if (response.status === 401 && typeof window !== "undefined") {
        window.dispatchEvent(new Event("threat-hunt-auth-expired"));
      }
      const body = await response.json().catch(() => null);
      throw new ApiError(errorDetail(body, "PDF download failed."), response.status);
    }
    const url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `hunt-${id}.pdf`;
    anchor.click();
    URL.revokeObjectURL(url);
  },
};
