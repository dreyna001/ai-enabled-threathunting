export type JsonObject = Record<string, unknown>;

export interface User {
  user_id: string;
  username: string;
  display_name: string;
}

export interface Session {
  access_token: string;
  token_type: string;
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

export interface HuntResults {
  findings: JsonObject[];
  evidence: JsonObject[];
  entities: JsonObject[];
  timeline: JsonObject[];
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

async function request<T>(path: string, token?: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      headers: {
        ...(init.body ? { "Content-Type": "application/json" } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...init.headers,
      },
    });
  } catch {
    throw new ApiError(
      "The API could not be reached. Confirm the backend is running and try again.",
      0,
    );
  }

  if (!response.ok) {
    const body = await response.json().catch(() => null);
    throw new ApiError(errorDetail(body, `Request failed (${response.status}).`), response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

export const workflowApi = {
  login: (username: string, password: string) =>
    request<Session>("/api/auth/login", undefined, {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  listHunts: (token: string) => request<Hunt[]>("/api/hunts", token),
  createHunt: (token: string, body: CreateHuntInput) =>
    request<Hunt>("/api/hunts", token, { method: "POST", body: JSON.stringify(body) }),
  discover: (token: string, id: string) =>
    request<Hunt>(`/api/hunts/${id}/discover`, token, { method: "POST" }),
  savePlan: (token: string, id: string, expectedVersion: number, plan: HuntPlan) =>
    request<Hunt>(`/api/hunts/${id}/plan`, token, {
      method: "PUT",
      body: JSON.stringify({ expected_version: expectedVersion, plan }),
    }),
  revisePlan: (token: string, id: string, instruction: string) =>
    request<Hunt>(`/api/hunts/${id}/plan/revise`, token, {
      method: "POST",
      body: JSON.stringify({ instruction }),
    }),
  approvePlan: (token: string, id: string, analystNote?: string) =>
    request<Hunt>(`/api/hunts/${id}/plan/approve`, token, {
      method: "POST",
      body: JSON.stringify({ analyst_note: analystNote || null }),
    }),
  rejectPlan: (token: string, id: string, analystNote: string) =>
    request<Hunt>(`/api/hunts/${id}/plan/reject`, token, {
      method: "POST",
      body: JSON.stringify({ analyst_note: analystNote }),
    }),
  execute: (token: string, id: string) =>
    request<Hunt>(`/api/hunts/${id}/execute`, token, { method: "POST" }),
  results: (token: string, id: string) =>
    request<HuntResults>(`/api/hunts/${id}/results`, token),
  report: (token: string, id: string) =>
    request<ReportPreview>(`/api/hunts/${id}/report`, token),
  saveReport: (token: string, id: string, expectedVersion: number, content: JsonObject) =>
    request<ReportPreview>(`/api/hunts/${id}/report`, token, {
      method: "PUT",
      body: JSON.stringify({ expected_version: expectedVersion, content }),
    }),
  finalizeReport: (token: string, id: string, expectedVersion: number) =>
    request<ReportPreview>(`/api/hunts/${id}/report/finalize`, token, {
      method: "POST",
      body: JSON.stringify({ expected_version: expectedVersion }),
    }),
  downloadPdf: async (token: string, id: string) => {
    const response = await fetch(`/api/hunts/${id}/report/pdf`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) {
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
