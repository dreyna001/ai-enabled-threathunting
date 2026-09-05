export type HealthStatus = "ready" | "not_ready";
export type HealthCheckStatus = "pass" | "fail";

export interface HealthCheck {
  name: string;
  status: HealthCheckStatus;
  detail?: string;
}

export interface HealthResponse {
  status: HealthStatus;
  checks: HealthCheck[];
}

export class HealthApiError extends Error {
  readonly code: "network" | "invalid_response" | "http_error";

  constructor(
    message: string,
    code: "network" | "invalid_response" | "http_error",
  ) {
    super(message);
    this.name = "HealthApiError";
    this.code = code;
  }
}

const HEALTH_PATH = "/health/ready";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseHealthCheck(value: unknown): HealthCheck | null {
  if (!isRecord(value) || typeof value.name !== "string") {
    return null;
  }

  if (value.status !== "pass" && value.status !== "fail") {
    return null;
  }

  if (value.detail !== undefined && value.detail !== null && typeof value.detail !== "string") {
    return null;
  }

  return {
    name: value.name,
    status: value.status,
    ...(typeof value.detail === "string" ? { detail: value.detail } : {}),
  };
}

export function parseHealthResponse(value: unknown): HealthResponse | null {
  if (!isRecord(value) || (value.status !== "ready" && value.status !== "not_ready")) {
    return null;
  }

  if (!Array.isArray(value.checks)) {
    return null;
  }

  const checks = value.checks.map(parseHealthCheck);
  if (checks.some((check) => check === null)) {
    return null;
  }

  return {
    status: value.status,
    checks: checks as HealthCheck[],
  };
}

function apiBaseUrl(): string {
  const configuredBaseUrl = import.meta.env.VITE_API_BASE_URL;
  return typeof configuredBaseUrl === "string" ? configuredBaseUrl.replace(/\/$/, "") : "";
}

function healthUrl(): string {
  return `${apiBaseUrl()}${HEALTH_PATH}`;
}

export async function getHealth(signal?: AbortSignal): Promise<HealthResponse> {
  let response: Response;
  try {
    response = await fetch(healthUrl(), {
      method: "GET",
      headers: { Accept: "application/json" },
      signal,
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw error;
    }

    throw new HealthApiError(
      "The health service could not be reached.",
      "network",
    );
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new HealthApiError(
      "The health service returned an invalid response.",
      "invalid_response",
    );
  }

  const health = parseHealthResponse(body);
  if (!health) {
    throw new HealthApiError(
      "The health service returned an invalid response.",
      "invalid_response",
    );
  }

  // Readiness endpoints commonly use HTTP 503 for a valid not-ready response.
  if (!response.ok && health.status !== "not_ready") {
    throw new HealthApiError(
      "The health service reported an unexpected failure.",
      "http_error",
    );
  }

  return health;
}
