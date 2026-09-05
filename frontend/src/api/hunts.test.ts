import { afterEach, describe, expect, it, vi } from "vitest";
import { workflowApi } from "./hunts";

describe("workflow API session transport", () => {
  afterEach(() => vi.restoreAllMocks());

  it("uses the HttpOnly session cookie and CSRF header without a bearer token", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    fetchMock
      .mockResolvedValueOnce(new Response(JSON.stringify({ user: { user_id: "u1", username: "analyst", display_name: "Analyst" } }), {
        status: 200,
        headers: { "Content-Type": "application/json", "X-CSRF-Token": "csrf-1" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ hunt_id: "h1" }), { status: 201 }));

    const session = await workflowApi.login("analyst", "secret");
    await workflowApi.createHunt(session.access_token, {
      title: "Test hunt",
      hypothesis: "A bounded hypothesis",
      objective: "Validate the workflow",
      threat_intelligence: "",
      synthetic_data: "",
    });

    expect(fetchMock).toHaveBeenNthCalledWith(1, "/api/auth/login", expect.objectContaining({ credentials: "include" }));
    const request = fetchMock.mock.calls[1]?.[1] as RequestInit;
    const headers = new Headers(request.headers);
    expect(request.credentials).toBe("include");
    expect(headers.get("X-CSRF-Token")).toBe("csrf-1");
    expect(headers.get("Authorization")).toBeNull();
  });

  it("signals session expiry on an unauthorized API response", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ detail: "authentication required" }), { status: 401 }));
    const onExpired = vi.fn();
    Object.defineProperty(globalThis, "window", { value: { dispatchEvent: onExpired }, configurable: true });
    await expect(workflowApi.listHunts(undefined)).rejects.toMatchObject({ status: 401 });
    expect(onExpired).toHaveBeenCalledTimes(1);
    delete (globalThis as { window?: unknown }).window;
    fetchMock.mockRestore();
  });

  it("provides an explicit logout request", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 204 }));
    await workflowApi.logout();
    expect(fetchMock).toHaveBeenCalledWith("/api/auth/logout", expect.objectContaining({ method: "POST", credentials: "include" }));
  });
});
