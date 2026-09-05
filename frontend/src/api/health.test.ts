import { describe, expect, it } from "vitest";
import { parseHealthResponse } from "./health";

describe("parseHealthResponse", () => {
  it("accepts the readiness contract", () => {
    expect(
      parseHealthResponse({
        status: "ready",
        checks: [{ name: "database", status: "pass", detail: "reachable" }],
      }),
    ).toEqual({
      status: "ready",
      checks: [{ name: "database", status: "pass", detail: "reachable" }],
    });
  });

  it("accepts null detail values emitted by the backend", () => {
    expect(
      parseHealthResponse({
        status: "ready",
        checks: [{ name: "database", status: "pass", detail: null }],
      }),
    ).toEqual({
      status: "ready",
      checks: [{ name: "database", status: "pass" }],
    });
  });

  it("rejects malformed or incomplete responses", () => {
    expect(parseHealthResponse({ status: "ready" })).toBeNull();
    expect(parseHealthResponse({ status: "ready", checks: [{ name: "database" }] })).toBeNull();
    expect(parseHealthResponse({ status: "failed", checks: [] })).toBeNull();
  });
});
