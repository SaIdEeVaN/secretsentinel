import { describe, expect, it } from "vitest";
import { ApiError, api, request, setAuthToken } from "../api/client.js";
import { mockApi } from "./mockApi.js";

describe("api client", () => {
  it("sends JSON only with a body and never includes credentials", async () => {
    const { calls } = mockApi({ "GET /health": { status: "ok" }, "POST /scans": { scan_id: "s", status: "queued" } });
    await api.health();
    await api.startScan({ repository_id: "r", mode: "dir" });
    expect(calls[0].init.headers["Content-Type"]).toBeUndefined();
    expect(calls[1].init.headers["Content-Type"]).toBe("application/json");
    expect(calls[1].init.credentials).toBe("omit");
  });

  it("maps controlled error codes to ApiError", async () => {
    mockApi({ "GET /findings": { __status: 403, body: { error: { code: "PATH_NOT_ALLOWED", message: "outside roots" } } } });
    await expect(request("/findings")).rejects.toMatchObject({ code: "PATH_NOT_ALLOWED", status: 403 });
    await expect(request("/findings")).rejects.toBeInstanceOf(ApiError);
  });

  it("adds the in-memory bearer token when set", async () => {
    const { calls } = mockApi({ "GET /health": { status: "ok" } });
    setAuthToken("tok");
    await api.health();
    setAuthToken(null);
    await api.health();
    expect(calls[0].init.headers.Authorization).toBe("Bearer tok");
    expect(calls[1].init.headers.Authorization).toBeUndefined();
    expect(window.localStorage.length === 0 || !Object.values(window.localStorage).includes("tok")).toBe(true);
  });

  it("downloads reports with the in-memory token and still handles JSON errors", async () => {
    const { calls } = mockApi({
      "GET /scans/s1/export": { schema: "secretsentinel-report/v1" },
      "GET /scans/failed/export": { __status: 409, body: { error: { code: "INVALID_STATE", message: "Scan not complete" } } },
    });
    setAuthToken("tab-only-token");
    try {
      const blob = await api.exportScan("s1", "json");
      expect(await blob.text()).toContain("secretsentinel-report/v1");
      expect(calls[0].init.headers.Authorization).toBe("Bearer tab-only-token");
      await expect(api.exportScan("failed", "csv")).rejects.toMatchObject({ code: "INVALID_STATE", status: 409 });
    } finally {
      setAuthToken(null);
    }
  });
});
