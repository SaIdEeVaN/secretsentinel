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
});
