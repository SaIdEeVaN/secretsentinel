import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "../App.jsx";
import { UNAUTHORIZED_EVENT, api, setAuthToken } from "../api/client.js";
import { STATUS, mockApi } from "./mockApi.js";

const HOSTED = { ...STATUS, hosted: true, auth_required: true, local_scanning_enabled: false, ingest_enabled: true, allowed_roots: [] };
const EMPTY_METRICS = {
  repositories: 0, scans_total: 0, scans_completed: 0, scans_failed: 0, open_findings: 0, blocking_open_findings: 0,
  severity_counts: { critical: 0, high: 0, medium: 0, low: 0 }, family_counts: {}, latest_scans: [], trend: [],
};

function hostedApi(validToken) {
  const authed = (body) => (init) =>
    init.headers?.Authorization === `Bearer ${validToken}` ? body : { __status: 401, body: { error: { code: "UNAUTHORIZED", message: "Authentication is required." } } };
  return mockApi({
    "GET /system/status": authed(HOSTED),
    "GET /metrics/overview": authed(EMPTY_METRICS),
    "GET /findings": authed({ items: [], total: 0, page: 1, page_size: 8 }),
  });
}

afterEach(() => setAuthToken(null));

describe("hosted dashboard", () => {
  it("asks for the API token, rejects a wrong one and then opens the dashboard", async () => {
    hostedApi("right-token");
    render(<MemoryRouter><App /></MemoryRouter>);
    const input = await screen.findByLabelText("API token");
    await userEvent.type(input, "wrong-token");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("not accepted");
    await userEvent.clear(input);
    await userEvent.type(input, "right-token");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    // CI-fed dashboard: onboarding explains uploads; there is no local "New Scan".
    expect(await screen.findByText("Waiting for the first scan upload")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /New Scan/ })).not.toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Sign out" }).length).toBeGreaterThan(0);
  });

  it("returns to sign-in when the server starts rejecting the token", async () => {
    hostedApi("tok");
    setAuthToken("tok");
    render(<MemoryRouter><App /></MemoryRouter>);
    await screen.findByText("Waiting for the first scan upload");
    window.dispatchEvent(new CustomEvent(UNAUTHORIZED_EVENT));
    expect(await screen.findByLabelText("API token")).toBeInTheDocument();
  });

  it("keeps the token for the tab only (sessionStorage), never localStorage", async () => {
    const { calls } = mockApi({ "GET /health": { status: "ok" } });
    setAuthToken("tab-token");
    expect(window.sessionStorage.getItem("secretsentinel.apiToken")).toBe("tab-token");
    expect(JSON.stringify({ ...window.localStorage })).not.toContain("tab-token");
    await api.health();
    expect(calls[0].init.headers.Authorization).toBe("Bearer tab-token");
    setAuthToken(null);
    expect(window.sessionStorage.getItem("secretsentinel.apiToken")).toBeNull();
  });

  it("announces 401 responses so the app can ask for a token", async () => {
    mockApi({ "GET /findings": { __status: 401, body: { error: { code: "UNAUTHORIZED", message: "x" } } } });
    const seen = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, seen);
    await expect(api.findings()).rejects.toMatchObject({ status: 401 });
    window.removeEventListener(UNAUTHORIZED_EVENT, seen);
    expect(seen).toHaveBeenCalledTimes(1);
  });

  it("local mode keeps New Scan and needs no sign-in", async () => {
    mockApi({
      "GET /system/status": STATUS,
      "GET /metrics/overview": EMPTY_METRICS,
      "GET /findings": { items: [], total: 0, page: 1, page_size: 8 },
    });
    render(<MemoryRouter><App /></MemoryRouter>);
    expect(await screen.findByText("Get started")).toBeInTheDocument();
    await waitFor(() => expect(screen.getAllByRole("link", { name: /New Scan/ }).length).toBeGreaterThan(0));
    expect(screen.queryByLabelText("API token")).not.toBeInTheDocument();
  });
});
