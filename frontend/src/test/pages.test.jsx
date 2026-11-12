import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import FindingDetail from "../pages/FindingDetail.jsx";
import Findings from "../pages/Findings.jsx";
import NewScan from "../pages/NewScan.jsx";
import Overview from "../pages/Overview.jsx";
import ScanDetail from "../pages/ScanDetail.jsx";
import { STATUS, finding, mockApi, scan } from "./mockApi.js";

const EMPTY_METRICS = {
  repositories: 0, scans_total: 0, scans_completed: 0, scans_failed: 0, open_findings: 0, blocking_open_findings: 0,
  severity_counts: { critical: 0, high: 0, medium: 0, low: 0 }, family_counts: {}, latest_scans: [], trend: [],
};

function renderAt(path, element, routePath = path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path={routePath} element={element} />
        <Route path="*" element={<div>elsewhere</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("Overview", () => {
  it("shows onboarding with a demo option when there are no scans", async () => {
    mockApi({ "GET /metrics/overview": EMPTY_METRICS, "GET /system/status": STATUS, "GET /findings": { items: [], total: 0, page: 1, page_size: 8 } });
    renderAt("/", <Overview />);
    expect(await screen.findByText("Get started")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /create demo repository/i })).toBeEnabled();
  });

  it("summarises counts from the API", async () => {
    mockApi({
      "GET /metrics/overview": {
        ...EMPTY_METRICS, repositories: 2, scans_total: 15, scans_completed: 15, open_findings: 3, blocking_open_findings: 1,
        severity_counts: { critical: 1, high: 2, medium: 0, low: 0 }, latest_scans: [scan()], trend: [],
      },
      "GET /system/status": STATUS,
      "GET /findings": { items: [finding()], total: 1, page: 1, page_size: 8 },
    });
    renderAt("/", <Overview />);
    expect(await screen.findByText("Open findings by severity")).toBeInTheDocument();
    expect(screen.getByText("Blocking now").nextSibling).toHaveTextContent("1");
    expect(await screen.findAllByText("Potential EVM signing secret")).not.toHaveLength(0);
  });
});

describe("NewScan", () => {
  it("prevents duplicate scan requests while one is running", async () => {
    let starts = 0;
    mockApi({
      "GET /repositories": [{ id: "r1", display_name: "demo", local_path: "/x", allowed: true, created_at: "2026-11-10T10:00:00Z" }],
      "GET /system/status": STATUS,
      "POST /scans": () => {
        starts += 1;
        return { scan_id: "s1", status: "queued" };
      },
      "GET /scans/s1": scan({ id: "s1", status: "running" }),
    });
    renderAt("/scan/new", <NewScan />);
    const button = await screen.findByRole("button", { name: /start scan/i });
    await waitFor(() => expect(button).toBeEnabled());
    await userEvent.click(button);
    await screen.findByText(/scan queued/i);
    expect(screen.getByRole("button", { name: /scan in progress/i })).toBeDisabled();
    expect(starts).toBe(1);
  });
});

describe("FindingDetail", () => {
  it("shows remediation and has no way to reveal the secret", async () => {
    const detail = {
      ...finding(),
      remediation: { key: "ROTATE_SIGNING_KEY", title: "Treat the signing key as compromised", risk: "Irreversible.", urgency: "critical", steps: ["Create a NEW wallet"], notes: [] },
      rule_description: "desc",
      still_detected: true,
      latest_scan_id: "s",
      occurrences: 1,
    };
    mockApi({ "GET /findings/11111111-1111-4111-8111-111111111111": detail });
    renderAt("/findings/11111111-1111-4111-8111-111111111111", <FindingDetail />, "/findings/:findingId");
    expect(await screen.findByText(/Treat the signing key as compromised/)).toBeInTheDocument();
    expect(screen.getByText("Create a NEW wallet")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /reveal|show secret|view secret/i })).not.toBeInTheDocument();
    expect(screen.getByText(/never stored, returned or displayed/)).toBeInTheDocument();
  });
});

describe("Findings", () => {
  it("resets pagination together with filters", async () => {
    const { calls } = mockApi({
      "GET /repositories": [], "GET /rules": { rules: [] },
      "GET /findings": { items: [finding()], total: 60, page: 1, page_size: 25 },
    });
    renderAt("/findings", <Findings />);
    await screen.findByText(/Page 1 of 3/);
    await userEvent.click(within(screen.getByRole("group", { name: "Severity" })).getByRole("button", { name: /^High/ }));
    await userEvent.click(screen.getByRole("button", { name: /Next/ }));
    await screen.findByText(/Page 2 of 3/);
    await userEvent.click(screen.getByRole("button", { name: "Reset filters" }));
    await screen.findByText(/Page 1 of 3/);
    await waitFor(() => {
      const params = new URL(calls.filter((c) => c.path.split("?")[0] === "/findings").at(-1).path, "http://local").searchParams;
      expect(params.get("page")).toBe("1");
      expect(params.has("severity")).toBe(false);
    });
  });
});

describe("Findings filter chips", () => {
  const FACETS = {
    total: 3,
    severity: { critical: 1, high: 2, medium: 0, low: 0 },
    status: { open: 2, acknowledged: 1, resolved: 0, suppressed: 0 },
  };

  it("shows counts on each chip and a summary of open findings", async () => {
    mockApi({
      "GET /repositories": [], "GET /rules": { rules: [] },
      "GET /findings": { items: [finding()], total: 3, page: 1, page_size: 25 },
      "GET /findings/facets": FACETS,
    });
    renderAt("/findings", <Findings />);
    const sev = await screen.findByRole("group", { name: "Severity" });
    await waitFor(() => expect(within(sev).getByRole("button", { name: /^All/ })).toHaveTextContent("All3"));
    expect(within(sev).getByRole("button", { name: /^High/ })).toHaveTextContent("High2");
    const st = screen.getByRole("group", { name: "Status" });
    expect(within(st).getByRole("button", { name: /^Acknowledged/ })).toHaveTextContent("Acknowledged1");
    expect(screen.getByText(/open findings in the latest scans/)).toBeInTheDocument();
  });

  it("filters the list and the counts when a chip is chosen", async () => {
    const { calls } = mockApi({
      "GET /repositories": [], "GET /rules": { rules: [] },
      "GET /findings": { items: [finding()], total: 1, page: 1, page_size: 25 },
      "GET /findings/facets": FACETS,
    });
    renderAt("/findings", <Findings />);
    const st = await screen.findByRole("group", { name: "Status" });
    await userEvent.click(within(st).getByRole("button", { name: /^Open/ }));
    expect(within(st).getByRole("button", { name: /^Open/ })).toHaveAttribute("aria-pressed", "true");
    await waitFor(() => {
      const last = (prefix) => new URL(calls.filter((c) => c.path.split("?")[0] === prefix).at(-1).path, "http://local").searchParams;
      expect(last("/findings").get("status")).toBe("open");
      expect(last("/findings/facets").get("status")).toBe("open");
    });
  });

  it("still works when the counts cannot be loaded", async () => {
    mockApi({
      "GET /repositories": [], "GET /rules": { rules: [] },
      "GET /findings": { items: [finding()], total: 1, page: 1, page_size: 25 },
    });
    renderAt("/findings", <Findings />);
    const sev = await screen.findByRole("group", { name: "Severity" });
    expect(within(sev).getByRole("button", { name: /^All/ })).toHaveTextContent(/^All$/);
    expect(screen.queryByText(/open finding/)).not.toBeInTheDocument();
  });
});

describe("ScanDetail", () => {
  it("refreshes findings when completion arrives after an empty poll", async () => {
    let poll;
    let scanRequests = 0;
    let findingRequests = 0;
    const realSetInterval = globalThis.setInterval;
    vi.spyOn(globalThis, "setInterval").mockImplementation((callback, delay, ...args) => {
      if (delay === 1500) { poll = callback; return 0; }
      return realSetInterval(callback, delay, ...args);
    });
    mockApi({
      "GET /scans/s1": () => scan({ id: "s1", status: ++scanRequests === 1 ? "running" : "completed" }),
      "GET /scans/s1/findings": () => ({ items: ++findingRequests > 2 ? [finding()] : [], total: findingRequests > 2 ? 1 : 0, page: 1, page_size: 50 }),
    });
    renderAt("/scans/s1", <ScanDetail />, "/scans/:scanId");
    await screen.findByText("No findings recorded.");
    await waitFor(() => expect(poll).toBeTypeOf("function"));
    await act(async () => { poll(); });
    expect((await screen.findAllByText("Potential EVM signing secret")).length).toBeGreaterThan(0);
  });

  it("shows a cancellation failure instead of swallowing it", async () => {
    mockApi({
      "GET /scans/s1": scan({ id: "s1", status: "running" }),
      "GET /scans/s1/findings": { items: [], total: 0, page: 1, page_size: 50 },
      "POST /scans/s1/cancel": { __status: 409, body: { error: { code: "INVALID_STATE", message: "Scan already finished" } } },
    });
    renderAt("/scans/s1", <ScanDetail />, "/scans/:scanId");
    await userEvent.click(await screen.findByRole("button", { name: "Cancel", exact: true }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Scan already finished");
  });
});

describe("Overview posture", () => {
  const repo = (id, name, last_scan_status, last_policy_result) => ({
    id, display_name: name, local_path: "", allowed: false, created_at: "2026-11-10T10:00:00Z",
    last_scan_id: `scan-${id}`, last_scan_status, last_policy_result, last_scan_at: "2026-11-12T10:00:00Z",
  });
  const metrics = {
    ...EMPTY_METRICS, repositories: 3, scans_total: 3, scans_completed: 3, latest_scans: [scan()], trend: [],
  };

  it("names the repositories that need attention", async () => {
    mockApi({
      "GET /metrics/overview": metrics,
      "GET /system/status": STATUS,
      "GET /findings": { items: [], total: 0, page: 1, page_size: 8 },
      "GET /repositories": [
        repo("a", "owner/pathway", "completed", "fail"),
        repo("b", "owner/site", "failed", "not_evaluated"),
        repo("c", "owner/clean", "completed", "pass"),
      ],
    });
    renderAt("/", <Overview />);
    expect(await screen.findByText("1 of 3 repositories have blocking findings in their latest scan.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "owner/pathway" })).toHaveAttribute("href", "/scans/scan-a");
    expect(screen.getByRole("link", { name: "owner/site" })).toBeInTheDocument();
    expect(screen.getByText("1 pass · 1 fail · 1 error")).toBeInTheDocument();
  });

  it("says when every repository passed, without claiming they are secure", async () => {
    mockApi({
      "GET /metrics/overview": metrics,
      "GET /system/status": STATUS,
      "GET /findings": { items: [], total: 0, page: 1, page_size: 8 },
      "GET /repositories": [repo("a", "owner/a", "completed", "pass"), repo("b", "owner/b", "completed", "pass")],
    });
    renderAt("/", <Overview />);
    expect(await screen.findByText("No blocking findings in the latest scan of all 2 repositories.")).toBeInTheDocument();
    expect(screen.getByText(/not a guarantee/)).toBeInTheDocument();
    expect(screen.queryByText(/secure/i)).not.toBeInTheDocument();
  });

  it("uses singular wording for one repository", async () => {
    mockApi({
      "GET /metrics/overview": { ...metrics, repositories: 1 },
      "GET /system/status": STATUS,
      "GET /findings": { items: [], total: 0, page: 1, page_size: 8 },
      "GET /repositories": [repo("a", "owner/a", "completed", "fail")],
    });
    renderAt("/", <Overview />);
    expect(await screen.findByText("The repository has blocking findings in its latest scan.")).toBeInTheDocument();
  });
});
