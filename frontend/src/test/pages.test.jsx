import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it } from "vitest";
import FindingDetail from "../pages/FindingDetail.jsx";
import NewScan from "../pages/NewScan.jsx";
import Overview from "../pages/Overview.jsx";
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
