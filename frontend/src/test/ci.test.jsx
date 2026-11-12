import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import Sidebar from "../components/Sidebar.jsx";
import CiChecks, { groupByRepository } from "../pages/CiChecks.jsx";
import { finding, mockApi, scan } from "./mockApi.js";

const A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const SCANS = [
  scan({ id: "s-a2", repository_id: A, repository_name: "owner/alpha", mode: "ci", policy_result: "fail", created_at: "2026-11-12T10:00:00Z" }),
  scan({ id: "s-b1", repository_id: B, repository_name: "owner/beta", mode: "ci", policy_result: "pass", blocking_findings: 0, total_findings: 0, created_at: "2026-11-12T09:00:00Z" }),
  scan({ id: "s-a1", repository_id: A, repository_name: "owner/alpha", mode: "ci", status: "failed", policy_result: "not_evaluated", error_code: "SCAN_TIMEOUT", created_at: "2026-11-11T10:00:00Z" }),
];

const renderPage = () =>
  render(
    <MemoryRouter initialEntries={["/ci"]}>
      <CiChecks />
    </MemoryRouter>,
  );

describe("groupByRepository", () => {
  it("keeps one entry per repository with its runs newest first", () => {
    const groups = groupByRepository(SCANS);
    expect(groups.map((g) => g.name)).toEqual(["owner/alpha", "owner/beta"]);
    expect(groups[0].runs.map((s) => s.id)).toEqual(["s-a2", "s-a1"]);
  });
});

describe("CiChecks", () => {
  it("asks only for CI uploads and lists each repository once", async () => {
    const { calls } = mockApi({
      "GET /scans": { items: SCANS, total: 3, page: 1, page_size: 200 },
      "GET /findings": { items: [finding({ scan_id: "s-a2" })], total: 1, page: 1, page_size: 25 },
    });
    renderPage();
    const list = await screen.findByRole("region", { name: /Repositories/ });
    expect(within(list).getAllByRole("button")).toHaveLength(2);
    const params = new URL(calls.find((c) => c.path.startsWith("/scans")).path, "http://local").searchParams;
    expect(params.get("mode")).toBe("ci");
  });

  it("shows the latest run's blocking result and a sanitized log of its findings", async () => {
    mockApi({
      "GET /scans": { items: SCANS, total: 3, page: 1, page_size: 200 },
      "GET /findings": { items: [finding({ scan_id: "s-a2" })], total: 1, page: 1, page_size: 25 },
    });
    renderPage();
    expect(await screen.findByText(/1 blocking finding\(s\) at or above “high”/)).toBeInTheDocument();
    expect(await screen.findByText(/web3-evm-private-key-assignment\s+src\/config\.js:21/)).toBeInTheDocument();
    expect(screen.getByText(/policy fail-on=high → FAIL/)).toBeInTheDocument();
  });

  it("switches to an older run and explains a failed scan", async () => {
    mockApi({
      "GET /scans": { items: SCANS, total: 3, page: 1, page_size: 200 },
      "GET /findings": { items: [], total: 0, page: 1, page_size: 25 },
    });
    renderPage();
    const runs = await screen.findByRole("group", { name: "Recent runs" });
    await userEvent.click(within(runs).getByRole("button", { name: /error/ }));
    expect(await screen.findByText(/Scan could not complete; security status is unknown/)).toBeInTheDocument();
    expect(screen.getByText(/! SCAN_TIMEOUT/)).toBeInTheDocument();
  });

  it("selects another repository from the list", async () => {
    mockApi({
      "GET /scans": { items: SCANS, total: 3, page: 1, page_size: 200 },
      "GET /findings": { items: [], total: 0, page: 1, page_size: 25 },
    });
    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /owner\/beta/ }));
    await waitFor(() => expect(screen.getByRole("heading", { name: "owner/beta" })).toBeInTheDocument());
    expect(screen.getByText(/No blocking findings at or above “high”/)).toBeInTheDocument();
  });

  it("explains where uploads come from when there are none", async () => {
    mockApi({ "GET /scans": { items: [], total: 0, page: 1, page_size: 200 } });
    renderPage();
    expect(await screen.findByText("No CI uploads yet.")).toBeInTheDocument();
  });
});

describe("Sidebar", () => {
  it("lists CI Checks and keeps Settings last when attestations are enabled", () => {
    render(
      <MemoryRouter>
        <Sidebar blockchainEnabled localScanning={false} theme="dark" onToggleTheme={() => {}} />
      </MemoryRouter>,
    );
    const labels = within(screen.getByRole("navigation", { name: "Primary" }))
      .getAllByRole("link")
      .map((a) => a.textContent.trim());
    expect(labels).toContain("⟳CI Checks");
    expect(labels.at(-1)).toMatch(/Settings$/);
    expect(labels.at(-2)).toMatch(/Attestations$/);
  });
});
