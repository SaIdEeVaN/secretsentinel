import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { SeverityPolicy } from "../pages/Rules.jsx";
import Scans from "../pages/Scans.jsx";
import Settings from "../pages/Settings.jsx";
import { STATUS, mockApi, scan } from "./mockApi.js";

const wrap = (el) => render(<MemoryRouter>{el}</MemoryRouter>);

describe("Scan History", () => {
  it("filters by result chip and repository and shows the commit", async () => {
    const { calls } = mockApi({
      "GET /scans": { items: [scan({ id: "s1", commit_sha: "abcdef1234567890abcdef1234567890abcdef12" })], total: 1, page: 1, page_size: 20 },
      "GET /repositories": [{ id: "r1", display_name: "owner/app" }],
    });
    wrap(<Scans />);
    expect(await screen.findByText("abcdef1")).toBeInTheDocument();
    await userEvent.click(within(screen.getByRole("group", { name: "Result" })).getByRole("button", { name: /^Fail/ }));
    await userEvent.selectOptions(await screen.findByLabelText("Repository"), "r1");
    await waitFor(() => {
      const last = new URL(calls.filter((c) => c.path.split("?")[0] === "/scans").at(-1).path, "http://local").searchParams;
      expect(last.get("policy_result")).toBe("fail");
      expect(last.get("repository_id")).toBe("r1");
      expect(last.get("page")).toBe("1");
    });
  });
});

describe("Severity policy", () => {
  const actions = () => screen.getAllByRole("row").slice(1).map((r) => r.lastChild.textContent);

  it("blocks at and above the threshold, warns or informs below it", () => {
    wrap(<SeverityPolicy failOn="high" />);
    expect(actions()).toEqual(["BLOCK", "BLOCK", "WARN", "INFORM"]);
  });

  it("never blocks when the threshold is none", () => {
    wrap(<SeverityPolicy failOn="none" />);
    expect(actions()).toEqual(["WARN", "WARN", "WARN", "INFORM"]);
  });
});

describe("Settings", () => {
  it("groups system status into tagged cards", async () => {
    mockApi({ "GET /system/status": { ...STATUS, hosted: true, auth_required: true }, "GET /repositories": [], "GET /audit-events": [] });
    wrap(<Settings onAuthChanged={() => {}} />);
    const scanner = await screen.findByRole("region", { name: "Scanner" });
    expect(scanner).toHaveTextContent("ready");
    expect(scanner).toHaveTextContent("v8.30.1");
    expect(screen.getByRole("region", { name: "Scanning" })).toHaveTextContent("hosted");
    expect(screen.getByRole("region", { name: "Server & access" })).toHaveTextContent("token required");
  });
});
