import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import FindingTable from "../components/FindingTable.jsx";
import ScanStatus, { CLEAN_TEXT, FAILED_TEXT, ResultPill } from "../components/ScanStatus.jsx";
import SeverityBadge from "../components/SeverityBadge.jsx";
import { finding, scan } from "./mockApi.js";

describe("SeverityBadge", () => {
  it("conveys severity with text and an icon, not colour alone", () => {
    render(<SeverityBadge severity="critical" />);
    const badge = screen.getByText("Critical");
    expect(badge.closest("span")).toHaveAttribute("title", expect.stringMatching(/estimate/));
    expect(badge.parentElement.textContent).toContain("◆");
  });
});

describe("ScanStatus", () => {
  it.each(["not_evaluated", undefined, "unexpected"])("does not pass a completed scan with policy result %s", (policy_result) => {
    render(<><ResultPill scan={scan({ policy_result })} /><ScanStatus scan={scan({ policy_result })} /></>);
    expect(screen.getByText("ERROR")).toBeInTheDocument();
    expect(screen.getByText(FAILED_TEXT)).toBeInTheDocument();
    expect(screen.queryByText("PASS")).not.toBeInTheDocument();
  });
  it("uses the PRD wording for clean scans and never claims security", () => {
    render(<ScanStatus scan={scan({ policy_result: "pass", total_findings: 0, blocking_findings: 0 })} />);
    expect(screen.getByText(CLEAN_TEXT)).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/100% secure/i);
  });

  it("reports failed scans as unknown status, never as pass", () => {
    const s = scan({ status: "failed", policy_result: "not_evaluated", error_code: "SCAN_TIMEOUT", error_message: "timed out" });
    render(
      <>
        <ScanStatus scan={s} />
        <ResultPill scan={s} />
      </>,
    );
    expect(screen.getByText(FAILED_TEXT)).toBeInTheDocument();
    expect(screen.getByText("ERROR")).toBeInTheDocument();
    expect(screen.queryByText("PASS")).not.toBeInTheDocument();
  });

  it("announces progress politely while running", () => {
    render(<ScanStatus scan={{ id: "x", status: "running" }} />);
    expect(screen.getByRole("status")).toHaveTextContent(/running/i);
  });
});

describe("FindingTable", () => {
  it("renders only redacted metadata and supports keyboard selection", async () => {
    const onSelect = vi.fn();
    const f = finding({ secret: "SHOULD_NEVER_RENDER", match: "SHOULD_NEVER_RENDER" });
    render(<FindingTable findings={[f]} onSelect={onSelect} />);
    expect(screen.getAllByText("Potential EVM signing secret").length).toBeGreaterThan(0);
    expect(screen.getAllByText("src/config.js:21").length).toBeGreaterThan(0);
    expect(document.body.textContent).not.toContain("SHOULD_NEVER_RENDER");
    const row = screen.getAllByRole("row")[1];
    row.focus();
    await userEvent.keyboard("{Enter}");
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ id: f.id }));
    expect(screen.getAllByText(/Blocking/).length).toBeGreaterThan(0);
  });
});
