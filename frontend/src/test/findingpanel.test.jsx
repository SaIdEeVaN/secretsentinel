import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import Findings from "../pages/Findings.jsx";
import { FindingDetailPanel } from "../pages/FindingDetail.jsx";
import { finding, mockApi } from "./mockApi.js";

const ID = "11111111-1111-4111-8111-111111111111";
const DETAIL = {
  ...finding(),
  remediation: {
    key: "ROTATE_SIGNING_KEY",
    title: "Treat the signing key as compromised",
    risk: "Irreversible.",
    urgency: "critical",
    steps: ["Create a NEW wallet"],
    notes: ["Deleting the line or rewriting Git history does NOT revoke a credential."],
  },
  rule_description: "desc",
  still_detected: true,
  latest_scan_id: "s",
  occurrences: 1,
};
const EVENT = {
  id: "e1",
  actor: "local-user",
  action: "finding.status_changed",
  entity_type: "finding",
  entity_id: ID,
  occurred_at: new Date(Date.now() - 2 * 86_400_000).toISOString(),
  metadata: { previous: "open", new: "acknowledged" },
};

const panel = (props = {}) =>
  render(
    <MemoryRouter>
      <FindingDetailPanel findingId={ID} compact {...props} />
    </MemoryRouter>,
  );

describe("FindingDetailPanel (side panel)", () => {
  it("has a header with the finding id and a Close button", async () => {
    mockApi({ [`GET /findings/${ID}`]: DETAIL, "GET /audit-events": [] });
    const onClose = vi.fn();
    panel({ onClose });
    expect(await screen.findByText("finding 11111111")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("states the redaction and offers no way to reveal a value", async () => {
    mockApi({ [`GET /findings/${ID}`]: DETAIL, "GET /audit-events": [] });
    panel();
    expect(await screen.findByText(/Matched value not retained/)).toBeInTheDocument();
    expect(screen.getByText(/both are estimates/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /reveal|show secret|view secret/i })).not.toBeInTheDocument();
  });

  it("sets the triage status from the segmented control", async () => {
    const { calls } = mockApi({
      [`GET /findings/${ID}`]: DETAIL,
      [`PATCH /findings/${ID}`]: { ...DETAIL, status: "acknowledged" },
      "GET /audit-events": [],
    });
    panel();
    await userEvent.click(await screen.findByRole("button", { name: "Acknowledged" }));
    await waitFor(() => {
      const patch = calls.find((c) => c.method === "PATCH");
      expect(patch).toBeTruthy();
      expect(JSON.parse(patch.init.body)).toEqual({ status: "acknowledged" });
    });
  });

  it("lists the audit trail for this finding only", async () => {
    const { calls } = mockApi({ [`GET /findings/${ID}`]: DETAIL, "GET /audit-events": [EVENT] });
    panel();
    expect(await screen.findByText("Status changed: open → acknowledged")).toBeInTheDocument();
    const audit = calls.find((c) => c.path.startsWith("/audit-events"));
    expect(new URL(audit.path, "http://local").searchParams.get("entity_id")).toBe(ID);
  });

  it("says so when there is nothing in the audit trail", async () => {
    mockApi({ [`GET /findings/${ID}`]: DETAIL, "GET /audit-events": [] });
    panel();
    expect(await screen.findByText("No recorded changes yet.")).toBeInTheDocument();
  });

  it("highlights the 'does not revoke' note as a warning", async () => {
    mockApi({ [`GET /findings/${ID}`]: DETAIL, "GET /audit-events": [] });
    panel();
    const note = await screen.findByText(/does NOT revoke a credential/);
    expect(note.className).toContain("text-warn");
  });

  it("does not fetch the audit trail on the full page", async () => {
    const { calls } = mockApi({ [`GET /findings/${ID}`]: DETAIL });
    render(
      <MemoryRouter>
        <FindingDetailPanel findingId={ID} />
      </MemoryRouter>,
    );
    await screen.findByText(/Treat the signing key as compromised/);
    expect(calls.some((c) => c.path.startsWith("/audit-events"))).toBe(false);
  });
});

describe("Findings with the side panel", () => {
  it("opens the panel beside the list on wide screens and closes it again", async () => {
    vi.spyOn(window, "matchMedia").mockImplementation((query) => ({
      matches: true,
      media: query,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
    }));
    mockApi({
      "GET /repositories": [],
      "GET /rules": { rules: [] },
      "GET /findings": { items: [finding()], total: 1, page: 1, page_size: 25 },
      [`GET /findings/${ID}`]: DETAIL,
      "GET /audit-events": [],
    });
    render(
      <MemoryRouter>
        <Findings />
      </MemoryRouter>,
    );
    await userEvent.click((await screen.findAllByText("Potential EVM signing secret"))[0]);
    expect(await screen.findByText("finding 11111111")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByText("finding 11111111")).not.toBeInTheDocument());
  });
});

describe("Suppression details", () => {
  const suppressed = (suppression) => ({ ...DETAIL, status: "suppressed", blocking: false, suppression_id: "db-1a2b3c4d", suppression });

  it("shows reason, expiry and reviewer of a dashboard suppression", async () => {
    mockApi({
      [`GET /findings/${ID}`]: suppressed({ id: "db-1a2b3c4d", origin: "dashboard", reason: "Synthetic test fixture", reviewer: "alice", expires_at: "2099-01-01", active: true }),
      "GET /audit-events": [],
    });
    panel();
    const box = await screen.findByLabelText("Suppression");
    expect(box).toHaveTextContent("Synthetic test fixture");
    expect(box).toHaveTextContent("2099-01-01");
    expect(box).toHaveTextContent("alice");
    expect(screen.queryByRole("group", { name: "Set status" })).not.toBeInTheDocument();
  });

  it("flags an expired dashboard suppression", async () => {
    mockApi({
      [`GET /findings/${ID}`]: suppressed({ id: "db-1a2b3c4d", origin: "dashboard", reason: "Old reason", reviewer: "bob", expires_at: "2020-01-01", active: true }),
      "GET /audit-events": [],
    });
    panel();
    expect(await screen.findByText(/expired: it no longer applies/)).toBeInTheDocument();
  });

  it("names the policy file entry when the suppression came from .secretsentinel.yml", async () => {
    mockApi({
      [`GET /findings/${ID}`]: { ...suppressed({ id: "baseline-1", origin: "policy" }), suppression_id: "baseline-1" },
      "GET /audit-events": [],
    });
    panel();
    expect(await screen.findByText("baseline-1")).toBeInTheDocument();
    expect(screen.getByText(/\.secretsentinel\.yml/)).toBeInTheDocument();
  });
});
