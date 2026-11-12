import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

test.beforeEach(async ({ request }) => {
  const response = await request.get("/api/v1/system/status");
  expect(response.ok()).toBeTruthy();
  expect((await response.json()).scanner.available).toBe(true);
  const repositories = await (await request.get("/api/v1/repositories")).json();
  for (const repo of repositories) expect((await request.delete(`/api/v1/repositories/${repo.id}`)).ok()).toBeTruthy();
});

async function finishScan(page) {
  await page.getByRole("button", { name: "Start scan", exact: true }).click();
  const details = page.getByRole("link", { name: /View scan details/ });
  await expect(details).toBeVisible({ timeout: 30_000 });
  await details.click();
  await expect(page.getByRole("heading", { name: "Scan details", exact: true })).toBeVisible();
}

test("demo scans current files and deleted history, exports reports and supports triage", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await page.getByRole("button", { name: "Create demo repository" }).click();
  await expect(page.getByRole("heading", { name: "New Scan", exact: true })).toBeVisible();
  await finishScan(page);
  await expect(page.getByText(/2 blocking finding/)).toBeVisible();
  for (const format of ["json", "csv", "sarif"]) {
    await page.getByLabel("Report format").selectOption(format);
    const downloadEvent = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download report" }).click();
    const download = await downloadEvent;
    expect(download.suggestedFilename()).toMatch(new RegExp(`\\.${format}$`));
    const report = readFileSync(await download.path(), "utf8");
    expect(report).not.toMatch(/"Secret"\s*:|"Match"\s*:/);
    if (format === "json") {
      expect(JSON.parse(report).scan.total_findings).toBe(3);
      expect(JSON.parse(report).findings.some((f) => f.commit_sha && f.relative_path === ".env")).toBe(true);
    }
  }
  await page.getByText("Potential EVM signing secret", { exact: true }).filter({ visible: true }).click();
  await expect(page.getByRole("heading", { name: /Recommended response/ })).toBeVisible();
  await page.getByRole("button", { name: "Acknowledge", exact: true }).click();
  await expect(page.getByRole("button", { name: "Acknowledge", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText(/Blocking · Acknowledged/)).toBeVisible();
  expect(errors).toEqual([]);
});

test("a blocking leak can be removed and rescanned without leaking values to the browser or database", async ({ page, request }) => {
  const status = await (await request.get("/api/v1/system/status")).json();
  const folder = join(status.allowed_roots[0], "fix-and-rescan");
  mkdirSync(folder, { recursive: true });
  const canary = createHash("sha256").update("public synthetic browser-test value").digest("hex");
  writeFileSync(join(folder, ".env"), `DEPLOYER_PRIVATE_KEY=0x${canary}\n`);
  const payloads = [];
  page.on("response", (response) => {
    if (new URL(response.url()).pathname.startsWith("/api/")) payloads.push(response.text().catch(() => ""));
  });
  await page.goto("/scan/new");
  await page.getByLabel("Local folder path").fill(folder);
  await page.getByRole("button", { name: "Register folder", exact: true }).click();
  await expect(page.getByRole("button", { name: "Start scan", exact: true })).toBeEnabled();
  await page.locator('input[name="mode"][value="dir"]').check({ force: true });
  await finishScan(page);
  await expect(page.getByText(/1 blocking finding/)).toBeVisible();
  const scanId = page.url().split("/").at(-1);
  const findings = await (await request.get(`/api/v1/scans/${scanId}/findings`)).json();
  const oldFinding = findings.items[0].id;
  await page.getByRole("button", { name: "Download report" }).click();
  unlinkSync(join(folder, ".env"));
  await page.getByRole("link", { name: "Rescan", exact: true }).click();
  // Wait until the form has loaded the repository list (as on the first scan): choosing the
  // mode while the page is still shifting can make the forced click miss the hidden radio.
  await expect(page.getByRole("button", { name: "Start scan", exact: true })).toBeEnabled();
  await page.locator('input[name="mode"][value="dir"]').check({ force: true });
  await finishScan(page);
  await expect(page.getByText("No matching secrets detected in the scanned scope.")).toBeVisible();
  await page.goto(`/findings/${oldFinding}`);
  await expect(page.getByText(/Not detected in the latest scan/)).toBeVisible();
  const browserData = (await Promise.all(payloads)).join("\n") + await page.locator("body").innerText()
    + await page.evaluate(() => JSON.stringify({ local: { ...localStorage }, session: { ...sessionStorage } }));
  expect(browserData.includes(canary)).toBe(false);
  for (const name of ["history.db", "history.db-wal", "history.db-shm"]) {
    const file = join(dirname(status.allowed_roots[0]), name);
    if (existsSync(file)) expect(readFileSync(file).includes(Buffer.from(canary))).toBe(false);
  }
});

test("rejects a folder outside the configured roots and keeps navigation usable on phones", async ({ page, request }, testInfo) => {
  const status = await (await request.get("/api/v1/system/status")).json();
  const outside = join(dirname(status.allowed_roots[0]), "outside");
  mkdirSync(outside, { recursive: true });
  await page.goto("/scan/new");
  await page.getByLabel("Local folder path").fill(outside);
  await page.getByRole("button", { name: "Register folder", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("PATH_NOT_ALLOWED");
  await expect(page.getByRole("button", { name: "Start scan", exact: true })).toBeDisabled();
  if (testInfo.project.name === "mobile") await page.getByRole("button", { name: "Toggle navigation" }).click();
  await page.getByRole("link", { name: "Settings", exact: true }).click();
  await expect(page.getByRole("heading", { name: "System status", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
