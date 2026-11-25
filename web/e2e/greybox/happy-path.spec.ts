import { readFileSync } from "node:fs";
import { test, expect } from "@playwright/test";
import { startGreyboxViaUi, uiLogin, uniq } from "./helpers";

// Grey-box happy path against the synthetic target (findings, defenses).
test.use({ permissions: ["clipboard-read", "clipboard-write"] });

test("grey-box analysis end to end: findings, graph link, defenses, report", async ({ page }) => {
  await uiLogin(page);
  await startGreyboxViaUi(page, { name: uniq("happy") });

  // The run completes with findings.
  await expect(page.getByText(/Completed: \d+ findings?/)).toBeVisible({ timeout: 90_000 });

  // Findings tab lists the planted weaknesses.
  await page.getByRole("tab", { name: "Findings" }).click();
  const gitFinding = page.getByRole("button", { name: /Exposed file: \/\.git\/HEAD/ });
  await expect(gitFinding).toBeVisible();
  // /.env answers 200 with a soft-404 body: the negative control must not become a finding.
  await expect(page.getByRole("button", { name: /Exposed file: \/\.env/ })).toHaveCount(0);

  // Finding detail -> "Show in graph" selects the node and opens its details.
  await gitFinding.click();
  await page.getByRole("button", { name: "Show in graph" }).click();
  await expect(page).toHaveURL(/tab=exploration/);
  await expect(page).toHaveURL(/node=/);
  const nodeDrawer = page.getByRole("dialog", { name: /Finding details/ });
  await expect(nodeDrawer).toContainText("Exposed file: /.git/HEAD");
  await nodeDrawer.getByRole("button", { name: "Close" }).click();
  await expect(nodeDrawer).toBeHidden();

  // Defenses: ModSecurity and Sigma rules, copyable and downloadable.
  await page.getByRole("tab", { name: "Defenses" }).click();
  const rule = page.locator("pre", { hasText: "SecRule" }).first();
  await expect(rule).toBeVisible();
  await expect(page.locator("pre", { hasText: /^title:|logsource/ }).first()).toBeVisible(); // Sigma
  const copyBtn = page.getByRole("button", { name: /^Copy / }).first();
  // Retried as a unit: the list can re-render (live refresh) between click and feedback.
  await expect(async () => {
    await copyBtn.click();
    await expect(copyBtn).toContainText("Copied", { timeout: 3_000 });
  }).toPass({ timeout: 15_000 });
  const clip = await page.evaluate(() => navigator.clipboard.readText());
  expect(clip.length).toBeGreaterThan(10);

  for (const fmt of ["ModSecurity", "Sigma"]) {
    const [dl] = await Promise.all([
      page.waitForEvent("download"),
      page.getByRole("button", { name: fmt, exact: true }).click(),
    ]);
    const body = readFileSync(await dl.path(), "utf8");
    expect(body.length, `${fmt} download is not empty`).toBeGreaterThan(20);
    expect(dl.suggestedFilename()).toBeTruthy();
  }

  // Report renders and downloads.
  await page.getByRole("tab", { name: "Report" }).click();
  const report = page.getByRole("region", { name: "Report" });
  await expect(report).toContainText(/\.git\/HEAD/);
  const [reportDl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download (.md)" }).click(),
  ]);
  expect(reportDl.suggestedFilename()).toMatch(/\.md$/);
  expect(readFileSync(await reportDl.path(), "utf8")).toContain(".git/HEAD");
  const [headerDl] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "Download report" }).click(),
  ]);
  expect(headerDl.suggestedFilename()).toMatch(/\.md$/);
});
