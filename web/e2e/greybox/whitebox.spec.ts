import { test, expect } from "@playwright/test";
import { uiLogin, uniq } from "./helpers";

// White-box through the mock engine (VIGILO_EXECUTION_ENGINE=mock): no Docker/Temporal,
// the run writes sample deliverables and finishes immediately.
test("white-box: repository -> job -> mock run -> results", async ({ page }) => {
  await uiLogin(page);
  const repo = uniq("wb-repo");
  const job = uniq("wb-job");

  // Repository: upload source files (the drawer opens from "Add repository").
  await page.getByRole("link", { name: "Repositories" }).click();
  await page.getByRole("button", { name: "Add repository" }).click();
  await page.locator("#repo-name").fill(repo);
  await page.locator("input#repo-upload").setInputFiles([
    { name: "app.py", mimeType: "text/x-python", buffer: Buffer.from("import os\nos.system(input())\n") },
    { name: "requirements.txt", mimeType: "text/plain", buffer: Buffer.from("flask==1.0\n") },
  ]);
  await page.locator("form").getByRole("button", { name: "Add repository" }).click();
  await expect(page.getByText(repo).first()).toBeVisible();

  // Job: pick the repository, name it, create.
  await page.getByRole("link", { name: "Jobs" }).click();
  await page.locator("#job-repo").selectOption({ label: repo });
  await page.locator("#job-name").fill(job);
  await page.getByRole("button", { name: "Create job" }).click();
  const row = page.locator("div.px-4.py-3").filter({ hasText: job });
  await expect(row).toBeVisible();

  // Run it: the mock engine finishes immediately.
  await row.getByRole("button", { name: "Run", exact: true }).click();
  await expect(page).toHaveURL(/\/runs\/[0-9a-f-]{36}/);
  const runId = /\/runs\/([0-9a-f-]{36})/.exec(page.url())![1];
  await expect(page.getByText("Trace Rail")).toBeVisible();
  await expect(page.getByText(/Completed/).first()).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole("heading", { name: "Comprehensive Security Assessment Report" })).toBeVisible();
  expect(runId).toBeTruthy();
});
