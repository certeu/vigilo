import { test, expect } from "@playwright/test";

// Requires the API running (VIGILO_EXECUTION_ENGINE=mock) with seeded demo data and
// a seeded admin. Credentials via env if needed.
const EMAIL = process.env.E2E_EMAIL || "admin@example.com";
const PASSWORD = process.env.E2E_PASSWORD || "change-me-now";

async function login(page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
}

test("dashboard shows the security overview with charts", async ({ page }) => {
  await login(page);
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
  await expect(page.getByText("Findings by severity")).toBeVisible();
  await expect(page.getByText("Repositories with the most findings")).toBeVisible();
  await page.waitForTimeout(700); // let charts animate in
  await page.screenshot({ path: "e2e/artifacts/dashboard.png", fullPage: true });
});

test("repository detail shows timeline, dependencies, executions + settings drawer", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Repositories" }).click();
  await page.getByRole("link", { name: "acme-webapp" }).first().click();
  await expect(page.getByText("Findings over time")).toBeVisible();
  await expect(page.getByText("Vulnerable dependencies (latest)")).toBeVisible();
  await expect(page.getByText(/Executions \(/)).toBeVisible();
  await page.waitForTimeout(700);
  await page.screenshot({ path: "e2e/artifacts/repo-detail.png", fullPage: true });
  // open the settings drawer (pipeline config lives here now, not on the page)
  await page.getByRole("button", { name: /settings/i }).click();
  await expect(page.getByText("Repository settings")).toBeVisible();
  await expect(page.getByText("Custom scan instructions")).toBeVisible();
  await page.screenshot({ path: "e2e/artifacts/repo-settings.png", fullPage: true });
});

test("admin page has invitations and user management", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Admin" }).click();
  await expect(page.getByText("Invite a colleague")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await page.screenshot({ path: "e2e/artifacts/admin.png", fullPage: true });
});

test("schedules page allows a one-off run", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Schedules" }).click();
  await expect(page.getByRole("heading", { name: "Schedules" })).toBeVisible();
  await expect(page.getByLabel("Trigger")).toBeVisible();
  await page.screenshot({ path: "e2e/artifacts/schedules.png", fullPage: true });
});

test("upload repo: select files and create", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Repositories" }).click();
  await page.getByLabel("Name").fill("uploaded-repo");
  // source defaults to "upload" → the file input must appear
  const fileInput = page.locator('input#repo-upload');
  await expect(fileInput).toBeVisible();
  await fileInput.setInputFiles([
    { name: "app.py", mimeType: "text/x-python", buffer: Buffer.from("x = 1\n") },
    { name: "requirements.txt", mimeType: "text/plain", buffer: Buffer.from("flask==1.0\n") },
  ]);
  await page.getByRole("button", { name: /add repository/i }).click();
  // the new repo appears in the list
  await expect(page.getByText("uploaded-repo")).toBeVisible();
  await page.screenshot({ path: "e2e/artifacts/upload.png", fullPage: true });
});

test("create repo, job, and run shows the Trace Rail", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Repositories" }).click();
  await page.getByLabel("Name").fill("e2e-demo-repo");
  await page.getByRole("button", { name: /add repository/i }).click();
  await page.getByRole("link", { name: "Jobs" }).click();
  await page.getByLabel("Name").fill("e2e-demo-job");
  await page.getByRole("button", { name: /create job/i }).click();
  await page.getByRole("button", { name: /^run$/i }).first().click();
  await expect(page.getByText("Trace Rail")).toBeVisible();
  await page.screenshot({ path: "e2e/artifacts/run-detail.png", fullPage: true });
});
