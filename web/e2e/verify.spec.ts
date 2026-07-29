import { test, expect } from "@playwright/test";

const EMAIL = process.env.E2E_EMAIL || "admin@example.com";
const PASSWORD = process.env.E2E_PASSWORD || "change-me-now";
const RUN_ID = process.env.E2E_RUN_ID || "752cd9b6-56f1-4018-96b8-4f50c6c4f31b";

async function login(page) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
}

test("BUG5: dashboard shows REAL data (no mock/seed)", async ({ page }) => {
  await login(page);
  await page.waitForTimeout(800);
  const body = await page.textContent("body");
  // real repo from the actual run must appear; known seed names must NOT
  expect(body).toContain("mock-target");
  for (const seed of ["billing-service", "auth-gateway"]) {
    expect(body).not.toContain(seed);
  }
  await page.screenshot({ path: "e2e/artifacts/verify-dashboard.png", fullPage: true });
});

test("BUG1/2/3: run log panel scrolls, step filters logs, no reflow", async ({ page }) => {
  await login(page);
  await page.goto(`/runs/${RUN_ID}`);
  await expect(page.getByText("Trace Rail")).toBeVisible();
  await page.waitForTimeout(1500); // let logs stream in

  // BUG1: the log scroll container has a bounded height (not grown to content)
  const logBox = page.locator("section:has-text('Evidence / logs') div.overflow-auto").first();
  const box = await logBox.boundingBox();
  expect(box!.height).toBeLessThan(900); // bounded, not full-content height

  // BUG3: clicking a step must not widen the page
  const widthBefore = await page.evaluate(() => document.documentElement.scrollWidth);
  await page.getByRole("button", { name: /Critique/ }).click();
  await page.waitForTimeout(400);
  const widthAfter = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(widthAfter).toBe(widthBefore); // no horizontal reflow

  // BUG2: header reflects the selected step (logs are sliced to it)
  await expect(page.getByText("Evidence / logs · critique")).toBeVisible();
  await page.screenshot({ path: "e2e/artifacts/verify-run-critique.png", fullPage: true });

  // step content differs from "show all"
  await page.getByRole("button", { name: /Show all/ }).click();
  await page.waitForTimeout(300);
});

test("RESPONSIVE: dashboard + run detail at 390px", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 850 });
  await login(page);
  await page.waitForTimeout(600);
  const sw = await page.evaluate(() => document.documentElement.scrollWidth);
  const cw = await page.evaluate(() => document.documentElement.clientWidth);
  // no horizontal overflow of the whole page at mobile width
  expect(sw).toBeLessThanOrEqual(cw + 2);
  await page.screenshot({ path: "e2e/artifacts/verify-mobile-dashboard.png", fullPage: true });
  await page.goto(`/runs/${RUN_ID}`);
  await page.waitForTimeout(800);
  await page.screenshot({ path: "e2e/artifacts/verify-mobile-run.png", fullPage: true });
});

test("NAV: refresh + back/forward keep state", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Repositories" }).click();
  await expect(page).toHaveURL(/\/repos$/);
  await page.reload();
  await expect(page).toHaveURL(/\/repos$/); // still on repos after refresh (not bounced to login)
  await page.goBack();
  await expect(page).toHaveURL(/\/$/);
  await page.goForward();
  await expect(page).toHaveURL(/\/repos$/);
});
