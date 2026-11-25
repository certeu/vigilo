import { test, expect } from "@playwright/test";
import { adminToken, cancelRunViaApi, CLOSED_URL, runStatus, startGreyboxViaUi, uiLogin, uniq } from "./helpers";

test("cancel: a running analysis stops within 5 s", async ({ page, request }) => {
  await uiLogin(page);
  const runId = await startGreyboxViaUi(page, { name: uniq("cancel"), rate: 1, concurrency: 1 });
  await expect(page.getByText("Running", { exact: true }).first()).toBeVisible();
  await expect.poll(async () => (await runStatus(request, await adminToken(request), runId)).counters?.requests ?? 0)
    .toBeGreaterThan(0); // some work is genuinely in flight

  await page.getByRole("button", { name: "Cancel run" }).click();
  await expect(page.getByRole("dialog")).toContainText("Cancel this run?");
  const t0 = Date.now();
  await page.getByRole("dialog").getByRole("button", { name: "Cancel run" }).click();
  await expect(page.getByText(/^Cancelled by /)).toBeVisible({ timeout: 5_000 });
  const took = Date.now() - t0;
  expect(took, "cancel acknowledged in ms").toBeLessThan(5_000);

  const api = await runStatus(request, await adminToken(request), runId);
  expect(api.status).toBe("cancelled");
  // The cancel button is gone and the run does not come back to life.
  await expect(page.getByRole("button", { name: "Cancel run" })).toHaveCount(0);
  await page.waitForTimeout(2_000);
  expect((await runStatus(request, await adminToken(request), runId)).status).toBe("cancelled");
});

test("failure: an unreachable target ends as a readable failure", async ({ page, request }) => {
  await uiLogin(page);
  const runId = await startGreyboxViaUi(page, { name: uniq("down"), url: CLOSED_URL });
  await expect(page.getByText(/Failed: Target unreachable/)).toBeVisible({ timeout: 60_000 });
  const api = await runStatus(request, await adminToken(request), runId);
  expect(api.status).toBe("failed");
  expect(api.error_summary).toMatch(/Target unreachable/);
  expect(api.error_summary).not.toMatch(/Traceback|Error:|\bat \w+\.py/); // no raw stack trace
});

// Regression: the lease heartbeat (VIGILO_GREYBOX_HEARTBEAT_S=2 in this suite) used to
// cancel runs that outlived one heartbeat interval.
test("long run: a run outliving several heartbeats is not cancelled", async ({ page, request }) => {
  test.setTimeout(150_000);
  await uiLogin(page);
  const runId = await startGreyboxViaUi(page, { name: uniq("long"), rate: 4, concurrency: 2 });
  const token = await adminToken(request);
  const started = Date.now();

  // Alive well past 3 heartbeats (2 s each).
  await page.waitForTimeout(8_000);
  const mid = await runStatus(request, token, runId);
  expect(["running", "preparing", "succeeded"]).toContain(mid.status);

  await expect(page.getByText(/^Completed/).first()).toBeVisible({ timeout: 120_000 });
  const done = await runStatus(request, token, runId);
  expect(done.status).toBe("succeeded");
  expect(done.cancelled_by ?? null).toBeNull();
  expect(done.end_reason).not.toBe("lease_expired");
  expect(Date.now() - started, "the run outlived the 2 s heartbeat").toBeGreaterThan(6_000);
  await expect(page.getByText(/Cancelled/)).toHaveCount(0);
});
