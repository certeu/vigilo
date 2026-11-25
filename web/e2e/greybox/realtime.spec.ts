import { test, expect } from "@playwright/test";
import { adminToken, cancelRunViaApi, graphNodeCount, headerCounter, startGreyboxViaUi, uiLogin, uniq } from "./helpers";

// The run workspace follows a running analysis without reloads.
test("a slowed run streams events, graph nodes and counters live", async ({ page, request }) => {
  await uiLogin(page);
  // 1 request/s, one at a time: the run takes minutes, so growth is observable.
  const runId = await startGreyboxViaUi(page, { name: uniq("live"), rate: 1, concurrency: 1 });
  try {
    await page.evaluate(() => { (window as any).__noReload = true; });
    await expect(page.getByRole("tab", { name: "Activity", selected: true })).toBeVisible();

    // Connection badge says Live.
    await expect(page.getByText(/^Live/).first()).toBeVisible();
    await expect(page.getByText("Running", { exact: true }).first()).toBeVisible();

    // Activity: events are listed and keep arriving.
    const eventCount = async () => {
      const t = (await page.getByText(/^[\d,]+( of [\d,]+)? events$/).textContent()) ?? "";
      return Number(/^([\d,]+)/.exec(t)?.[1].replace(/,/g, "") ?? 0);
    };
    await expect.poll(eventCount, { timeout: 20_000 }).toBeGreaterThan(0);
    const e0 = await eventCount();
    await expect.poll(eventCount, { timeout: 30_000, intervals: [1000] }).toBeGreaterThan(e0 + 2);

    // Header counters change on their own.
    const r0 = await headerCounter(page, "Requests");
    const ev0 = await headerCounter(page, "Events");
    await expect.poll(() => headerCounter(page, "Requests"), { timeout: 30_000, intervals: [1000] }).toBeGreaterThan(r0);
    await expect.poll(() => headerCounter(page, "Events"), { timeout: 30_000, intervals: [1000] }).toBeGreaterThan(ev0);

    // Graph node count grows while the run goes on (workspace stream is shared by the tabs).
    await page.getByRole("tab", { name: "Graph" }).click();
    await expect.poll(() => graphNodeCount(page), { timeout: 30_000 }).toBeGreaterThan(0);
    const n0 = await graphNodeCount(page);
    await expect.poll(() => graphNodeCount(page), { timeout: 45_000, intervals: [1000] }).toBeGreaterThan(n0);

    // Still the same page load: nothing reloaded it.
    expect(await page.evaluate(() => (window as any).__noReload === true)).toBe(true);
    await expect(page.getByText(/^Live/).first()).toBeVisible();
  } finally {
    await cancelRunViaApi(request, await adminToken(request), runId);
  }
});
