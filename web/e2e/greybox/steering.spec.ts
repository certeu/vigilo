import { test, expect } from "@playwright/test";
import { adminToken, API, authHeaders, cancelRunViaApi, startGreyboxViaUi, uiLogin, uniq } from "./helpers";

// Analyst hints steer a running analysis; scope is never widened.
test("Run chat: focus, skip_check and an out-of-scope seed", async ({ page, request }) => {
  await uiLogin(page);
  const runId = await startGreyboxViaUi(page, { name: uniq("steer"), rate: 1, concurrency: 1 });
  const token = await adminToken(request);
  try {
    await expect(page.getByText("Running", { exact: true }).first()).toBeVisible();
    await page.getByRole("button", { name: /^Chat/ }).click();
    const drawer = page.getByRole("dialog", { name: "Run chat" });
    await expect(drawer).toBeVisible();

    const send = async (action: string, text: string, target: string | null) => {
      await drawer.getByLabel("Send as").selectOption({ label: action });
      await drawer.getByLabel("Message", { exact: true }).fill(text);
      if (target !== null) {
        const field = drawer.getByLabel(/^(Path or URL|URL to crawl from|Check)$/);
        if (action === "Skip a check") await field.selectOption(target);
        else await field.fill(target);
      }
      await drawer.getByRole("button", { name: "Send" }).click();
    };
    const hintRow = (text: string) => drawer.getByRole("listitem").filter({ hasText: text });

    // 1. focus on an in-scope path -> addressed
    const focusText = uniq("focus-admin");
    await send("Focus on a path", focusText, "/admin/");
    await expect(hintRow(focusText).getByText("Applied").first()).toBeVisible({ timeout: 30_000 });

    // 2. skip a check -> addressed, with human-readable result
    const skipText = uniq("skip-exp");
    await send("Skip a check", skipText, "exposure.files");
    await expect(hintRow(skipText).getByText("Applied").first()).toBeVisible({ timeout: 30_000 });
    await expect(hintRow(skipText)).toContainText(/exposure\.files/);

    // 3. out-of-scope seed -> rejected, explained in plain words
    const seedText = uniq("seed-out");
    await send("Add a crawl seed", seedText, "http://example.org/elsewhere/");
    await expect(hintRow(seedText).getByText("Rejected").first()).toBeVisible({ timeout: 30_000 });
    await expect(hintRow(seedText)).toContainText(/Rejected: that (host|target) is outside the authorised scope/);
    await page.screenshot({ path: "test-results/greybox/steering-drawer.png" });

    // The chat closes; the toggle stays in the header.
    await drawer.getByRole("button", { name: "Close chat" }).click();
    await expect(drawer).toBeHidden();
    await expect(page.getByRole("button", { name: /^Chat/ })).toBeVisible();

    // A hint node shows up in the graph.
    await page.getByRole("tab", { name: "Graph" }).click();
    await expect(page.getByText(focusText).first()).toBeVisible({ timeout: 20_000 });

    // skip_check took effect: work orders of that check were skipped with reason "operator".
    await expect.poll(async () => {
      const r = await request.get(`${API}/greybox/runs/${runId}/events?kinds=work_order.skipped&limit=200`, { headers: authHeaders(token) });
      const items: any[] = (await r.json()).items ?? [];
      return items.filter((e) => e.data?.reason === "operator" && /exposure\.files/.test(e.summary ?? "")).length;
    }, { timeout: 30_000 }).toBeGreaterThan(0);
  } finally {
    await cancelRunViaApi(request, token, runId);
  }
});
