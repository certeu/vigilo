import { test, expect } from "@playwright/test";
import { adminToken, API, apiToken, authHeaders, startGreyboxViaUi, uiLogin, uniq, USER_PASSWORD } from "./helpers";

// A second, non-admin user must not see user A's grey-box targets or runs, in the UI or the API.
test("grey-box data is isolated between users", async ({ browser, page, request }) => {
  // user A (admin) creates a target + run through the UI
  await uiLogin(page);
  const targetName = uniq("alice-secret-target");
  const runId = await startGreyboxViaUi(page, { name: targetName });
  await expect(page.getByText(/^Completed/).first()).toBeVisible({ timeout: 90_000 });
  const aToken = await adminToken(request);
  const run = await (await request.get(`${API}/greybox/runs/${runId}`, { headers: authHeaders(aToken) })).json();
  const targetId: string = run.target.id ?? run.target_id;
  const findings = await (await request.get(`${API}/greybox/runs/${runId}/findings`, { headers: authHeaders(aToken) })).json();
  expect(findings.items.length).toBeGreaterThan(0);

  // user B is created by the admin (API: the UI invitation flow needs a mail relay)
  const bEmail = `${uniq("bob")}@example.com`;
  const created = await request.post(`${API}/users`, {
    headers: authHeaders(aToken),
    data: { email: bEmail, password: USER_PASSWORD, role: "user" },
  });
  expect(created.status(), await created.text()).toBe(201);
  const bToken = await apiToken(request, bEmail, USER_PASSWORD);

  // API: B gets 404 (never 403: existence is not leaked) on every run/target route of A
  const bGet = async (path: string) => (await request.get(`${API}${path}`, { headers: authHeaders(bToken) })).status();
  for (const path of [
    `/greybox/runs/${runId}`, `/greybox/runs/${runId}/findings`, `/greybox/runs/${runId}/events`,
    `/greybox/runs/${runId}/report`, `/greybox/runs/${runId}/defenses`, `/greybox/runs/${runId}/hints`,
    `/greybox/runs/${runId}/graph/exploration`, `/greybox/runs/${runId}/findings/${findings.items[0].id}`,
    `/greybox/targets/${targetId}`,
  ]) {
    expect(await bGet(path), path).toBe(404);
  }
  const cancel = await request.post(`${API}/greybox/runs/${runId}/cancel`, { headers: authHeaders(bToken), data: {} });
  expect(cancel.status()).toBe(404);
  const bTargets = await (await request.get(`${API}/greybox/targets`, { headers: authHeaders(bToken) })).json();
  expect(JSON.stringify(bTargets)).not.toContain(targetName);
  expect(bTargets.items).toHaveLength(0);

  // UI: B's lists are empty and A's URLs render "not found"
  const ctx = await browser.newContext();
  const b = await ctx.newPage();
  await uiLogin(b, bEmail, USER_PASSWORD);
  await b.goto("/greybox");
  await expect(b.getByText(targetName)).toHaveCount(0);
  await b.goto("/analyses");
  await expect(b.getByText(targetName)).toHaveCount(0);
  await b.goto(`/greybox/runs/${runId}`);
  await expect(b.getByText("Run not found")).toBeVisible();
  await expect(b.getByText(targetName)).toHaveCount(0);
  await b.goto(`/greybox/targets/${targetId}`);
  await expect(b.getByText("Target not found")).toBeVisible();
  await ctx.close();
});
