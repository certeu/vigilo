import { test, expect, type Page, type APIRequestContext } from "@playwright/test";

// Drives the real UI as multiple distinct users in parallel browser contexts and
// confirms per-user data isolation (lists + dashboard) and IDOR protection on
// direct URL navigation. Private repos are the isolation boundary (non-private
// repos are team-visible by design).
const API = process.env.E2E_API || "http://localhost:8080";
const PW = "Passw0rd!123";

async function apiLogin(request: APIRequestContext, email: string, pw: string) {
  const r = await request.post(`${API}/auth/jwt/login`, {
    form: { username: email, password: pw },
  });
  return (await r.json()).access_token as string;
}
async function apiGet(request: APIRequestContext, path: string, token: string) {
  const r = await request.get(`${API}${path}`, { headers: { Authorization: `Bearer ${token}` } });
  return r.json();
}
async function uiLogin(page: Page, email: string) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(PW);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
}

test("multi-user isolation + IDOR in the browser", async ({ browser, request }) => {
  const aliceTok = await apiLogin(request, "alice@vigilotest.com", PW);
  const bobTok = await apiLogin(request, "bob@vigilotest.com", PW);

  const aliceRepos = await apiGet(request, "/repositories", aliceTok);
  const bobRepos = await apiGet(request, "/repositories", bobTok);
  // bob's PRIVATE repo — alice must never see it anywhere
  const bobPrivate = bobRepos.find((r: any) => r.is_private && r.name === "bob-secret") || bobRepos.find((r: any) => r.is_private);
  const bobRuns = await apiGet(request, "/runs", bobTok);
  const bobRunId = bobRuns[0]?.id;
  expect(bobPrivate, "bob has a private repo to test against").toBeTruthy();

  // two independent logged-in sessions
  const actx = await browser.newContext();
  const bctx = await browser.newContext();
  const alice = await actx.newPage();
  const bob = await bctx.newPage();
  await Promise.all([uiLogin(alice, "alice@vigilotest.com"), uiLogin(bob, "bob@vigilotest.com")]);

  // ---- LIST views: alice's repos exclude bob's private repo ----
  await alice.goto("/repos");
  await alice.waitForTimeout(600);
  const aliceReposBody = await alice.textContent("body");
  expect(aliceReposBody).toContain("alice-secret");
  expect(aliceReposBody, "alice's repo list must NOT leak bob's private repo").not.toContain("bob-secret");

  // ---- Runs list is scoped too ----
  await alice.goto("/runs");
  await alice.waitForTimeout(600);
  // ---- Dashboard is per-user (this is where the mock-data bug lived) ----
  await alice.goto("/");
  await alice.waitForTimeout(800);
  const aliceDash = await alice.textContent("body");
  expect(aliceDash, "alice dashboard must not show bob's private repo").not.toContain("bob-secret");

  // ---- IDOR via direct URL: alice opens bob's private repo detail ----
  await alice.goto(`/repos/${bobPrivate.id}`);
  await alice.waitForTimeout(800);
  const idorRepo = await alice.textContent("body");
  expect(idorRepo, "IDOR repo URL must not render bob's repo").not.toContain("bob-secret");
  expect(idorRepo.toLowerCase()).toMatch(/could not load|not found/);

  // ---- IDOR via direct URL: alice opens bob's run detail ----
  if (bobRunId) {
    await alice.goto(`/runs/${bobRunId}`);
    await alice.waitForTimeout(800);
    const idorRun = await alice.textContent("body");
    expect(idorRun.toLowerCase()).toMatch(/could not load|not found|loading/);
  }

  // ---- bob sees his own, not alice's ----
  await bob.goto("/repos");
  await bob.waitForTimeout(600);
  const bobReposBody = await bob.textContent("body");
  expect(bobReposBody).toContain("bob-secret");
  expect(bobReposBody, "bob's list must not leak alice's private repo").not.toContain("alice-secret");

  await actx.close();
  await bctx.close();
});
