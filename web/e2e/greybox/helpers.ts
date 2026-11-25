import { expect, type APIRequestContext, type Page } from "@playwright/test";

export const API_PORT = Number(process.env.GB_API_PORT ?? 18580);
export const TARGET_PORT = Number(process.env.GB_TARGET_PORT ?? 18581);
export const API = `http://127.0.0.1:${API_PORT}`;
export const TARGET_URL = `http://127.0.0.1:${TARGET_PORT}/`;
/** Nothing listens here: used for the "target unreachable" failure path. */
export const CLOSED_URL = "http://127.0.0.1:18599/";

export const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@example.com";
export const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "E2e-Passw0rd-xyz";
export const USER_PASSWORD = "E2e-Other-Passw0rd-42";

/** Unique, readable suffix so reruns and specs never collide on names. */
export const uniq = (p: string) => `${p}-${Date.now().toString(36)}${Math.floor(Math.random() * 1e4)}`;

export async function apiToken(request: APIRequestContext, email: string, password: string): Promise<string> {
  const r = await request.post(`${API}/auth/jwt/login`, { form: { username: email, password } });
  expect(r.ok(), `login ${email}: ${r.status()}`).toBeTruthy();
  return (await r.json()).access_token as string;
}

export const authHeaders = (token: string) => ({ Authorization: `Bearer ${token}` });

export async function uiLogin(page: Page, email = ADMIN_EMAIL, password = ADMIN_PASSWORD) {
  await page.goto("/login");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: /sign in/i }).click();
  await expect(page.getByRole("heading", { name: "Security overview" })).toBeVisible();
}

export interface TargetForm {
  name: string;
  url?: string;
  /** requests / s (UI minimum 1). */
  rate?: number;
  concurrency?: number;
  maxPages?: number;
}

/**
 * Drives New analysis -> Grey-box -> form -> "Start analysis" and returns the run id
 * taken from the resulting /greybox/runs/<id> URL.
 */
export async function startGreyboxViaUi(page: Page, t: TargetForm): Promise<string> {
  await page.goto("/analyses/new");
  await page.getByRole("link", { name: "Choose Grey-box" }).click();
  await expect(page.getByRole("heading", { name: "Grey-box configuration" })).toBeVisible();
  await page.getByLabel("Name", { exact: true }).fill(t.name);
  await page.getByLabel("Target base URL").fill(t.url ?? TARGET_URL);
  if (t.rate !== undefined || t.concurrency !== undefined || t.maxPages !== undefined) {
    await page.getByText("Advanced options").click();
    if (t.rate !== undefined) await page.getByLabel("Rate limit").fill(String(t.rate));
    if (t.concurrency !== undefined) await page.getByLabel("Concurrency").fill(String(t.concurrency));
    if (t.maxPages !== undefined) await page.getByLabel("Max pages").fill(String(t.maxPages));
  }
  await page.getByLabel(/I confirm I am authorised/).check();
  await page.getByRole("button", { name: "Start analysis" }).click();
  await page.waitForURL(/\/greybox\/runs\/[0-9a-f-]{36}/);
  return /\/greybox\/runs\/([0-9a-f-]{36})/.exec(page.url())![1];
}

export async function runStatus(request: APIRequestContext, token: string, runId: string) {
  const r = await request.get(`${API}/greybox/runs/${runId}`, { headers: authHeaders(token) });
  expect(r.ok()).toBeTruthy();
  return (await r.json()) as Record<string, any>;
}

/** Numeric value of a header counter ("Requests", "Events", "Assets", ...). */
export async function headerCounter(page: Page, label: string): Promise<number> {
  const stat = page.getByLabel("Run counters").locator("div").filter({ has: page.getByText(label, { exact: true }) }).first();
  const txt = (await stat.locator("dd").first().textContent()) ?? "";
  return Number(/[\d,]+/.exec(txt)?.[0].replace(/,/g, "") ?? NaN);
}

/** Total node count from the graph toolbar ("12 of 40 nodes . v7" -> 40). */
export async function graphNodeCount(page: Page): Promise<number> {
  const t = (await page.getByText(/\d+ of \d+ nodes/).first().textContent()) ?? "";
  return Number(/of (\d+) nodes/.exec(t)?.[1] ?? NaN);
}

export async function cancelRunViaApi(request: APIRequestContext, token: string, runId: string) {
  await request.post(`${API}/greybox/runs/${runId}/cancel`, { headers: authHeaders(token), data: {} });
}

/** The admin token (shared by specs that need API access next to the UI). */
export async function adminToken(request: APIRequestContext) {
  return apiToken(request, ADMIN_EMAIL, ADMIN_PASSWORD);
}
