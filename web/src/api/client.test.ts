import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { request, setToken, setUnauthorizedHandler } from "./client";

// vitest runs in node here: provide a minimal localStorage and a fake fetch.
function stubStorage() {
  const store = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => store.get(k) ?? null,
    setItem: (k: string, v: string) => void store.set(k, v),
    removeItem: (k: string) => void store.delete(k),
  });
}

function stubFetch(status: number, body = "") {
  vi.stubGlobal("fetch", vi.fn(async () => new Response(body, { status })));
}

describe("401 handling in request()", () => {
  beforeEach(() => stubStorage());
  afterEach(() => {
    setUnauthorizedHandler(null);
    vi.unstubAllGlobals();
  });

  it("calls the unauthorized handler and drops the token on a 401 with a token", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    setToken("expired.jwt");
    stubFetch(401);
    await expect(request("/runs")).rejects.toMatchObject({ status: 401 });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(localStorage.getItem("vigilo_token")).toBeNull();
  });

  it("does not call the handler for a 401 without a token (anonymous call)", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    stubFetch(401);
    await expect(request("/runs")).rejects.toMatchObject({ status: 401 });
    expect(handler).not.toHaveBeenCalled();
  });

  it("does not call the handler for other errors (403, 500) or successes", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    setToken("valid.jwt");
    stubFetch(403, JSON.stringify({ detail: "no" }));
    await expect(request("/x")).rejects.toMatchObject({ status: 403 });
    stubFetch(200, JSON.stringify({ ok: true }));
    await expect(request("/x")).resolves.toEqual({ ok: true });
    expect(handler).not.toHaveBeenCalled();
    expect(localStorage.getItem("vigilo_token")).toBe("valid.jwt");
  });
});
