import { describe, expect, it } from "vitest";
import type { Hint } from "../types";
import { CHAT_TICK, buildConversation, chatOutcome, chatStatus, hintIdsOf, repliedIds, unreadCount } from "./chatModel";

const hint = (o: Partial<Hint> = {}): Hint => ({
  id: "h1", run_id: "r", text: "t", action: "note", target: null, about_node_id: null, node_id: null, status: "open",
  result: null, work_order_ids: [], created_by: "u", created_by_name: "A", created_at: "2026-01-01T00:00:00Z", addressed_at: null, ...o,
});

describe("chatStatus", () => {
  it("queued -> applied / rejected -> reading -> replied", () => {
    expect(chatStatus(hint())).toBe("queued");
    expect(chatStatus(hint({ status: "addressed", result: "noted" }))).toBe("applied");
    expect(chatStatus(hint({ status: "rejected", result: "out_of_scope" }))).toBe("rejected");
    expect(chatStatus(hint({ status: "addressed", seen_cycle: 3 }))).toBe("reading");
    expect(chatStatus(hint({ seen_cycle: 3, reply: "Looking at /admin now." }))).toBe("replied");
  });
  it("works without the optional backend fields and uses live llm.request ids", () => {
    expect(chatStatus(hint({ status: "addressed" }), new Set(["h1"]))).toBe("reading");
    expect(chatStatus(hint(), new Set(["other"]))).toBe("queued");
    expect(chatStatus(hint({ reply: "   " }))).toBe("queued");
  });
  it("has a tick for every status", () => {
    for (const s of ["queued", "applied", "rejected", "reading", "replied"] as const) expect(CHAT_TICK[s].label).toBeTruthy();
  });
});

describe("chatOutcome", () => {
  it("hides the redundant 'noted' of a plain message, keeps action results and rejections", () => {
    expect(chatOutcome(hint({ status: "addressed", result: "noted" }))).toBeNull();
    expect(chatOutcome(hint())).toBeNull();
    expect(chatOutcome(hint({ action: "focus", status: "addressed", result: "prioritised 2 work orders" }))?.tone).toBe("success");
    expect(chatOutcome(hint({ status: "rejected", result: "host_not_allowed" }))?.text).toMatch(/outside the authorised scope/);
  });
});

describe("buildConversation", () => {
  it("orders oldest first and places each reply at its reply time", () => {
    const a = hint({ id: "a", created_at: "2026-01-01T00:00:00Z", reply: "ok a", replied_at: "2026-01-01T00:05:00Z" });
    const b = hint({ id: "b", created_at: "2026-01-01T00:02:00Z" });
    const c = hint({ id: "c", created_at: "2026-01-01T00:06:00Z", reply: "ok c" });
    // Served newest first.
    const items = buildConversation([c, b, a]);
    expect(items.map((i) => i.key)).toEqual(["u:a", "u:b", "a:a", "u:c", "a:c"]);
    expect(items[2]).toMatchObject({ kind: "agent", text: "ok a" });
    expect(items[0]).toMatchObject({ kind: "user", status: "replied" });
    expect(items[1]).toMatchObject({ kind: "user", status: "queued" });
  });
  it("keeps a reply after its message when replied_at is missing or earlier", () => {
    const h = hint({ reply: "x", replied_at: "2025-12-31T00:00:00Z" });
    expect(buildConversation([h]).map((i) => i.kind)).toEqual(["user", "agent"]);
  });
  it("passes live reading ids to the status", () => {
    expect(buildConversation([hint()], new Set(["h1"]))[0]).toMatchObject({ status: "reading" });
  });
});

describe("unread and llm.request ids", () => {
  it("counts replies not yet seen", () => {
    const hs = [hint({ id: "a", reply: "r" }), hint({ id: "b", reply: "r" }), hint({ id: "c" })];
    expect(repliedIds(hs)).toEqual(["a", "b"]);
    expect(unreadCount(hs, new Set())).toBe(2);
    expect(unreadCount(hs, new Set(["a"]))).toBe(1);
    expect(unreadCount(hs, new Set(["a", "b"]))).toBe(0);
  });
  it("reads hint_ids defensively", () => {
    expect(hintIdsOf({ hint_ids: ["a", 3, "b"] })).toEqual(["a", "b"]);
    expect(hintIdsOf({})).toEqual([]);
    expect(hintIdsOf(null)).toEqual([]);
  });
});
