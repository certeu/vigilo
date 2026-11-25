import { REASON_TEXT, hintOutcome, reasonSentence } from "./hintLogic";
import { describe, expect, it } from "vitest";
import { ApiError } from "../../../api/client";
import { CATEGORY_STYLE, KIND_STYLE, REL_STYLE, statusCategory } from "../graph/encoding";
import { FEEDBACK_RELS } from "../graph/model";
import { incrementalLayout } from "../graph/layout";
import { NODE_KINDS, STATUSES_BY_KIND } from "../graph/types";
import type { Hint } from "../types";
import {
  EMPTY_DRAFT, buildHintPayload, hintErrorMessage, suggestTarget, upsertHint, validateHint,
  type HintDraft,
} from "./hintLogic";

const d = (o: Partial<HintDraft>): HintDraft => ({ ...EMPTY_DRAFT, ...o });
const hint = (o: Partial<Hint> = {}): Hint => ({
  id: "h1", run_id: "r", text: "t", action: "note", target: null, about_node_id: null, node_id: null, status: "open",
  result: null, work_order_ids: [], created_by: "u", created_by_name: "A", created_at: "2026-01-01T00:00:00Z", addressed_at: null, ...o,
});

describe("validateHint / buildHintPayload", () => {
  it("note needs only text and drops any target", () => {
    expect(validateHint(d({ text: "  " })).text).toBeTruthy();
    expect(validateHint(d({ text: "hi" }))).toEqual({});
    expect(buildHintPayload(d({ text: " hi ", target: "/x", aboutNodeId: "n1" }))).toEqual({
      text: "hi", action: "note", target: null, about_node_id: "n1",
    });
  });
  it("focus, add_seed and deprioritize require a path or URL", () => {
    for (const action of ["focus", "add_seed", "deprioritize"] as const) {
      expect(validateHint(d({ action, text: "x" })).target).toBeTruthy();
      expect(validateHint(d({ action, text: "x", target: "admin" })).target).toBeTruthy();
      expect(validateHint(d({ action, text: "x", target: "/admin" }))).toEqual({});
      expect(validateHint(d({ action, text: "x", target: "https://h.test/a" }))).toEqual({});
    }
    expect(buildHintPayload(d({ action: "focus", text: "x", target: " /admin " })).target).toBe("/admin");
  });
  it("skip_check requires a check id", () => {
    expect(validateHint(d({ action: "skip_check", text: "x" })).target).toBeTruthy();
    expect(validateHint(d({ action: "skip_check", text: "x", target: "headers.security" }))).toEqual({});
  });
  it("rejects text over 2000 characters", () => {
    expect(validateHint(d({ text: "a".repeat(2001) })).text).toBeTruthy();
    expect(validateHint(d({ text: "a".repeat(2000) }))).toEqual({});
  });
});

describe("list maintenance", () => {
  it("upserts newest first without duplicates", () => {
    const u = upsertHint([hint()], hint({ id: "h2", created_at: "2026-01-02T00:00:00Z" }));
    expect(u.map((h) => h.id)).toEqual(["h2", "h1"]);
    expect(upsertHint(u, hint({ status: "addressed" })).filter((h) => h.id === "h1")).toHaveLength(1);
  });
});

describe("errors and targets", () => {
  it("explains 409, 422 and 429", () => {
    expect(hintErrorMessage(new ApiError(409, "x"))).toMatch(/finished/);
    expect(hintErrorMessage(new Error("boom"))).toBe("boom");
    expect(hintErrorMessage(new ApiError(429, "x"))).toMatch(/10 per minute/);
    expect(hintErrorMessage(new ApiError(422, "bad", "target outside scope"))).toMatch(/target outside scope/);
  });
  it("suggests a target from node data or label", () => {
    expect(suggestTarget({ url: "https://h.test/a" })).toBe("https://h.test/a");
    expect(suggestTarget({ endpoint: "/search" })).toBe("/search");
    expect(suggestTarget({ tool: "x" }, "crawl.site /login")).toBe("/login");
    expect(suggestTarget({}, "Missing CSP")).toBeNull();
  });
});

describe("hint graph encoding", () => {
  it("is a known kind with open/addressed/rejected", () => {
    expect(NODE_KINDS).toContain("hint");
    expect(STATUSES_BY_KIND.hint).toEqual(["open", "addressed", "rejected"]);
    expect(KIND_STYLE.hint.tile).toMatch(/violet|hint/);
  });
  it("open is active, addressed done, rejected muted", () => {
    expect(statusCategory("hint", "open")).toBe("running");
    expect(statusCategory("hint", "addressed")).toBe("observed");
    expect(statusCategory("hint", "rejected")).toBe("rejected");
    expect(statusCategory("lead", "open")).toBe("planned");
    expect(CATEGORY_STYLE.rejected.body).toMatch(/opacity/);
  });
  it("guides is a violet dashed feedback edge that does not rank", () => {
    expect(REL_STYLE.guides.color).toBe("#6D28D9");
    expect(REL_STYLE.guides.dash).toBeTruthy();
    expect(FEEDBACK_RELS.has("guides")).toBe(true);
  });
  it("places a new hint next to the node it guides", () => {
    const prev = new Map([["wo", { x: 400, y: 0 }]]);
    const out = incrementalLayout(["wo", "h"], [{ src: "h", dst: "wo", rel: "guides" }], prev);
    expect(out.get("h")!.x).toBeLessThan(400);
  });
});

describe("reason codes and outcomes", () => {
  const codes = [
    "invalid_url", "userinfo_present", "scheme_not_allowed", "host_not_allowed", "port_not_allowed",
    "path_excluded", "path_not_in_scope", "out_of_scope", "invalid_target", "check_not_selected", "run_ended", "internal_error",
  ];
  it("has a sentence for every backend reason code, never mentioning scans", () => {
    for (const c of codes) {
      expect(REASON_TEXT[c], c).toBeTruthy();
      expect(REASON_TEXT[c]).not.toMatch(/scan|_/i);
    }
    expect(reasonSentence("scheme_not_allowed")).toBe("Rejected: this URL scheme is not in the authorised scope (check http vs https)");
  });
  it("humanises unknown codes and passes free text", () => {
    expect(reasonSentence("some_new_code")).toBe("Rejected: some new code");
    expect(reasonSentence("target is gone")).toBe("Rejected: target is gone");
    expect(reasonSentence(null)).toBe("Rejected: no reason given");
  });
  it("shows no-effect results in neutral tone, effective ones as success, rejections as warn", () => {
    const h = (status: "addressed" | "rejected", result: string | null) => hintOutcome({ status, result });
    expect(h("addressed", "deprioritised 0 work orders")).toEqual({ text: "Deprioritised 0 work orders.", tone: "neutral" });
    expect(h("addressed", "prioritised 0 work orders, added 0 seeds")?.tone).toBe("neutral");
    expect(h("addressed", "seed already planned")?.tone).toBe("neutral");
    expect(h("addressed", "noted")?.tone).toBe("neutral");
    expect(h("addressed", "prioritised 2 work orders, added 1 seed")?.tone).toBe("success");
    expect(h("addressed", "deprioritised 1 work order")?.tone).toBe("success");
    expect(h("rejected", "host_not_allowed")?.tone).toBe("warn");
  });
});
