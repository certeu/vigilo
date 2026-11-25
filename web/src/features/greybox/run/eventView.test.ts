import { describe, expect, it } from "vitest";
import type { GreyboxEvent } from "../events";
import { describeEvent, indexByWorkOrder, isEmptyValue, taskOutput, triggerText } from "./eventView";
import { eventTitle } from "./activityModel";

let seq = 0;
const ev = (kind: string, summary: string, data: Record<string, unknown> = {}, extra: Partial<GreyboxEvent> = {}): GreyboxEvent => ({
  seq: ++seq, run_id: "r", ts: "2026-01-01T00:00:00Z", kind, level: "info", source: "agent", agent_id: null, agent_name: null,
  work_order_id: null, tool_call_id: null, summary, status: "ok", duration_ms: null, refs: {}, data, ...extra,
});
const labels = (e: GreyboxEvent) => describeEvent(e).lines.map((l) => l.label);

describe("planner.decision", () => {
  it("renders the pasted waiting decision as a sentence without the empty fields", () => {
    const e = ev("planner.decision", "waiting", {
      decision: "waiting_for_explorer", reason: "waiting for the exploration agent (up to 390s): the queue is empty",
      work_order_ids: [], considered: 0, grace_s: 390,
    });
    const v = describeEvent(e);
    expect(v.headline).toBe("Waiting for the exploration agent (up to 390s): the queue is empty");
    expect(v.lines).toEqual([
      { label: "Why", value: "the queue is empty", mono: false },
      { label: "Waits at most", value: "390 s", mono: false },
    ]);
    expect(JSON.stringify(v)).not.toContain("considered");
  });
  it("shows the explorer's reasoning for a dispatch and the work order count", () => {
    const v = describeEvent(ev("planner.decision", "x", {
      decision: "dispatch", reason: "explorer: Crawl the frontier first.", work_order_ids: ["a", "b"], considered: 0,
      trigger: { kind: "agent", assessment: ["c", "e"] },
    }));
    expect(v.headline).toBe("Explorer's plan queued 2 work orders");
    expect(v.lines).toContainEqual({ label: "Explorer's reasoning", value: "Crawl the frontier first.", mono: false });
    expect(v.lines).toContainEqual({ label: "Triggered by", value: "the exploration agent's proposal", mono: false });
  });
  it("summarises settle_lead, rejected, retry and no-work decisions", () => {
    expect(describeEvent(ev("planner.decision", "x", { decision: "settle_lead", reason: "lead 'git-metadata-depth' refuted (ruled_out)", trigger: { kind: "wo_terminal", node_ids: ["1", "2", "3"] } })).headline)
      .toBe("Lead 'git-metadata-depth' settled: refuted (ruled out)");
    const rej = describeEvent(ev("planner.decision", "x", { decision: "rejected", reason: "active_probe_not_enabled", tool: "infra.tls", detail: "infra.tls is an active probe; the target has not opted in" }));
    expect(rej.headline).toBe("Rejected infra.tls: infra.tls is an active probe; the target has not opted in");
    expect(describeEvent(ev("planner.decision", "x", { decision: "model_retry", reason: "model call failed, retrying in 1s: no text", attempt: 1, error: "no text" })).lines.map((l) => l.label)).toEqual(["Attempt", "Error"]);
    expect(describeEvent(ev("planner.decision", "x", { decision: "explorer_no_work", why: "failed", assessment: "" })).headline).toBe("The exploration agent proposed no new work (failed)");
    const round = describeEvent(ev("planner.decision", "x", { decision: "explorer_no_work", why: "ok", assessment: "incomplete", empty_rounds: 1, max_empty_rounds: 3 }));
    expect(round.headline).toBe("The exploration agent proposed no new work (ok) (empty round 1 of 3)");
    expect(round.lines.map((l) => l.label)).toContain("Empty rounds");
    expect(describeEvent(ev("planner.decision", "x", { decision: "explorer_exhausted", why: "adequate", empty_rounds: 3, max_empty_rounds: 3 })).headline)
      .toBe("The exploration agent found no new avenues: completing (empty round 3 of 3)");
    expect(describeEvent(ev("planner.decision", "asking again", { decision: "explorer_ask_again", why: "ok" })).headline).toBe("Asking the exploration agent again");
  });
  it("describes triggers", () => {
    expect(triggerText({ kind: "wo_terminal", node_ids: ["a", "b"] })).toBe("work orders finished (2 nodes)");
    expect(triggerText("idle")).toBe("nothing left queued");
    expect(triggerText(undefined)).toBeNull();
  });
});

describe("work orders and tools", () => {
  it("never prints an empty result as 'done:'", () => {
    const e = ev("work_order.completed", "verify.cookies.flags done: ", { result_summary: "" });
    expect(describeEvent(e).headline).toBe("verify.cookies.flags done (no result summary recorded)");
    expect(eventTitle(e)).toBe("verify.cookies.flags done (no result summary recorded)");
  });
  it("shows tool args and results", () => {
    const s = describeEvent(ev("tool.started", "x started", { tool: "verify.headers.security", args: { finding_id: "f1", url: "https://t/", header: "hsts", expect: "absent", empty: "" } }));
    expect(s.headline).toBe("verify.headers.security started on https://t/");
    expect(s.lines.map((l) => l.label)).toEqual(["Tool", "Finding", "URL", "Header", "Expected"]);
    const ok = describeEvent(ev("tool.succeeded", "x", { tool: "discovery.crawl", result: { fetched: 8, endpoints: 8, failed: 0, frontier: 9, extra: [] } }));
    expect(ok.headline).toBe("discovery.crawl succeeded: fetched 8, endpoints 8, failed 0, frontier 9");
    expect(describeEvent(ev("tool.succeeded", "x", { tool: "verify.cors.policy", result: {} })).headline).toContain("no result details recorded");
  });
  it("explains failures", () => {
    const v = describeEvent(ev("work_order.failed", "x", { error: "connect_error", attempt: 1, will_retry: true }));
    expect(v.lines.map((l) => `${l.label}=${l.value}`)).toEqual(["Error=connect_error", "Attempt=1", "Will retry=yes"]);
  });
  it("describes created work orders with the reason", () => {
    const v = describeEvent(ev("work_order.created", "s", { kind: "verify", tool: "verify.headers.security", title: "Verify headers.security", reason: "needs a reproducible check", priority: 10 }));
    expect(v.headline).toBe("Verify headers.security");
    expect(v.lines).toContainEqual({ label: "Why", value: "needs a reproducible check", mono: false });
  });
});

describe("other kinds", () => {
  it("http.exchange, finding, observation, surface", () => {
    expect(labels(ev("http.exchange", "GET /a -> 200", { exchange_id: 4, method: "GET", url: "http://t/a", status_code: 200, duration_ms: 3, redirect_hop: 0 })))
      .toEqual(["Request", "Status", "Took", "Exchange"]);
    expect(describeEvent(ev("finding.verified", "v", { method: "refetch: header still absent", exchange_ids: [285, 289] })).lines[1].value).toBe("exchange #285, #289");
    const obs = describeEvent(ev("observation.recorded", "GET /x -> 200", { facts: { status: 200, links: 0, params: [], forms: 0, redirect_to: null } }));
    expect(obs.lines).toEqual([{ label: "Status", value: "200", mono: false }]);
    expect(describeEvent(ev("surface.updated", "s", { kind: "service", risk_score: null, changed: ["risk_factors", "edge"] })).lines[1]?.value).toBe("risk factors, edge");
  });
  it("llm.response lists hypotheses and tools", () => {
    const v = describeEvent(ev("llm.response", "cycle 1", { assessment: "incomplete", hypothesis_labels: ["a", "b"], action_tools: ["discovery.crawl"], trigger: "start" }));
    expect(v.lines.map((l) => `${l.label}=${l.value}`)).toEqual(["Assessment=incomplete", "Triggered by=run start", "Hypotheses=a, b", "Tools requested=discovery.crawl"]);
  });
  it("falls back to non-empty data fields", () => {
    expect(describeEvent(ev("log.warning", "w", { a: 1, b: [], c: "", d: { e: null } })).lines).toEqual([{ label: "a", value: "1" }]);
    expect(isEmptyValue({ x: [] })).toBe(true);
    expect(isEmptyValue(0)).toBe(false);
  });
});

describe("task output", () => {
  const w = "wo1";
  const rel = [
    ev("work_order.created", "c", {}, { work_order_id: w }),
    ev("tool.started", "s", { tool: "discovery.crawl", args: { url: "http://t/" } }, { work_order_id: w }),
    ev("http.exchange", "g", { method: "GET", url: "http://t/", status_code: 200 }, { work_order_id: w }),
    ev("http.exchange", "g", { method: "GET", url: "http://t/x", status_code: 404 }, { work_order_id: w }),
    ev("work_order.completed", "done", { result_summary: "crawled 2 pages" }, { work_order_id: w }),
    ev("tool.succeeded", "ok", { tool: "discovery.crawl", result: { fetched: 2, failed: 0 } }, { work_order_id: w }),
    ev("observation.recorded", "GET / -> 200", {}, { work_order_id: w }),
    ev("asset.discovered", "endpoint /x", {}, { work_order_id: w }),
    ev("finding.created", "c", { finding_id: "f", title: "Missing HSTS", severity: "low" }, { work_order_id: w }),
    ev("finding.verified", "verified: Missing HSTS", { finding_id: "f" }, { work_order_id: w }),
  ];
  it("gathers what the tool did and observed", () => {
    const o = taskOutput(rel)!;
    expect(o.tool).toBe("discovery.crawl");
    expect(o.args[0].value).toBe("http://t/");
    expect(o.requests.map((r) => r.status)).toEqual([200, 404]);
    expect(o.resultSummary).toBe("crawled 2 pages");
    expect(o.result.map((r) => r.label)).toEqual(["fetched", "failed"]);
    expect(o.observations).toEqual(["GET / -> 200"]);
    expect(o.assets).toBe(1);
    expect(o.findings).toEqual([{ title: "Missing HSTS", severity: "low", status: "verified" }]);
  });
  it("indexes by work order and returns null with nothing to show", () => {
    expect(indexByWorkOrder(rel).get(w)?.length).toBe(rel.length);
    expect(taskOutput([])).toBeNull();
  });
  it("caps long request lists", () => {
    const many = Array.from({ length: 40 }, () => ev("http.exchange", "g", { url: "http://t/", status_code: 200 }));
    const o = taskOutput(many)!;
    expect(o.requests.length).toBe(30);
    expect(o.requestsMore).toBe(10);
  });
});
