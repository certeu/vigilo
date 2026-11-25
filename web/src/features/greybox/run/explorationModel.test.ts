import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import type { GreyboxEvent } from "../events";
import { buildCycles, explorationCounts, latestTodolist, schedulerNotes } from "./explorationModel";
import { CycleTimeline } from "./OverviewTab";

let seq = 0;
const ev = (kind: string, data: Record<string, unknown>, summary = ""): GreyboxEvent => ({
  seq: ++seq, run_id: "r", ts: "2026-01-01T00:00:00Z", kind, level: "info", source: "agent", agent_id: null, agent_name: null,
  work_order_id: null, tool_call_id: null, summary, status: "ok", duration_ms: null, refs: {}, data,
});
const resp = (cycle: number, extra: Record<string, unknown> = {}) =>
  ev("llm.response", { cycle, reasoning: `r${cycle}`, assessment: "incomplete", hypotheses: 1, actions: 2, hypothesis_labels: ["h"], action_tools: ["discovery.crawl", "discovery.crawl"], trigger: "start", todolist: [{ step: `s${cycle}`, status: "done" }], ...extra });

describe("buildCycles", () => {
  it("collapses retries of a failed call into one cycle with a failure count", () => {
    const cycles = buildCycles([
      ev("llm.request", { cycle: 1, reason: "delta" }),
      ev("llm.failed", { error: "boom" }),
      ev("llm.request", { cycle: 1, reason: "delta" }),
      resp(1),
      ev("llm.request", { cycle: 2, reason: "idle" }),
    ]);
    expect(cycles.map((c) => [c.cycle, c.state, c.failures])).toEqual([[1, "done", 1], [2, "thinking", 0]]);
    expect(cycles[0]).toMatchObject({ assessment: "incomplete", hypotheses: 1, actions: 2, trigger: "run start", reasoning: "r1" });
    expect(cycles[1].trigger).toBe("nothing left queued");
  });
  it("keeps a failed cycle failed with its error", () => {
    const c = buildCycles([ev("llm.request", { cycle: 3, reason: "delta" }), ev("llm.failed", { error: "SSL" })]);
    expect(c[0]).toMatchObject({ state: "failed", error: "SSL" });
  });
});

describe("todolist, notes, counts", () => {
  const events = [
    ev("planner.decision", { decision: "dispatch", reason: "explorer: go", work_order_ids: ["a"] }),
    resp(1),
    ev("planner.decision", { decision: "settle_lead", reason: "lead 'x' confirmed (reported)" }),
    ev("planner.decision", { decision: "waiting_for_explorer", reason: "waiting", grace_s: 5 }),
    resp(2, { todolist: [{ step: "latest", status: "pending" }] }),
    ev("work_order.created", {}), ev("tool.succeeded", {}), ev("finding.created", {}), ev("finding.verified", {}), ev("llm.failed", {}),
  ];
  it("takes the newest todo list", () => {
    expect(latestTodolist(events)).toEqual([{ step: "latest", status: "pending" }]);
    expect(latestTodolist([])).toEqual([]);
  });
  it("skips plain dispatch and waiting decisions in the notes", () => {
    expect(schedulerNotes(events).map((n) => n.text)).toEqual(["Lead 'x' settled: confirmed (reported)"]);
  });
  it("counts", () => {
    expect(explorationCounts(events)).toEqual({ cycles: 2, failedCalls: 1, workOrdersQueued: 1, toolsRun: 1, findingsCandidate: 1, findingsVerified: 1 });
  });
});

describe("CycleTimeline", () => {
  const html = (cycles: ReturnType<typeof buildCycles>, active = true) =>
    renderToString(createElement(MemoryRouter, null, createElement(CycleTimeline, { cycles, active }))).replace(/<!-- -->/g, "");
  it("renders cycles with trigger, assessment and counts and no fixed phases", () => {
    const out = html(buildCycles([resp(1), ev("llm.request", { cycle: 2, reason: "delta" })]));
    expect(out).toContain("Cycle 1");
    expect(out).toContain("after run start");
    expect(out).toContain("assessment: incomplete");
    expect(out).toContain("1 hypothesis");
    expect(out).toContain("2 actions");
    expect(out).toContain("thinking");
    expect(out).not.toMatch(/Verification|Reporting/);
  });
  it("explains the empty state", () => {
    expect(html([], true)).toContain("Waiting for the exploration agent");
    expect(html([], false)).toContain("No reasoning cycle");
  });
});
