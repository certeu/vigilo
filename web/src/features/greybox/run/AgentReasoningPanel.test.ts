import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { AgentReasoningView } from "./AgentReasoningPanel";
import { explorerLive } from "../explorerView";
import { layeredLayout } from "../graph/layout";
import { NO_MODEL_MESSAGE, NoModelNotice, startErrorMessage } from "../NewGreyboxForm";
import { ApiError } from "../../../api/client";
import type { GreyboxEvent } from "../events";

let seq = 0;
const ev = (kind: string, summary: string, data: Record<string, unknown> = {}): GreyboxEvent =>
  ({ seq: ++seq, kind, summary, data, level: "info", agent_id: null, agent_name: null } as unknown as GreyboxEvent);
const response = (cycle: number) =>
  ev("llm.response", `explorer reasoning cycle ${cycle}: incomplete`, {
    cycle, reasoning: "Login <i>form</i> found", assessment: "incomplete", hypotheses: 2, actions: 3,
    todolist: [{ step: "Probe login", status: "in_progress" }], model: "claude-x", tokens: 2400, trigger: "idle",
  });

describe("explorerLive", () => {
  it("is idle without llm events", () => {
    expect(explorerLive([ev("run.started", "x")]).phase).toBe("idle");
  });
  it("shows the latest completed cycle", () => {
    const l = explorerLive([response(1), response(2)]);
    expect(l.phase).toBe("responded");
    expect(l.cycle).toBe(2);
    expect(l.last?.todolist[0].status).toBe("in_progress");
  });
  it("is thinking after a request, keeping the previous cycle visible", () => {
    const l = explorerLive([response(1), ev("llm.request", "explorer reasoning cycle 2 (idle)", { cycle: 2 })]);
    expect(l.phase).toBe("thinking");
    expect(l.cycle).toBe(2);
    expect(l.last?.cycle).toBe(1);
  });
  it("reports failures and the scheduler decision", () => {
    const l = explorerLive([response(1), ev("llm.failed", "failed", { error: "timeout" }), ev("planner.decision", "w", { decision: "waiting_for_explorer" })]);
    expect(l.phase).toBe("failed");
    expect(l.error).toBe("timeout");
    expect(l.decision).toContain("waiting");
  });
  it("ignores decisions older than the latest llm event", () => {
    expect(explorerLive([ev("planner.decision", "w", { decision: "explorer_adequate" }), response(3)]).decision).toBeNull();
  });
  it("shows the empty-round and completion decisions", () => {
    expect(explorerLive([response(1), ev("planner.decision", "w", { decision: "explorer_no_work" })]).decision).toContain("asking again");
    expect(explorerLive([response(1), ev("planner.decision", "w", { decision: "explorer_exhausted" })]).decision).toContain("completing");
  });
});

describe("AgentReasoningView", () => {
  const html = (events: GreyboxEvent[], active = true) =>
    renderToString(createElement(MemoryRouter, null, createElement(AgentReasoningView, { live: explorerLive(events), active })));
  it("renders reasoning (escaped), todo status, counts, model and tokens", () => {
    const h = html([response(2)]);
    expect(h).toContain("Cycle 2");
    expect(h).toContain("Login &lt;i&gt;form&lt;/i&gt; found");
    expect(h).toContain("in progress");
    expect(h).toContain("2 hypotheses");
    expect(h).toContain("3 actions");
    expect(h).toContain("claude-x");
    expect(h).toContain("2.4k tokens");
  });
  it("shows waiting and thinking states", () => {
    expect(html([])).toContain("Waiting for the first reasoning cycle");
    expect(html([ev("llm.request", "cycle 1", { cycle: 1 })])).toContain("Thinking");
  });
});

describe("no-model blocking", () => {
  it("shows the config hint", () => {
    expect(renderToString(createElement(NoModelNotice))).toContain("deploy/config-reference.md");
    expect(NO_MODEL_MESSAGE).toContain("No AI model configured");
  });
  it("surfaces the server message on 409 without run_id and 422", () => {
    expect(startErrorMessage(new ApiError(409, "No AI model configured", null, { detail: "x" }))).toBe("No AI model configured");
    expect(startErrorMessage(new ApiError(409, "active", null, { run_id: "r" }))).toContain("already active");
    expect(startErrorMessage(new ApiError(422, "No model", null, null))).toContain("No model");
  });
});

describe("exploration graph spine", () => {
  it("ranks objective -> reasoning -> lead -> work order -> action -> observation left to right", () => {
    const ids = ["o", "r", "l", "w", "a", "b"];
    const edges = [
      { src: "o", dst: "r", rel: "spawned" }, { src: "r", dst: "l", rel: "spawned" }, { src: "r", dst: "w", rel: "spawned" },
      { src: "w", dst: "l", rel: "investigated" }, { src: "w", dst: "a", rel: "executed" }, { src: "a", dst: "b", rel: "observed" },
    ] as const;
    const p = layeredLayout(ids, edges);
    const x = (i: string) => p.get(i)!.x;
    expect(x("o")).toBeLessThan(x("r"));
    expect(x("r")).toBeLessThan(x("l"));
    expect(x("r")).toBeLessThan(x("w"));
    expect(x("w")).toBeLessThan(x("a"));
    expect(x("a")).toBeLessThan(x("b"));
  });
});
