import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { cycleOf, explorerDetail, formatTokens, llmMeta, llmTitle, parseTodolist } from "./explorerView";
import { eventTitle, kindStyle } from "./run/activityModel";
import { ReasoningSection } from "./graph/NodeDetails";
import { statusCategory } from "./graph/encoding";
import type { ExplorationNode } from "./graph/types";

const resp = (data: Record<string, unknown>, summary = "explorer reasoning cycle 2: incomplete") =>
  ({ kind: "llm.response", summary, data });

describe("explorer events", () => {
  it("titles each llm.* kind", () => {
    expect(llmTitle({ kind: "llm.request", summary: "x", data: {} })).toBe("Explorer thinking…");
    expect(llmTitle(resp({ assessment: "incomplete", hypotheses: 3, actions: 2 }))).toBe("Explorer cycle 2: incomplete — 3 hypotheses, 2 actions");
    expect(llmTitle(resp({ assessment: "complete", hypotheses: 1, actions: 1 }))).toContain("1 hypothesis, 1 action");
    expect(llmTitle({ kind: "llm.failed", summary: "s", data: { error: "timeout" } })).toBe("Explorer call failed: timeout");
    expect(llmTitle({ kind: "http.request", summary: "s", data: {} })).toBeNull();
  });
  it("falls back to the summary for other kinds", () => {
    expect(eventTitle({ kind: "run.started", summary: "hello", data: {} })).toBe("hello");
  });
  it("labels and styles the chips", () => {
    expect(kindStyle("llm.response").label).toBe("Explorer");
    expect(kindStyle("llm.failed").label).toBe("Explorer failed");
  });
  it("formats model and tokens subtly", () => {
    expect(llmMeta({ model: "m1", tokens: 12345, trigger: "idle" })).toBe("m1 · 12k tokens · trigger: idle");
    expect(llmMeta({})).toBeNull();
    expect(formatTokens(950)).toBe("950");
    expect(formatTokens(1500)).toBe("1.5k");
  });
  it("parses cycle numbers and tolerates bad todolists", () => {
    expect(cycleOf("explorer reasoning cycle 12: done")).toBe(12);
    expect(cycleOf("nope")).toBeNull();
    expect(parseTodolist("x")).toEqual([]);
    expect(parseTodolist([{ step: "a", status: "done" }, { step: "b", status: "weird" }, 5, "c"]))
      .toEqual([{ step: "a", status: "done" }, { step: "b", status: "pending" }, { step: "c", status: "pending" }]);
  });
  it("accepts counts (events) and label lists (graph nodes)", () => {
    expect(explorerDetail({ hypotheses: ["a", "b"], actions: 4 })).toMatchObject({ hypotheses: 2, actions: 4 });
  });
});

const node = (status: string): ExplorationNode => ({
  id: "n1", kind: "reasoning", key: "reasoning|1", label: "Explorer cycle 1", status, version: 1,
  data: {
    reasoning: "The login form looks injectable <b>x</b>", model: "claude-x", tokens: 2400, trigger: "idle",
    todolist: [{ step: "Probe login", status: "in_progress" }, { step: "Map API", status: "done" }],
  },
} as unknown as ExplorationNode);

describe("reasoning node", () => {
  it("shows reasoning text (escaped), todolist statuses, model, tokens, trigger", () => {
    const html = renderToString(createElement(ReasoningSection, { node: node("active") }));
    expect(html).toContain("The login form looks injectable &lt;b&gt;x&lt;/b&gt;");
    expect(html).toContain("in progress");
    expect(html).toContain("Probe login");
    expect(html).toContain("claude-x");
    expect(html).toContain("2.4k");
    expect(html).toContain("idle");
    expect(html).not.toContain("Superseded");
  });
  it("marks superseded cycles and mutes them", () => {
    expect(renderToString(createElement(ReasoningSection, { node: node("superseded") }))).toContain("Superseded by a later");
    expect(statusCategory("reasoning", "superseded")).toBe("skipped");
    expect(statusCategory("reasoning", "active")).toBe("running");
  });
});
