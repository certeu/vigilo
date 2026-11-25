import { describe, expect, it } from "vitest";
import type { GreyboxEvent } from "../events";
import {
  DEFAULT_FILTERS, DETAIL_H, ROW_H, computeWindow, filterEvents, formatData, indexOfSeq, isHintKind, kindStyle,
  nearestIndex, parseSeqParam, rowTop,
} from "./activityModel";

const ev = (seq: number, over: Partial<GreyboxEvent> = {}): GreyboxEvent => ({
  seq, run_id: "r", ts: "2026-11-20T10:00:00.123456Z", kind: "tool.started", level: "info", source: "agent",
  agent_id: "a1", agent_name: "checker-1", work_order_id: null, tool_call_id: null, summary: `summary ${seq}`,
  status: "ok", duration_ms: null, refs: {}, data: {}, ...over,
});

describe("filterEvents", () => {
  const list = [
    ev(1, { kind: "run.started", level: "info", agent_id: null, agent_name: null }),
    ev(2, { kind: "http.exchange", level: "debug" }),
    ev(3, { kind: "scope.blocked", level: "warning", summary: "Blocked http://evil.invalid/" }),
    ev(4, { kind: "tool.failed", level: "error", agent_id: "a2", agent_name: "checker-2" }),
  ];
  it("applies the minimum level (default hides debug)", () => {
    expect(filterEvents(list, DEFAULT_FILTERS).map((e) => e.seq)).toEqual([1, 3, 4]);
    expect(filterEvents(list, { ...DEFAULT_FILTERS, level: "warning" }).map((e) => e.seq)).toEqual([3, 4]);
    expect(filterEvents(list, { ...DEFAULT_FILTERS, level: "debug" })).toHaveLength(4);
  });
  it("filters by kind group, agent and case-insensitive text", () => {
    const all = { ...DEFAULT_FILTERS, level: "debug" };
    expect(filterEvents(list, { ...all, group: "tool" }).map((e) => e.seq)).toEqual([4]);
    expect(filterEvents(list, { ...all, agent: "-" }).map((e) => e.seq)).toEqual([1]);
    expect(filterEvents(list, { ...all, agent: "a2" }).map((e) => e.seq)).toEqual([4]);
    expect(filterEvents(list, { ...all, q: "EVIL" }).map((e) => e.seq)).toEqual([3]);
    expect(filterEvents(list, { ...all, q: "checker-2" }).map((e) => e.seq)).toEqual([4]);
  });
});

describe("windowing", () => {
  it("renders a small slice of 10k rows and keeps total height exact", () => {
    const w = computeWindow({ count: 10_000, expanded: [], scrollTop: 150_000, viewportH: 600 });
    expect(w.end - w.start).toBeLessThan(60);
    expect(w.padTop).toBe(w.start * ROW_H);
    expect(w.total).toBe(10_000 * ROW_H);
    expect(w.padTop + (w.end - w.start) * ROW_H + w.padBottom).toBe(w.total);
  });
  it("accounts for expanded rows", () => {
    expect(rowTop(5, [2, 9])).toBe(5 * ROW_H + DETAIL_H);
    const w = computeWindow({ count: 100, expanded: [2, 50], scrollTop: 0, viewportH: 300 });
    expect(w.total).toBe(100 * ROW_H + 2 * DETAIL_H);
    expect(w.start).toBe(0);
    expect(w.padTop + w.padBottom + [...Array(w.end - w.start).keys()].reduce((a, i) => a + ROW_H + ([2, 50].includes(w.start + i) ? DETAIL_H : 0), 0)).toBe(w.total);
  });
  it("handles the empty list", () => {
    expect(computeWindow({ count: 0, expanded: [], scrollTop: 0, viewportH: 500 })).toEqual({ start: 0, end: 0, padTop: 0, padBottom: 0, total: 0 });
  });
});

describe("helpers", () => {
  it("finds events by seq", () => {
    const l = [ev(3), ev(5), ev(9)];
    expect(indexOfSeq(l, 5)).toBe(1);
    expect(indexOfSeq(l, 4)).toBe(-1);
    expect(nearestIndex(l, 4)).toBe(1);
    expect(nearestIndex(l, 99)).toBe(2);
  });
  it("parses the seq deep link strictly", () => {
    expect(parseSeqParam("42")).toBe(42);
    for (const bad of [null, "", "0", "-3", "1.5", "abc", "1e3", "9".repeat(20)]) expect(parseSeqParam(bad)).toBeNull();
  });
  it("styles analyst hints distinctly and keeps other kinds generic", () => {
    expect(isHintKind("hint.added")).toBe(true);
    expect(kindStyle("hint.added")).toMatchObject({ label: "Analyst hint" });
    expect(kindStyle("hint.added").chip).toContain("hint-");
    expect(kindStyle("hint.replied").label).toBe("Agent replied");
    expect(kindStyle("hint.future").label).toBe("Analyst hint");
    expect(kindStyle("tool.started").label).toBe("tool.started");
  });
  it("formats data as plain JSON text and truncates huge payloads", () => {
    expect(formatData({ a: "<img src=x onerror=alert(1)>" })).toContain("<img src=x onerror=alert(1)>");
    expect(formatData("x".repeat(30_000)).length).toBeLessThan(20_100);
  });
});

import { eventFields as _ef, eventJson as _ej, findingEventInfo as _fi, graphNodeSearch as _gs } from "./activityModel";

describe("expanded event view", () => {
  it("turns data into bounded key/value rows", () => {
    const big = { a_key: "x".repeat(1000), n: 3, o: { z: 1 } };
    const { fields, hidden } = _ef(big);
    expect(fields[0].key).toBe("a key");
    expect(fields[0].value.length).toBeLessThan(410);
    expect(fields[2].value).toBe('{"z":1}');
    expect(hidden).toBe(0);
    expect(_ef(Object.fromEntries(Array.from({ length: 50 }, (_, i) => [`k${i}`, i]))).hidden).toBe(10);
  });
  it("copies full JSON", () => {
    expect(_ej({ data: { a: 1 } })).toBe('{\n  "a": 1\n}');
  });
  it("extracts finding title and node", () => {
    expect(_fi({ kind: "tool.started", summary: "x", data: {}, refs: {} })).toBeNull();
    expect(_fi({ kind: "finding.created", summary: "candidate finding: Missing CSP (low)", data: { title: "Missing CSP" }, refs: { node_ids: ["n1"] } }))
      .toEqual({ title: "Missing CSP", nodeId: "n1" });
    expect(_fi({ kind: "finding.rejected", summary: "rejected: Open redirect (not reproducible)", data: {}, refs: {} }))
      .toEqual({ title: "Open redirect", nodeId: null });
  });
  it("builds the graph link", () => {
    expect(_gs("a b")).toBe("?tab=exploration&node=a%20b");
  });
});
