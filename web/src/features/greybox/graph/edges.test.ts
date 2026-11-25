import { describe, expect, it } from "vitest";
import { EMPTY_GRAPH, deriveView, mergeGraph, type ViewOptions } from "./model";
import {
  edgeLabel, edgeLabelVisible, edgeTooltip, edgeVisible, mergeEdges, reasoningChain, withTimeline, LABEL_ZOOM,
} from "./edges";
import { currentReasoning, isThinking, nodeVisual, phaseOf } from "./nodeState";
import { layeredLayout, incrementalLayout } from "./layout";
import { CATEGORY_STYLE, STATUS_CATEGORIES } from "./encoding";
import { NODE_KINDS, type ExplorationEdge, type ExplorationGraphResponse, type ExplorationNode } from "./types";
import small from "./fixtures/smallRun.json";
import large from "./fixtures/largeRun.json";

type Fx = { nodes: Partial<ExplorationNode>[]; edges: ExplorationEdge[] };
const load = (fx: Fx) => {
  const resp = {
    version: 99, since_version: 0, full: true, truncated: false, total_nodes: fx.nodes.length, total_edges: fx.edges.length,
    nodes: fx.nodes, edges: fx.edges,
  } as ExplorationGraphResponse;
  return mergeGraph(EMPTY_GRAPH, resp, 0).state;
};
const opts: ViewOptions = {
  kinds: new Set(NODE_KINDS), categories: new Set(STATUS_CATEGORIES), agents: new Set(), collapsed: new Set(),
  foldActions: false, focus: null, cap: 5000, siblingLimit: 0, expandedGroups: new Map(),
};
const e = (id: string, src: string, dst: string, rel: ExplorationEdge["rel"]) => ({ id, src, dst, rel });

describe("mergeEdges", () => {
  it("merges antiparallel relations (lead spawned work order / work order investigated lead) into one", () => {
    const m = mergeEdges([e("a", "L", "W", "spawned"), e("b", "W", "L", "investigated")]);
    expect(m).toHaveLength(1);
    expect(m[0]).toMatchObject({ src: "L", dst: "W", rel: "spawned", secondary: false });
    expect(m[0].rels.map((r) => r.rel)).toEqual(["spawned", "investigated"]);
    expect(edgeLabel(m[0])).toBe("spawned +1");
  });

  it("keeps the most important relation's direction and marks evidence-only pairs secondary", () => {
    const m = mergeEdges([e("c", "O", "L", "contradicts"), e("s", "O", "L", "supports")]);
    expect(m).toHaveLength(1);
    expect(m[0]).toMatchObject({ rel: "contradicts", secondary: true });
  });

  it("lists every relation in the tooltip", () => {
    const [m] = mergeEdges([e("a", "L", "W", "spawned"), e("b", "W", "L", "investigated")]);
    expect(edgeTooltip(m, (id) => id)).toBe("L spawned W\nW investigates L");
  });

  it("real runs: at most one edge per node pair after merging", () => {
    for (const fx of [small, large]) {
      const st = load(fx as unknown as Fx);
      const view = deriveView(st, opts);
      const merged = mergeEdges(view.edges);
      const pairs = new Set(merged.map((m) => [m.src, m.dst].sort().join("|")));
      expect(pairs.size).toBe(merged.length);
      expect(merged.length).toBeLessThan(view.edges.length);
    }
  });
});

describe("timeline", () => {
  it("chains reasoning cycles in order and drops redundant objective edges", () => {
    const st = load(large as unknown as Fx);
    const view = deriveView(st, opts);
    const chain = reasoningChain(view.nodes);
    expect(chain.length).toBeGreaterThan(2);
    const withT = withTimeline(view.edges, view.nodes);
    const timeline = withT.filter((x) => x.id.startsWith("timeline:"));
    expect(timeline).toHaveLength(chain.length - 1);
    expect(timeline[0]).toMatchObject({ src: chain[0].id, dst: chain[1].id });
    const objToCycles = withT.filter((x) => st.nodes.get(x.src)?.kind === "objective" && st.nodes.get(x.dst)?.kind === "reasoning");
    expect(objToCycles).toHaveLength(1);
    expect(objToCycles[0].dst).toBe(chain[0].id);
  });

  it("does nothing with a single cycle", () => {
    const view = deriveView(load(small as unknown as Fx), opts);
    expect(withTimeline(view.edges, view.nodes)).toHaveLength(view.edges.length);
  });

  it("lays reasoning cycles out left to right in order", () => {
    const view = deriveView(load(large as unknown as Fx), opts);
    const edges = mergeEdges(withTimeline(view.edges, view.nodes)).filter((m) => !m.secondary);
    const pos = layeredLayout(view.nodes.map((n) => n.id), edges);
    const chain = reasoningChain(view.nodes);
    for (let i = 1; i < chain.length; i++) expect(pos.get(chain[i].id)!.x).toBeGreaterThan(pos.get(chain[i - 1].id)!.x);
    const obj = view.nodes.find((n) => n.kind === "objective")!;
    expect(pos.get(obj.id)!.x).toBeLessThan(pos.get(chain[0].id)!.x);
  });

  it("incremental layout keeps existing positions when nodes arrive", () => {
    const view = deriveView(load(small as unknown as Fx), opts);
    const edges = mergeEdges(view.edges).filter((m) => !m.secondary);
    const ids = view.nodes.map((n) => n.id);
    const first = layeredLayout(ids.slice(0, 5), edges);
    const next = incrementalLayout(ids, edges, first);
    for (const [id, p] of first) expect(next.get(id)).toEqual(p);
    expect(next.size).toBe(ids.length);
  });
});

describe("label and visibility policy", () => {
  const base = { touchesSelected: false, hovered: false, zoom: 0.8, edgeCount: 100 };
  it("hides labels by default", () => expect(edgeLabelVisible(base)).toBe(false));
  it("shows on hover or selection", () => {
    expect(edgeLabelVisible({ ...base, hovered: true })).toBe(true);
    expect(edgeLabelVisible({ ...base, touchesSelected: true })).toBe(true);
  });
  it("shows at high zoom only on small graphs", () => {
    expect(edgeLabelVisible({ ...base, zoom: LABEL_ZOOM, edgeCount: 20 })).toBe(true);
    expect(edgeLabelVisible({ ...base, zoom: LABEL_ZOOM, edgeCount: 200 })).toBe(false);
  });
  it("evidence links need the toggle or a selected endpoint", () => {
    const [ev] = mergeEdges([e("c", "O", "L", "contradicts")]);
    const [sp] = mergeEdges([e("s", "L", "W", "spawned")]);
    expect(edgeVisible(ev, false, null)).toBe(false);
    expect(edgeVisible(ev, true, null)).toBe(true);
    expect(edgeVisible(ev, false, "L")).toBe(true);
    expect(edgeVisible(ev, false, "X")).toBe(false);
    expect(edgeVisible(sp, false, null)).toBe(true);
  });
});

describe("state styling", () => {
  const n = (kind: ExplorationNode["kind"], status: ExplorationNode["status"], id = "n1", key = "1"): ExplorationNode => ({
    id, kind, key, label: "x", status, agent_id: null, work_order_id: null, finding_id: null, asset_id: null,
    event_seq: null, data: {}, version: 1,
  });
  const live = { runActive: true, currentReasoningId: null, thinking: false };

  it("maps statuses to phases", () => {
    expect(phaseOf(n("work_order", "running"))).toBe("running");
    expect(phaseOf(n("work_order", "pending"))).toBe("pending");
    expect(phaseOf(n("work_order", "done"))).toBe("done");
    expect(phaseOf(n("action", "failed"))).toBe("failed");
    expect(phaseOf(n("lead", "refuted"))).toBe("muted");
    expect(phaseOf(n("reasoning", "superseded"))).toBe("muted");
  });

  it("running pulses only while the run is live", () => {
    expect(nodeVisual(n("work_order", "running"), live)).toMatchObject({ pulse: true });
    expect(nodeVisual(n("work_order", "running"), live).className).toContain("gx-state-running");
    expect(nodeVisual(n("work_order", "running"), { ...live, runActive: false })).toMatchObject({ pulse: false, className: "" });
  });

  it("pending, done, failed, muted are distinct and muted stays readable", () => {
    expect(nodeVisual(n("work_order", "pending"), live).className).toContain("gx-state-pending");
    expect(nodeVisual(n("work_order", "done"), live)).toMatchObject({ pulse: false, className: "" });
    expect(nodeVisual(n("action", "failed"), live).className).toContain("gx-state-failed");
    const muted = nodeVisual(n("lead", "refuted"), live).className;
    expect(muted).toContain("gx-state-muted");
    for (const c of ["rejected", "skipped"] as const) {
      expect(Number(/opacity-(\d+)/.exec(CATEGORY_STYLE[c].body)![1])).toBeGreaterThanOrEqual(85);
    }
  });

  it("current cycle is the latest active one and thinks when idle", () => {
    const nodes = [n("reasoning", "superseded", "r1", "1"), n("reasoning", "superseded", "r2", "2"), n("reasoning", "active", "r10", "10"), n("reasoning", "active", "r3", "3")];
    const cur = currentReasoning(nodes)!;
    expect(cur.id).toBe("r10");
    const v = nodeVisual(cur, { runActive: true, currentReasoningId: cur.id, thinking: true });
    expect(v).toMatchObject({ current: true, thinking: true, pulse: true });
    expect(nodeVisual(nodes[0], { runActive: true, currentReasoningId: cur.id, thinking: true }).current).toBe(false);
  });

  it("thinking: explicit llm flag wins, else inferred from in-flight work", () => {
    const busy = [n("work_order", "running")];
    const idle = [n("work_order", "done")];
    expect(isThinking(busy, true)).toBe(false);
    expect(isThinking(idle, true)).toBe(true);
    expect(isThinking(idle, false)).toBe(false);
    expect(isThinking(busy, true, true)).toBe(true);
    expect(isThinking(idle, true, false)).toBe(false);
  });

  it("real run: the single active cycle is current", () => {
    const st = load(small as unknown as Fx);
    expect(currentReasoning(st.nodes.values())?.status).toBe("active");
  });
});
