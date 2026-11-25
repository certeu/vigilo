import { describe, expect, it } from "vitest";
import { defaultViewFor, deriveView, EMPTY_GRAPH, findingsCentred, LARGE_GRAPH_NODES, expireMarks, mergeGraph, searchNodes, type ViewOptions } from "./model";
import { computeFit, MIN_READABLE_ZOOM, incrementalLayout, layeredLayout, NODE_H, NODE_W } from "./layout";
import { STATUS_CATEGORIES } from "./encoding";
import { NODE_KINDS, type ExplorationGraphResponse } from "./types";
import { buildLargeRun, buildStoryRun } from "./dev/syntheticRun";

const opts = (o: Partial<ViewOptions> = {}): ViewOptions => ({
  kinds: new Set(NODE_KINDS),
  categories: new Set(STATUS_CATEGORIES),
  agents: new Set(),
  collapsed: new Set(),
  foldActions: false,
  focus: null,
  cap: 5000,
  siblingLimit: 0,
  expandedGroups: new Map(),
  ...o,
});

function replay(run = buildStoryRun(), upTo = run.v) {
  let st = mergeGraph(EMPTY_GRAPH, run.respond(1, 0, 5000), 0).state;
  for (let v = 2; v <= upTo; v++) st = mergeGraph(st, run.respond(v, st.version, 5000), v).state;
  return { run, st };
}

describe("mergeGraph", () => {
  it("deltas converge to the full snapshot", () => {
    const { run, st } = replay();
    const full = mergeGraph(EMPTY_GRAPH, run.respond(run.v, 0, 5000), 0).state;
    expect(st.version).toBe(run.v);
    expect([...st.nodes.keys()].sort()).toEqual([...full.nodes.keys()].sort());
    for (const [id, n] of full.nodes) expect(st.nodes.get(id)).toEqual(n);
    expect([...st.edges.keys()].sort()).toEqual([...full.edges.keys()].sort());
  });

  it("marks new and changed nodes after the first load only", () => {
    const run = buildStoryRun();
    const a = mergeGraph(EMPTY_GRAPH, run.respond(1, 0, 5000), 100);
    expect(a.state.fresh.size).toBe(0);
    const b = mergeGraph(a.state, run.respond(2, 1, 5000), 200);
    expect(b.added).toContain("act-crawl");
    expect(b.updated).toContain("wo-crawl");
    expect(b.state.fresh.get("act-crawl")).toBe(200);
    expect(b.state.changed.get("wo-crawl")).toBe(200);
    expect(expireMarks(b.state, 200 + 10_000, 6_000).fresh.size).toBe(0);
  });

  it("ignores stale copies and out-of-order responses", () => {
    const run = buildStoryRun();
    const late = mergeGraph(EMPTY_GRAPH, run.respond(5, 0, 5000), 0).state;
    const old: ExplorationGraphResponse = run.respond(2, 1, 5000);
    const after = mergeGraph(late, old, 1).state;
    expect(after).toBe(late);
    const mixed = mergeGraph(late, { ...run.respond(5, 4, 5000), nodes: [...run.respond(2, 0, 5000).nodes] }, 1).state;
    expect(mixed.nodes.get("wo-crawl")?.status).toBe("done");
  });

  it("reports truncation", () => {
    const run = buildStoryRun();
    const r = run.respond(run.v, 0, 5);
    expect(r.truncated).toBe(true);
    const st = mergeGraph(EMPTY_GRAPH, r, 0).state;
    expect(st.truncated).toBe(true);
    expect(st.totalNodes).toBeGreaterThan(5);
  });
});

describe("deriveView", () => {
  it("filters by kind and status", () => {
    const { st } = replay();
    const v = deriveView(st, opts({ kinds: new Set(["finding"]) }));
    expect(v.nodes.every((n) => n.kind === "finding")).toBe(true);
    const verified = deriveView(st, opts({ categories: new Set(["verified"]) }));
    expect(verified.nodes.map((n) => n.id).sort()).toEqual(["f-xss", "lead-q"]);
  });

  it("collapses a branch and counts what it hides", () => {
    const { st } = replay();
    const v = deriveView(st, opts({ collapsed: new Set(["wo-crawl"]) }));
    const ids = new Set(v.nodes.map((n) => n.id));
    expect(ids.has("wo-crawl")).toBe(true);
    expect(ids.has("act-crawl")).toBe(false);
    expect(ids.has("obs-search")).toBe(false);
    expect(v.hiddenBelow.get("wo-crawl")).toBeGreaterThan(2);
    // obs-hdr is reachable through wo-fp, so collapsing wo-crawl keeps f-hdr.
    expect(ids.has("f-hdr")).toBe(true);
  });

  it("folds actions into work orders with synthetic edges", () => {
    const { st } = replay();
    const v = deriveView(st, opts({ foldActions: true }));
    expect(v.nodes.some((n) => n.kind === "action")).toBe(false);
    expect(v.foldedActions.get("wo-crawl")).toEqual({ succeeded: 1 });
    expect(v.edges.some((e) => e.src === "wo-crawl" && e.dst === "obs-search" && e.folded)).toBe(true);
  });

  it("focus keeps the neighbourhood only", () => {
    const { st } = replay();
    const v = deriveView(st, opts({ focus: { id: "f-xss", hops: 1 } }));
    expect(v.nodes.map((n) => n.id).sort()).toEqual(["act-vxss", "def-xss", "f-xss", "obs-xss", "wo-vxss"].sort());
  });

  it("caps large graphs, keeping important kinds", () => {
    const run = buildLargeRun(3000);
    const st = mergeGraph(EMPTY_GRAPH, run.respond(run.v, 0, 5000), 0).state;
    const v = deriveView(st, opts({ cap: 1500 }));
    expect(v.nodes.length).toBe(1500);
    expect(v.capped).toBe(st.nodes.size - 1500);
    expect(v.nodes.some((n) => n.kind === "objective")).toBe(true);
    expect(v.nodes.filter((n) => n.kind === "finding").length).toBe([...st.nodes.values()].filter((n) => n.kind === "finding").length);
  });
});

describe("sibling groups", () => {
  it("folds children past the limit into a group and expands by step", () => {
    const run = buildLargeRun(300);
    const st = mergeGraph(EMPTY_GRAPH, run.respond(run.v, 0, 5000), 0).state;
    const v = deriveView(st, opts({ siblingLimit: 20 }));
    const wos = v.nodes.filter((n) => n.kind === "work_order");
    expect(wos.length).toBe(20);
    expect(v.groups).toHaveLength(1);
    expect(v.groups[0].parent).toBe("obj");
    expect(v.groups[0].hidden + 20).toBe(v.groups[0].total);
    // descendants of folded work orders are hidden too
    expect(v.nodes.length).toBeLessThan(80);
    // failed work orders are pinned into the visible slice
    expect(wos.some((n) => n.status === "failed")).toBe(true);
    const more = deriveView(st, opts({ siblingLimit: 20, expandedGroups: new Map([["obj|work_order", 40]]) }));
    expect(more.nodes.filter((n) => n.kind === "work_order").length).toBe(40);
  });
});

describe("searchNodes", () => {
  it("matches label, status and agent name", () => {
    const { st } = replay();
    expect(searchNodes(st.nodes.values(), "xss", st.agents)).toContain("f-xss");
    expect(searchNodes(st.nodes.values(), "verifier-1", st.agents)).toContain("act-vxss");
    expect(searchNodes(st.nodes.values(), "  ", st.agents)).toEqual([]);
  });
});

describe("layout", () => {
  const overlaps = (ps: { x: number; y: number }[]) => {
    for (let i = 0; i < ps.length; i++)
      for (let j = i + 1; j < ps.length; j++)
        if (Math.abs(ps[i].x - ps[j].x) < NODE_W && Math.abs(ps[i].y - ps[j].y) < NODE_H) return true;
    return false;
  };

  it("keeps existing positions and places new nodes right of their parent without overlap", () => {
    const run = buildStoryRun();
    let st = mergeGraph(EMPTY_GRAPH, run.respond(4, 0, 5000), 0).state;
    let v = deriveView(st, opts());
    let pos = incrementalLayout(v.nodes.map((n) => n.id), v.edges, new Map());
    const before = new Map(pos);
    for (let k = 5; k <= run.v; k++) {
      st = mergeGraph(st, run.respond(k, st.version, 5000), k).state;
      v = deriveView(st, opts());
      pos = incrementalLayout(v.nodes.map((n) => n.id), v.edges, pos);
    }
    for (const [id, p] of before) expect(pos.get(id)).toEqual(p);
    expect(pos.get("lead-q")!.x).toBeGreaterThan(pos.get("obs-search")!.x);
    expect(overlaps(v.nodes.map((n) => pos.get(n.id)!))).toBe(false);
  });

  it("layered layout places every node", () => {
    const { st } = replay();
    const v = deriveView(st, opts());
    const pos = layeredLayout(v.nodes.map((n) => n.id), v.edges);
    expect(pos.size).toBe(v.nodes.length);
    expect(overlaps([...pos.values()])).toBe(false);
  });
});

describe("default view at scale", () => {
  it("is the plain view up to the threshold and folded + findings-centred above it", () => {
    expect(defaultViewFor(LARGE_GRAPH_NODES)).toEqual({ foldActions: false, centred: false });
    expect(defaultViewFor(LARGE_GRAPH_NODES + 1)).toEqual({ foldActions: true, centred: true });
    expect(defaultViewFor(93, 100).centred).toBe(false);
  });

  it("findings-centred subset keeps findings, leads, hints, defenses and one hop", () => {
    const { st } = replay();
    const set = findingsCentred(st.nodes, st.edges.values(), 1)!;
    expect(set).not.toBeNull();
    for (const n of st.nodes.values()) if (["finding", "lead", "hint", "defense"].includes(n.kind)) expect(set.has(n.id)).toBe(true);
    expect(set.size).toBeLessThanOrEqual(st.nodes.size);
    const v = deriveView(st, opts({ only: set }));
    expect(v.nodes.every((n) => set.has(n.id))).toBe(true);
    // Folded + centred never shows an action.
    expect(deriveView(st, opts({ only: set, foldActions: true })).nodes.some((n) => n.kind === "action")).toBe(false);
  });

  it("returns null without any seed so the caller shows everything", () => {
    expect(findingsCentred(new Map(), [], 1)).toBeNull();
  });
});

describe("computeFit", () => {
  const grid = (n: number) => {
    const pos = new Map<string, { x: number; y: number }>();
    for (let i = 0; i < n; i++) pos.set(`n${i}`, { x: 0, y: i * (NODE_H + 18) });
    return { ids: [...pos.keys()], pos };
  };
  const size = { width: 1200, height: 520 };

  it("fits a small graph and may zoom up to 1", () => {
    const { ids, pos } = grid(2);
    const f = computeFit(ids, pos, size)!;
    expect(f.clamped).toBe(false);
    expect(f.zoom).toBeLessThanOrEqual(1);
    expect(f.zoom).toBeGreaterThanOrEqual(MIN_READABLE_ZOOM);
  });

  it("never shrinks below the readable zoom and anchors top-left when the graph is too tall", () => {
    const { ids, pos } = grid(60);
    const f = computeFit(ids, pos, size)!;
    expect(f.clamped).toBe(true);
    expect(f.zoom).toBe(MIN_READABLE_ZOOM);
    expect(f.y).toBeCloseTo(size.height * 0.08);
  });

  it("returns null with nothing to fit or no canvas size", () => {
    expect(computeFit([], new Map(), size)).toBeNull();
    const { ids, pos } = grid(1);
    expect(computeFit(ids, pos, { width: 0, height: 0 })).toBeNull();
  });
});
