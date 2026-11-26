// Pure exploration-graph model: delta merge, derived view (filters, collapse,
// folding, focus, cap) and search. No React, no layout library: unit-tested.
import type {
  ExplorationEdge, ExplorationEdgeRel, ExplorationGraphResponse, ExplorationNode, ExplorationNodeKind,
} from "./types";
import { statusCategory, type StatusCategory } from "./encoding";

export interface GraphState {
  /** Graph version of the last merged response (0 = nothing loaded). */
  version: number;
  nodes: ReadonlyMap<string, ExplorationNode>;
  edges: ReadonlyMap<string, ExplorationEdge>;
  /** Node id -> client time (ms) it first appeared after the initial snapshot. */
  fresh: ReadonlyMap<string, number>;
  /** Node id -> client time (ms) its status last changed in a delta. */
  changed: ReadonlyMap<string, number>;
  truncated: boolean;
  /** Nodes the server left out, per kind, while truncated. */
  truncatedByKind: Readonly<Partial<Record<ExplorationNodeKind, number>>>;
  totalNodes: number;
  totalEdges: number;
  agents: ReadonlyMap<string, string>;
  loaded: boolean;
}

export const EMPTY_GRAPH: GraphState = {
  version: 0,
  nodes: new Map(),
  edges: new Map(),
  fresh: new Map(),
  changed: new Map(),
  truncated: false,
  truncatedByKind: {},
  totalNodes: 0,
  totalEdges: 0,
  agents: new Map(),
  loaded: false,
};

export interface MergeResult {
  state: GraphState;
  added: string[];
  updated: string[];
}

/**
 * Merges a snapshot or delta. Deltas are upserts (the graph has no deletes, 9.8).
 * An older copy never overwrites a newer one, so out-of-order responses are safe.
 * A full snapshot replaces the node set but still reports what is new, so a
 * re-sync after a gap keeps highlight semantics.
 */
export function mergeGraph(prev: GraphState, resp: ExplorationGraphResponse, now: number): MergeResult {
  if (prev.loaded && resp.version < prev.version && !resp.full) {
    return { state: prev, added: [], updated: [] };
  }
  const initial = !prev.loaded;
  const nodes = new Map(resp.full ? [] : prev.nodes);
  const edges = new Map(resp.full ? [] : prev.edges);
  const fresh = new Map(prev.fresh);
  const changed = new Map(prev.changed);
  const added: string[] = [];
  const updated: string[] = [];

  for (const n of resp.nodes) {
    const old = prev.nodes.get(n.id);
    if (old && old.version > n.version) {
      nodes.set(n.id, old);
      continue;
    }
    nodes.set(n.id, n);
    if (!old) {
      added.push(n.id);
      if (!initial) fresh.set(n.id, now);
    } else if (old.status !== n.status || old.label !== n.label) {
      updated.push(n.id);
      if (!initial) changed.set(n.id, now);
    }
  }
  for (const e of resp.edges) {
    const old = prev.edges.get(e.id);
    if (old && old.version > e.version) {
      edges.set(e.id, old);
      continue;
    }
    edges.set(e.id, e);
  }
  if (resp.full) {
    // Keep nodes a full snapshot left out only if the server said it truncated.
    if (resp.truncated) {
      for (const [id, n] of prev.nodes) if (!nodes.has(id)) nodes.set(id, n);
      for (const [id, e] of prev.edges) if (!edges.has(id)) edges.set(id, e);
    }
  }
  const agents = new Map(prev.agents);
  for (const a of resp.agents ?? []) agents.set(a.id, a.name);
  for (const n of resp.nodes) if (n.agent_id && n.agent_name) agents.set(n.agent_id, n.agent_name);

  return {
    state: {
      version: Math.max(prev.version, resp.version),
      nodes,
      edges,
      fresh,
      changed,
      truncated: resp.truncated || (prev.truncated && !resp.full),
      truncatedByKind: resp.truncated ? (resp.truncated_by_kind ?? {}) : resp.full ? {} : prev.truncatedByKind,
      totalNodes: Math.max(resp.total_nodes, nodes.size),
      totalEdges: Math.max(resp.total_edges, edges.size),
      agents,
      loaded: true,
    },
    added,
    updated,
  };
}

/** Drops highlight marks older than `ttlMs`; returns the same object when nothing expired. */
export function expireMarks(state: GraphState, now: number, ttlMs: number): GraphState {
  const keep = (m: ReadonlyMap<string, number>) => {
    let dirty = false;
    const out = new Map<string, number>();
    for (const [k, t] of m) {
      if (now - t < ttlMs) out.set(k, t);
      else dirty = true;
    }
    return dirty ? out : m;
  };
  const fresh = keep(state.fresh);
  const changed = keep(state.changed);
  return fresh === state.fresh && changed === state.changed ? state : { ...state, fresh, changed };
}

// ---------------------------------------------------------------------------
// Structure
// ---------------------------------------------------------------------------

/**
 * Edges that point back at something already on the canvas (a work order
 * addressing the lead that spawned it, a verification judging an existing
 * finding). Drawn, but they neither define the tree for collapse nor the ranks.
 */
export const FEEDBACK_RELS: ReadonlySet<ExplorationEdgeRel> = new Set(["investigated", "verified", "refuted", "contradicts", "guides", "mitigates"]);

export interface Adjacency {
  out: Map<string, ExplorationEdge[]>;
  inc: Map<string, ExplorationEdge[]>;
}

export function adjacency(edges: Iterable<ExplorationEdge>, has: (id: string) => boolean): Adjacency {
  const out = new Map<string, ExplorationEdge[]>();
  const inc = new Map<string, ExplorationEdge[]>();
  for (const e of edges) {
    if (!has(e.src) || !has(e.dst) || e.src === e.dst) continue;
    (out.get(e.src) ?? out.set(e.src, []).get(e.src)!).push(e);
    (inc.get(e.dst) ?? inc.set(e.dst, []).get(e.dst)!).push(e);
  }
  return { out, inc };
}

/** Forward (tree) children of a node. */
export function forwardChildren(adj: Adjacency, id: string): string[] {
  return (adj.out.get(id) ?? []).filter((e) => !FEEDBACK_RELS.has(e.rel)).map((e) => e.dst);
}

/** Nodes within `hops` of `id`, over any edge, both directions. */
export function neighbourhood(adj: Adjacency, id: string, hops: number): Set<string> {
  const seen = new Set([id]);
  let frontier = [id];
  for (let h = 0; h < hops && frontier.length; h++) {
    const next: string[] = [];
    for (const k of frontier) {
      for (const e of adj.out.get(k) ?? []) if (!seen.has(e.dst)) (seen.add(e.dst), next.push(e.dst));
      for (const e of adj.inc.get(k) ?? []) if (!seen.has(e.src)) (seen.add(e.src), next.push(e.src));
    }
    frontier = next;
  }
  return seen;
}

// ---------------------------------------------------------------------------
// Derived view
// ---------------------------------------------------------------------------

export interface ViewOptions {
  kinds: ReadonlySet<ExplorationNodeKind>;
  categories: ReadonlySet<StatusCategory>;
  /** Agent ids to keep; empty = all. "" stands for "no agent" (planner/system). */
  agents: ReadonlySet<string>;
  collapsed: ReadonlySet<string>;
  /** Hide action nodes and draw work order -> observation directly. */
  foldActions: boolean;
  focus: { id: string; hops: number } | null;
  /** Hard cap of rendered nodes. */
  cap: number;
  /** Children of one kind shown per parent before the rest fold into "+N more" (0 = off). */
  siblingLimit: number;
  /** Group key (`parent|kind`) -> how many children to show. */
  expandedGroups: ReadonlyMap<string, number>;
  /** Restrict the view to these node ids (findings-centred default view); null/undefined = no restriction. */
  only?: ReadonlySet<string> | null;
}

/** Above this many nodes the default view folds actions and centres on findings. */
export const LARGE_GRAPH_NODES = 40;

export interface DefaultView {
  foldActions: boolean;
  /** Start with the findings-centred subset instead of everything. */
  centred: boolean;
}

/** Default view for a graph of `nodeCount` nodes (user choices override it). */
export function defaultViewFor(nodeCount: number, threshold: number = LARGE_GRAPH_NODES): DefaultView {
  const large = nodeCount > threshold;
  return { foldActions: large, centred: large };
}

const CENTRE_KINDS: ReadonlySet<ExplorationNodeKind> = new Set(["finding", "lead", "hint", "defense"]);

/**
 * Findings-centred subset: findings, leads, hints and defenses plus `hops` hops of
 * neighbours (over any edge). Returns null when there are no such seeds, so callers
 * fall back to the whole graph instead of showing an empty canvas.
 */
export function findingsCentred(
  nodes: ReadonlyMap<string, ExplorationNode>,
  edges: Iterable<ExplorationEdge>,
  hops = 1,
): Set<string> | null {
  const seeds = [...nodes.values()].filter((n) => CENTRE_KINDS.has(n.kind)).map((n) => n.id);
  if (!seeds.length) return null;
  const adj = adjacency(edges, (id) => nodes.has(id));
  const out = new Set<string>();
  for (const id of seeds) for (const k of neighbourhood(adj, id, hops)) out.add(k);
  return out;
}

/** "+N more <kind>" placeholder for children folded under one parent. */
export interface SiblingGroup {
  /** Render id (`group:<key>`). */
  id: string;
  key: string;
  parent: string;
  kind: ExplorationNodeKind;
  hidden: number;
  total: number;
}

/** Sticky outcomes and live work stay visible in a folded group; then oldest first (stable as it grows). */
function siblingRank(n: ExplorationNode): number {
  const order: Record<StatusCategory, number> = {
    verified: 0, candidate: 1, attempted: 2, running: 3, planned: 4, observed: 5, skipped: 6, rejected: 7,
    defense_proposed: 8, defense_unverified: 9,
  };
  return order[statusCategory(n.kind, n.status)];
}

export interface ViewEdge {
  id: string;
  src: string;
  dst: string;
  rel: ExplorationEdgeRel;
  /** Synthesised by folding (work order -> observation through a hidden action). */
  folded?: boolean;
}

export interface GraphView {
  nodes: ExplorationNode[];
  edges: ViewEdge[];
  /** Node id -> number of descendants hidden by its collapse. */
  hiddenBelow: Map<string, number>;
  /** Node id -> number of forward children (whether shown or not). */
  childCount: Map<string, number>;
  /** Work order id -> counts of its folded actions by status. */
  foldedActions: Map<string, Record<string, number>>;
  /** Folded sibling groups whose parent is visible. */
  groups: SiblingGroup[];
  /** Matching nodes left out by the cap. */
  capped: number;
  /** Nodes matching the filters before collapse / focus / cap. */
  matching: number;
}

const KIND_PRIORITY: Record<ExplorationNodeKind, number> = {
  objective: 0, finding: 1, lead: 2, work_order: 3, observation: 4, action: 5, hint: 6, defense: 7,
  reasoning: 8,
};

export function deriveView(state: GraphState, opts: ViewOptions): GraphView {
  const all = state.nodes;
  // 1. Filters.
  const pass = (n: ExplorationNode) =>
    opts.kinds.has(n.kind) &&
    opts.categories.has(statusCategory(n.kind, n.status)) &&
    (opts.agents.size === 0 || opts.agents.has(n.agent_id ?? ""));
  let keep = new Set<string>();
  for (const n of all.values()) if (pass(n)) keep.add(n.id);
  if (opts.only) for (const id of [...keep]) if (!opts.only.has(id)) keep.delete(id);
  const matching = keep.size;

  // 2. Fold actions into their work order.
  const foldedActions = new Map<string, Record<string, number>>();
  const extraEdges: ViewEdge[] = [];
  const fullAdj = adjacency(state.edges.values(), (id) => all.has(id));
  if (opts.foldActions) {
    for (const n of all.values()) {
      if (n.kind !== "action") continue;
      keep.delete(n.id);
      const wo = (fullAdj.inc.get(n.id) ?? []).find((e) => e.rel === "executed")?.src;
      if (!wo) continue;
      const c = foldedActions.get(wo) ?? {};
      c[n.status] = (c[n.status] ?? 0) + 1;
      foldedActions.set(wo, c);
      for (const e of fullAdj.out.get(n.id) ?? []) {
        extraEdges.push({ id: `fold:${wo}:${e.rel}:${e.dst}`, src: wo, dst: e.dst, rel: e.rel, folded: true });
      }
    }
  }

  const edgeList: ViewEdge[] = [];
  const seen = new Set<string>();
  for (const e of [...state.edges.values(), ...extraEdges]) {
    if (!keep.has(e.src) || !keep.has(e.dst) || e.src === e.dst) continue;
    const k = `${e.src}|${e.rel}|${e.dst}`;
    if (seen.has(k)) continue;
    seen.add(k);
    edgeList.push({ id: e.id, src: e.src, dst: e.dst, rel: e.rel, folded: "folded" in e ? e.folded : undefined });
  }
  const adj = adjacency(
    edgeList.map((e) => ({ ...e, version: 0 })),
    (id) => keep.has(id),
  );

  // 3. Collapse and sibling groups. A node stays if a root reaches it without
  // passing through a collapsed node or a folded sibling slot.
  const childCount = new Map<string, number>();
  for (const id of keep) childCount.set(id, forwardChildren(adj, id).length);
  const hiddenBelow = new Map<string, number>();
  let groups: SiblingGroup[] = [];
  const blocked = new Set<string>();
  const groupMembers = new Map<string, string[]>();
  if (opts.siblingLimit > 0) {
    for (const id of keep) {
      if (opts.collapsed.has(id)) continue;
      const kids = forwardChildren(adj, id);
      if (kids.length <= opts.siblingLimit) continue;
      const byKind = new Map<ExplorationNodeKind, string[]>();
      for (const c of kids) {
        const k = all.get(c)!.kind;
        (byKind.get(k) ?? byKind.set(k, []).get(k)!).push(c);
      }
      for (const [kind, list] of byKind) {
        const key = `${id}|${kind}`;
        const shown = opts.expandedGroups.get(key) ?? opts.siblingLimit;
        if (list.length <= shown) continue;
        list.sort((a, b) => siblingRank(all.get(a)!) - siblingRank(all.get(b)!) || all.get(a)!.version - all.get(b)!.version || a.localeCompare(b));
        const over = list.slice(shown);
        for (const c of over) blocked.add(`${id}|${c}`);
        groupMembers.set(key, over);
        groups.push({ id: `group:${key}`, key, parent: id, kind, hidden: over.length, total: list.length });
      }
    }
  }
  if (opts.collapsed.size || blocked.size) {
    const roots = [...keep].filter((id) => !(adj.inc.get(id) ?? []).some((e) => !FEEDBACK_RELS.has(e.rel)));
    const reached = new Set<string>(roots);
    const stack = [...roots];
    while (stack.length) {
      const id = stack.pop()!;
      if (opts.collapsed.has(id)) continue;
      for (const c of forwardChildren(adj, id)) {
        if (blocked.has(`${id}|${c}`) || reached.has(c)) continue;
        reached.add(c);
        stack.push(c);
      }
    }
    // Hide only what lies below a collapsed node / folded slot and is not reachable
    // another way (nodes on root-less cycles stay visible).
    const below = (starts: string[]): Set<string> => {
      const vis = new Set<string>();
      const st = [...starts];
      while (st.length) {
        const k = st.pop()!;
        if (vis.has(k)) continue;
        vis.add(k);
        for (const c of forwardChildren(adj, k)) st.push(c);
      }
      return vis;
    };
    const hidden = new Set<string>();
    for (const id of opts.collapsed) {
      if (!keep.has(id)) continue;
      let n = 0;
      for (const c of below(forwardChildren(adj, id))) if (!reached.has(c) && c !== id) (n++, hidden.add(c));
      if (n) hiddenBelow.set(id, n);
    }
    for (const g of groups) for (const c of below(groupMembers.get(g.key) ?? [])) if (!reached.has(c)) hidden.add(c);
    groups = groups
      .map((g) => ({ ...g, hidden: (groupMembers.get(g.key) ?? []).filter((c) => hidden.has(c)).length }))
      .filter((g) => g.hidden > 0 && !hidden.has(g.parent));
    keep = new Set([...keep].filter((id) => !hidden.has(id)));
  }

  // 4. Focus: only the neighbourhood of one node.
  if (opts.focus && keep.has(opts.focus.id)) {
    const near = neighbourhood(adj, opts.focus.id, opts.focus.hops);
    keep = new Set([...keep].filter((id) => near.has(id)));
  }

  // 5. Cap: most important kinds first, then most recent.
  let nodes = [...keep].map((id) => all.get(id)!).filter(Boolean);
  let capped = 0;
  if (nodes.length > opts.cap) {
    nodes.sort((a, b) => KIND_PRIORITY[a.kind] - KIND_PRIORITY[b.kind] || b.version - a.version || a.id.localeCompare(b.id));
    capped = nodes.length - opts.cap;
    nodes = nodes.slice(0, opts.cap);
    keep = new Set(nodes.map((n) => n.id));
  }
  nodes.sort((a, b) => a.version - b.version || a.id.localeCompare(b.id));
  const edges = edgeList.filter((e) => keep.has(e.src) && keep.has(e.dst));
  groups = groups.filter((g) => keep.has(g.parent));
  return { nodes, edges, hiddenBelow, childCount, foldedActions, groups, capped, matching };
}

/** Case-insensitive match on label, key, kind, status, agent name and ids. */
export function searchNodes(nodes: Iterable<ExplorationNode>, query: string, agents: ReadonlyMap<string, string>): string[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const out: string[] = [];
  for (const n of nodes) {
    const agent = n.agent_id ? (agents.get(n.agent_id) ?? n.agent_name ?? "") : "";
    const hay = `${n.label}\n${n.key}\n${n.kind}\n${n.status}\n${agent}\n${n.id}\n${n.finding_id ?? ""}\n${n.work_order_id ?? ""}`.toLowerCase();
    if (hay.includes(q)) out.push(n.id);
  }
  return out;
}
