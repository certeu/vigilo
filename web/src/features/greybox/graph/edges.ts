// Edge hygiene for the exploration graph (pure, unit-tested): one visual edge per
// node pair, a reasoning-cycle timeline, a label policy and a "secondary links" policy.
import type { ViewEdge } from "./model";
import type { ExplorationEdgeRel, ExplorationNode, ExplorationNodeStatus } from "./types";
import { REL_STYLE } from "./encoding";

/**
 * Evidence relations: they annotate the spine (what supports / contradicts / addresses
 * what) but are not part of it. Hidden unless a node is selected or the toggle is on.
 */
export const SECONDARY_RELS: ReadonlySet<ExplorationEdgeRel> = new Set(["investigated", "supports", "contradicts", "refuted", "guides"]);

/** Which relation names a merged edge, most important first. */
const REL_PRIORITY: readonly ExplorationEdgeRel[] = [
  "verified", "spawned", "executed", "observed", "mitigates", "refuted", "contradicts", "supports", "guides", "investigated",
];
const prio = (r: ExplorationEdgeRel) => REL_PRIORITY.indexOf(r);

export interface MergedEdge {
  /** Stable id: the id of the primary relation (or the synthetic id). */
  id: string;
  /** Direction of the primary relation. */
  src: string;
  dst: string;
  rel: ExplorationEdgeRel;
  /** Every relation between the pair (including the primary), with its own direction. */
  rels: { rel: ExplorationEdgeRel; src: string; dst: string }[];
  /** True when no relation of the pair is part of the spine. */
  secondary: boolean;
  folded: boolean;
  /** Timeline link between consecutive reasoning cycles (not from the server). */
  synthetic: boolean;
}

/** Collapses parallel / antiparallel relations between a pair of nodes into one edge. */
export function mergeEdges(edges: readonly ViewEdge[]): MergedEdge[] {
  const byPair = new Map<string, ViewEdge[]>();
  for (const e of edges) {
    if (e.src === e.dst) continue;
    const k = e.src < e.dst ? `${e.src}|${e.dst}` : `${e.dst}|${e.src}`;
    (byPair.get(k) ?? byPair.set(k, []).get(k)!).push(e);
  }
  const out: MergedEdge[] = [];
  for (const group of byPair.values()) {
    const sorted = [...group].sort((a, b) => prio(a.rel) - prio(b.rel) || a.id.localeCompare(b.id));
    const p = sorted[0];
    const rels: MergedEdge["rels"] = [];
    const seen = new Set<string>();
    for (const e of sorted) {
      const k = `${e.rel}|${e.src}`;
      if (seen.has(k)) continue;
      seen.add(k);
      rels.push({ rel: e.rel, src: e.src, dst: e.dst });
    }
    out.push({
      id: p.id,
      src: p.src,
      dst: p.dst,
      rel: p.rel,
      rels,
      secondary: rels.every((r) => SECONDARY_RELS.has(r.rel)),
      folded: group.every((e) => !!e.folded),
      synthetic: group.every((e) => e.id.startsWith("timeline:")),
    });
  }
  return out;
}

/** Cycle order: the numeric key ("1", "2", ...), then version. */
function cycleOrder(a: ExplorationNode, b: ExplorationNode): number {
  const na = Number.parseInt(a.key, 10);
  const nb = Number.parseInt(b.key, 10);
  if (Number.isFinite(na) && Number.isFinite(nb) && na !== nb) return na - nb;
  return a.version - b.version || a.id.localeCompare(b.id);
}

/** Visible reasoning nodes in cycle order. */
export function reasoningChain(nodes: Iterable<ExplorationNode>): ExplorationNode[] {
  return [...nodes].filter((n) => n.kind === "reasoning").sort(cycleOrder);
}

/**
 * Adds a timeline between consecutive reasoning cycles and drops the now-redundant
 * "objective -> cycle N" edges (N > 1): the chain already implies them.
 */
export function withTimeline(edges: readonly ViewEdge[], nodes: readonly ExplorationNode[]): ViewEdge[] {
  const chain = reasoningChain(nodes);
  if (chain.length < 2) return [...edges];
  const kind = new Map(nodes.map((n) => [n.id, n.kind]));
  const later = new Set(chain.slice(1).map((n) => n.id));
  const kept = edges.filter((e) => !(later.has(e.dst) && kind.get(e.src) !== "reasoning"));
  const out = [...kept];
  for (let i = 1; i < chain.length; i++) {
    out.push({ id: `timeline:${chain[i - 1].id}:${chain[i].id}`, src: chain[i - 1].id, dst: chain[i].id, rel: "spawned" });
  }
  return out;
}

/** Zoom at which labels show on every edge (small graphs only). */
export const LABEL_ZOOM = 1.15;
export const LABEL_ALL_MAX_EDGES = 40;

export interface LabelContext {
  /** An end of the edge is the selected node. */
  touchesSelected: boolean;
  hovered: boolean;
  zoom: number;
  edgeCount: number;
}

/** Labels are off by default: shown on hover / selection, or when zoomed in on a small graph. */
export function edgeLabelVisible(c: LabelContext): boolean {
  return c.touchesSelected || c.hovered || (c.zoom >= LABEL_ZOOM && c.edgeCount <= LABEL_ALL_MAX_EDGES);
}

/** Short label: the most important relation, "+N" when others were merged into it. */
export function edgeLabel(e: MergedEdge): string {
  const base = REL_STYLE[e.rel].label;
  return e.rels.length > 1 ? `${base} +${e.rels.length - 1}` : base;
}

/** Tooltip listing every relation between the pair, in reading order. */
export function edgeTooltip(e: MergedEdge, labelOf: (id: string) => string): string {
  return e.rels
    .map((r) => `${labelOf(r.src)} ${REL_STYLE[r.rel].label} ${labelOf(r.dst)}`)
    .join("\n");
}

/** Evidence links are drawn only when the toggle is on or a node they touch is selected. */
export function edgeVisible(e: MergedEdge, showEvidence: boolean, selected: string | null): boolean {
  if (!e.secondary) return true;
  if (showEvidence) return true;
  return !!selected && (e.src === selected || e.dst === selected);
}

/** Statuses of work that is in flight, used to animate the edge into it. */
const LIVE_STATUSES: ReadonlySet<ExplorationNodeStatus> = new Set(["running", "investigating"]);
export const isLiveStatus = (s: ExplorationNodeStatus) => LIVE_STATUSES.has(s);
