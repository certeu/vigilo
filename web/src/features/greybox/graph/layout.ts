// Layout: a layered left-to-right dagre pass for the first snapshot (or on
// "Re-layout"), then incremental placement for nodes that arrive later. Existing
// positions are never moved, so the canvas does not jump while a run grows: a new
// node is put one column right of its parent, in the nearest free row slot.
import dagre from "@dagrejs/dagre";
import { FEEDBACK_RELS } from "./model";
import type { ExplorationEdgeRel } from "./types";

export const NODE_W = 224;
export const NODE_H = 88;
export const GAP_X = 120;
export const GAP_Y = 32;
/** Back-pointing relations for layout. `verified` (action -> finding) is forward here: findings sit right of the action that verified them. */
const BACK_RELS: ReadonlySet<string> = new Set([...FEEDBACK_RELS].filter((r) => r !== "verified"));
const PITCH_X = NODE_W + GAP_X;
const PITCH_Y = NODE_H + GAP_Y;

export interface Point {
  x: number;
  y: number;
}
export type Positions = Map<string, Point>;

export interface LayoutEdge {
  src: string;
  dst: string;
  rel: ExplorationEdgeRel;
}

/** Full layered layout (LR). Feedback edges do not define ranks. */
export function layeredLayout(ids: readonly string[], edges: readonly LayoutEdge[]): Positions {
  const g = new dagre.graphlib.Graph({ multigraph: false });
  const big = ids.length > 600;
  g.setGraph({
    rankdir: "LR",
    nodesep: GAP_Y,
    ranksep: GAP_X,
    marginx: 24,
    marginy: 24,
    // network-simplex is the nicest but super-linear; longest-path keeps big graphs snappy.
    ranker: big ? "longest-path" : "network-simplex",
  });
  g.setDefaultEdgeLabel(() => ({}));
  const has = new Set(ids);
  for (const id of ids) g.setNode(id, { width: NODE_W, height: NODE_H });
  for (const e of edges) {
    if (!has.has(e.src) || !has.has(e.dst) || e.src === e.dst) continue;
    // defense -> finding is drawn that way but laid out finding -> defense (to its right).
    if (e.rel === "mitigates") g.setEdge(e.dst, e.src);
    else if (!BACK_RELS.has(e.rel)) g.setEdge(e.src, e.dst);
  }
  dagre.layout(g);
  const out: Positions = new Map();
  for (const id of ids) {
    const n = g.node(id);
    // dagre returns centres; React Flow wants the top-left corner.
    if (n) out.set(id, { x: Math.round(n.x - NODE_W / 2), y: Math.round(n.y - NODE_H / 2) });
  }
  return out;
}

/** Spatial hash of occupied card slots. */
class Occupancy {
  private cells = new Map<string, Point[]>();
  private key(cx: number, cy: number) {
    return `${cx}:${cy}`;
  }
  add(p: Point) {
    const cx = Math.floor(p.x / PITCH_X);
    const cy = Math.floor(p.y / PITCH_Y);
    const k = this.key(cx, cy);
    (this.cells.get(k) ?? this.cells.set(k, []).get(k)!).push(p);
  }
  free(p: Point): boolean {
    const cx = Math.floor(p.x / PITCH_X);
    const cy = Math.floor(p.y / PITCH_Y);
    for (let dx = -1; dx <= 1; dx++) {
      for (let dy = -1; dy <= 1; dy++) {
        for (const q of this.cells.get(this.key(cx + dx, cy + dy)) ?? []) {
          if (Math.abs(q.x - p.x) < NODE_W + GAP_X / 2 && Math.abs(q.y - p.y) < NODE_H + GAP_Y / 2) return false;
        }
      }
    }
    return true;
  }
}

/** Nearest free slot in the column at `x`, searching outwards from `y`. */
function nearestFree(occ: Occupancy, x: number, y: number): Point {
  for (let i = 0; i < 2000; i++) {
    const step = Math.ceil(i / 2) * PITCH_Y * (i % 2 === 0 ? 1 : -1);
    const p = { x, y: y + step };
    if (occ.free(p)) return p;
  }
  return { x, y };
}

/**
 * Positions for `ids`: existing entries in `prev` are kept as they are; the
 * missing ones are placed next to an already-placed parent (or child, or at the
 * bottom-left). Returns a new map that also retains `prev` entries for ids not in
 * `ids` (hidden nodes come back where they were). If nothing is placed yet, it
 * runs the layered layout.
 */
export function incrementalLayout(ids: readonly string[], edges: readonly LayoutEdge[], prev: Positions): Positions {
  const out: Positions = new Map(prev);
  const missing = ids.filter((id) => !out.has(id));
  if (!missing.length) return out;
  const placedVisible = ids.some((id) => out.has(id));
  if (!placedVisible) {
    for (const [id, p] of layeredLayout(ids, edges)) out.set(id, p);
    return out;
  }
  const occ = new Occupancy();
  for (const id of ids) {
    const p = out.get(id);
    if (p) occ.add(p);
  }
  const parents = new Map<string, string[]>();
  const children = new Map<string, string[]>();
  for (const e of edges) {
    if (e.src === e.dst) continue;
    if (e.rel === "mitigates") {
      // The finding is the layout parent of its defense.
      (parents.get(e.src) ?? parents.set(e.src, []).get(e.src)!).push(e.dst);
      (children.get(e.dst) ?? children.set(e.dst, []).get(e.dst)!).push(e.src);
      continue;
    }
    if (BACK_RELS.has(e.rel)) {
      (children.get(e.src) ?? children.set(e.src, []).get(e.src)!).push(e.dst);
      continue;
    }
    (parents.get(e.dst) ?? parents.set(e.dst, []).get(e.dst)!).push(e.src);
    (children.get(e.src) ?? children.set(e.src, []).get(e.src)!).push(e.dst);
  }
  let pending = missing;
  // Place in waves: each wave places nodes whose parent already has a position.
  while (pending.length) {
    const next: string[] = [];
    let progress = false;
    for (const id of pending) {
      const ps = (parents.get(id) ?? []).map((p) => out.get(p)).filter((p): p is Point => !!p);
      if (ps.length) {
        const x = Math.max(...ps.map((p) => p.x)) + PITCH_X;
        const y = ps.reduce((s, p) => s + p.y, 0) / ps.length;
        const p = nearestFree(occ, x, Math.round(y));
        out.set(id, p);
        occ.add(p);
        progress = true;
      } else next.push(id);
    }
    if (!progress) {
      // No placed parent: next to a placed neighbour, else below everything.
      const id = next.shift()!;
      const kid = (children.get(id) ?? []).map((c) => out.get(c)).find((p): p is Point => !!p);
      let p: Point;
      if (kid) p = nearestFree(occ, kid.x - PITCH_X, kid.y);
      else {
        let minX = Infinity;
        let maxY = -Infinity;
        for (const q of out.values()) {
          minX = Math.min(minX, q.x);
          maxY = Math.max(maxY, q.y);
        }
        p = nearestFree(occ, Number.isFinite(minX) ? minX : 0, Number.isFinite(maxY) ? maxY + PITCH_Y : 0);
      }
      out.set(id, p);
      occ.add(p);
    }
    pending = next;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Fit-to-view that keeps text readable
// ---------------------------------------------------------------------------

/** Card body text is 11.5 px: at this zoom it renders at about 10 px, the legibility floor. */
export const MIN_READABLE_ZOOM = 0.85;
export const FIT_MAX_ZOOM = 1;
export const FIT_PADDING = 0.08;

export interface FitResult {
  x: number;
  y: number;
  zoom: number;
  /** The whole graph does not fit at the readable zoom: the view is anchored top-left and the user pans. */
  clamped: boolean;
}

/**
 * Viewport that fits `ids` (positions in `pos`) into a `width` x `height` canvas without
 * dropping below `minZoom`. When the graph would need a smaller zoom, keep `minZoom` and
 * anchor at the top-left of the bounds (the objective side) so the user scrolls/pans
 * instead of reading shrunken text. Returns null with nothing to fit.
 */
export function computeFit(
  ids: readonly string[],
  pos: ReadonlyMap<string, Point>,
  size: { width: number; height: number },
  opts: { minZoom?: number; maxZoom?: number; padding?: number } = {},
): FitResult | null {
  const minZoom = opts.minZoom ?? MIN_READABLE_ZOOM;
  const maxZoom = opts.maxZoom ?? FIT_MAX_ZOOM;
  const padding = opts.padding ?? FIT_PADDING;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const id of ids) {
    const p = pos.get(id);
    if (!p) continue;
    minX = Math.min(minX, p.x);
    minY = Math.min(minY, p.y);
    maxX = Math.max(maxX, p.x + NODE_W);
    maxY = Math.max(maxY, p.y + NODE_H);
  }
  if (!Number.isFinite(minX) || size.width <= 0 || size.height <= 0) return null;
  const w = maxX - minX;
  const h = maxY - minY;
  const availW = size.width * (1 - 2 * padding);
  const availH = size.height * (1 - 2 * padding);
  const fit = Math.min(availW / w, availH / h);
  const zoom = Math.min(maxZoom, Math.max(minZoom, fit));
  const clamped = fit < minZoom;
  const padX = size.width * padding;
  const padY = size.height * padding;
  if (clamped) return { zoom, clamped, x: padX - minX * zoom, y: padY - minY * zoom };
  // Fits: centre the bounds.
  return { zoom, clamped, x: (size.width - w * zoom) / 2 - minX * zoom, y: (size.height - h * zoom) / 2 - minY * zoom };
}
