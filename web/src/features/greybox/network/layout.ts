// Deterministic, top-aligned column layout for the Network map:
// host -> service -> endpoints / clusters -> parameters, with defenses beside or
// under what they protect. Top-aligned blocks in discovery order mean a node that
// arrives later only pushes what comes AFTER it down; nothing is re-centred, so the
// canvas does not jump while the run grows. No layout library, unit-tested.
import type { NetworkView, ViewKind, ViewNode } from "./model";

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

export const SIZE: Record<ViewKind, { w: number; h: number }> = {
  host: { w: 224, h: 64 },
  service: { w: 296, h: 164 },
  endpoint: { w: 252, h: 58 },
  cluster: { w: 252, h: 58 },
  parameter: { w: 200, h: 34 },
  defense: { w: 236, h: 64 },
};

export const COL_X = { host: 0, service: 280, endpoint: 660, parameter: 960, defenseEp: 1200 } as const;
export const CLUSTER_INDENT = 22;
const GAP = 10;
const BLOCK_GAP = 22;
const PARAM_GAP = 6;

export interface NetworkLayout {
  rects: Map<string, Rect>;
  width: number;
  height: number;
}

export function layoutNetwork(view: Pick<NetworkView, "nodes">): NetworkLayout {
  const byId = new Map<string, ViewNode>();
  const kids = new Map<string, ViewNode[]>();
  const roots: ViewNode[] = [];
  const defensesOf = new Map<string, ViewNode[]>();
  for (const n of view.nodes) byId.set(n.id, n);
  for (const n of view.nodes) {
    if (n.kind === "defense") {
      const t = n.protects ?? "";
      (defensesOf.get(t) ?? defensesOf.set(t, []).get(t)!).push(n);
    } else if (n.parent && byId.has(n.parent)) (kids.get(n.parent) ?? kids.set(n.parent, []).get(n.parent)!).push(n);
    else roots.push(n);
  }

  const rects = new Map<string, Rect>();
  const put = (id: string, kind: ViewKind, x: number, y: number, w = SIZE[kind].w): number => {
    rects.set(id, { x, y, w, h: SIZE[kind].h });
    return SIZE[kind].h;
  };

  /** Stack defenses in a column starting at y; returns the height used. */
  const stackDefenses = (target: string, x: number, y: number): number => {
    let used = 0;
    for (const d of defensesOf.get(target) ?? []) {
      put(d.id, "defense", x, y + used);
      used += SIZE.defense.h + GAP;
    }
    return used;
  };

  const placeParams = (ep: ViewNode, y: number): number => {
    let used = 0;
    for (const p of kids.get(ep.id) ?? []) {
      if (p.kind !== "parameter") continue;
      put(p.id, "parameter", COL_X.parameter, y + used);
      used += SIZE.parameter.h + PARAM_GAP;
    }
    return used;
  };

  /** Place a node of the endpoint column (endpoint or cluster, plus members); returns the block height. */
  const placeEndpointish = (n: ViewNode, y: number, indent: number): number => {
    const x = COL_X.endpoint + indent;
    if (n.kind === "cluster") {
      put(n.id, "cluster", x, y);
      const dh = stackDefenses(n.id, COL_X.defenseEp, y);
      let used = Math.max(SIZE.cluster.h + GAP, dh);
      for (const m of kids.get(n.id) ?? []) used += placeEndpointish(m, y + used, CLUSTER_INDENT);
      return used;
    }
    if (n.kind === "parameter") {
      // Orphan parameter.
      put(n.id, "parameter", COL_X.parameter, y);
      return SIZE.parameter.h + PARAM_GAP;
    }
    put(n.id, "endpoint", x, y, SIZE.endpoint.w - indent);
    const ph = placeParams(n, y);
    const dh = stackDefenses(n.id, COL_X.defenseEp, y);
    let used = Math.max(SIZE.endpoint.h + GAP, ph, dh);
    for (const c of kids.get(n.id) ?? []) if (c.kind !== "parameter") used += placeEndpointish(c, y + used, indent + CLUSTER_INDENT);
    return used;
  };

  const placeService = (n: ViewNode, y: number): number => {
    put(n.id, "service", COL_X.service, y);
    const below = stackDefenses(n.id, COL_X.service, y + SIZE.service.h + GAP);
    let used = 0;
    for (const c of kids.get(n.id) ?? []) used += placeEndpointish(c, y + used, 0);
    return Math.max(used, SIZE.service.h + (below ? GAP + below : 0)) + BLOCK_GAP;
  };

  const placeHost = (n: ViewNode, y: number): number => {
    put(n.id, "host", COL_X.host, y);
    const below = stackDefenses(n.id, COL_X.host, y + SIZE.host.h + GAP);
    let used = 0;
    for (const c of kids.get(n.id) ?? []) {
      used += c.kind === "service" ? placeService(c, y + used) : placeEndpointish(c, y + used, 0);
    }
    return Math.max(used, SIZE.host.h + (below ? GAP + below : 0)) + BLOCK_GAP;
  };

  let y = 0;
  for (const r of roots) {
    if (r.kind === "host") y += placeHost(r, y);
    else if (r.kind === "service") y += placeService(r, y);
    else y += placeEndpointish(r, y, 0);
  }
  // Defenses whose target is not in the view are dropped by the view; none to place here.

  let width = 0;
  let height = 0;
  for (const r of rects.values()) {
    width = Math.max(width, r.x + r.w);
    height = Math.max(height, r.y + r.h);
  }
  return { rects, width, height };
}

// ---------------------------------------------------------------------------
// Fit that keeps text readable (min font 11 px => never below this zoom)
// ---------------------------------------------------------------------------

/** Card text is 12 px minimum, so 0.92 keeps it at 11 px on screen: below that the map pans instead of shrinking. */
export const MIN_ZOOM_FIT = 0.92;
export const MAX_ZOOM_FIT = 1;

export interface Fit {
  x: number;
  y: number;
  zoom: number;
  /** The map does not fit at the readable zoom: anchored top-left, the user pans. */
  clamped: boolean;
}

export function fitRects(
  rects: Iterable<Rect>,
  size: { width: number; height: number },
  opts: { minZoom?: number; maxZoom?: number; padding?: number } = {},
): Fit | null {
  const minZoom = opts.minZoom ?? MIN_ZOOM_FIT;
  const maxZoom = opts.maxZoom ?? MAX_ZOOM_FIT;
  const pad = opts.padding ?? 0.05;
  let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
  for (const r of rects) {
    minX = Math.min(minX, r.x);
    minY = Math.min(minY, r.y);
    maxX = Math.max(maxX, r.x + r.w);
    maxY = Math.max(maxY, r.y + r.h);
  }
  if (!Number.isFinite(minX) || size.width <= 0 || size.height <= 0) return null;
  const w = maxX - minX;
  const h = maxY - minY;
  const fit = Math.min((size.width * (1 - 2 * pad)) / w, (size.height * (1 - 2 * pad)) / h);
  const zoom = Math.min(maxZoom, Math.max(minZoom, fit));
  const padX = size.width * pad;
  const padY = size.height * pad;
  if (fit < minZoom) return { zoom, clamped: true, x: padX - minX * zoom, y: padY - minY * zoom };
  return { zoom, clamped: false, x: (size.width - w * zoom) / 2 - minX * zoom, y: (size.height - h * zoom) / 2 - minY * zoom };
}
