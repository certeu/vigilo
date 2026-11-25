// Pure model of the Network map: delta merge, coverage, per-asset visual state,
// surface mapping, path clustering and the derived (collapsed) view. No React, no
// layout library: unit-tested.
//
// The exploration graph's mergeGraph/GraphState are typed for exploration nodes, so the
// merge here is a small generic upsert with the same semantics (an older copy never
// overwrites a newer one; deltas are upserts; marks for "new" / "changed" assets).
import { classifyPath, isStaticLike, staticPrefix, type AssetClass } from "../assetClass";
import type { AssetCoverage, AssetEdge, AssetEdgeRel, AssetGraphResponse, AssetKind, AssetNode } from "../types";

// ---------------------------------------------------------------------------
// Merge
// ---------------------------------------------------------------------------

export interface AssetGraphState {
  version: number;
  nodes: ReadonlyMap<string, AssetNode>;
  edges: ReadonlyMap<string, AssetEdge>;
  /** Asset id -> client time (ms) it first appeared after the initial snapshot. */
  fresh: ReadonlyMap<string, number>;
  /** Asset id -> client time (ms) a delta changed its state, counts or surface. */
  changed: ReadonlyMap<string, number>;
  /** Server-reported coverage (authoritative when present). */
  coverage: AssetCoverage | null;
  truncated: boolean;
  truncatedByKind: Readonly<Partial<Record<AssetKind, number>>>;
  loaded: boolean;
}

export const EMPTY_ASSET_GRAPH: AssetGraphState = {
  version: 0,
  nodes: new Map(),
  edges: new Map(),
  fresh: new Map(),
  changed: new Map(),
  coverage: null,
  truncated: false,
  truncatedByKind: {},
  loaded: false,
};

function nodeChanged(a: AssetNode, b: AssetNode): boolean {
  return (
    a.state !== b.state || a.label !== b.label || a.tested !== b.tested || a.in_scope !== b.in_scope ||
    a.finding_count !== b.finding_count || JSON.stringify(a.data?.surface) !== JSON.stringify(b.data?.surface)
  );
}

export interface AssetMergeResult {
  state: AssetGraphState;
  added: string[];
  updated: string[];
}

export function mergeAssetGraph(prev: AssetGraphState, resp: AssetGraphResponse, now: number): AssetMergeResult {
  if (prev.loaded && resp.version < prev.version && !resp.full) return { state: prev, added: [], updated: [] };
  const initial = !prev.loaded;
  const nodes = new Map(resp.full && !resp.truncated ? [] : prev.nodes);
  const edges = new Map(resp.full && !resp.truncated ? [] : prev.edges);
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
    } else if (nodeChanged(old, n)) {
      updated.push(n.id);
      if (!initial) changed.set(n.id, now);
    }
  }
  for (const e of resp.edges) {
    const old = prev.edges.get(e.id);
    edges.set(e.id, old && old.version > e.version ? old : e);
  }
  return {
    state: {
      version: Math.max(prev.version, resp.version),
      nodes,
      edges,
      fresh,
      changed,
      coverage: resp.coverage ?? prev.coverage,
      truncated: resp.truncated || (prev.truncated && !resp.full),
      truncatedByKind: resp.truncated ? (resp.truncated_by_kind ?? {}) : resp.full ? {} : prev.truncatedByKind,
      loaded: true,
    },
    added,
    updated,
  };
}

/** Drops marks older than `ttlMs`; returns the same object when nothing expired. */
export function expireAssetMarks(state: AssetGraphState, now: number, ttlMs: number): AssetGraphState {
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
// Coverage
// ---------------------------------------------------------------------------

export interface CoverageSummary {
  inScope: number;
  tested: number;
  /** 0..1, or null when nothing is in scope yet. */
  fraction: number | null;
  percent: number | null;
  definition: string;
  /** "server" when the API reported it, "local" when derived from the loaded nodes. */
  source: "server" | "local";
}

export const DEFAULT_COVERAGE_DEFINITION = "Share of in-scope pages and API endpoints that at least one work order has tested. Static assets are not counted.";

export function coverageFraction(inScope: number, tested: number): number | null {
  if (!(inScope > 0)) return null;
  return Math.max(0, Math.min(1, tested / inScope));
}

/** The server's coverage when given, else counted from the loaded endpoint nodes. */
export function coverageSummary(state: Pick<AssetGraphState, "coverage" | "nodes">): CoverageSummary {
  let inScope: number;
  let tested: number;
  let source: CoverageSummary["source"];
  if (state.coverage) {
    inScope = state.coverage.in_scope_endpoints;
    tested = Math.min(state.coverage.tested_endpoints, inScope);
    source = "server";
  } else {
    inScope = 0;
    tested = 0;
    for (const n of state.nodes.values()) {
      if (n.kind !== "endpoint" || !n.in_scope || isFoldedStatic(n)) continue;
      inScope++;
      if (n.tested) tested++;
    }
    source = "local";
  }
  const fraction = coverageFraction(inScope, tested);
  return {
    inScope,
    tested,
    fraction,
    percent: fraction === null ? null : Math.round(fraction * 100),
    definition: state.coverage?.definition || DEFAULT_COVERAGE_DEFINITION,
    source,
  };
}

// ---------------------------------------------------------------------------
// Visual state of an asset
// ---------------------------------------------------------------------------

export type AssetVisual = "finding" | "tested" | "in_scope" | "out_of_scope";

/** Finding-linked beats tested beats merely in scope; out of scope is always muted. */
export function assetVisual(n: Pick<AssetNode, "in_scope" | "tested" | "finding_count">): AssetVisual {
  if (!n.in_scope) return "out_of_scope";
  if (n.finding_count > 0) return "finding";
  if (n.tested) return "tested";
  return "in_scope";
}

export interface VisualStyle {
  label: string;
  glyph: string;
  description: string;
  /** Card border classes (the ring). */
  border: string;
  chip: string;
  body: string;
  /** Minimap fill. */
  fill: string;
}

export const VISUAL_STYLE: Record<AssetVisual, VisualStyle> = {
  finding: {
    label: "Has findings",
    glyph: "!",
    description: "A finding is linked to this asset.",
    border: "border-severity-critical border-2",
    chip: "border-severity-critical/40 bg-red-50 text-severity-critical",
    body: "",
    fill: "#B4232C",
  },
  tested: {
    label: "Tested",
    glyph: "✓",
    description: "In scope and checked by at least one work order.",
    border: "border-emerald-700 border-2",
    chip: "border-emerald-600/40 bg-emerald-50 text-emerald-800",
    body: "",
    fill: "#047857",
  },
  in_scope: {
    label: "In scope",
    glyph: "○",
    description: "In scope, not tested yet.",
    border: "border-accent/70",
    chip: "border-accent/40 bg-accent/5 text-accent",
    body: "",
    fill: "#3B5BDB",
  },
  out_of_scope: {
    label: "Out of scope",
    glyph: "–",
    description: "Seen, but the scope guard keeps the run away from it.",
    border: "border-dashed border-slate/50",
    chip: "border-line bg-canvas text-slate",
    body: "opacity-70",
    fill: "#9aa3b2",
  },
};

// ---------------------------------------------------------------------------
// Surface mapping (service.data.surface, endpoint.data.surface)
// ---------------------------------------------------------------------------

const isRec = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v : null);
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

export type RiskLevel = "low" | "medium" | "high";

export function riskLevel(score: number | null): RiskLevel | null {
  if (score === null) return null;
  return score >= 67 ? "high" : score >= 34 ? "medium" : "low";
}

export interface CookieRow {
  name: string;
  secure: boolean | null;
  httpOnly: boolean | null;
  sameSite: string | null;
  /** Missing protections, in words. */
  issues: string[];
}

export interface ServiceSurface {
  server: string | null;
  technologies: string[];
  headers: { present: string[]; missing: string[]; presentCount: number; missingCount: number; total: number; ratio: number | null };
  cookies: CookieRow[];
  cors: { reflectsOrigin: boolean; allowsCredentials: boolean; wildcard: boolean; risky: boolean } | null;
  redirects: { count: number; externalBlocked: number } | null;
  tls: string | null;
  /** false when the service is plain http (the Secure cookie flag is then moot). */
  https: boolean | null;
  versionDisclosure: string[];
  sensitivePaths: Array<{ path: string; reason: string; served: boolean }>;
  authPaths: string[];
  /** The API's own breakdown of the score (largest first), when it sends one. */
  riskFactors: Array<{ id: string; points: number; detail: string }>;
  endpoints: { total: number; static: number; tested: number; withFindings: number; authLike: number; sensitive: number } | null;
  riskScore: number | null;
  riskLevel: RiskLevel | null;
  /** Plain-language reasons behind the risk score, derived from the same signals. */
  explanation: string[];
}

function tlsText(v: unknown): string | null {
  if (typeof v === "string") return str(v);
  if (typeof v === "boolean") return v ? "HTTPS" : "Plain http (no TLS)";
  if (!isRec(v)) return null;
  if (typeof v.https === "boolean") {
    if (!v.https) return "Plain http (no TLS)";
    return v.hsts === true ? "HTTPS, HSTS set" : v.hsts === false ? "HTTPS, HSTS missing" : "HTTPS";
  }
  const parts: string[] = [];
  const version = str(v.version) ?? str(v.protocol);
  if (version) parts.push(version);
  if (v.expired === true) parts.push("certificate expired");
  if (v.self_signed === true) parts.push("self-signed");
  return parts.length ? parts.join(", ") : null;
}

/** Maps `service.data.surface` (tolerating absent or partial pieces). Returns null with no surface at all. */
export function serviceSurface(data: Record<string, unknown> | null | undefined): ServiceSurface | null {
  const s = data?.surface;
  if (!isRec(s)) return null;
  const sh = isRec(s.security_headers) ? s.security_headers : {};
  const present = strList(sh.present);
  const missing = strList(sh.missing);
  const presentCount = num(sh.present_count) ?? present.length;
  const missingCount = num(sh.missing_count) ?? missing.length;
  const total = presentCount + missingCount;
  const https = isRec(s.tls) && typeof s.tls.https === "boolean" ? s.tls.https : null;
  const cookies: CookieRow[] = isRec(s.cookie_flags)
    ? Object.entries(s.cookie_flags)
        .map(([name, f]) => {
          const r = isRec(f) ? f : {};
          const secure = typeof r.secure === "boolean" ? r.secure : null;
          const httpOnly = typeof r.httponly === "boolean" ? r.httponly : typeof r.http_only === "boolean" ? r.http_only : null;
          const sameSite = str(r.samesite) ?? str(r.same_site);
          const issues: string[] = [];
          if (secure === false && https !== false) issues.push("no Secure flag");
          if (httpOnly === false) issues.push("no HttpOnly flag");
          if (!sameSite || sameSite.toLowerCase() === "none") issues.push(sameSite ? "SameSite=None" : "no SameSite");
          return { name, secure, httpOnly, sameSite, issues };
        })
        .sort((a, b) => b.issues.length - a.issues.length || a.name.localeCompare(b.name))
    : [];
  const c = isRec(s.cors) ? s.cors : null;
  const cors = c
    ? {
        reflectsOrigin: c.reflects_origin === true,
        allowsCredentials: c.allows_credentials === true,
        wildcard: c.wildcard === true,
        risky: c.reflects_origin === true && c.allows_credentials === true,
      }
    : null;
  const r = isRec(s.redirects) ? s.redirects : null;
  const redirects = r ? { count: num(r.count) ?? 0, externalBlocked: num(r.external_blocked) ?? 0 } : null;
  const e = isRec(s.endpoints) ? s.endpoints : null;
  const endpoints = e
    ? {
        total: num(e.total) ?? 0,
        static: num(e.static) ?? 0,
        tested: num(e.tested) ?? 0,
        withFindings: num(e.with_findings) ?? 0,
        authLike: num(e.auth_like) ?? 0,
        sensitive: num(e.sensitive) ?? 0,
      }
    : null;
  const riskScore = num(s.risk_score) === null ? null : Math.max(0, Math.min(100, Math.round(num(s.risk_score)!)));
  const out: ServiceSurface = {
    server: str(s.server),
    technologies: strList(s.technologies),
    headers: { present, missing, presentCount, missingCount, total, ratio: total > 0 ? presentCount / total : null },
    cookies,
    cors,
    redirects,
    tls: tlsText(s.tls),
    https,
    versionDisclosure: strList(s.version_disclosure),
    sensitivePaths: Array.isArray(s.sensitive_paths)
      ? s.sensitive_paths.filter(isRec).map((p) => ({ path: String(p.path ?? ""), reason: String(p.reason ?? ""), served: p.served === true })).filter((p) => p.path)
      : [],
    authPaths: strList(s.auth_paths),
    riskFactors: Array.isArray(s.risk_factors)
      ? s.risk_factors.filter(isRec).map((f) => ({ id: String(f.id ?? ""), points: num(f.points) ?? 0, detail: String(f.detail ?? "") })).filter((f) => f.detail)
      : [],
    endpoints,
    riskScore,
    riskLevel: riskLevel(riskScore),
    explanation: [],
  };
  out.explanation = riskExplanation(out);
  return out;
}

/** The signals the score is built from, strongest first. Plain text, never HTML. */
export function riskExplanation(s: ServiceSurface): string[] {
  // The API's own factors are authoritative: they sum to the score.
  if (s.riskFactors.length) return s.riskFactors.map((f) => `${f.detail} (+${f.points})`);
  const out: string[] = [];
  if (s.endpoints && s.endpoints.withFindings > 0) {
    out.push(`${s.endpoints.withFindings} endpoint${s.endpoints.withFindings === 1 ? "" : "s"} with findings`);
  }
  if (s.cors?.risky) out.push("CORS reflects the Origin header and allows credentials");
  else if (s.cors?.wildcard && s.cors.allowsCredentials) out.push("CORS allows any origin with credentials");
  else if (s.cors?.reflectsOrigin) out.push("CORS reflects the Origin header");
  if (s.headers.missingCount > 0) {
    const names = s.headers.missing.slice(0, 4).join(", ");
    out.push(`${s.headers.missingCount} of ${s.headers.total} security headers missing${names ? ` (${names}${s.headers.missing.length > 4 ? ", …" : ""})` : ""}`);
  }
  const weak = s.cookies.filter((c) => c.issues.length > 0).length;
  if (weak > 0) out.push(`${weak} cookie${weak === 1 ? "" : "s"} without all protective flags`);
  if (s.endpoints && s.endpoints.sensitive > 0) out.push(`${s.endpoints.sensitive} sensitive endpoint${s.endpoints.sensitive === 1 ? "" : "s"} exposed`);
  if (s.endpoints && s.endpoints.authLike > 0) out.push(`${s.endpoints.authLike} authentication-like endpoint${s.endpoints.authLike === 1 ? "" : "s"}`);
  if (s.redirects && s.redirects.externalBlocked > 0) out.push(`${s.redirects.externalBlocked} redirect${s.redirects.externalBlocked === 1 ? "" : "s"} to other hosts blocked by scope`);
  if (s.https === false) out.push("The service is plain http (no TLS)");
  if (s.versionDisclosure.length) out.push(`Version banner disclosed in ${s.versionDisclosure.join(", ")}`);
  if (!out.length && s.riskScore !== null) out.push("No risk signals observed so far");
  return out;
}

export interface EndpointSurface {
  statusCodes: string[];
  contentTypes: string[];
  methods: string[];
  hasForm: boolean;
  passwordForm: boolean;
  /** Parameter count. */
  params: number;
  /** Why the endpoint looks sensitive (null when it does not). */
  sensitive: string | null;
  /** Largest response body seen, in bytes. */
  size: number | null;
}

function listish(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x));
  if (isRec(v)) return Object.keys(v);
  return [];
}

export function endpointSurface(data: Record<string, unknown> | null | undefined): EndpointSurface | null {
  const s = data?.surface;
  if (!isRec(s)) return null;
  const params = Array.isArray(s.params) ? s.params.length : (num(s.params) ?? 0);
  return {
    statusCodes: listish(s.status_codes),
    contentTypes: listish(s.content_types),
    methods: listish(s.methods),
    hasForm: s.has_form === true,
    passwordForm: s.password_form === true,
    params,
    sensitive: typeof s.sensitive === "string" ? str(s.sensitive) : s.sensitive === true ? "sensitive path" : null,
    size: num(s.size),
  };
}

// ---------------------------------------------------------------------------
// Static assets (build output, media): folded away by default
// ---------------------------------------------------------------------------

/** page / api / static / media / other: the server's verdict when present, else computed from path + content type. */
export function endpointClass(n: Pick<AssetNode, "label" | "key" | "data">): AssetClass {
  const surf = n.data?.surface;
  const given = isRec(surf) ? surf.class : null;
  if (given === "page" || given === "api" || given === "static" || given === "media" || given === "other") return given;
  const cts = isRec(surf) ? listish(surf.content_types) : [];
  return classifyPath(endpointPath(n), cts[0] ?? null);
}

/**
 * An in-scope static asset or media file with no finding: folded into its prefix group.
 * Out-of-scope ones (third-party origins) and any with a finding (a secret in a bundle)
 * stay visible as ordinary endpoints.
 */
export function isFoldedStatic(n: AssetNode): boolean {
  return n.kind === "endpoint" && n.in_scope && n.finding_count === 0 && isStaticLike(endpointClass(n));
}

// ---------------------------------------------------------------------------
// Structure helpers
// ---------------------------------------------------------------------------

/** Structural parent: parent_id, else the `contains` / `has_param` edge pointing at the node. */
export function parentMap(state: Pick<AssetGraphState, "nodes" | "edges">): Map<string, string> {
  const out = new Map<string, string>();
  for (const n of state.nodes.values()) if (n.parent_id && state.nodes.has(n.parent_id) && n.kind !== "defense") out.set(n.id, n.parent_id);
  for (const e of state.edges.values()) {
    if ((e.rel === "contains" || e.rel === "has_param") && !out.has(e.dst) && state.nodes.has(e.src) && state.nodes.has(e.dst)) out.set(e.dst, e.src);
  }
  return out;
}

/** Walks up to the owning service (or the asset itself when it is one). */
export function owningService(id: string, nodes: ReadonlyMap<string, AssetNode>, parents: ReadonlyMap<string, string>): AssetNode | null {
  let cur: string | undefined = id;
  for (let i = 0; cur && i < 8; i++) {
    const n = nodes.get(cur);
    if (n?.kind === "service") return n;
    cur = parents.get(cur);
  }
  return null;
}

/** Path of an endpoint: data.path / data.url when given, else parsed from the label or key ("GET /a/b?x=1"). */
export function endpointPath(n: Pick<AssetNode, "label" | "key" | "data">): string {
  const d = n.data ?? {};
  for (const cand of [d.path, d.url, n.label, n.key]) {
    if (typeof cand !== "string") continue;
    const m = /(?:^|\s)(?:https?:\/\/[^/\s]+)?(\/[^\s?#]*)/.exec(cand);
    if (m) return m[1] || "/";
  }
  return n.label || n.key || "/";
}

export function endpointMethod(n: Pick<AssetNode, "label" | "data">): string | null {
  const m = typeof n.data?.method === "string" ? n.data.method : /^([A-Z]{3,7})\s/.exec(n.label)?.[1];
  return m ? m.toUpperCase() : null;
}

/** First path segment as the cluster prefix ("/api/users" -> "/api"; "/" and "/x" stay flat unless shared). */
export function pathPrefix(path: string): string {
  const seg = path.split("/").filter(Boolean)[0];
  return seg ? `/${seg}` : "/";
}

// ---------------------------------------------------------------------------
// Derived view: tree with clusters and collapsed parameters
// ---------------------------------------------------------------------------

/** A prefix needs this many endpoints in a service to become a cluster. */
export const CLUSTER_MIN = 4;
/** Above this many endpoints in the view, clusters start collapsed. */
export const AUTO_COLLAPSE_ENDPOINTS = 40;

export type ViewKind = "host" | "service" | "endpoint" | "parameter" | "defense" | "cluster";

export interface ViewNode {
  /** Render id: the asset id, or `cluster:<service>|<prefix>`. */
  id: string;
  kind: ViewKind;
  asset: AssetNode | null;
  /** Parent in the layout tree (null for roots). */
  parent: string | null;
  /** Cluster details. */
  cluster?: {
    prefix: string; total: number; tested: number; findings: number; expanded: boolean; service: string;
    /** A group of static assets (build output / media) rather than of pages. */
    isStatic?: boolean;
    /** Summed response size of a static group, when known. */
    bytes?: number | null;
  };
  /** Endpoint: parameter count and whether its parameters are shown. */
  params?: { count: number; expanded: boolean };
  /** For a defense: the asset it protects. */
  protects?: string;
}

export interface ViewEdgeOut {
  id: string;
  src: string;
  dst: string;
  rel: AssetEdgeRel;
  secondary: boolean;
}

export interface NetworkView {
  nodes: ViewNode[];
  edges: ViewEdgeOut[];
  endpointCount: number;
  /** Visible endpoints vs all (clusters collapse some). */
  hiddenEndpoints: number;
}

export interface ViewOptions {
  showSecondary: boolean;
  /** Cluster render id -> forced expanded (true) / collapsed (false); absent = automatic. */
  clusterOverrides: ReadonlyMap<string, boolean>;
  /** Endpoint ids whose parameters are shown. */
  expandedParams: ReadonlySet<string>;
  showDefenses: boolean;
  /** Static asset groups start expanded (default false: one collapsed group per prefix). */
  showStatic?: boolean;
  /** Ids that must be visible (selection / deep link): their cluster is expanded. */
  reveal?: ReadonlySet<string>;
}

export const clusterId = (service: string, prefix: string) => `cluster:${service}|${prefix}`;
export const staticClusterId = (service: string, prefix: string) => `cluster:${service}|static:${prefix}`;

const byVersion = (a: AssetNode, b: AssetNode) => a.version - b.version || a.id.localeCompare(b.id);

export function deriveNetworkView(state: Pick<AssetGraphState, "nodes" | "edges">, opts: ViewOptions): NetworkView {
  const { nodes, edges } = state;
  const parents = parentMap(state);
  const kids = new Map<string, AssetNode[]>();
  const roots: AssetNode[] = [];
  for (const n of nodes.values()) {
    if (n.kind === "defense") continue;
    const p = parents.get(n.id);
    if (p) (kids.get(p) ?? kids.set(p, []).get(p)!).push(n);
    else roots.push(n);
  }
  for (const l of kids.values()) l.sort(byVersion);
  roots.sort((a, b) => kindOrder(a.kind) - kindOrder(b.kind) || byVersion(a, b));

  const endpointCount = [...nodes.values()].filter((n) => n.kind === "endpoint" && !isFoldedStatic(n)).length;
  const autoCollapsed = endpointCount > AUTO_COLLAPSE_ENDPOINTS;
  const out: ViewNode[] = [];
  /** Hidden asset id -> the visible node that stands for it (its cluster). */
  const stand = new Map<string, string>();
  let hiddenEndpoints = 0;

  /** Called right after the endpoint's own ViewNode was pushed. */
  const addParams = (ep: AssetNode) => {
    const ps = (kids.get(ep.id) ?? []).filter((k) => k.kind === "parameter");
    const expanded = opts.expandedParams.has(ep.id);
    out[out.length - 1].params = { count: ps.length, expanded };
    for (const p of ps) {
      if (expanded) out.push({ id: p.id, kind: "parameter", asset: p, parent: ep.id });
      else stand.set(p.id, ep.id);
    }
  };

  const emit = (n: AssetNode, parent: string | null) => {
    if (n.kind === "parameter") {
      // Orphan parameter (parent not loaded): shown as-is.
      out.push({ id: n.id, kind: "parameter", asset: n, parent });
      return;
    }
    if (n.kind === "endpoint") {
      out.push({ id: n.id, kind: "endpoint", asset: n, parent });
      addParams(n);
      // Child endpoints (nested paths) follow directly under it.
      for (const c of kids.get(n.id) ?? []) if (c.kind !== "parameter") emit(c, n.id);
      return;
    }
    const k: ViewKind = n.kind === "host" ? "host" : n.kind === "service" ? "service" : "endpoint";
    out.push({ id: n.id, kind: k, asset: n, parent });
    const children = kids.get(n.id) ?? [];
    if (n.kind === "service" || n.kind === "host") {
      const eps = children.filter((c) => c.kind === "endpoint");
      const rest = children.filter((c) => c.kind !== "endpoint");
      for (const c of rest) emit(c, n.id);
      emitEndpoints(n, eps);
    } else for (const c of children) emit(c, n.id);
  };

  const emitStatic = (owner: AssetNode, statics: AssetNode[]) => {
    const groups = new Map<string, AssetNode[]>();
    for (const e of statics) {
      const p = staticPrefix(endpointPath(e));
      (groups.get(p) ?? groups.set(p, []).get(p)!).push(e);
    }
    for (const [prefix, group] of [...groups].sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]))) {
      const cid = staticClusterId(owner.id, prefix);
      const revealed = !!opts.reveal && group.some((g) => opts.reveal!.has(g.id) || (kids.get(g.id) ?? []).some((k) => opts.reveal!.has(k.id)));
      const expanded = opts.clusterOverrides.get(cid) ?? (revealed || !!opts.showStatic);
      let bytes: number | null = null;
      for (const g of group) {
        const sz = endpointSurface(g.data)?.size;
        if (sz != null) bytes = (bytes ?? 0) + sz;
      }
      out.push({
        id: cid, kind: "cluster", asset: null, parent: owner.id,
        cluster: { prefix, total: group.length, tested: group.filter((g) => g.tested).length, findings: 0, expanded, service: owner.id, isStatic: true, bytes },
      });
      for (const g of group) {
        if (expanded) {
          out.push({ id: g.id, kind: "endpoint", asset: g, parent: cid });
          addParams(g);
        } else {
          stand.set(g.id, cid);
          hiddenEndpoints++;
          for (const p of kids.get(g.id) ?? []) stand.set(p.id, cid);
        }
      }
    }
  };

  const emitEndpoints = (owner: AssetNode, all: AssetNode[]) => {
    const eps = all.filter((e) => !isFoldedStatic(e));
    const statics = all.filter(isFoldedStatic);
    const byPrefix = new Map<string, AssetNode[]>();
    for (const e of eps) {
      const p = pathPrefix(endpointPath(e));
      (byPrefix.get(p) ?? byPrefix.set(p, []).get(p)!).push(e);
    }
    const done = new Set<string>();
    for (const e of eps) {
      const prefix = pathPrefix(endpointPath(e));
      const group = byPrefix.get(prefix)!;
      if (group.length < CLUSTER_MIN || prefix === "/") {
        out.push({ id: e.id, kind: "endpoint", asset: e, parent: owner.id });
        addParams(e);
        continue;
      }
      if (done.has(prefix)) continue;
      done.add(prefix);
      const cid = clusterId(owner.id, prefix);
      const forced = opts.clusterOverrides.get(cid);
      const revealed = !!opts.reveal && group.some((g) => opts.reveal!.has(g.id));
      const expanded = forced ?? (revealed || !autoCollapsed);
      out.push({
        id: cid,
        kind: "cluster",
        asset: null,
        parent: owner.id,
        cluster: {
          prefix,
          total: group.length,
          tested: group.filter((g) => g.tested).length,
          findings: group.reduce((s, g) => s + (g.finding_count > 0 ? 1 : 0), 0),
          expanded,
          service: owner.id,
        },
      });
      for (const g of group) {
        if (expanded) {
          out.push({ id: g.id, kind: "endpoint", asset: g, parent: cid });
          addParams(g);
        } else {
          stand.set(g.id, cid);
          hiddenEndpoints++;
          for (const p of kids.get(g.id) ?? []) stand.set(p.id, cid);
        }
      }
    }
    if (statics.length) emitStatic(owner, statics);
  };

  for (const r of roots) emit(r, null);

  // Defenses attach through `protects`.
  if (opts.showDefenses) {
    const visible = new Set(out.map((v) => v.id));
    for (const e of edges.values()) {
      if (e.rel !== "protects") continue;
      const d = nodes.get(e.src);
      if (!d || d.kind !== "defense" || !nodes.has(e.dst)) continue;
      const target = visible.has(e.dst) ? e.dst : stand.get(e.dst);
      if (!target) continue;
      out.push({ id: d.id, kind: "defense", asset: d, parent: null, protects: target });
    }
    // Defenses with no protects edge but a parent_id.
    const have = new Set(out.map((v) => v.id));
    for (const n of nodes.values()) {
      if (n.kind !== "defense" || have.has(n.id) || !n.parent_id) continue;
      const target = visible.has(n.parent_id) ? n.parent_id : stand.get(n.parent_id);
      if (target) out.push({ id: n.id, kind: "defense", asset: n, parent: null, protects: target });
    }
  }

  const shown = new Set(out.map((v) => v.id));
  const resolve = (id: string) => (shown.has(id) ? id : stand.get(id) ?? null);
  const outEdges: ViewEdgeOut[] = [];
  const seen = new Set<string>();
  const push = (id: string, src: string, dst: string, rel: AssetEdgeRel, secondary: boolean) => {
    if (src === dst) return;
    const key = `${src}|${rel}|${dst}`;
    if (seen.has(key)) return;
    seen.add(key);
    outEdges.push({ id, src, dst, rel, secondary });
  };
  // Structural edges from the layout tree (clusters sit between a service and its endpoints).
  for (const v of out) {
    if (v.kind === "defense" && v.protects) push(`protects:${v.id}`, v.id, v.protects, "protects", false);
    else if (v.parent && v.kind !== "defense") {
      const rel: AssetEdgeRel = v.kind === "parameter" ? "has_param" : "contains";
      push(`tree:${v.parent}>${v.id}`, v.parent, v.id, rel, false);
    }
  }
  if (opts.showSecondary) {
    for (const e of edges.values()) {
      if (e.rel !== "links_to" && e.rel !== "redirects_to") continue;
      const s = resolve(e.src);
      const d = resolve(e.dst);
      if (s && d) push(e.id, s, d, e.rel, true);
    }
  }
  return { nodes: out, edges: outEdges, endpointCount, hiddenEndpoints };
}

function kindOrder(k: AssetKind): number {
  return k === "host" ? 0 : k === "service" ? 1 : k === "endpoint" ? 2 : 3;
}

// ---------------------------------------------------------------------------
// Table alternative: filters
// ---------------------------------------------------------------------------

export type AssetStateFilter = "all" | AssetVisual | "untested";

export interface AssetFilters {
  kind: AssetKind | "all";
  state: AssetStateFilter;
  query: string;
  /** Include folded static assets (and their parameters). */
  showStatic?: boolean;
}

export const NO_ASSET_FILTERS: AssetFilters = { kind: "all", state: "all", query: "" };

export function filterAssets(nodes: Iterable<AssetNode>, f: AssetFilters): AssetNode[] {
  const q = f.query.trim().toLowerCase();
  const out: AssetNode[] = [];
  const all = [...nodes];
  const hidden = f.showStatic ? new Set<string>() : hiddenStaticIds(all);
  for (const n of all) {
    if (hidden.has(n.id)) continue;
    if (f.kind !== "all" && n.kind !== f.kind) continue;
    if (f.state !== "all") {
      const v = assetVisual(n);
      if (f.state === "untested" ? !(n.in_scope && !n.tested) : v !== f.state) continue;
    }
    if (q && !`${n.label}\n${n.key}\n${n.kind}\n${n.state}\n${n.id}`.toLowerCase().includes(q)) continue;
    out.push(n);
  }
  return out.sort(
    (a, b) => kindOrder(a.kind) - kindOrder(b.kind) || b.finding_count - a.finding_count || a.label.localeCompare(b.label) || a.id.localeCompare(b.id),
  );
}

/** Ids of folded static endpoints and of their parameters. */
export function hiddenStaticIds(nodes: Iterable<AssetNode>): Set<string> {
  const all = [...nodes];
  const ids = new Set(all.filter(isFoldedStatic).map((n) => n.id));
  for (const n of all) if (n.kind === "parameter" && n.parent_id && ids.has(n.parent_id)) ids.add(n.id);
  return ids;
}

export interface StaticGroupSummary { prefix: string; files: number; bytes: number | null }

/** Folded static assets per prefix, biggest first (for "hidden" summaries). */
export function staticGroups(nodes: Iterable<AssetNode>): StaticGroupSummary[] {
  const m = new Map<string, StaticGroupSummary>();
  for (const n of nodes) {
    if (!isFoldedStatic(n)) continue;
    const prefix = staticPrefix(endpointPath(n));
    const g = m.get(prefix) ?? m.set(prefix, { prefix, files: 0, bytes: null }).get(prefix)!;
    g.files++;
    const sz = endpointSurface(n.data)?.size;
    if (sz != null) g.bytes = (g.bytes ?? 0) + sz;
  }
  return [...m.values()].sort((a, b) => b.files - a.files || a.prefix.localeCompare(b.prefix));
}

/** Counts per kind for the toolbar. */
export function kindCounts(nodes: Iterable<AssetNode>): Record<AssetKind, number> & { staticAssets: number } {
  const all = [...nodes];
  const hidden = hiddenStaticIds(all);
  const c = { host: 0, service: 0, endpoint: 0, parameter: 0, defense: 0, staticAssets: 0 };
  for (const n of all) {
    if (hidden.has(n.id)) {
      if (n.kind === "endpoint") c.staticAssets++;
      continue;
    }
    c[n.kind]++;
  }
  return c;
}

/** Service label without the scheme's default port ("https://h:443" -> "https://h"). */
export function displayService(label: string): string {
  return label.replace(/^(https:\/\/[^/]+?):443(?=\/|$)/i, "$1").replace(/^(http:\/\/[^/]+?):80(?=\/|$)/i, "$1");
}
