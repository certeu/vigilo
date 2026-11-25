// Pure logic of the HTTP Traffic view: filters, status colouring, row flags,
// live merge, redaction helpers and the "Copy as curl" builder. No React here.
import { classifyPath, groupLabel, isStaticLike, staticPrefix } from "../assetClass";
import { reasonSentence } from "../run/hintLogic";
import type { Exchange, ExchangeSide, ExchangeSummary, TrafficQuery } from "../types";

/** Documented per-body storage cap. The API does not expose it. */
export const BODY_STORE_CAP_KB = 64;

export type StatusClass = "all" | "2xx" | "3xx" | "4xx" | "5xx" | "none";
export const STATUS_CLASSES: readonly StatusClass[] = ["all", "2xx", "3xx", "4xx", "5xx", "none"];
export const STATUS_CLASS_LABEL: Record<StatusClass, string> = {
  all: "Any status", "2xx": "2xx", "3xx": "3xx", "4xx": "4xx", "5xx": "5xx", none: "No response",
};

export interface TrafficFilters {
  method: string; // "" = any
  statusClass: StatusClass;
  host: string;
  pathPrefix: string;
  blockedOnly: boolean;
  hasFindings: boolean;
  workOrderId: string;
  findingId: string;
}
export const DEFAULT_TRAFFIC_FILTERS: TrafficFilters = {
  method: "", statusClass: "all", host: "", pathPrefix: "", blockedOnly: false, hasFindings: false, workOrderId: "", findingId: "",
};
export const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const;

/** Filters that the server applies (the API only knows an exact status_code, so status class and has-findings are client-side). */
export function filtersToQuery(f: TrafficFilters, extra: Pick<TrafficQuery, "limit" | "after_id"> = {}): TrafficQuery {
  const q: TrafficQuery = {};
  if (f.method) q.method = f.method;
  if (f.host.trim()) q.host = f.host.trim().toLowerCase();
  if (f.pathPrefix.trim()) q.path_prefix = f.pathPrefix.trim();
  if (f.blockedOnly) q.blocked = true;
  if (f.workOrderId) q.work_order_id = f.workOrderId;
  if (f.findingId) q.finding_id = f.findingId;
  if (extra.limit) q.limit = Math.min(200, extra.limit);
  if (extra.after_id != null) q.after_id = extra.after_id;
  return q;
}

/** Stable key of the server-side part of the filters: a change refetches from scratch. */
export const serverKey = (f: TrafficFilters): string => JSON.stringify(filtersToQuery(f));

export function statusClass(code: number | null | undefined): Exclude<StatusClass, "all"> {
  if (code == null || code < 100 || code > 599) return "none";
  return `${Math.floor(code / 100)}xx` as Exclude<StatusClass, "all" | "none">;
}

/** Tailwind text colour by status class (never colour alone: the number is always shown). */
export const STATUS_COLOR: Record<Exclude<StatusClass, "all">, string> = {
  "2xx": "text-emerald-700",
  "3xx": "text-accent",
  "4xx": "text-severity-medium",
  "5xx": "text-severity-critical",
  none: "text-slate",
};
export const statusColor = (code: number | null | undefined): string => STATUS_COLOR[statusClass(code)];

export function matchesClient(x: ExchangeSummary, f: TrafficFilters): boolean {
  if (f.statusClass !== "all" && statusClass(x.status_code) !== f.statusClass) return false;
  if (f.hasFindings && x.finding_ids.length === 0) return false;
  return true;
}
export const clientFilter = (items: readonly ExchangeSummary[], f: TrafficFilters): ExchangeSummary[] =>
  f.statusClass === "all" && !f.hasFindings ? (items as ExchangeSummary[]) : items.filter((x) => matchesClient(x, f));

/** Append rows keyed by id, ascending, dropping ids already present (after_id pages and live fetches can overlap). */
export function mergeRows(existing: readonly ExchangeSummary[], incoming: readonly ExchangeSummary[]): ExchangeSummary[] {
  if (incoming.length === 0) return existing as ExchangeSummary[];
  const seen = new Set(existing.map((x) => x.id));
  const fresh = incoming.filter((x) => (seen.has(x.id) ? false : (seen.add(x.id), true)));
  if (fresh.length === 0) return existing as ExchangeSummary[];
  const out = [...existing, ...fresh];
  for (let i = 1; i < out.length; i++) if (out[i - 1].id > out[i].id) return out.sort((a, b) => a.id - b.id);
  return out;
}

export const lastId = (rows: readonly ExchangeSummary[]): number => (rows.length ? rows[rows.length - 1].id : 0);

/** exchange id carried by an http.exchange / scope.blocked event, if any. */
export function eventExchangeId(e: { data?: Record<string, unknown>; refs?: { exchange_ids?: number[] } }): number | null {
  const d = e.data?.exchange_id;
  if (typeof d === "number") return d;
  const r = e.refs?.exchange_ids?.[0];
  return typeof r === "number" ? r : null;
}

// ---- static asset folding ----

export interface StaticGroupItem {
  type: "group";
  /** host:port + prefix: third-party origins get their own group. */
  key: string;
  host: string;
  prefix: string;
  count: number;
  bytes: number | null;
  expanded: boolean;
  label: string;
}
export interface ExchangeItem { type: "exchange"; x: ExchangeSummary; /** Member of an expanded static group. */ nested: boolean }
export type TrafficItem = ExchangeItem | StaticGroupItem;

/**
 * A static asset (script, stylesheet, font, image) that answered normally. Blocked
 * requests, errors, 4xx/5xx answers and anything linked to a finding stay visible: those
 * are exactly what an analyst needs among thousands of chunk downloads.
 */
export function isFoldedStaticExchange(x: ExchangeSummary): boolean {
  if (x.blocked || x.error || x.finding_ids.length > 0) return false;
  const code = x.status_code;
  if (code == null || code >= 400) return false;
  return isStaticLike(classifyPath(x.path ?? "/", x.content_type));
}

export interface FoldOptions {
  /** Flat list, nothing folded. */
  showStatic: boolean;
  /** Group keys the user opened. */
  expanded: ReadonlySet<string>;
  /** An exchange that must stay visible (the open detail): its group is expanded. */
  reveal?: number | null;
}

export const staticGroupKey = (x: Pick<ExchangeSummary, "scheme" | "host" | "port" | "path">): string =>
  `${hostPort({ scheme: x.scheme, host: x.host, port: x.port })}|${staticPrefix(x.path ?? "/")}`;

/** Rows to list: static assets of one host and prefix collapse into a single group row placed
 * at the first member's position (members follow it when the group is expanded). */
export function foldStatic(rows: readonly ExchangeSummary[], o: FoldOptions): TrafficItem[] {
  if (o.showStatic) return rows.map((x) => ({ type: "exchange", x, nested: false }));
  const members = new Map<string, ExchangeSummary[]>();
  for (const x of rows) {
    if (!isFoldedStaticExchange(x)) continue;
    const k = staticGroupKey(x);
    (members.get(k) ?? members.set(k, []).get(k)!).push(x);
  }
  const out: TrafficItem[] = [];
  const placed = new Set<string>();
  for (const x of rows) {
    if (!isFoldedStaticExchange(x)) {
      out.push({ type: "exchange", x, nested: false });
      continue;
    }
    const key = staticGroupKey(x);
    if (placed.has(key)) continue;
    placed.add(key);
    const list = members.get(key)!;
    const expanded = o.expanded.has(key) || (o.reveal != null && list.some((m) => m.id === o.reveal));
    let bytes: number | null = null;
    for (const m of list) if (m.response_size != null) bytes = (bytes ?? 0) + m.response_size;
    const host = hostPort(x);
    const prefix = staticPrefix(x.path ?? "/");
    out.push({ type: "group", key, host, prefix, count: list.length, bytes, expanded, label: groupLabel(prefix, list.length, bytes, host) });
    if (expanded) for (const m of list) out.push({ type: "exchange", x: m, nested: true });
  }
  return out;
}

/** Static files still hidden in collapsed groups, or null when nothing is folded. */
export function foldSummary(items: readonly TrafficItem[]): { files: number; groups: number } | null {
  let files = 0;
  let groups = 0;
  for (const i of items) if (i.type === "group" && !i.expanded) { files += i.count; groups++; }
  return groups ? { files, groups } : null;
}

// ---- presentation helpers ----

export function hostPort(x: Pick<ExchangeSummary, "scheme" | "host" | "port">): string {
  if (!x.host) return "—";
  const dflt = (x.scheme === "https" && x.port === 443) || (x.scheme === "http" && x.port === 80);
  return x.port != null && !dflt ? `${x.host}:${x.port}` : x.host;
}

export function formatSize(n: number | null | undefined): string {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}
export const formatMs = (n: number | null | undefined): string => (n == null ? "—" : n < 1000 ? `${n} ms` : `${(n / 1000).toFixed(1)} s`);

const IP_CATEGORY: Record<string, string> = {
  loopback: "a loopback address", private: "a private network address", link_local: "a link-local address",
  metadata: "a cloud metadata address", multicast: "a multicast address", reserved: "a reserved address",
  unspecified: "an unspecified address",
};

/** "Blocked by scope policy: …" in plain words; scope codes reuse the hint reason sentences. */
export function blockSentence(reason: string | null | undefined): string {
  const m = /^ip_denied:(.+)$/.exec(reason ?? "");
  const why = m
    ? `the host resolves to ${IP_CATEGORY[m[1]] ?? `a denied address (${m[1].replace(/_/g, " ")})`}, which is never contacted`
    : reasonSentence(reason).replace(/^(Rejected|Not applied):\s*/, "").replace(/^./, (c) => c.toLowerCase());
  return `Blocked by scope policy: ${why}`;
}

const ERROR_TEXT: Record<string, string> = {
  connect_error: "connection refused or no route to host",
  dns_error: "the host name did not resolve",
  timeout: "the request timed out",
  transport_error: "the connection failed",
};
export const errorSentence = (e: string): string => ERROR_TEXT[e] ?? e;

export function omittedSentence(reason: string | null | undefined): string {
  switch (reason) {
    case "binary": return "binary content is never stored";
    case "not_captured": return "no body was captured";
    case "too_large": case "too_big": return "the body was too large";
    default: return reason ? reason.replace(/_/g, " ") : "not stored";
  }
}

/** Short row summary of the flags. */
export interface RowFlags { blocked: boolean; error: boolean; hop: number; findings: number }
export const rowFlags = (x: ExchangeSummary): RowFlags => ({
  blocked: x.blocked, error: !!x.error, hop: x.redirect_hop, findings: x.finding_ids.length,
});

// ---- redaction ----

export const REDACTED = "***";
export const isRedacted = (v: string): boolean => v.includes(REDACTED);
const PLACEHOLDER = "<REDACTED>";
export const placeholderize = (s: string): string => s.split(REDACTED).join(PLACEHOLDER).split("%2A%2A%2A").join(PLACEHOLDER);

// ---- body viewer ----

export interface BodyView { text: string; pretty: boolean }

export function isJsonType(ct: string | null | undefined, text: string): boolean {
  if (/json/i.test(ct ?? "")) return true;
  const t = text.trimStart();
  return (t.startsWith("{") || t.startsWith("[")) && /[}\]]\s*$/.test(t);
}
/** Pretty-print JSON; null when it does not parse (e.g. a truncated body). */
export function prettyJson(text: string): string | null {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return null;
  }
}

export const contentTypeOf = (side: ExchangeSide): string | null =>
  side.headers.find(([n]) => n.toLowerCase() === "content-type")?.[1] ?? null;

// ---- Copy as curl ----

const shq = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;
const SKIP_HEADERS = new Set(["host", "content-length", "connection", "accept-encoding", "transfer-encoding"]);

export const CURL_NOTE = "Redacted values are kept as <REDACTED> placeholders: fill them in before running.";

export function buildCurl(x: Pick<Exchange, "method" | "url" | "request">): string {
  const parts = [`curl -X ${shq(x.method)} ${shq(placeholderize(x.url))}`];
  for (const [n, v] of x.request.headers) {
    if (SKIP_HEADERS.has(n.toLowerCase())) continue;
    parts.push(`-H ${shq(`${n}: ${placeholderize(v)}`)}`);
  }
  const body = x.request.body;
  const lines = [`# ${CURL_NOTE}`];
  if (body) {
    parts.push(`--data-raw ${shq(placeholderize(body))}`);
    if (x.request.body_truncated) lines.push("# The stored request body was truncated.");
  } else if (x.request.body_omitted_reason) {
    lines.push(`# Request body not stored (${omittedSentence(x.request.body_omitted_reason)}).`);
  }
  return `${lines.join("\n")}\n${parts.join(" \\\n  ")}`;
}

// ---- URL params ----

export function filtersFromParams(p: URLSearchParams): TrafficFilters {
  return {
    ...DEFAULT_TRAFFIC_FILTERS,
    workOrderId: p.get("work_order") ?? p.get("work_order_id") ?? "",
    findingId: p.get("finding") ?? p.get("finding_id") ?? "",
  };
}
export function parseExchangeParam(v: string | null): number | null {
  if (!v || !/^\d{1,15}$/.test(v)) return null;
  return Number(v);
}
/** Link to the Traffic tab with an exchange open (Findings evidence, Network map). */
export const trafficLink = (exchangeId: number): string => `?tab=traffic&exchange=${exchangeId}`;
