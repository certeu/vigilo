// Pure helpers for the Live Activity tab: filtering, kind presentation and the
// fixed-height windowing maths (collapsed rows have one height, expanded rows add a
// fixed detail height), so 5k+ events render only ~40 DOM rows without a dependency.
import { levelRank, type GreyboxEvent } from "../events";
import { isLlmKind, llmTitle } from "../explorerView";
import { describeEvent } from "./eventView";

export interface ActivityFilters {
  /** Minimum level ("debug" shows everything). */
  level: string;
  /** Kind group ("*" = all) or a kind prefix such as "tool". */
  group: string;
  /** agent_id, "*" for all, "-" for events without an agent. */
  agent: string;
  q: string;
}

export const DEFAULT_FILTERS: ActivityFilters = { level: "info", group: "*", agent: "*", q: "" };

/** First segment of the kind: run, planner, agent, work_order, tool, http, scope, asset, ... */
export const kindGroup = (kind: string): string => {
  const i = kind.indexOf(".");
  return i === -1 ? kind : kind.slice(0, i);
};

export function filterEvents(events: readonly GreyboxEvent[], f: ActivityFilters): GreyboxEvent[] {
  const min = levelRank(f.level);
  const q = f.q.trim().toLowerCase();
  const out: GreyboxEvent[] = [];
  for (const e of events) {
    if (levelRank(e.level) < min) continue;
    if (f.group !== "*" && kindGroup(e.kind) !== f.group) continue;
    if (f.agent !== "*" && (f.agent === "-" ? e.agent_id !== null : e.agent_id !== f.agent)) continue;
    if (q) {
      const hay = `${e.kind} ${e.summary ?? ""} ${e.agent_name ?? ""} #${e.seq}`.toLowerCase();
      if (!hay.includes(q)) continue;
    }
    out.push(e);
  }
  return out;
}

export function distinctGroups(events: readonly GreyboxEvent[]): string[] {
  return [...new Set(events.map((e) => kindGroup(e.kind)))].sort();
}

export function distinctAgents(events: readonly GreyboxEvent[]): { id: string; name: string }[] {
  const m = new Map<string, string>();
  for (const e of events) if (e.agent_id && !m.has(e.agent_id)) m.set(e.agent_id, e.agent_name ?? e.agent_id.slice(0, 8));
  return [...m].map(([id, name]) => ({ id, name })).sort((a, b) => a.name.localeCompare(b.name));
}

export interface KindStyle {
  label: string;
  /** Tailwind classes for the small kind chip. */
  chip: string;
}

const HINT_CHIP = "border-hint-line bg-hint-soft text-hint-ink";

/** Analyst steering / run chat events (hint.added / addressed / rejected / replied) use the `hint` colour token. */
export const isHintKind = (kind: string): boolean => kind.startsWith("hint.");

const HINT_LABEL: Record<string, string> = {
  "hint.added": "Analyst hint",
  "hint.addressed": "Analyst hint addressed",
  "hint.rejected": "Analyst hint rejected",
  "hint.replied": "Agent replied",
};

const LLM_CHIP = "border-indigo-200 bg-indigo-50 text-indigo-800";
const LLM_LABEL: Record<string, string> = { "llm.request": "Explorer", "llm.response": "Explorer", "llm.failed": "Explorer failed" };

/** Row text: a readable sentence per kind (explorer cycles, planner decisions, tool results...). */
export const eventTitle = (e: Pick<GreyboxEvent, "kind" | "summary" | "data">): string =>
  llmTitle(e) ?? describeEvent(e).headline;

export function kindStyle(kind: string): KindStyle {
  if (isLlmKind(kind)) {
    return { label: LLM_LABEL[kind], chip: kind === "llm.failed" ? "border-severity-critical/40 bg-canvas text-severity-critical" : LLM_CHIP };
  }
  if (isHintKind(kind)) return { label: HINT_LABEL[kind] ?? "Analyst hint", chip: HINT_CHIP };
  return { label: kind, chip: "border-line bg-canvas text-slate" };
}

export const LEVEL_DOT: Record<string, string> = {
  debug: "bg-slate/40",
  info: "bg-accent/70",
  warning: "bg-severity-medium",
  error: "bg-severity-critical",
};

/** Escaped, pretty-printed JSON for the detail pane. Plain text only: React escapes it. */
export function formatData(data: unknown, maxChars = 20_000): string {
  let s: string;
  try {
    s = JSON.stringify(data ?? {}, null, 2) ?? "{}";
  } catch {
    s = String(data);
  }
  return s.length > maxChars ? `${s.slice(0, maxChars)}\n… (${s.length - maxChars} more characters)` : s;
}

export const ROW_H = 30;
export const DETAIL_H = 340;

export interface WindowInput {
  count: number;
  /** Sorted indices of expanded rows. */
  expanded: readonly number[];
  scrollTop: number;
  viewportH: number;
  overscan?: number;
  rowH?: number;
  detailH?: number;
}
export interface WindowResult {
  start: number;
  end: number; // exclusive
  padTop: number;
  padBottom: number;
  total: number;
}

function lowerBound(arr: readonly number[], x: number): number {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (arr[mid] < x) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

/** Top offset of row i. */
export function rowTop(i: number, expanded: readonly number[], rowH = ROW_H, detailH = DETAIL_H): number {
  return i * rowH + lowerBound(expanded, i) * detailH;
}

export function computeWindow(w: WindowInput): WindowResult {
  const { count, expanded, scrollTop, viewportH, overscan = 8, rowH = ROW_H, detailH = DETAIL_H } = w;
  const total = rowTop(count, expanded, rowH, detailH);
  if (count === 0) return { start: 0, end: 0, padTop: 0, padBottom: 0, total: 0 };
  // First row whose bottom is below scrollTop (binary search on monotonic rowTop).
  let lo = 0, hi = count - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (rowTop(mid + 1, expanded, rowH, detailH) > scrollTop) hi = mid;
    else lo = mid + 1;
  }
  const first = lo;
  let last = first;
  while (last < count && rowTop(last, expanded, rowH, detailH) < scrollTop + viewportH) last++;
  const start = Math.max(0, first - overscan);
  const end = Math.min(count, last + overscan);
  const padTop = rowTop(start, expanded, rowH, detailH);
  return { start, end, padTop, padBottom: Math.max(0, total - rowTop(end, expanded, rowH, detailH)), total };
}

/** Index of an event by seq in an ascending list (binary search); -1 when absent. */
export function indexOfSeq(list: readonly GreyboxEvent[], seq: number): number {
  let lo = 0, hi = list.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const s = list[mid].seq;
    if (s === seq) return mid;
    if (s < seq) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/** Nearest index with seq >= target (for jumping to an event hidden by a filter). */
export function nearestIndex(list: readonly GreyboxEvent[], seq: number): number {
  let lo = 0, hi = list.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (list[mid].seq < seq) lo = mid + 1;
    else hi = mid;
  }
  return Math.min(lo, list.length - 1);
}

export function parseSeqParam(v: string | null): number | null {
  if (!v || !/^\d+$/.test(v)) return null;
  const n = Number(v);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

// ---- expanded-event view ----

export interface EventField {
  key: string;
  value: string;
}

const VALUE_MAX = 400;
const FIELDS_MAX = 40;

function fieldValue(v: unknown): string {
  let t: string;
  if (v === null || v === undefined) t = "—";
  else if (typeof v === "string") t = v;
  else if (typeof v === "number" || typeof v === "boolean") t = String(v);
  else {
    try { t = JSON.stringify(v) ?? String(v); } catch { t = String(v); }
  }
  return t.length > VALUE_MAX ? `${t.slice(0, VALUE_MAX)}…` : t;
}

/** Top-level data entries as readable key/value rows (bounded; plain text only). */
export function eventFields(data: Record<string, unknown> | null | undefined): { fields: EventField[]; hidden: number } {
  const entries = Object.entries(data ?? {});
  return {
    fields: entries.slice(0, FIELDS_MAX).map(([key, v]) => ({ key: key.replace(/_/g, " "), value: fieldValue(v) })),
    hidden: Math.max(0, entries.length - FIELDS_MAX),
  };
}

/** Full, unclipped JSON for the "Copy JSON" button. */
export function eventJson(e: Pick<GreyboxEvent, "data">): string {
  try {
    return JSON.stringify(e.data ?? {}, null, 2) ?? "{}";
  } catch {
    return String(e.data);
  }
}

export interface FindingEventInfo {
  title: string;
  nodeId: string | null;
}

/** Title and graph node of a finding.* event (data.title, else parsed from the summary). */
export function findingEventInfo(e: Pick<GreyboxEvent, "kind" | "summary" | "data" | "refs">): FindingEventInfo | null {
  if (!e.kind.startsWith("finding.")) return null;
  let title = typeof e.data?.title === "string" ? e.data.title : "";
  if (!title) {
    title = (e.summary ?? "").replace(/^(candidate finding|verified|rejected):\s*/i, "").replace(/\s*\([^()]*\)$/, "");
  }
  return { title: title || "Finding", nodeId: e.refs?.node_ids?.[0] ?? null };
}

/** Run URL query that selects a graph node (the Exploration tab reads `node`). */
export function graphNodeSearch(nodeId: string): string {
  return `?tab=exploration&node=${encodeURIComponent(nodeId)}`;
}
