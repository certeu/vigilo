// Grey-box event wire types. `kind` stays a plain string on
// purpose: new kinds (e.g. hint.added) must render without a client release.

export type EventLevel = "debug" | "info" | "warning" | "error";
export const EVENT_LEVELS: readonly EventLevel[] = ["debug", "info", "warning", "error"];
export type EventSource = "system" | "planner" | "agent" | "api";
export type EventStatus = "ok" | "error" | "blocked" | "pending" | "skipped" | "cancelled";

export interface EventRefs {
  node_ids: string[];
  asset_ids: string[];
  finding_id: string | null;
  exchange_ids: number[];
}

export interface GreyboxEvent {
  seq: number;
  run_id: string;
  ts: string;
  kind: string;
  level: EventLevel | string;
  source: EventSource | string;
  agent_id: string | null;
  agent_name: string | null;
  work_order_id: string | null;
  tool_call_id: string | null;
  summary: string;
  status: EventStatus | string | null;
  duration_ms: number | null;
  refs?: Partial<EventRefs>;
  /** Redacted JSON. Render values as text only, never as HTML. */
  data: Record<string, unknown>;
}

/** GET /greybox/runs/{id}/events (9.6). */
export interface EventsPage {
  items: GreyboxEvent[];
  last_seq: number;
  has_more_before: boolean;
  has_more_after: boolean;
  run_status: string;
}

export type StreamState = "connecting" | "live" | "reconnecting" | "disconnected" | "finished";

const LEVEL_RANK: Record<string, number> = { debug: 0, info: 1, warning: 2, error: 3 };
export const levelRank = (l: string): number => LEVEL_RANK[l] ?? 1;

const TERMINAL_RUN = new Set(["succeeded", "failed", "cancelled"]);
export const isTerminalRunStatus = (s: string | null | undefined): boolean => !!s && TERMINAL_RUN.has(s);

/** Minimal runtime guard: the stream is a trust boundary, never throw on a bad frame. */
export function isGreyboxEvent(v: unknown): v is GreyboxEvent {
  if (!v || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return typeof e.seq === "number" && Number.isFinite(e.seq) && typeof e.kind === "string";
}

/** Matcher for subscribe(): exact kind, "prefix.*" wildcard, a list of those, or a predicate. */
export type EventMatch = string | readonly string[] | ((e: GreyboxEvent) => boolean);

export function compileMatch(match: EventMatch): (e: GreyboxEvent) => boolean {
  if (typeof match === "function") return match;
  const pats = typeof match === "string" ? [match] : match;
  const exact = new Set(pats.filter((p) => !p.endsWith(".*") && p !== "*"));
  const prefixes = pats.filter((p) => p.endsWith(".*")).map((p) => p.slice(0, -1)); // keeps the dot
  const all = pats.includes("*");
  return (e) => all || exact.has(e.kind) || prefixes.some((p) => e.kind.startsWith(p));
}
