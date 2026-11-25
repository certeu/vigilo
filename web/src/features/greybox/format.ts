// Small display helpers shared by grey-box and unified pages.
import { statusLabel } from "../../lib/status";

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  const s = Math.max(0, Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const r = s % 60;
  if (h) return `${h}h ${m}m`;
  if (m) return r ? `${m}m ${r}s` : `${m}m`;
  return `${r}s`;
}

/** Exact local time, for title attributes and absolute displays. */
export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}

/** Local time of day (no date, no ms) for dense timelines; the exact time goes in the title. */
export function formatClock(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour12: false });
}

/** Exact local time with milliseconds (Live Activity expanded view only). */
export function formatDateMs(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour12: false })}.${ms}`;
}

/** "just now", "5 min ago", "3 h ago", "2 d ago"; older than 30 days falls back to a date. */
export function formatRelative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return "—";
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const diff = Math.round((now - t) / 1000);
  if (diff < -60) return new Date(t).toLocaleDateString();
  if (diff < 45) return "just now";
  const min = Math.round(diff / 60);
  if (min < 60) return `${min} min ago`;
  const h = Math.round(diff / 3600);
  if (h < 24) return `${h} h ago`;
  const d = Math.round(diff / 86400);
  if (d <= 30) return `${d} d ago`;
  return new Date(t).toLocaleDateString();
}

/** Props for a <time>-like element: relative text plus the exact local time as title. */
export function timeParts(iso: string | null | undefined, now?: number): { text: string; title: string | undefined } {
  return { text: formatRelative(iso, now), title: iso ? formatDate(iso) : undefined };
}

export function shortId(id: string): string {
  return id.slice(0, 8);
}

/** Random idempotency key (8..64 chars) for POST /greybox/targets/{id}/runs. */
export function newIdempotencyKey(): string {
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) return crypto.randomUUID();
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
}


/** UI label for a run status ("Completed" for `succeeded`). */
export function runStatusLabel(status: string): string {
  return statusLabel(status);
}

/** Human wording for `end_reason` values defined. Unknown values are shown as-is. */
const END_REASON: Record<string, string> = {
  completed: "All planned work finished",
  stalled: "Stopped: the agent ran out of admissible work with surface left unexplored",
  budget_requests: "Stopped: request budget reached",
  budget_time: "Stopped: time budget reached",
  cancelled: "Cancelled",
  error: "Stopped by an error",
  lease_expired: "Worker lost contact (lease expired)",
};
export function endReasonLabel(reason: string | null | undefined): string {
  if (!reason) return "—";
  return END_REASON[reason] ?? reason;
}
