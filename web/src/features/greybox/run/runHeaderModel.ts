import { endReasonLabel } from "../format";
import { skippedSummary } from "../checksAvailability";
import { RUN_TERMINAL, type RunRead, type RunStatus } from "../types";

export type TabKey = "findings" | "activity" | "exploration" | "defenses" | "report" | "overview" | "traffic" | "network";

/** Findings for a finished run, the live Activity feed for one still working. */
export function defaultTab(status: RunStatus): TabKey {
  return RUN_TERMINAL.has(status) ? "findings" : "activity";
}

const FIRST_LINE_MAX = 110;

/** First line of a (possibly multi-line, long) error, trimmed. `truncated` means a banner should show the rest. */
export function errorHead(error: string): { head: string; truncated: boolean } {
  const lines = error.trim().split(/\r?\n/);
  const first = lines[0].trim();
  const cut = first.length > FIRST_LINE_MAX;
  return { head: cut ? `${first.slice(0, FIRST_LINE_MAX - 1).trimEnd()}…` : first, truncated: cut || lines.length > 1 };
}

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

/**
 * The single outcome line of the run header. null while the run is active (the status
 * and live indicator say it all). `who` resolves a user id to a name for cancelled runs.
 */
export function outcomeLine(run: RunRead, who?: (id: string) => string): string | null {
  return outcomeParts(run, who)?.text ?? null;
}

const BUDGET_STOP: Record<string, string> = {
  budget_requests: "stopped: request budget reached",
  budget_time: "stopped: time budget reached",
};

/** Outcome text plus tone ("warn" when a budget stopped the run) and the skipped-checks note. */
export function outcomeParts(
  run: RunRead,
  who?: (id: string) => string,
): { text: string; tone: "default" | "warn"; note: string | null } | null {
  const text = outcomeText(run, who);
  if (text === null) return null;
  const budget = run.status === "succeeded" && !!run.end_reason && run.end_reason in BUDGET_STOP;
  const note = run.status === "succeeded" ? skippedSummary(run.skipped_checks) : null;
  return { text: note ? `${text} · ${note}` : text, tone: budget ? "warn" : "default", note };
}

function outcomeText(run: RunRead, who?: (id: string) => string): string | null {
  if (!RUN_TERMINAL.has(run.status)) return null;
  if (run.status === "failed") {
    const err = run.error_summary ? errorHead(run.error_summary).head : endReasonLabel(run.end_reason);
    return err && err !== "—" ? `Failed: ${err}` : "Failed";
  }
  if (run.status === "cancelled") {
    const by = run.cancelled_by ? (who ? who(run.cancelled_by) : run.cancelled_by) : null;
    const head = by ? `Cancelled by ${by}` : "Cancelled";
    return run.cancel_reason ? `${head}: ${run.cancel_reason}` : head;
  }
  const c = run.findings;
  const total = c ? c.verified + c.candidate : 0;
  const budget = run.end_reason ? BUDGET_STOP[run.end_reason] : undefined;
  const head = budget ? `Completed (${budget})` : "Completed";
  const stop = !budget && run.end_reason && run.end_reason !== "completed" ? ` · ${endReasonLabel(run.end_reason)}` : "";
  if (!c) return `${head}${stop}`;
  if (total === 0) return `${head}: no findings${stop}`;
  return `${head}: ${plural(total, "finding")} (${c.verified} verified)${stop}`;
}
