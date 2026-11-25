// Presentation helpers for the exploration agent ("Explorer"): shared by the Live
// Activity tab (llm.* events) and the graph (reasoning nodes). Pure, plain text only.
import type { GreyboxEvent } from "./events";

export type TodoStatus = "pending" | "in_progress" | "done";

export interface TodoItem {
  step: string;
  status: TodoStatus;
}

export const TODO_LABEL: Record<TodoStatus, string> = { pending: "pending", in_progress: "in progress", done: "done" };

const asStatus = (v: unknown): TodoStatus => (v === "done" || v === "in_progress" ? v : "pending");

/** Defensive: the payload is untrusted JSON; anything malformed is dropped. */
export function parseTodolist(v: unknown): TodoItem[] {
  if (!Array.isArray(v)) return [];
  const out: TodoItem[] = [];
  for (const t of v.slice(0, 50)) {
    if (typeof t === "string" && t.trim()) out.push({ step: t, status: "pending" });
    else if (t && typeof t === "object" && typeof (t as { step?: unknown }).step === "string") {
      const o = t as { step: string; status?: unknown };
      out.push({ step: o.step, status: asStatus(o.status) });
    }
  }
  return out;
}

/** "12.3k" style token count. */
export function formatTokens(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "";
  return n < 1000 ? String(Math.round(n)) : `${(n / 1000).toFixed(n < 10_000 ? 1 : 0).replace(/\.0$/, "")}k`;
}

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v : null);
/** A count, or the length of a list of labels (events carry counts, graph nodes carry lists). */
const count = (v: unknown): number | null => (Array.isArray(v) ? v.length : num(v));

export interface ExplorerDetail {
  reasoning: string | null;
  assessment: string | null;
  todolist: TodoItem[];
  model: string | null;
  tokens: number | null;
  trigger: string | null;
  hypotheses: number | null;
  actions: number | null;
}

/** Common view over llm.response event data and reasoning node data. */
export function explorerDetail(data: Record<string, unknown> | null | undefined): ExplorerDetail {
  const d = data ?? {};
  return {
    reasoning: str(d.reasoning),
    assessment: str(d.assessment),
    todolist: parseTodolist(d.todolist),
    model: str(d.model),
    tokens: num(d.tokens),
    trigger: str(d.trigger),
    hypotheses: count(d.hypotheses),
    actions: count(d.actions),
  };
}

export const isLlmKind = (kind: string): boolean => kind === "llm.request" || kind === "llm.response" || kind === "llm.failed";

const plural = (n: number, w: string) => `${n} ${w}${n === 1 ? "" : "s"}`;

/** Cycle number, parsed from the summary ("explorer reasoning cycle 3: ..."). */
export function cycleOf(summary: string | null | undefined): number | null {
  const m = /cycle (\d+)/i.exec(summary ?? "");
  return m ? Number(m[1]) : null;
}

/** One-line, human label of an llm.* event; null for any other kind. */
export function llmTitle(e: Pick<GreyboxEvent, "kind" | "summary" | "data">): string | null {
  if (!isLlmKind(e.kind)) return null;
  const n = cycleOf(e.summary);
  if (e.kind === "llm.request") return "Explorer thinking…";
  if (e.kind === "llm.failed") {
    const err = str(e.data?.error);
    return `Explorer call failed${err ? `: ${err}` : ""}`;
  }
  const d = explorerDetail(e.data);
  const parts: string[] = [];
  if (d.hypotheses !== null) parts.push(plural(d.hypotheses, "hypothesis").replace("hypothesiss", "hypotheses"));
  if (d.actions !== null) parts.push(plural(d.actions, "action"));
  const head = `Explorer cycle ${n ?? "?"}${d.assessment ? `: ${d.assessment}` : ""}`;
  return parts.length ? `${head} — ${parts.join(", ")}` : head;
}

/** Subtle "model · 12.3k tokens" line; null when neither is known. */
export function llmMeta(data: Record<string, unknown> | null | undefined): string | null {
  const d = explorerDetail(data);
  const parts = [d.model, d.tokens !== null ? `${formatTokens(d.tokens)} tokens` : null, d.trigger ? `trigger: ${d.trigger}` : null];
  const s = parts.filter(Boolean).join(" · ");
  return s || null;
}

// ---- live "Agent reasoning" panel ----

export type ExplorerPhase = "idle" | "thinking" | "failed" | "responded";

export interface ExplorerLive {
  phase: ExplorerPhase;
  /** Cycle being worked on (thinking/failed) or last completed (responded). */
  cycle: number | null;
  /** Latest completed cycle (may be older than `cycle` while thinking). */
  last: (ExplorerDetail & { cycle: number | null; seq: number }) | null;
  error: string | null;
  /** Latest scheduler remark about the explorer, human text, or null. */
  decision: string | null;
}

export const DECISION_TEXT: Record<string, string> = {
  waiting_for_explorer: "Scheduler is waiting for the exploration agent",
  explorer_adequate: "Agent judged the assessment adequate; nothing more to do",
  explorer_no_work: "Agent proposed no admissible work; asking again",
  explorer_ask_again: "Asking the agent again for new work",
  explorer_exhausted: "Agent found no new avenues in consecutive rounds; completing",
};

const cycleNum = (e: Pick<GreyboxEvent, "summary" | "data">): number | null => num(e.data?.cycle) ?? cycleOf(e.summary);

/** Latest explorer state from the event list (ascending seq). Scans backwards and stops early. */
export function explorerLive(events: readonly GreyboxEvent[]): ExplorerLive {
  let phase: ExplorerPhase = "idle";
  let cycle: number | null = null;
  let error: string | null = null;
  let last: ExplorerLive["last"] = null;
  let decision: string | null = null;
  let seenLlm = false;
  for (let i = events.length - 1; i >= 0; i--) {
    const e = events[i];
    if (e.kind === "planner.decision") {
      // Only a decision newer than the newest llm.* event is still "current".
      const d = str(e.data?.decision);
      if (!seenLlm && decision === null && d && DECISION_TEXT[d]) decision = DECISION_TEXT[d];
      continue;
    }
    if (!isLlmKind(e.kind)) continue;
    if (!seenLlm) {
      seenLlm = true;
      cycle = cycleNum(e);
      if (e.kind === "llm.request") phase = "thinking";
      else if (e.kind === "llm.failed") (phase = "failed", (error = str(e.data?.error)));
      else phase = "responded";
    }
    if (e.kind === "llm.response") {
      last = { ...explorerDetail(e.data), cycle: cycleNum(e), seq: e.seq };
      break;
    }
  }
  return { phase, cycle: cycle ?? last?.cycle ?? null, last, error, decision };
}
