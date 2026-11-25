// Model-driven view of a run for the Overview tab: what the exploration agent decided,
// cycle by cycle, built only from the run's llm.* / planner.decision events. There is no
// fixed phase list: the model chooses every step.
import type { GreyboxEvent } from "../events";
import { parseTodolist, type TodoItem } from "../explorerView";
import { describeEvent, triggerText } from "./eventView";

export interface Cycle {
  cycle: number;
  /** seq of the llm.response (or the request while still thinking). */
  seq: number;
  ts: string;
  state: "thinking" | "done" | "failed";
  /** Why the agent was consulted ("run start", "new results since the last cycle"...). */
  trigger: string | null;
  assessment: string | null;
  hypotheses: number | null;
  actions: number | null;
  tools: string[];
  reasoning: string | null;
  error: string | null;
  /** Failed model calls before the outcome of this cycle. */
  failures: number;
}

const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const count = (v: unknown, list: unknown): number | null => (Array.isArray(list) ? list.length : num(v));

/** One entry per cycle number (retries of a failed call collapse into it), ascending. */
export function buildCycles(events: readonly GreyboxEvent[]): Cycle[] {
  const byCycle = new Map<number, Cycle>();
  let open: Cycle | null = null;
  for (const e of events) {
    const d = e.data ?? {};
    if (e.kind === "llm.request") {
      const n = num(d.cycle) ?? (open ? open.cycle : byCycle.size + 1);
      const prev = byCycle.get(n);
      const c: Cycle = {
        cycle: n, seq: e.seq, ts: e.ts, state: "thinking", trigger: triggerText(d.reason),
        assessment: null, hypotheses: null, actions: null, tools: [], reasoning: null, error: null,
        failures: prev?.failures ?? 0,
      };
      byCycle.set(n, c);
      open = c;
    } else if (e.kind === "llm.failed") {
      if (open) {
        open.state = "failed";
        open.error = str(d.error);
        open.failures++;
      }
    } else if (e.kind === "llm.response") {
      const n = num(d.cycle) ?? open?.cycle ?? byCycle.size + 1;
      const prev = byCycle.get(n);
      const tools = Array.isArray(d.action_tools) ? d.action_tools.filter((t): t is string => typeof t === "string") : [];
      byCycle.set(n, {
        cycle: n, seq: e.seq, ts: e.ts, state: "done",
        trigger: triggerText(d.trigger) ?? prev?.trigger ?? null,
        assessment: str(d.assessment), hypotheses: count(d.hypotheses, d.hypothesis_labels),
        actions: count(d.actions, d.action_tools), tools, reasoning: str(d.reasoning),
        error: null, failures: prev?.failures ?? 0,
      });
      open = null;
    }
  }
  return [...byCycle.values()].sort((a, b) => a.cycle - b.cycle);
}

/** Todo list of the newest completed cycle. */
export function latestTodolist(events: readonly GreyboxEvent[]): TodoItem[] {
  for (let i = events.length - 1; i >= 0; i--) {
    if (events[i].kind === "llm.response") return parseTodolist(events[i].data?.todolist);
  }
  return [];
}

export interface SchedulerNote {
  seq: number;
  ts: string;
  text: string;
}

/** Newest planner remarks that are not plain dispatches (leads, rejections, waits, retries). */
export function schedulerNotes(events: readonly GreyboxEvent[], limit = 5): SchedulerNote[] {
  const out: SchedulerNote[] = [];
  for (let i = events.length - 1; i >= 0 && out.length < limit; i--) {
    const e = events[i];
    if (e.kind !== "planner.decision") continue;
    const decision = str(e.data?.decision);
    if (decision === "dispatch" || decision === "waiting_for_explorer") continue;
    out.push({ seq: e.seq, ts: e.ts, text: describeEvent(e).headline });
  }
  return out.reverse();
}

export interface ExplorationCounts {
  cycles: number;
  failedCalls: number;
  workOrdersQueued: number;
  toolsRun: number;
  findingsCandidate: number;
  findingsVerified: number;
}

/** Counters derived from the loaded events (the run summary counters are shown alongside). */
export function explorationCounts(events: readonly GreyboxEvent[]): ExplorationCounts {
  const c: ExplorationCounts = { cycles: 0, failedCalls: 0, workOrdersQueued: 0, toolsRun: 0, findingsCandidate: 0, findingsVerified: 0 };
  const cycles = new Set<number>();
  for (const e of events) {
    switch (e.kind) {
      case "llm.response": { const n = num(e.data?.cycle); if (n !== null) cycles.add(n); else c.cycles++; break; }
      case "llm.failed": c.failedCalls++; break;
      case "work_order.created": c.workOrdersQueued++; break;
      case "tool.succeeded": c.toolsRun++; break;
      case "finding.created": c.findingsCandidate++; break;
      case "finding.verified": c.findingsVerified++; break;
    }
  }
  c.cycles += cycles.size;
  return c;
}
