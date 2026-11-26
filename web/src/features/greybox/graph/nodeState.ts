// What a node looks like right now: pure so it is testable without a DOM.
import type { ExplorationNode } from "./types";
import { statusCategory, type StatusCategory } from "./encoding";

export type Phase = "running" | "pending" | "done" | "failed" | "muted" | "other";

const PHASE: Partial<Record<StatusCategory, Phase>> = {
  running: "running", planned: "pending", observed: "done", attempted: "failed", skipped: "muted", rejected: "muted",
};

export function phaseOf(n: Pick<ExplorationNode, "kind" | "status">): Phase {
  return PHASE[statusCategory(n.kind, n.status)] ?? "other";
}

export interface NodeVisual {
  phase: Phase;
  /** Pulse / spinner: in flight AND the run is live. */
  pulse: boolean;
  /** The reasoning cycle the agent is on now. */
  current: boolean;
  /** The current cycle is waiting on the model. */
  thinking: boolean;
  /** Extra card classes (outline, tint, opacity); the base border comes from the category. */
  className: string;
}

export interface VisualContext {
  runActive: boolean;
  currentReasoningId: string | null;
  thinking: boolean;
}

/** Muted nodes stay readable (category body opacity is 0.9); mostly colour / outline change. */
export function nodeVisual(n: ExplorationNode, ctx: VisualContext): NodeVisual {
  const phase = phaseOf(n);
  const current = n.kind === "reasoning" && n.id === ctx.currentReasoningId;
  const thinking = current && ctx.thinking && ctx.runActive;
  const live = phase === "running" && ctx.runActive && n.kind !== "objective";
  const pulse = live || thinking;
  const cls: string[] = [];
  if (phase === "running" && ctx.runActive) cls.push("gx-state-running");
  if (phase === "failed") cls.push("gx-state-failed", "!border-severity-critical", "!bg-red-50/60");
  if (phase === "muted") cls.push("gx-state-muted", "bg-canvas");
  if (phase === "pending") cls.push("gx-state-pending");
  if (current) cls.push("gx-state-current");
  if (thinking) cls.push("gx-state-thinking");
  return { phase, pulse, current, thinking, className: cls.join(" ") };
}

/** The active reasoning cycle with the highest number (the agent's present). */
export function currentReasoning(nodes: Iterable<ExplorationNode>): ExplorationNode | null {
  let best: ExplorationNode | null = null;
  for (const n of nodes) {
    if (n.kind !== "reasoning" || n.status !== "active") continue;
    if (!best) best = n;
    else {
      const a = Number.parseInt(n.key, 10);
      const b = Number.parseInt(best.key, 10);
      if ((Number.isFinite(a) && Number.isFinite(b) && a > b) || ((!Number.isFinite(a) || a === b) && n.version > best.version)) best = n;
    }
  }
  return best;
}

/**
 * "Thinking": an llm.request is outstanding (`llmOutstanding`, when the caller knows),
 * else inferred: the run is live and nothing the current cycle spawned is pending or running.
 */
export function isThinking(nodes: Iterable<ExplorationNode>, runActive: boolean, llmOutstanding?: boolean): boolean {
  if (!runActive) return false;
  if (llmOutstanding !== undefined) return llmOutstanding;
  for (const n of nodes) {
    if (n.kind === "work_order" && (n.status === "pending" || n.status === "running")) return false;
    if (n.kind === "action" && n.status === "running") return false;
  }
  return true;
}
