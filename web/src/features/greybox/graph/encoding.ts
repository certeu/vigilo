// Visual encoding of the exploration graph. Kind = icon + card outline + text label;
// status = glyph + text label + colour (colour is never the only cue). Tailwind
// class strings are literal so the JIT keeps them.
import type { ExplorationEdgeRel, ExplorationNodeKind, ExplorationNodeStatus } from "./types";

/**
 * What the UI distinguishes (10.1): planned, in progress, observed / done,
 * attempted (failed or blocked), skipped, candidate, verified, rejected.
 */
export type StatusCategory =
  | "planned" | "running" | "observed" | "attempted" | "skipped" | "candidate" | "verified" | "rejected"
  | "defense_proposed" | "defense_unverified";

export const STATUS_CATEGORIES: readonly StatusCategory[] = [
  "planned", "running", "observed", "attempted", "skipped", "candidate", "verified", "rejected",
  "defense_proposed", "defense_unverified",
];

export function statusCategory(kind: ExplorationNodeKind, status: ExplorationNodeStatus): StatusCategory {
  // A hint is live guidance: open = in force (active), addressed = done, rejected = muted.
  if (kind === "hint" && status === "open") return "running";
  if (kind === "defense") return status === "unverified" ? "defense_unverified" : "defense_proposed";
  if (kind === "reasoning") return status === "superseded" ? "skipped" : "running";
  switch (status) {
    case "pending":
    case "open":
      return "planned";
    case "active":
    case "running":
    case "investigating":
      return "running";
    case "done":
    case "addressed":
    case "succeeded":
    case "recorded":
      return "observed";
    case "failed":
    case "blocked":
      return "attempted";
    case "skipped":
    case "cancelled":
      return "skipped";
    case "candidate":
      return "candidate";
    case "verified":
    case "confirmed":
      return "verified";
    case "rejected":
    case "refuted":
      return "rejected";
    case "inconclusive":
      return "skipped";
    default:
      return kind === "observation" ? "observed" : "planned";
  }
}

export interface CategoryStyle {
  label: string;
  /** Text glyph shown next to the status label (screen readers get the label). */
  glyph: string;
  /** Status chip classes. */
  chip: string;
  /** Card border classes. */
  border: string;
  /** Card body extra classes (e.g. faded). */
  body: string;
  description: string;
}

export const CATEGORY_STYLE: Record<StatusCategory, CategoryStyle> = {
  planned: {
    label: "Planned",
    glyph: "○",
    chip: "border-slate/40 bg-white text-slate",
    border: "border-dashed border-slate/60",
    body: "",
    description: "Pending work order, open lead: decided but not started.",
  },
  running: {
    label: "In progress",
    glyph: "◐",
    chip: "border-accent/40 bg-accent/5 text-accent",
    border: "border-accent",
    body: "",
    description: "Running work order or action, lead under investigation, active objective.",
  },
  observed: {
    label: "Observed / done",
    glyph: "●",
    chip: "border-line bg-canvas text-ink",
    border: "border-ink/40",
    body: "",
    description: "Recorded observation, succeeded action, completed work order.",
  },
  attempted: {
    label: "Attempted (failed)",
    glyph: "✕",
    chip: "border-severity-critical/40 bg-red-50 text-severity-critical",
    border: "border-severity-critical",
    body: "",
    description: "Tool or work order that failed or was blocked by the scope guard.",
  },
  skipped: {
    label: "Skipped",
    glyph: "–",
    chip: "border-line bg-canvas text-slate",
    border: "border-dotted border-slate/60",
    body: "opacity-90",
    description: "Skipped (budget, scope, duplicate), cancelled, or lead inconclusive.",
  },
  candidate: {
    label: "Candidate",
    glyph: "?",
    chip: "border-severity-medium/40 bg-amber-50 text-severity-medium",
    border: "border-severity-medium",
    body: "",
    description: "Finding not yet verified.",
  },
  verified: {
    label: "Verified",
    glyph: "✓",
    chip: "border-emerald-600/40 bg-emerald-50 text-emerald-800",
    border: "border-emerald-700 border-2",
    body: "",
    description: "Finding reproduced by a verification action, or lead confirmed.",
  },
  rejected: {
    label: "Rejected",
    glyph: "⊘",
    chip: "border-line bg-canvas text-slate line-through decoration-slate/60",
    border: "border-dashed border-slate/60",
    body: "opacity-90",
    description: "Finding not reproduced, or lead refuted.",
  },
  defense_proposed: {
    label: "Defense proposed",
    glyph: "◆",
    chip: "border-teal-600/40 bg-teal-50 text-teal-800",
    border: "border-teal-600 border-2",
    body: "",
    description: "Suggested detection or WAF rule for a finding. Review before deploying.",
  },
  defense_unverified: {
    label: "Defense unverified",
    glyph: "◇",
    chip: "border-teal-600/30 bg-white text-teal-700",
    border: "border-dashed border-teal-600/60",
    body: "opacity-80",
    description: "Rule not checked against the target. Test it before deploying.",
  },
};

export const STATUS_LABEL: Record<ExplorationNodeStatus, string> = {
  active: "active", done: "done", open: "open", investigating: "investigating", confirmed: "confirmed",
  refuted: "refuted", inconclusive: "inconclusive", pending: "pending", running: "running", failed: "failed", skipped: "skipped",
  cancelled: "cancelled", succeeded: "succeeded", blocked: "blocked", recorded: "recorded",
  candidate: "candidate", verified: "verified", rejected: "rejected", addressed: "addressed", proposed: "proposed", unverified: "unverified",
  superseded: "superseded",
};

export interface KindStyle {
  label: string;
  /** Short legend description. */
  description: string;
  /** Icon tile classes. */
  tile: string;
  /** Card shape classes (radius), a second non-colour cue for the kind. */
  shape: string;
  /** Minimap fill. */
  fill: string;
}

export const KIND_STYLE: Record<ExplorationNodeKind, KindStyle> = {
  objective: {
    label: "Objective",
    description: "What the run sets out to assess.",
    tile: "bg-ink text-white",
    shape: "rounded-2xl",
    fill: "#12161F",
  },
  lead: {
    label: "Lead",
    description: "A hypothesis worth checking, raised by an observation.",
    tile: "bg-hint text-white",
    shape: "rounded-[18px_4px_18px_4px]",
    fill: "#6d28d9",
  },
  work_order: {
    label: "Work order",
    description: "A planned unit of work, assigned to a worker.",
    tile: "bg-sky-800 text-white",
    shape: "rounded-md",
    fill: "#075985",
  },
  action: {
    label: "Action",
    description: "One tool invocation by a worker.",
    tile: "bg-slate text-white",
    shape: "rounded-sm",
    fill: "#606A7B",
  },
  observation: {
    label: "Observation",
    description: "A fact a tool recorded (evidence).",
    tile: "bg-teal-700 text-white",
    shape: "rounded-[4px_18px_4px_18px]",
    fill: "#0f766e",
  },
  finding: {
    label: "Finding",
    description: "A vulnerability: candidate, verified or rejected.",
    tile: "bg-severity-critical text-white",
    shape: "rounded-lg",
    fill: "#B4232C",
  },
  hint: {
    label: "Hint",
    description: "Analyst guidance added during the run. Never widens scope or budgets.",
    tile: "bg-hint/80 text-white ring-1 ring-hint-line",
    shape: "rounded-[4px_18px_18px_18px]",
    fill: "#8b5cf6",
  },
  defense: {
    label: "Defense",
    description: "Suggested detection or WAF rule that mitigates a finding. Generated after the run.",
    tile: "bg-teal-600 text-white",
    shape: "rounded-[18px_18px_4px_18px]",
    fill: "#0d9488",
  },
  reasoning: {
    label: "Reasoning",
    description: "One exploration-agent cycle: the model's analysis and todo list. Everything it spawns is parented here.",
    tile: "bg-indigo-700 text-white",
    shape: "rounded-[18px_4px_18px_18px]",
    fill: "#4338ca",
  },
};

export interface RelStyle {
  label: string;
  color: string;
  dash?: string;
  width: number;
  description: string;
}

export const REL_STYLE: Record<ExplorationEdgeRel, RelStyle> = {
  spawned: { label: "spawned", color: "#606A7B", width: 1.4, description: "The planner decided this because of that." },
  executed: { label: "executed", color: "#075985", width: 1.4, description: "The worker ran the tool." },
  observed: { label: "observed", color: "#0f766e", width: 1.4, description: "The tool produced the fact." },
  investigated: { label: "investigates", color: "#6d28d9", dash: "2 4", width: 1.2, description: "The work order addresses the lead." },
  supports: { label: "supports", color: "#B45309", width: 1.8, description: "Evidence for a finding or lead." },
  contradicts: { label: "contradicts", color: "#B4232C", dash: "2 3", width: 1.4, description: "Evidence against a lead's hypothesis." },
  verified: { label: "verified", color: "#047857", width: 2.4, description: "Verification reproduced the finding." },
  guides: { label: "guides", color: "#6D28D9", dash: "5 4", width: 1.6, description: "An analyst hint steers this node or work order." },
  mitigates: { label: "mitigates", color: "#0d9488", width: 1.8, description: "The suggested rule defends against this finding." },
  refuted: { label: "refuted", color: "#B4232C", dash: "6 4", width: 1.8, description: "Verification failed to reproduce it." },
};

export const SEVERITY_CHIP: Record<string, string> = {
  critical: "border-severity-critical/40 text-severity-critical",
  high: "border-severity-high/40 text-severity-high",
  medium: "border-severity-medium/40 text-severity-medium",
  low: "border-severity-low/40 text-severity-low",
  info: "border-severity-info/40 text-severity-info",
};
