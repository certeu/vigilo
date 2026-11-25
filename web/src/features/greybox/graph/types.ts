// Exploration graph wire types. Mirrors the API's graph envelope and its node
// kinds, statuses and relations exactly. Fields marked
// "proposed" are NOT in the contract yet; they
// are optional so the UI works with or without them.

export type ExplorationNodeKind = "objective" | "lead" | "work_order" | "action" | "observation" | "finding" | "hint" | "defense" | "reasoning";

export const NODE_KINDS: readonly ExplorationNodeKind[] = [
  "objective", "lead", "work_order", "action", "observation", "finding", "hint", "defense", "reasoning",
];

/** Per-kind statuses (10.1). Kept as a union of every value; `STATUSES_BY_KIND` scopes them. */
export type ExplorationNodeStatus =
  // objective
  | "active" | "done"
  // lead
  | "open" | "investigating" | "confirmed" | "refuted" | "inconclusive"
  // work_order (also "done")
  | "pending" | "running" | "failed" | "skipped" | "cancelled"
  // action (also "running", "failed")
  | "succeeded" | "blocked"
  // observation
  | "recorded"
  // finding
  | "candidate" | "verified" | "rejected"
  // hint (also "open", "rejected")
  | "addressed"
  // defense
  | "proposed" | "unverified"
  // reasoning (exploration-agent cycle; also "active")
  | "superseded";

export const STATUSES_BY_KIND: Record<ExplorationNodeKind, readonly ExplorationNodeStatus[]> = {
  reasoning: ["active", "superseded"],
  objective: ["active", "done"],
  lead: ["open", "investigating", "confirmed", "refuted", "inconclusive"],
  work_order: ["pending", "running", "done", "failed", "skipped", "cancelled"],
  action: ["running", "succeeded", "failed", "blocked", "cancelled"],
  observation: ["recorded"],
  finding: ["candidate", "verified", "rejected"],
  hint: ["open", "addressed", "rejected"],
  defense: ["proposed", "unverified"],
};

export type ExplorationEdgeRel =
  | "spawned" | "executed" | "observed" | "investigated" | "supports" | "contradicts" | "verified" | "refuted" | "guides" | "mitigates";

export const EDGE_RELS: readonly ExplorationEdgeRel[] = [
  "spawned", "executed", "observed", "investigated", "supports", "contradicts", "verified", "refuted", "guides", "mitigates",
];

export interface ExplorationNode {
  id: string;
  kind: ExplorationNodeKind;
  key: string;
  label: string;
  status: ExplorationNodeStatus;
  agent_id: string | null;
  work_order_id: string | null;
  finding_id: string | null;
  asset_id: string | null;
  /** seq of the event that created it (deep link to Live Activity). */
  event_seq: number | null;
  /** Small, redacted JSON. Render values as text only. */
  data: Record<string, unknown>;
  version: number;
  // ---- proposed additions (optional until the contract adopts them) ----
  /** Graph version at which the node was first written (new vs. changed in a delta). */
  created_version?: number;
  created_at?: string;
  updated_at?: string;
  /** Primary parent (the node that spawned it); used to place new nodes and to collapse branches. */
  parent_id?: string | null;
  /** Joined at read time like events' `agent_name`. */
  agent_name?: string | null;
  /** Up to 20 HTTP exchange ids that back this node (evidence, links to Traffic). */
  exchange_ids?: number[];
  /** seq of the event that last changed the status. */
  last_event_seq?: number | null;
  /** Finding nodes: severity, so the card can show it without another fetch. */
  severity?: "critical" | "high" | "medium" | "low" | "info" | null;
  /**
   * Work orders / leads: explicit result, including negative ones (a
   * coverage ledger), so "checked, nothing found" is distinct from "not checked".
   */
  outcome?: WorkOutcome | null;
  /** Assets this node touched (anchors); `asset_id` stays the primary one. */
  asset_ids?: string[];
}

export type WorkOutcome = "reported" | "no_issue_found" | "ruled_out" | "not_applicable" | "needs_follow_up";

export const OUTCOME_LABEL: Record<WorkOutcome, string> = {
  reported: "finding reported",
  no_issue_found: "no issue found",
  ruled_out: "ruled out",
  not_applicable: "not applicable",
  needs_follow_up: "needs follow-up",
};

export interface ExplorationEdge {
  id: string;
  src: string;
  dst: string;
  rel: ExplorationEdgeRel;
  version: number;
}

export interface ExplorationGraphResponse {
  version: number;
  since_version: number;
  full: boolean;
  truncated: boolean;
  /** Present when truncated: nodes missing per kind (9.8). */
  truncated_by_kind?: Partial<Record<ExplorationNodeKind, number>>;
  total_nodes: number;
  total_edges: number;
  nodes: ExplorationNode[];
  edges: ExplorationEdge[];
  /** proposed: agent directory for the filter (id -> name, role). */
  agents?: { id: string; name: string; role: string }[];
}

/** Node drawer payload (9.8). The contract only names its parts; extra fields are tolerated. */
/** Neighbour summary in the node drawer (9.8). */
export interface ExplorationNeighbour {
  id: string;
  kind: ExplorationNodeKind;
  label: string;
  status: ExplorationNodeStatus;
  severity: string | null;
  outcome: string | null;
  rel: ExplorationEdgeRel;
  direction: "in" | "out";
}

/** GET /greybox/runs/{run_id}/graph/exploration/nodes/{node_id} (9.8). Mirrors
 * `ExplorationNodeDetail` in src/greybox_web/schemas.py; the linked work order,
 * finding and exchange summaries are typed loosely until the drawer uses them. */
export interface ExplorationNodeDetail {
  node: ExplorationNode;
  in_edges: ExplorationEdge[];
  out_edges: ExplorationEdge[];
  neighbours: ExplorationNeighbour[];
  work_order: Record<string, unknown> | null;
  finding: Record<string, unknown> | null;
  agent_name: string | null;
  exchanges: Array<Record<string, unknown> & { id: number }>;
}
