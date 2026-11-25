// Grey-box API types. Mirrors the grey-box API (src/greybox_web/schemas.py) exactly;
// keep in sync by hand (no OpenAPI codegen in this repo).

export type RunStatus =
  | "queued" | "preparing" | "running" | "cancelling" | "succeeded" | "failed" | "cancelled";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus = "candidate" | "verified" | "rejected";

export const RUN_TERMINAL: ReadonlySet<RunStatus> = new Set(["succeeded", "failed", "cancelled"]);

/** Target-neutral boundary for network assessments (server: netscope.py). */
export interface NetworkScope {
  targets: string[];
  ports: (number | string)[];
  protocols: ("tcp" | "dns" | "http")[];
  rate_per_s?: number;
  connect_timeout_s?: number;
}

export type AssessmentMode = "web" | "network" | "artifact";

export interface ScopePolicy {
  allowed_hosts: string[];
  allowed_schemes: ("http" | "https")[];
  allowed_ports: number[];
  path_prefixes: string[];
  excluded_paths: string[];
  redirect_policy: "in_scope" | "none";
  allow_auth_testing: boolean;
  /** Present only for network assessments. */
  network?: NetworkScope | null;
  /** State-changing requests (PUT/PATCH/DELETE) only when true. */
  activity?: { state_changing: boolean } | null;
}

/** All enforced by the engine. */
export interface Limits {
  max_requests: number;
  max_duration_s: number;
  max_concurrency: number;
  rate_limit_rps: number;
  request_timeout_s: number;
  max_pages: number;
}

export interface CredentialRef {
  id: string;
  label: string;
  kind: "cookie_header";
}

export interface FindingCounts {
  candidate: number;
  verified: number;
  rejected: number;
  /** Counts candidate + verified only. */
  by_severity: Record<Severity, number>;
}

export interface GreyboxCheck {
  id: string;
  title: string;
  description: string;
  /** Missing on older servers. */
  area?: string;
  evidence?: string;
  default_enabled: boolean;
  requires_auth_testing: boolean;
  /** Missing (older backend) means available. */
  available?: boolean;
  unavailable_reason?: string | null;
}

export interface SkippedCheck {
  id: string;
  reason: string;
}

export interface AgentBackend {
  id: string;
  label: string;
  models: string[];
  /** false: shown disabled, with `reason` as the hint. */
  available?: boolean;
  reason?: string;
}

export interface AgentConfig {
  /** false: no model is configured; runs cannot start. */
  available: boolean;
  /** Selectable model backends (same ones white-box uses). */
  backends?: AgentBackend[];
  /** Server default selection. */
  default?: { backend: string; model: string | null } | null;
  /** Legacy single-backend fields (older servers). */
  backend?: string;
  model?: string;
  max_calls?: number;
  max_tokens?: number;
  timeout_s?: number;
}

export interface GreyboxConfig {
  enabled: boolean;
  executor: string;
  allow_private_targets: boolean;
  checks: GreyboxCheck[];
  limits: { defaults: Limits; max: Limits };
  agent?: AgentConfig;
}

export interface TargetCreate {
  name: string;
  description?: string | null;
  base_url: string;
  scope?: Partial<ScopePolicy>;
  limits?: Partial<Limits>;
  /** null (or omitted) = server defaults; see TargetRead.checks. */
  checks?: string[] | null;
  credential_id?: string | null;
  /** Synthetic test accounts (login_account credentials) the run logs in with. */
  account_ids?: string[];
  /** Opt-in egress proxy; null/omitted = direct. */
  egress_proxy_id?: string | null;
  /** Model backend id / model for the exploration agent; null/omitted = server default. */
  model_backend?: string | null;
  model?: string | null;
  /** web (default) | network | artifact: selects the run's capabilities. */
  assessment_mode?: AssessmentMode;
}

export type TargetUpdate = Partial<TargetCreate> & { archived?: boolean };

export interface TargetRead {
  id: string;
  owner_id: string;
  name: string;
  description: string | null;
  base_url: string;
  scope: ScopePolicy;
  scope_summary: string[];
  limits: Limits;
  /** Always the resolved list (stored null resolves to the defaults). */
  checks: string[];
  credential: CredentialRef | null;
  accounts?: CredentialRef[];
  egress_proxy_id?: string | null;
  egress_proxy?: { id: string; name: string } | null;
  archived: boolean;
  model_backend?: string | null;
  model?: string | null;
  created_at: string;
  updated_at: string;
  last_run: { id: string; status: RunStatus; created_at: string } | null;
  assessment_mode?: AssessmentMode;
}

/**
 * One validation error. `loc` always starts with "body" and may contain numeric list
 * indexes, e.g. ["body","scope","allowed_hosts",1] (same shape as a 422 `detail[]`).
 */
export interface ValidationError {
  loc: (string | number)[];
  msg: string;
  type?: string;
}

export interface TargetValidation {
  valid: boolean;
  normalized: TargetCreate | null;
  scope_summary: string[];
  errors: ValidationError[];
  warnings: string[];
}

export interface Page<T> {
  items: T[];
  next_cursor: string | null;
}

export interface RunSummary {
  id: string;
  target: { id: string; name: string; base_url: string };
  owner_id: string;
  status: RunStatus;
  phase: string | null;
  end_reason: string | null;
  cancel_requested: boolean;
  findings: FindingCounts;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

export type ReportStatus = "pending" | "generating" | "ready" | "failed";

export interface RunCounters {
  /** = last_seq */
  events: number;
  requests: number;
  requests_blocked: number;
  assets: number;
  endpoints: number;
  work_orders: {
    pending: number; running: number; done: number; failed: number; skipped: number; cancelled: number;
  };
  agents_active: number;
}

// Contract 9.5. Counters are computed server-side from persisted rows; the UI shows only
// the fields that are actually present (no client-side guesses), so the newer fields are
// typed optional to stay honest against partial M2 builds.
export interface RunRead extends RunSummary {
  error_summary: string | null;
  scope: ScopePolicy;
  scope_summary: string[];
  limits: Limits;
  checks: string[];
  credential: CredentialRef | null;
  egress_proxy?: { id: string; name: string } | null;
  model_backend?: string | null;
  model?: string | null;
  skipped_checks?: SkippedCheck[] | null;
  counters?: Partial<RunCounters> | null;
  last_seq?: number;
  graph_version?: number;
  heartbeat_at?: string | null;
  last_event_at?: string | null;
  report_status?: ReportStatus;
  /** Not returned by the API yet (cancel reason is only sent in the cancel request); shown when present. */
  cancel_reason?: string | null;
  cancelled_by?: string | null;
  /** The honest completion verdict (server coverage.py); null while running. */
  coverage_verdict?: CoverageVerdict | null;
  auth_states?: string[];
  /** POST /greybox/runs/{id}/resume is possible. */
  resumable?: boolean;
}

export type CoverageOutcome = "completed" | "partial" | "blocked" | "needs_authorisation" | "budget_exhausted";

export interface CoverageVerdict {
  outcome: CoverageOutcome;
  reasons: string[];
  limitations: string[];
  /** Per loaded skill: definition-of-done criteria counts by status. */
  skills?: Record<string, { satisfied: number; unsatisfied: number; blocked: number; not_applicable: number }>;
}

export interface ResumeRunRequest {
  max_requests?: number;
  max_duration_s?: number;
}

export interface StartRunRequest {
  authorization_confirmed: true;
  idempotency_key?: string;
}

export interface CancelRunRequest {
  reason?: string;
}

/** GET /greybox/runs/{id}/report (9.9). */
export interface ReportRead {
  status: ReportStatus;
  markdown: string | null;
  generated_at: string | null;
  error: string | null;
}


// ---- Analyst hints (steering a live run) ----

export type HintAction = "note" | "focus" | "add_seed" | "skip_check" | "deprioritize";
export type HintStatus = "open" | "addressed" | "rejected";

export interface HintCreate {
  text: string;
  action: HintAction;
  /** Required for every action except `note`: URL or path, or a check id for `skip_check`. */
  target: string | null;
  about_node_id: string | null;
}

/** POST/GET /greybox/runs/{id}/hints (run chat messages). `result` is the outcome (addressed) or the reason (rejected). */
export interface Hint {
  id: string;
  run_id: string;
  text: string;
  action: HintAction;
  target: string | null;
  about_node_id: string | null;
  node_id: string | null;
  status: HintStatus;
  result: string | null;
  work_order_ids: string[];
  created_by: string;
  created_by_name: string | null;
  created_at: string;
  addressed_at: string | null;
  /** Run chat (optional until every backend serves them): the exploration agent's answer. */
  reply?: string | null;
  replied_at?: string | null;
  /** Explorer cycle that produced the reply / first read the message. */
  reply_cycle?: number | null;
  seen_cycle?: number | null;
  /** Label of `about_node_id` at send time. */
  about_label?: string | null;
}

// ---- Post-execution defensive recommendations (detection rules, WAF suggestions) ----
export type DefenseKind = "waf_rule" | "detection_rule" | "config" | "hardening";
export type DefenseFormat = "modsecurity" | "sigma" | "nginx" | "apache" | "text";
export type DefenseStatus = "proposed" | "unverified";
/** Formats the download endpoint accepts ("all" is a zip). */
export type DefenseDownloadFormat = "modsecurity" | "sigma" | "nginx" | "apache" | "all";

/** GET /greybox/runs/{id}/defenses. `content` is derived from untrusted target data: render as text only. */
export interface Defense {
  id: string;
  run_id: string;
  /** Empty / null for network-wide (scope "asset") recommendations. */
  finding_id: string | null;
  node_id: string | null;
  kind: DefenseKind;
  format: DefenseFormat;
  title: string;
  rationale: string;
  content: string;
  confidence: string | number | null;
  status: DefenseStatus;
  created_at: string;
  // ---- network-wide recommendations (optional until every backend serves them) ----
  /** The asset (host / service / endpoint) the rule protects. */
  asset_id?: string | null;
  /** "finding": derived from one finding; "asset": network-wide, about an asset's surface. */
  scope?: DefenseScope;
  finding_ids?: string[];
}

export type DefenseScope = "finding" | "asset";

export interface DefenseFilter {
  asset_id?: string;
  scope?: DefenseScope;
  finding_id?: string;
  kind?: DefenseKind;
  format?: DefenseFormat;
}

// ---- Findings (9.9). Additive fields: defense_count (summary), defense_ids (detail). ----

export type FindingConfidence = "low" | "medium" | "high";

export interface FindingSummary {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  confidence: FindingConfidence;
  check_id: string;
  affected_asset: { id: string; kind: string; label: string } | null;
  agent_name: string | null;
  evidence_count: number;
  /** Additive; treat a missing value as 0. */
  defense_count?: number;
  created_at: string;
  updated_at: string;
  /** vulnerability | misconfiguration | hardening | informational (additive). */
  finding_class?: FindingClass;
}

export type FindingClass = "vulnerability" | "misconfiguration" | "hardening" | "informational";

export interface FindingRemediation {
  summary?: string;
  steps?: string[];
  validation?: string[];
  reproduction?: string[];
  severity_rationale?: string;
}

export interface FindingEvidence {
  role: "baseline" | "proof" | "verification";
  exchange_id: number | null;
  /** Derived from target traffic: untrusted, render as text only. */
  excerpt: string;
  note: string | null;
}

export interface FindingVerification {
  method: string;
  attempts: number;
  result: "confirmed" | "not_reproduced";
  exchange_ids: number[];
  verified_at: string;
  agent_id: string | null;
  work_order_id: string | null;
}

export interface Finding extends FindingSummary {
  run_id: string;
  description: string;
  cwe: string | null;
  /** Concrete fix and retest guidance (additive). */
  remediation?: FindingRemediation | null;
  location: { url: string; method: string; parameter: string | null };
  evidence: FindingEvidence[];
  verification: FindingVerification | null;
  detection_hints: { type: "log_signature" | "siem_query" | "waf_rule"; title: string; content: string }[];
  references: { title: string; url: string }[];
  provenance: {
    agent_id: string | null;
    agent_name: string | null;
    work_order_id: string | null;
    node_id: string | null;
    first_event_seq: number;
  };
  defense_ids?: string[];
}

// ---- HTTP traffic. Stored data is already redacted; text only, never HTML. ----

export interface ExchangeSummary {
  id: number;
  ts: string;
  method: string;
  scheme: string | null;
  host: string | null;
  port: number | null;
  path: string | null;
  status_code: number | null;
  duration_ms: number | null;
  content_type: string | null;
  response_size: number | null;
  tool: string;
  agent_id: string | null;
  agent_name: string | null;
  work_order_id: string | null;
  blocked: boolean;
  block_reason: string | null;
  error: string | null;
  redirect_hop: number;
  finding_ids: string[];
  /** Sent through an egress proxy (absent on older servers). */
  via_proxy?: boolean;
}

export interface ExchangeSide {
  headers: [string, string][];
  body: string | null;
  body_truncated: boolean;
  body_omitted_reason: string | null;
}

export interface Exchange extends ExchangeSummary {
  url: string;
  resolved_ip: string | null;
  parent_exchange_id: number | null;
  request: ExchangeSide;
  response: ExchangeSide;
}

export interface ExchangeList {
  items: ExchangeSummary[];
  next_after_id: number | null;
  /** Only "enabled" exists today; anything else means capture is not available. */
  capture: string;
}

export interface TrafficQuery {
  method?: string;
  status_code?: number;
  host?: string;
  path_prefix?: string;
  agent_id?: string;
  work_order_id?: string;
  finding_id?: string;
  blocked?: boolean;
  limit?: number;
  after_id?: number | null;
}

// ---- Asset (network) graph. Same envelope as the exploration graph. ----

export type AssetKind = "host" | "service" | "endpoint" | "parameter" | "defense";
export type AssetEdgeRel = "contains" | "has_param" | "links_to" | "redirects_to" | "protects";

export interface AssetNode {
  id: string;
  kind: AssetKind;
  key: string;
  label: string;
  parent_id: string | null;
  state: string;
  in_scope: boolean;
  tested: boolean;
  finding_count: number;
  /** Small, redacted JSON derived from the target. Render values as text only. */
  data: Record<string, unknown>;
  version: number;
}

export interface AssetEdge {
  id: string;
  src: string;
  dst: string;
  rel: AssetEdgeRel;
  version: number;
}

export interface AssetCoverage {
  in_scope_endpoints: number;
  tested_endpoints: number;
  /** Static assets / media left out of both counts. */
  static_endpoints?: number;
  definition?: string;
}

export interface AssetGraphResponse {
  version: number;
  since_version: number;
  full: boolean;
  truncated: boolean;
  truncated_by_kind?: Partial<Record<AssetKind, number>>;
  total_nodes?: number;
  total_edges?: number;
  nodes: AssetNode[];
  edges: AssetEdge[];
  coverage?: AssetCoverage | null;
}

/** GET /greybox/runs/{id}/assets/{asset_id}: the asset node's fields plus its linked records
 * (a nested `node` form is normalised by the client). Linked records are typed loosely. */
export interface AssetDetail extends AssetNode {
  work_orders?: Array<{ id: string; title?: string | null; tool?: string | null; status?: string | null; result_summary?: string | null }>;
  findings?: Array<{ id: string; title?: string | null; severity?: Severity | null; status?: string | null }>;
  exchanges?: Array<{ id: number; method?: string | null; scheme?: string | null; host?: string | null; port?: number | null; path?: string | null; status_code?: number | null; blocked?: boolean }>;
  children_count?: number;
}

// ---- Egress proxies (admin-managed, opt-in per target). A 404 means the feature is off. ----

export interface EgressProxy {
  id: string;
  name: string;
  url: string;
  has_credentials: boolean;
  allowed_hosts: string[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

/** Credentials are write-only: omitted = keep (edit), "" = clear. */
export interface EgressProxyWrite {
  name: string;
  url: string;
  username?: string;
  password?: string;
  allowed_hosts: string[];
  enabled: boolean;
}

export interface AvailableEgressProxy {
  id: string;
  name: string;
  allowed_hosts: string[];
}

export interface PreflightResult {
  ok: boolean;
  status_code: number | null;
  final_url: string | null;
  blocked_reason: string | null;
  resolved_ips: string[];
  elapsed_ms: number;
}

// ---------------------------------------------------------------- security model
// GET /greybox/runs/{id}/model (src/greybox_web/secmodel_store.view): what each
// identity was observed to receive per interface, what the agent established as
// EXPECTED access (with its basis), and the correlation signals still to verify.
export type AccessCounts = Partial<Record<"allow" | "deny" | "missing" | "error", number>>;

export interface SecurityModelExpectation {
  subject: string;
  operation: string;
  resource: string;
  expected: "allow" | "deny";
  basis: "documented" | "configured" | "observed_ui" | "stated";
  claimed_basis?: string;
  evidence?: string[];
  unresolved?: string[];
  note?: string;
}

export interface SecurityModelSignal {
  kind: "inconsistent_boundary" | "contradicts_expectation";
  identity: string;
  resource_type: string;
  instance: string | null;
  summary: string;
  evidence: string[];
  interfaces: string[];
  status: string;
}

export interface SecurityModelView {
  identities: { identity: string; requests: number; role: string | null }[];
  entities: { key: string; kind: string; name: string; attributes: Record<string, unknown> }[];
  relations: { src: string; rel: string; dst: string; basis: string; evidence: string[] }[];
  expectations: SecurityModelExpectation[];
  interfaces: { interface: string; resource_type: string | null; access: Record<string, AccessCounts> }[];
  signals: SecurityModelSignal[];
  unresolved: { kind: string; detail: string; interface?: string; resource_type?: string }[];
  counts: Record<string, number>;
}
