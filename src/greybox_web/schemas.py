"""Grey-box API request/response models.

Structural validation (types, sizes, numeric ranges) happens here; semantic scope
rules (hosts, platform services, base URL in scope) live in ``scope.build_scope``.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

RunStatus = Literal["queued", "preparing", "running", "cancelling", "succeeded", "failed",
                    "cancelled"]
SEVERITIES = ("critical", "high", "medium", "low", "info")

# Limits (9.2): (min, max, default). All enforced by the engine (4.5).
LIMIT_BOUNDS: dict[str, tuple[int, int, int]] = {
    "max_requests": (1, 50000, 5000),
    "max_duration_s": (60, 28800, 3600),
    "max_concurrency": (1, 8, 4),
    "rate_limit_rps": (1, 50, 10),
    "request_timeout_s": (1, 30, 10),
    "max_pages": (1, 20000, 2000),
}


# Keys removed from the limits that older clients may still send (ignored).
LEGACY_LIMIT_KEYS = frozenset({"max_crawl_depth"})


def _bounded(name: str, optional: bool):
    lo, hi, default = LIMIT_BOUNDS[name]
    return Field(default=None if optional else default, ge=lo, le=hi)


class Limits(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_requests: int = _bounded("max_requests", False)
    max_duration_s: int = _bounded("max_duration_s", False)
    max_concurrency: int = _bounded("max_concurrency", False)
    rate_limit_rps: int = _bounded("rate_limit_rps", False)
    request_timeout_s: int = _bounded("request_timeout_s", False)
    max_pages: int = _bounded("max_pages", False)


class LimitsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_requests: int | None = _bounded("max_requests", True)
    max_duration_s: int | None = _bounded("max_duration_s", True)
    max_concurrency: int | None = _bounded("max_concurrency", True)
    rate_limit_rps: int | None = _bounded("rate_limit_rps", True)
    request_timeout_s: int | None = _bounded("request_timeout_s", True)
    max_pages: int | None = _bounded("max_pages", True)

    @model_validator(mode="before")
    @classmethod
    def _drop_legacy(cls, data):
        """Older clients still send keys that no longer exist: accept and ignore."""
        if isinstance(data, dict) and any(k in data for k in LEGACY_LIMIT_KEYS):
            data = {k: v for k, v in data.items() if k not in LEGACY_LIMIT_KEYS}
        return data


LIMITS_DEFAULTS = Limits()


def stored_limits(raw: dict | None) -> Limits:
    """Limits from stored JSON (targets, runs): keys that no longer exist (e.g. the
    removed ``max_crawl_depth``) are dropped so older rows keep working."""
    return Limits(**{k: v for k, v in (raw or {}).items() if k in Limits.model_fields})
LIMITS_MAX = Limits(**{k: hi for k, (_, hi, _) in LIMIT_BOUNDS.items()})


class ExplorationInput(BaseModel):
    """Opt-in for ACTIVE infrastructure probes the agents may propose (default: none)."""

    model_config = ConfigDict(extra="forbid")
    active_probes: list[str] = Field(default_factory=list, max_length=10)


class ScopeInput(BaseModel):
    """Partial ScopePolicy (6.1). Omitted fields default from ``base_url``.
    Entry counts and semantics are checked by ``scope.build_scope``; the caps here only
    bound request size."""

    model_config = ConfigDict(extra="forbid")
    allowed_hosts: list[str] | None = Field(default=None, max_length=100)
    allowed_schemes: list[str] | None = Field(default=None, max_length=10)
    allowed_ports: list[int] | None = Field(default=None, max_length=100)
    path_prefixes: list[str] | None = Field(default=None, max_length=200)
    excluded_paths: list[str] | None = Field(default=None, max_length=400)
    redirect_policy: Literal["in_scope", "none"] | None = None
    allow_auth_testing: bool | None = None
    exploration: ExplorationInput | None = None
    # Hosts the target redirects to on purpose (an identity provider, a partner
    # site). Never requested; the run announces them instead of following them.
    redirect_hosts: list[str] | None = Field(default=None, max_length=10)
    honor_declared_redirects: bool | None = None
    # Target-neutral boundary for non-HTTP capabilities (netscope.py): targets
    # (addresses / CIDR / exact names), ports, protocols, rate. Validated
    # semantically by scope.build_scope.
    network: dict[str, Any] | None = None
    # Activity policy: state-change permission plus a target-wide lifecycle
    # guarantee. Both are unknown/off by default.
    activity: dict[str, Any] | None = None

    @field_validator("allowed_hosts", "path_prefixes", "excluded_paths",
                     "redirect_hosts")
    @classmethod
    def _item_len(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and any(len(x) > 1000 for x in v):
            raise ValueError("Entries must be at most 1000 characters")
        return v


class ScopePolicyOut(BaseModel):
    allowed_hosts: list[str]
    allowed_schemes: list[Literal["http", "https"]]
    allowed_ports: list[int]
    path_prefixes: list[str]
    excluded_paths: list[str]
    redirect_policy: Literal["in_scope", "none"]
    allow_auth_testing: bool
    exploration: ExplorationInput = Field(default_factory=ExplorationInput)
    redirect_hosts: list[str] = Field(default_factory=list)
    honor_declared_redirects: bool = False
    network: dict[str, Any] | None = None
    activity: dict[str, Any] | None = None

    @model_serializer(mode="wrap")
    def _omit_default_exploration(self, handler):
        """Absent unless the analyst opted in to active probes (keeps stored scopes and
        API output unchanged for every existing target)."""
        out = handler(self)
        if not (out.get("exploration") or {}).get("active_probes"):
            out.pop("exploration", None)
        if not out.get("redirect_hosts"):
            out.pop("redirect_hosts", None)
        if not out.get("honor_declared_redirects"):
            out.pop("honor_declared_redirects", None)
        if not out.get("network"):
            out.pop("network", None)
        activity = out.get("activity") or {}
        if not activity.get("state_changing") and \
                activity.get("resource_lifecycle", "unknown") == "unknown":
            out.pop("activity", None)
        return out


class TargetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", protected_namespaces=())
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    base_url: str = Field(min_length=1, max_length=500)
    scope: ScopeInput | None = None
    limits: LimitsInput | None = None
    checks: list[str] | None = Field(default=None, max_length=50)
    credential_id: uuid.UUID | None = None
    # Optional login accounts for authenticated testing (ids of the owner's
    # login_account credentials). Never required; empty = unauthenticated only.
    account_ids: list[uuid.UUID] = Field(default_factory=list, max_length=8)
    egress_proxy_id: uuid.UUID | None = None
    # What kind of target this is (``modes.py``): web | network | artifact. It
    # decides which capabilities the run may use — never what it is allowed to
    # touch, which stays the scope.
    assessment_mode: Literal["web", "network", "artifact"] = "web"
    # Capabilities the operator switched off for this target (subset of the mode's).
    capabilities: list[str] | None = Field(default=None, max_length=8)
    # Model for the exploration agent: a backend id from /greybox/config agent.backends
    # and one of its models. Empty = the platform default.
    model_backend: str | None = Field(default=None, max_length=16)
    model: str | None = Field(default=None, max_length=100)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Name must not be empty")
        return v


class TargetUpdate(BaseModel):
    """PATCH: only fields present in the body change. ``scope`` and ``limits`` keys are
    merged over the stored values; ``checks: null`` resets to the defaults,
    ``credential_id: null`` removes the cookie credential and ``account_ids: null``
    removes all login accounts."""

    model_config = ConfigDict(extra="forbid", protected_namespaces=())
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    base_url: str | None = Field(default=None, min_length=1, max_length=500)
    scope: ScopeInput | None = None
    limits: LimitsInput | None = None
    checks: list[str] | None = Field(default=None, max_length=50)
    credential_id: uuid.UUID | None = None
    account_ids: list[uuid.UUID] = Field(default_factory=list, max_length=8)
    egress_proxy_id: uuid.UUID | None = None      # null removes the proxy
    assessment_mode: Literal["web", "network", "artifact"] | None = None
    capabilities: list[str] | None = Field(default=None, max_length=8)
    archived: bool | None = None
    model_backend: str | None = Field(default=None, max_length=16)
    model: str | None = Field(default=None, max_length=100)

    @field_validator("name")
    @classmethod
    def _strip_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("Name must not be empty")
        return v


class TargetNormalized(BaseModel):
    """``normalized`` in the validate response: what would be stored."""
    model_config = ConfigDict(protected_namespaces=())

    name: str
    description: str | None
    base_url: str
    scope: ScopePolicyOut
    limits: Limits
    checks: list[str] | None
    credential_id: uuid.UUID | None
    # normalized/persisted form: plain strings (the JSON column must never see a
    # UUID object); TargetRead shows AccountRef objects instead of raw ids
    account_ids: list[str] = Field(default_factory=list)
    egress_proxy_id: uuid.UUID | None = None
    assessment_mode: str = "web"
    capabilities: list[str] = Field(default_factory=list)
    model_backend: str | None = None
    model: str | None = None


class CredentialRef(BaseModel):
    id: uuid.UUID
    label: str
    kind: Literal["cookie_header"]


class AccountRef(BaseModel):
    """A linked login account: id and label only — the user name is public within the
    owner's targets, the password never leaves the vault."""
    id: uuid.UUID
    label: str
    kind: Literal["login_account"] = "login_account"


class LastRun(BaseModel):
    id: uuid.UUID
    status: RunStatus
    created_at: datetime


class TargetRead(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: uuid.UUID
    owner_id: uuid.UUID
    name: str
    description: str | None
    base_url: str
    scope: ScopePolicyOut
    scope_summary: list[str]
    limits: Limits
    checks: list[str]
    credential: CredentialRef | None
    accounts: list[AccountRef] = Field(default_factory=list)
    egress_proxy_id: uuid.UUID | None = None
    assessment_mode: str = "web"
    capabilities: list[str] = Field(default_factory=list)
    archived: bool
    model_backend: str | None = None
    model: str | None = None
    created_at: datetime
    updated_at: datetime
    last_run: LastRun | None


class TargetPage(BaseModel):
    items: list[TargetRead]
    next_cursor: str | None


class ValidationIssue(BaseModel):
    loc: list[str | int]
    msg: str
    type: str = "value_error"


class ValidateResponse(BaseModel):
    valid: bool
    normalized: TargetNormalized | None
    scope_summary: list[str]
    errors: list[ValidationIssue]
    warnings: list[str]


class CheckInfo(BaseModel):
    id: str
    title: str
    description: str
    area: str
    evidence: str
    default_enabled: bool
    requires_auth_testing: bool
    available: bool = True
    unavailable_reason: str | None = None


class LimitsConfig(BaseModel):
    defaults: Limits
    max: Limits


class ModelBackendInfo(BaseModel):
    """One selectable model backend (never secrets: no keys, no URLs)."""

    id: str
    label: str
    available: bool
    reason: str = ""
    models: list[str]


class AgentDefault(BaseModel):
    backend: str
    model: str


class AgentInfo(BaseModel):
    """The exploration agent: configured backends (same as white-box), the default and
    the per-run bounds."""

    available: bool
    backends: list[ModelBackendInfo]
    default: AgentDefault | None = None
    max_calls: int
    max_tokens: int
    timeout_s: float


class ConfigRead(BaseModel):
    enabled: bool
    executor: Literal["worker", "inprocess", "off"]
    allow_private_targets: bool
    egress_proxies_enabled: bool = False
    checks: list[CheckInfo]
    limits: LimitsConfig
    agent: AgentInfo = AgentInfo(available=False, backends=[], max_calls=0,
                                 max_tokens=0, timeout_s=0.0)


# ------------------------------------------------------------------ runs (9.5)


class RunStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authorization_confirmed: bool
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=64)


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(default=None, max_length=200)


class TargetRef(BaseModel):
    id: uuid.UUID
    name: str
    base_url: str


class FindingCounts(BaseModel):
    candidate: int
    verified: int
    rejected: int
    by_severity: dict[str, int]   # candidate + verified only


class WorkOrderCounts(BaseModel):
    pending: int
    running: int
    done: int
    failed: int
    skipped: int
    cancelled: int


class RunCounters(BaseModel):
    events: int
    requests: int
    requests_blocked: int
    assets: int
    endpoints: int
    work_orders: WorkOrderCounts
    agents_active: int


class RunSummary(BaseModel):
    id: uuid.UUID
    target: TargetRef
    owner_id: uuid.UUID
    status: RunStatus
    phase: str | None
    end_reason: str | None
    cancel_requested: bool
    findings: FindingCounts
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class SkippedCheck(BaseModel):
    id: str
    reason: str


class EgressProxyRef(BaseModel):
    id: uuid.UUID
    name: str


class RunRead(RunSummary):
    model_config = ConfigDict(protected_namespaces=())
    error_summary: str | None
    scope: ScopePolicyOut
    scope_summary: list[str]
    limits: Limits
    checks: list[str]
    credential: CredentialRef | None
    counters: RunCounters
    last_seq: int
    graph_version: int
    heartbeat_at: datetime | None
    last_event_at: datetime | None
    report_status: Literal["pending", "generating", "ready", "failed"]
    # Who asked to cancel and why (from run.cancel_requested; the reason is already
    # redacted event text). Null when no cancel was requested.
    cancelled_by: str | None = None
    cancel_reason: str | None = None
    # Requested checks that were not run because this build has no implementation.
    skipped_checks: list[SkippedCheck] = Field(default_factory=list)
    # The egress proxy this run's traffic goes through (snapshot at start), or null.
    egress_proxy: EgressProxyRef | None = None
    # The model this run uses (snapshot at start; empty only for runs that predate it).
    model_backend: str | None = None
    model: str | None = None
    # The honest completion verdict (coverage.py): outcome, reasons, limitations and
    # per-skill definition-of-done counts. None until the run finishes.
    coverage_verdict: dict[str, Any] | None = None
    # what the run met at the authentication boundary (identity_provider, ...)
    auth_states: list[str] = Field(default_factory=list)
    # the run can be continued with POST /runs/{id}/resume
    resumable: bool = False


class RunPage(BaseModel):
    items: list[RunSummary]
    next_cursor: str | None


class ReportRead(BaseModel):
    status: Literal["pending", "generating", "ready", "failed"]
    markdown: str | None
    generated_at: datetime | None
    error: str | None


class PreflightResult(BaseModel):
    ok: bool
    status_code: int | None
    final_url: str | None
    blocked_reason: str | None
    resolved_ips: list[str]
    elapsed_ms: int


# ------------------------------------------------------------------ unified analyses


class AnalysisSubject(BaseModel):
    type: Literal["repository", "target"]
    id: uuid.UUID
    name: str
    base_url: str | None = None   # grey-box targets only (null for repositories)


class AnalysisFindings(BaseModel):
    total: int
    by_severity: dict[str, int]


class AnalysisItem(BaseModel):
    mode: Literal["whitebox", "greybox"]
    id: uuid.UUID
    name: str
    subject: AnalysisSubject
    status: str
    phase: str | None
    owner_id: uuid.UUID | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_s: int | None
    findings: AnalysisFindings | None
    href: str


class AnalysesPage(BaseModel):
    items: list[AnalysisItem]
    next_cursor: str | None


# ------------------------------------------------------------------ graphs (9.8)


class GraphAgentRef(BaseModel):
    id: uuid.UUID
    name: str
    role: str


class ExplorationNodeOut(BaseModel):
    id: uuid.UUID
    kind: str
    key: str
    label: str
    status: str
    agent_id: uuid.UUID | None
    agent_name: str | None
    work_order_id: uuid.UUID | None
    finding_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    parent_id: uuid.UUID | None
    event_seq: int | None
    last_event_seq: int | None
    severity: str | None
    outcome: str | None
    exchange_ids: list[int]
    data: dict
    created_version: int
    version: int
    created_at: datetime
    updated_at: datetime


class GraphEdgeOut(BaseModel):
    id: uuid.UUID
    src: uuid.UUID
    dst: uuid.UUID
    rel: str
    version: int


class ExplorationGraphResponse(BaseModel):
    version: int
    since_version: int
    full: bool
    truncated: bool
    truncated_by_kind: dict[str, int] = Field(default_factory=dict)
    total_nodes: int
    total_edges: int
    agents: list[GraphAgentRef]
    nodes: list[ExplorationNodeOut]
    edges: list[GraphEdgeOut]


class GraphAssetRef(BaseModel):
    id: uuid.UUID
    kind: str
    label: str


class GraphWorkOrder(BaseModel):
    id: uuid.UUID
    kind: str
    tool: str
    title: str
    reason: str
    status: str
    priority: int
    asset: GraphAssetRef | None
    node_id: uuid.UUID | None
    parent_node_id: uuid.UUID | None
    agent_id: uuid.UUID | None
    agent_name: str | None
    attempts: int
    max_attempts: int
    lease_expires_at: datetime | None
    result_summary: str | None
    error: str | None
    created_seq: int
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None


class GraphFindingSummary(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    confidence: str
    check_id: str
    affected_asset: GraphAssetRef | None
    agent_name: str | None
    evidence_count: int
    created_at: datetime
    updated_at: datetime


class GraphExchangeSummary(BaseModel):
    id: int
    ts: datetime
    method: str
    scheme: str
    host: str
    port: int
    path: str
    status_code: int | None
    duration_ms: int | None
    content_type: str | None
    response_size: int | None
    tool: str
    agent_id: uuid.UUID | None
    agent_name: str | None
    work_order_id: uuid.UUID | None
    blocked: bool
    block_reason: str | None
    error: str | None
    redirect_hop: int
    finding_ids: list[uuid.UUID]


class NeighbourSummary(BaseModel):
    id: uuid.UUID
    kind: str
    label: str
    status: str
    severity: str | None
    outcome: str | None
    rel: str
    direction: Literal["in", "out"]


class ExplorationNodeDetail(BaseModel):
    node: ExplorationNodeOut
    in_edges: list[GraphEdgeOut]
    out_edges: list[GraphEdgeOut]
    neighbours: list[NeighbourSummary]
    work_order: GraphWorkOrder | None
    finding: GraphFindingSummary | None
    agent_name: str | None
    exchanges: list[GraphExchangeSummary]


class AssetNodeOut(BaseModel):
    id: uuid.UUID
    kind: str
    key: str
    label: str
    parent_id: uuid.UUID | None
    state: str
    in_scope: bool
    tested: bool
    finding_count: int
    data: dict
    version: int


class AssetCoverage(BaseModel):
    in_scope_endpoints: int
    tested_endpoints: int
    definition: str
    # Static assets and media (build output) are left out of both counts above.
    static_endpoints: int = 0


class AssetGraphResponse(BaseModel):
    version: int
    since_version: int
    full: bool
    truncated: bool
    truncated_by_kind: dict[str, int] = Field(default_factory=dict)
    total_nodes: int
    total_edges: int
    nodes: list[AssetNodeOut]
    edges: list[GraphEdgeOut]
    coverage: AssetCoverage


class AssetDetail(AssetNodeOut):
    work_orders: list[GraphWorkOrder]
    findings: list[GraphFindingSummary]
    exchanges: list[GraphExchangeSummary]
    children_count: int


# ------------------------------------------------------------------ events


class EventRefs(BaseModel):
    node_ids: list[str] = Field(default_factory=list)
    asset_ids: list[str] = Field(default_factory=list)
    finding_id: str | None = None
    exchange_ids: list[int] = Field(default_factory=list)


class GreyboxEventOut(BaseModel):
    """Event envelope shared by the history API and the SSE stream."""
    seq: int
    run_id: uuid.UUID
    ts: datetime
    kind: str
    level: str
    source: str
    agent_id: uuid.UUID | None
    agent_name: str | None
    work_order_id: uuid.UUID | None
    tool_call_id: str | None
    summary: str
    status: str | None
    duration_ms: int | None
    refs: EventRefs
    data: dict


class EventPage(BaseModel):
    items: list[GreyboxEventOut]
    last_seq: int
    has_more_before: bool
    has_more_after: bool
    run_status: str


# ------------------------------------------------------------------ hints (9.12)

HintAction = Literal["note", "focus", "add_seed", "skip_check", "deprioritize"]
HintStatus = Literal["open", "addressed", "rejected"]
HINT_TEXT_MAX = 2000
HINT_TARGET_MAX = 2000


class HintCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=HINT_TEXT_MAX)
    action: HintAction = "note"           # the run chat: free text is a note
    target: str | None = Field(default=None, max_length=HINT_TARGET_MAX)
    about_node_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _check(self) -> "HintCreate":
        if not self.text.strip():
            raise ValueError("text must not be blank")
        target = (self.target or "").strip()
        if self.action == "note":
            self.target = None
            return self
        if not target:
            raise ValueError(f"target is required for action {self.action}")
        if self.action != "skip_check" and not (
                target.startswith("/") or target.lower().startswith(("http://", "https://"))):
            raise ValueError("target must be a URL (http/https) or a path starting with /")
        self.target = target
        return self


class HintRead(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    text: str
    action: HintAction
    target: str | None
    about_node_id: uuid.UUID | None
    node_id: uuid.UUID | None
    status: HintStatus
    result: str | None
    work_order_ids: list[uuid.UUID]
    created_by: uuid.UUID
    created_by_name: str
    created_at: datetime
    addressed_at: datetime | None
    # The run chat: the agent's reply (or the platform's fallback), when and in which
    # explorer cycle; the first cycle that read the message; the about-node's label.
    reply: str | None = None
    replied_at: datetime | None = None
    reply_cycle: int | None = None
    seen_cycle: int | None = None
    about_label: str | None = None


class HintList(BaseModel):
    items: list[HintRead]


# ------------------------------------------------------------------ defenses (10.6)
DefenseKind = Literal["waf_rule", "detection_rule", "config", "hardening"]
DefenseScope = Literal["finding", "asset"]
DefenseFormat = Literal["modsecurity", "sigma", "nginx", "apache", "text"]
DefenseDownloadFormat = Literal["modsecurity", "sigma", "nginx", "apache", "all"]
DefenseStatus = Literal["proposed", "unverified"]


class DefenseRead(BaseModel):
    id: uuid.UUID
    run_id: uuid.UUID
    finding_id: uuid.UUID | None      # null for asset-scoped (10.7)
    asset_id: uuid.UUID | None        # additive (10.7): the protected asset
    scope: DefenseScope               # additive (10.7)
    finding_ids: list[uuid.UUID]      # additive (10.7): every finding it addresses
    node_id: uuid.UUID | None
    kind: DefenseKind
    format: DefenseFormat
    title: str
    rationale: str
    content: str
    confidence: Literal["high", "medium", "low"]
    status: DefenseStatus
    created_at: datetime


class DefenseList(BaseModel):
    items: list[DefenseRead]


# ------------------------------------------------------------------ findings and traffic (9.9)
FindingStatus = Literal["candidate", "verified", "rejected"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class AffectedAsset(BaseModel):
    id: uuid.UUID
    kind: str
    label: str


class FindingSummaryRead(BaseModel):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    confidence: str
    check_id: str
    affected_asset: AffectedAsset | None
    agent_name: str | None
    evidence_count: int
    defense_count: int          # additive (10.6)
    created_at: datetime
    updated_at: datetime
    # vulnerability | misconfiguration | hardening | informational (findclass.py);
    # additive: older clients ignore it
    finding_class: str = "vulnerability"
    canonical_issue_id: uuid.UUID | None = None
    verification_status: str | None = None
    observation_count: int = 0
    affected_location_count: int = 0


class FindingList(BaseModel):
    items: list[FindingSummaryRead]


class FindingLocation(BaseModel):
    url: str
    method: str
    parameter: str | None = None


class FindingEvidenceRead(BaseModel):
    role: str
    exchange_id: int | None = None
    excerpt: str
    note: str | None = None


class FindingVerificationRead(BaseModel):
    method: str
    attempts: int
    result: str
    exchange_ids: list[int]
    verified_at: str | None = None
    agent_id: str | None = None
    work_order_id: str | None = None
    # access-model decision on a reproduced access finding (secmodel_store.access_gate)
    model: dict | None = None


class FindingHintRead(BaseModel):
    type: str
    title: str
    content: str


class FindingReference(BaseModel):
    title: str
    url: str


class FindingProvenance(BaseModel):
    agent_id: uuid.UUID | None
    agent_name: str | None
    work_order_id: uuid.UUID | None
    node_id: uuid.UUID | None
    first_event_seq: int


class FindingRead(FindingSummaryRead):
    run_id: uuid.UUID
    description: str
    # {"summary", "steps", "validation", "reproduction", "severity_rationale"}
    remediation: dict[str, Any] | None = None
    cwe: str | None
    location: FindingLocation
    evidence: list[FindingEvidenceRead]
    verification: FindingVerificationRead | None
    detection_hints: list[FindingHintRead]
    references: list[FindingReference]
    provenance: FindingProvenance
    defense_ids: list[uuid.UUID]    # additive (10.6)
    affected_locations: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    root_cause: str | None = None
    correlation_rationale: str | None = None
    correlation_history: list[dict[str, Any]] = []
    retesting_guidance: str | None = None


class ExchangeSummaryRead(BaseModel):
    id: int
    ts: datetime
    method: str
    scheme: str | None
    host: str | None
    port: int | None
    path: str | None
    status_code: int | None
    duration_ms: int | None
    content_type: str | None
    response_size: int | None
    tool: str
    agent_id: uuid.UUID | None
    agent_name: str | None
    work_order_id: uuid.UUID | None
    blocked: bool
    block_reason: str | None
    error: str | None
    redirect_hop: int
    finding_ids: list[uuid.UUID]


class ExchangeList(BaseModel):
    items: list[ExchangeSummaryRead]
    next_after_id: int | None
    capture: Literal["enabled"] = "enabled"


class ExchangeSide(BaseModel):
    headers: list[tuple[str, str]]
    body: str | None
    body_truncated: bool
    body_omitted_reason: str | None


class ExchangeRead(ExchangeSummaryRead):
    url: str
    resolved_ip: str | None
    parent_exchange_id: int | None
    request: ExchangeSide
    response: ExchangeSide
