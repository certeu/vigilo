"""Grey-box ORM models.

Registered on the platform ``Base`` (``src.webapi.db``) so ``Base.metadata.create_all``
(tests, lifespan fallback) creates them; migration ``0009_greybox_web`` creates them
in deployed databases. This module imports only ``src.webapi.db`` to avoid an import
cycle with ``src.webapi.models`` (which imports this module at its bottom).

Every child table carries ``run_id`` (FK ``greybox_runs.id`` ON DELETE CASCADE) and an
index starting with ``run_id``: child queries always filter by ``run_id`` after the
ACL check (cross-run isolation invariant).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from src.webapi.db import Base

# Autoincrement 64-bit id on Postgres; SQLite only autoincrements INTEGER PRIMARY KEY.
BigIntPK = BigInteger().with_variant(Integer, "sqlite")

# Run statuses. Same vocabulary as white-box plus ``cancelling``.
GB_QUEUED = "queued"
GB_PREPARING = "preparing"
GB_RUNNING = "running"
GB_CANCELLING = "cancelling"
GB_SUCCEEDED = "succeeded"
GB_FAILED = "failed"
GB_CANCELLED = "cancelled"
GB_STATUSES = (
    GB_QUEUED, GB_PREPARING, GB_RUNNING, GB_CANCELLING, GB_SUCCEEDED, GB_FAILED, GB_CANCELLED,
)
GB_TERMINAL = frozenset({GB_SUCCEEDED, GB_FAILED, GB_CANCELLED})
GB_ACTIVE = frozenset(GB_STATUSES) - GB_TERMINAL
ACTIVE_RUN_PREDICATE = "status NOT IN ('succeeded', 'failed', 'cancelled')"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ts(nullable: bool = False, **kw):
    return mapped_column(DateTime(timezone=True), nullable=nullable, **kw)


def _run_fk():
    return mapped_column(
        Uuid, ForeignKey("greybox_runs.id", ondelete="CASCADE"), nullable=False
    )


class GreyboxEgressProxy(Base):
    """An admin-defined forward proxy a target may opt into. Not a run
    child and not in GREYBOX_TABLES (added by migration 0016, after 0009). The proxy
    credentials, when any, are one Fernet blob (``credentials_enc``): never returned,
    never logged."""
    __tablename__ = "greybox_egress_proxies"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    url: Mapped[str] = mapped_column(String(500), nullable=False)
    credentials_enc: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    allowed_hosts: Mapped[list] = mapped_column(JSON, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    updated_at: Mapped[datetime] = _ts(default=_utcnow, onupdate=_utcnow)


class GreyboxTarget(Base):
    __tablename__ = "greybox_targets"
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)
    limits: Mapped[dict] = mapped_column(JSON, nullable=False)
    checks: Mapped[list | None] = mapped_column(JSON, nullable=True)
    credential_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True
    )
    # Optional login accounts (user/password) for authenticated testing: ids of
    # owner-owned ``login_account`` credentials (no FK: SQLite has no FK pragma;
    # a deleted credential is filtered out at link time and at run start).
    account_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # No FK: deleting a proxy clears the reference explicitly (SQLite has no FK pragma).
    egress_proxy_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    # What kind of target this is (``modes.py``: web | network | artifact). It picks
    # which capabilities a run may use; the scope still decides what is reachable.
    assessment_mode: Mapped[str] = mapped_column(String(16), default="web",
                                                 nullable=False)
    # Capabilities the operator switched off for this target (JSON list).
    disabled_capabilities: Mapped[list] = mapped_column(JSON, default=list,
                                                        nullable=False)
    # Model choice for the exploration agent (src/greybox_web/modelsel.py): a white-box
    # backend id (claude | codex | opencode | fake) and one of its models. Empty = the
    # platform default. Snapshotted onto each run at start.
    model_backend: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    model: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    updated_at: Mapped[datetime] = _ts(default=_utcnow, onupdate=_utcnow)


class GreyboxRun(Base):
    __tablename__ = "greybox_runs"
    __table_args__ = (
        UniqueConstraint("owner_id", "idempotency_key", name="uq_greybox_runs_owner_idem"),
        Index("ix_greybox_runs_status_created", "status", "created_at"),
        Index("ix_greybox_runs_owner_created", "owner_id", "created_at"),
        Index("ix_greybox_runs_target_created", "target_id", "created_at"),
        Index("ix_greybox_runs_status_lease", "status", "lease_expires_at"),
        # One non-terminal run per target; backs service.start_run.
        Index("ux_greybox_runs_one_active_per_target", "target_id", unique=True,
              sqlite_where=text(ACTIVE_RUN_PREDICATE),
              postgresql_where=text(ACTIVE_RUN_PREDICATE)),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    target_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_targets.id", ondelete="CASCADE"), nullable=False
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default=GB_QUEUED)
    phase: Mapped[str | None] = mapped_column(String(32), nullable=True)
    end_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    scope: Mapped[dict] = mapped_column(JSON, nullable=False)
    limits: Mapped[dict] = mapped_column(JSON, nullable=False)
    checks: Mapped[list] = mapped_column(JSON, nullable=False)
    credential_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    # Snapshot of the target's login accounts (ids of owner-owned login_account
    # credentials), taken at start; the supervisor decrypts them at run start and
    # never stores the secrets anywhere else.
    account_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Snapshot {id, name, url} (no credentials) of the egress proxy at start, or null.
    egress_proxy: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Resolved model choice snapshot (backend id + concrete model); never a key.
    model_backend: Mapped[str] = mapped_column(String(16), default="", nullable=False)
    model: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cancel_requested_at: Mapped[datetime | None] = _ts(nullable=True)
    cancel_requested_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    # Who started the run (owner or an admin). ``owner_id`` is the target owner (ACL).
    # Added by migration 0010; no FK (audit snapshot, must not block user deletion).
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = _ts(nullable=True)
    heartbeat_at: Mapped[datetime | None] = _ts(nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_seq: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    graph_version: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    # Authentication states the run met ("identity_provider", "expired", "missing"):
    # written when a response shows the run was not looking at the application, read
    # by the completion verdict so a stale session can never end as "completed"
    # (field-assessment defect F5).
    auth_states: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # The honest completion verdict written at finalize (``coverage.assess``):
    # {outcome, reasons, limitations}. A run never claims more than this.
    coverage_verdict: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # Encrypted identity state (sessions + browser jars) for resume; see
    # sessionvault.py. Never exposed through the API.
    session_vault: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    requests_made: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    requests_blocked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    started_at: Mapped[datetime | None] = _ts(nullable=True)
    finished_at: Mapped[datetime | None] = _ts(nullable=True)


class GreyboxAgent(Base):
    __tablename__ = "greybox_agents"
    __table_args__ = (
        UniqueConstraint("run_id", "name", name="uq_greybox_agents_run_name"),
        Index("ix_greybox_agents_run", "run_id"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="idle")
    current_work_order_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    current_summary: Mapped[str | None] = mapped_column(String(300), nullable=True)
    work_orders_done: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    work_orders_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_event_seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    started_at: Mapped[datetime | None] = _ts(nullable=True)
    finished_at: Mapped[datetime | None] = _ts(nullable=True)


class GreyboxAsset(Base):
    __tablename__ = "greybox_assets"
    __table_args__ = (
        UniqueConstraint("run_id", "kind", "key", name="uq_greybox_assets_run_kind_key"),
        Index("ix_greybox_assets_run_version", "run_id", "version"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    key: Mapped[str] = mapped_column(String(600), nullable=False)
    label: Mapped[str] = mapped_column(String(300), nullable=False)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_assets.id"), nullable=True
    )
    in_scope: Mapped[bool] = mapped_column(Boolean, nullable=False)
    tested: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    first_seen_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    updated_at: Mapped[datetime] = _ts(default=_utcnow, onupdate=_utcnow)


class GreyboxAssetEdge(Base):
    __tablename__ = "greybox_asset_edges"
    __table_args__ = (
        UniqueConstraint("run_id", "src_id", "rel", "dst_id",
                         name="uq_greybox_asset_edges_run_src_rel_dst"),
        Index("ix_greybox_asset_edges_run_version", "run_id", "version"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    src_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_assets.id", ondelete="CASCADE"), nullable=False
    )
    dst_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_assets.id", ondelete="CASCADE"), nullable=False
    )
    rel: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)


class GreyboxWorkOrder(Base):
    __tablename__ = "greybox_work_orders"
    __table_args__ = (
        UniqueConstraint("run_id", "dedup_key", name="uq_greybox_work_orders_run_dedup"),
        Index("ix_greybox_work_orders_run_status_prio", "run_id", "status", "priority",
              "created_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    dedup_key: Mapped[str] = mapped_column(String(300), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    tool: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    params: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=50, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_assets.id", ondelete="SET NULL"), nullable=True
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    parent_node_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    lease_owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    lease_expires_at: Mapped[datetime | None] = _ts(nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    result_summary: Mapped[str | None] = mapped_column(String(500), nullable=True)
    error: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    started_at: Mapped[datetime | None] = _ts(nullable=True)
    finished_at: Mapped[datetime | None] = _ts(nullable=True)


class GreyboxGraphNode(Base):
    __tablename__ = "greybox_graph_nodes"
    __table_args__ = (
        UniqueConstraint("run_id", "kind", "key", name="uq_greybox_graph_nodes_run_kind_key"),
        Index("ix_greybox_graph_nodes_run_version", "run_id", "version"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    key: Mapped[str] = mapped_column(String(300), nullable=False)
    label: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    work_order_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    event_seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # Graph-study columns (migration 0011): written from M2 so M4 needs no backfill.
    parent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    created_version: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    last_event_seq: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(24), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    updated_at: Mapped[datetime] = _ts(default=_utcnow, onupdate=_utcnow)


class GreyboxGraphEdge(Base):
    __tablename__ = "greybox_graph_edges"
    __table_args__ = (
        UniqueConstraint("run_id", "src_id", "rel", "dst_id",
                         name="uq_greybox_graph_edges_run_src_rel_dst"),
        CheckConstraint("src_id <> dst_id", name="ck_greybox_graph_edges_no_self_loop"),
        Index("ix_greybox_graph_edges_run_version", "run_id", "version"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    src_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    dst_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_graph_nodes.id", ondelete="CASCADE"), nullable=False
    )
    rel: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)


class GreyboxFinding(Base):
    __tablename__ = "greybox_findings"
    __table_args__ = (
        UniqueConstraint("run_id", "dedup_key", name="uq_greybox_findings_run_dedup"),
        Index("ix_greybox_findings_run_version", "run_id", "version"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    dedup_key: Mapped[str] = mapped_column(String(300), nullable=False)
    check_id: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="candidate")
    confidence: Mapped[str] = mapped_column(String(8), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    location: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    affected_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_assets.id", ondelete="SET NULL"), nullable=True
    )
    canonical_issue_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_canonical_issues.id", ondelete="SET NULL"), nullable=True
    )
    node_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    work_order_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    evidence: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    verification: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    detection_hints: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    # vulnerability | misconfiguration | hardening | informational (findclass.py);
    # "" on rows written before migration 0022 (derived from check_id on read).
    finding_class: Mapped[str] = mapped_column(String(24), default="", nullable=False,
                                               server_default="")
    # {"summary", "steps", "validation", "reproduction", "severity_rationale"}
    remediation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    first_event_seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    updated_at: Mapped[datetime] = _ts(default=_utcnow, onupdate=_utcnow)


class GreyboxCanonicalIssue(Base):
    """Agent-owned actionable issue; membership is never inferred by the backend."""
    __tablename__ = "greybox_canonical_issues"
    __table_args__ = (Index("ix_greybox_canonical_issues_run_updated", "run_id", "updated_at"),)
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    finding_class: Mapped[str] = mapped_column(String(24), nullable=False)
    verification_status: Mapped[str] = mapped_column(String(24), nullable=False)
    root_cause: Mapped[str] = mapped_column(Text, nullable=False, default="")
    remediation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    retesting_guidance: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_observed_at: Mapped[datetime] = _ts(default=_utcnow)
    last_observed_at: Mapped[datetime] = _ts(default=_utcnow)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    updated_at: Mapped[datetime] = _ts(default=_utcnow, onupdate=_utcnow)


class GreyboxIssueFinding(Base):
    """Reversible association between an original finding and a canonical issue."""
    __tablename__ = "greybox_issue_findings"
    __table_args__ = (
        Index("ix_greybox_issue_findings_run_issue", "run_id", "issue_id", "active"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    issue_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_canonical_issues.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_findings.id", ondelete="CASCADE"), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    added_at: Mapped[datetime] = _ts(default=_utcnow)
    removed_at: Mapped[datetime | None] = _ts(nullable=True)


class GreyboxIssueObservation(Base):
    """Immutable, identity-attributed occurrence supporting an issue/finding."""
    __tablename__ = "greybox_issue_observations"
    __table_args__ = (
        UniqueConstraint("run_id", "event_key", name="uq_greybox_issue_observations_event"),
        Index("ix_greybox_issue_observations_run_issue", "run_id", "issue_id", "observed_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    issue_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_canonical_issues.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_findings.id", ondelete="SET NULL"), nullable=True)
    event_key: Mapped[str] = mapped_column(String(300), nullable=False)
    location: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    observation_status: Mapped[str] = mapped_column(String(24), nullable=False)
    impact_status: Mapped[str] = mapped_column(String(24), nullable=False, default="unverified")
    identity: Mapped[str | None] = mapped_column(String(64), nullable=True)
    evidence: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    observed_at: Mapped[datetime] = _ts(default=_utcnow)


class GreyboxCorrelationAudit(Base):
    """Append-only semantic grouping decision and rationale."""
    __tablename__ = "greybox_correlation_audit"
    __table_args__ = (
        UniqueConstraint("run_id", "idempotency_key", name="uq_greybox_correlation_idempotency"),
        Index("ix_greybox_correlation_audit_run_issue", "run_id", "canonical_issue_id", "created_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    action: Mapped[str] = mapped_column(String(24), nullable=False)
    canonical_issue_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_canonical_issues.id", ondelete="CASCADE"), nullable=False)
    related_issue_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    idempotency_key: Mapped[str] = mapped_column(String(300), nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)


class GreyboxEvent(Base):
    __tablename__ = "greybox_events"
    __table_args__ = (
        UniqueConstraint("run_id", "seq", name="uq_greybox_events_run_seq"),
        Index("ix_greybox_events_run_kind_seq", "run_id", "kind", "seq"),
        Index("ix_greybox_events_run_agent_seq", "run_id", "agent_id", "seq"),
        Index("ix_greybox_events_run_wo_seq", "run_id", "work_order_id", "seq"),
    )
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    run_id: Mapped[uuid.UUID] = _run_fk()
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    ts: Mapped[datetime] = _ts(default=_utcnow)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    level: Mapped[str] = mapped_column(String(8), nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_agents.id", ondelete="SET NULL"), nullable=True
    )
    work_order_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    tool_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    summary: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str | None] = mapped_column(String(16), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    refs: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class GreyboxHttpExchange(Base):
    __tablename__ = "greybox_http_exchanges"
    __table_args__ = (Index("ix_greybox_http_exchanges_run_id", "run_id", "id"),)
    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    run_id: Mapped[uuid.UUID] = _run_fk()
    ts: Mapped[datetime] = _ts(default=_utcnow)
    agent_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    work_order_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    tool: Mapped[str] = mapped_column(String(48), nullable=False)
    tool_call_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    url: Mapped[str] = mapped_column(String(2000), nullable=False)
    scheme: Mapped[str | None] = mapped_column(String(8), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    path: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    resolved_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    via_proxy: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False,
                                            server_default=text("false"))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    request_headers: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_body_truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    response_headers: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    response_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_body_truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    response_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    body_omitted_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    block_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(String(300), nullable=True)
    redirect_hop: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    parent_exchange_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # The identity the request carried: "anon", "provided-cookie" or an account
    # label (never a secret). Lets cross-identity analyses attribute what each
    # identity was shown (exploration/correlate.py). NULL on older rows.
    identity: Mapped[str | None] = mapped_column(String(64), nullable=True)


class GreyboxReport(Base):
    __tablename__ = "greybox_reports"
    run_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("greybox_runs.id", ondelete="CASCADE"), primary_key=True
    )
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    markdown: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    generated_at: Mapped[datetime | None] = _ts(nullable=True)


class GreyboxHint(Base):
    """Analyst steering for a running scan. ``text`` and ``target`` are
    redacted before the insert; the planner processes each open hint exactly once."""
    __tablename__ = "greybox_hints"
    __table_args__ = (
        Index("ix_greybox_hints_run_status", "run_id", "status", "created_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    text: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(String(16), nullable=False)
    target: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    about_node_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    node_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    result: Mapped[str | None] = mapped_column(String(500), nullable=True)
    work_order_ids: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_by_name: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = _ts(default=_utcnow)
    addressed_at: Mapped[datetime | None] = _ts(nullable=True)
    # The run chat (0018): the exploration agent's (or the platform's fallback)
    # reply, the cycle that produced it and the first cycle that read the message.
    reply: Mapped[str | None] = mapped_column(Text, nullable=True)
    replied_at: Mapped[datetime | None] = _ts(nullable=True)
    reply_cycle: Mapped[int | None] = mapped_column(Integer, nullable=True)
    seen_cycle: Mapped[int | None] = mapped_column(Integer, nullable=True)


class GreyboxDefense(Base):
    """A defensive recommendation (WAF/detection rule or configuration) generated in the
    reporting phase. ``scope="finding"`` ones are generated from a
    verified or candidate finding (``finding_id`` set); ``scope="asset"`` ones come from
    the live network analysis and protect a host, service or endpoint asset
    (``asset_id`` set, ``finding_id`` null). ``finding_ids`` lists every finding the
    recommendation addresses. Every text field is redacted before the insert."""
    __tablename__ = "greybox_defenses"
    __table_args__ = (
        Index("ix_greybox_defenses_run_finding", "run_id", "finding_id", "created_at"),
    )
    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = _run_fk()
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_findings.id", ondelete="CASCADE"), nullable=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("greybox_assets.id", ondelete="CASCADE"), nullable=True
    )
    scope: Mapped[str] = mapped_column(String(8), nullable=False, default="finding",
                                       server_default="finding")
    finding_ids: Mapped[list] = mapped_column(JSON, nullable=False, default=list,
                                              server_default="[]")
    # finding scope: the exploration-graph defense node; asset scope: the asset-graph
    # defense node.
    node_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="proposed")
    created_at: Mapped[datetime] = _ts(default=_utcnow)


# Child tables in dependency order (parents first). Used by the migration test and by
# explicit run deletion (SQLite does not enforce ON DELETE CASCADE without a PRAGMA).
RUN_CHILD_MODELS = (
    GreyboxAgent,
    GreyboxAsset,
    GreyboxAssetEdge,
    GreyboxWorkOrder,
    GreyboxGraphNode,
    GreyboxGraphEdge,
    GreyboxCanonicalIssue,
    GreyboxFinding,
    GreyboxIssueFinding,
    GreyboxIssueObservation,
    GreyboxCorrelationAudit,
    GreyboxEvent,
    GreyboxHttpExchange,
    GreyboxReport,
    GreyboxHint,
    GreyboxDefense,
)
GREYBOX_TABLES = (
    "greybox_targets",
    "greybox_runs",
    *(m.__tablename__ for m in RUN_CHILD_MODELS),
)
