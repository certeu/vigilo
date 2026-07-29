"""ORM models. DB-portable types only (runs on SQLite in tests, Postgres in prod)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from src.webapi.db import Base

ROLE_ADMIN = "admin"
ROLE_USER = "user"

# Run lifecycle states.
RUN_QUEUED = "queued"
RUN_PREPARING = "preparing"
RUN_RUNNING = "running"
RUN_SUCCEEDED = "succeeded"
RUN_FAILED = "failed"
RUN_CANCELLED = "cancelled"
RUN_TERMINAL = frozenset({RUN_SUCCEEDED, RUN_FAILED, RUN_CANCELLED})


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(SQLAlchemyBaseUserTableUUID, Base):
    __tablename__ = "users"
    role: Mapped[str] = mapped_column(String(16), default=ROLE_USER, nullable=False)
    # Bumped on every password change/reset. Embedded as a claim in issued JWTs; the
    # auth strategy rejects a token whose epoch != the user's current epoch, so a
    # password change invalidates all previously-issued sessions. (Migration 0006.)
    session_epoch: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0", nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Credential(Base):
    __tablename__ = "credentials"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)  # gitlab_token | cookie_header
    label: Mapped[str] = mapped_column(String(200), nullable=False)
    secret_enc: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    gitlab_base_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class AdminConfig(Base):
    __tablename__ = "admin_config"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    model_small: Mapped[str] = mapped_column(String(100), default="claude-haiku-4-5")
    model_medium: Mapped[str] = mapped_column(String(100), default="claude-sonnet-4-6")
    model_large: Mapped[str] = mapped_column(String(100), default="claude-opus-4-6")
    executor: Mapped[str] = mapped_column(String(16), default="claude")
    default_max_concurrent_pipelines: Mapped[int] = mapped_column(Integer, default=8)
    global_concurrent_run_cap: Mapped[int] = mapped_column(Integer, default=2)
    smtp_host: Mapped[str | None] = mapped_column(String(200), nullable=True)
    smtp_from: Mapped[str | None] = mapped_column(String(200), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class Invitation(Base):
    """An admin invitation to join, redeemable once via a token to set a password."""

    __tablename__ = "invitations"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    role: Mapped[str] = mapped_column(String(16), default=ROLE_USER, nullable=False)
    invited_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    accepted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Repository(Base):
    """An attachable source. Team-visible metadata; the credential used to fetch
    it (default_credential_id) stays private to its owner."""

    __tablename__ = "repositories"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    source_type: Mapped[str] = mapped_column(String(16), nullable=False)  # upload | gitlab
    gitlab_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    gitlab_project_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    default_credential_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("credentials.id"), nullable=True
    )
    webhook_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Per-repository overrides of the global admin config: keys among
    # {executor, model_small, model_medium, model_large}. Empty → use global.
    pipeline_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    # Custom scan instructions (Vigilo config equivalents): description + focus/avoid
    # rules. Keys: {description, focus, avoid}. Threaded into the pipeline per run.
    scan_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    # Privacy: when True, only the owner, explicitly-granted users, and admins may see
    # the repo and its jobs/runs/reports. When False, team-visible (all authenticated).
    is_private: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # True once source has been uploaded (upload repos) — a zip/tarball or a raw file tree.
    upload_ready: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Background ingestion state (added via Alembic migration 0004):
    #   idle → no source yet | importing → validating upload | ready | failed
    ingestion_status: Mapped[str] = mapped_column(
        String(16), default="idle", server_default="idle", nullable=False
    )
    ingestion_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # When True (GitLab source + write-scoped credential), remediation pushes fix
    # branches and opens merge requests back to the origin. Opt-in per repository.
    push_patches: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Soft-hide a repository from default listings (added via Alembic migration 0002).
    archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class RepositoryAccess(Base):
    """A grant giving one user access to a private repository."""

    __tablename__ = "repository_access"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Job(Base):
    """A saved run configuration: repo + stage preset + target + overrides."""

    __tablename__ = "jobs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id"), nullable=False, index=True
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    stage_preset: Mapped[str] = mapped_column(String(16), nullable=False)  # vuln|vuln_patch|full
    target_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    engine: Mapped[str] = mapped_column(String(16), default="whitebox", nullable=False)
    # Opt-in: email the triggering user (fallback: job/repo owner) the report when a
    # run of this job finishes. Off by default. (Migration 0007.)
    notify_email: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    pipeline_overrides: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )


class Run(Base):
    """One execution of a job."""

    __tablename__ = "runs"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id"), nullable=False, index=True
    )
    triggered_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"), nullable=True
    )
    trigger_type: Mapped[str] = mapped_column(
        String(16), default="manual", nullable=False
    )  # manual | schedule | gitlab_mr
    status: Mapped[str] = mapped_column(String(16), default=RUN_QUEUED, nullable=False)
    current_phase: Mapped[str | None] = mapped_column(String(64), nullable=True)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    workflow_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    task_queue: Mapped[str | None] = mapped_column(String(128), nullable=True)
    container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    data_dir: Mapped[str] = mapped_column(String(500), nullable=False)
    report_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    total_cost_usd: Mapped[float | None] = mapped_column(Float, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    gitlab_mr_iid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Git commit SHA the run actually scanned (captured at ingest; GitLab repos).
    # Added via Alembic migration 0005 — reproducibility: which code a report describes.
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    notify_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class RunMetrics(Base):
    """Extracted, denormalized metrics for a completed run (one row per run).

    Denormalized severity columns support fast timeline/aggregation queries; the
    full breakdown (category_counts, status_counts, totals) lives in ``data``.
    """

    __tablename__ = "run_metrics"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("runs.id"), nullable=False, unique=True, index=True
    )
    repository_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("repositories.id"), nullable=False, index=True
    )
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    informational: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    exploited: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    supply_chain: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Schedule(Base):
    """A recurring (cron) or event-driven (GitLab MR) trigger for a job."""

    __tablename__ = "schedules"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("jobs.id"), nullable=False, index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)  # once|recurring|gitlab_mr
    cron: Mapped[str | None] = mapped_column(String(100), nullable=True)  # recurring only
    run_at: Mapped[datetime | None] = mapped_column(  # one-off (kind='once')
        DateTime(timezone=True), nullable=True
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    temporal_schedule_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("runs.id"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
