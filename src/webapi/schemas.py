"""Pydantic API schemas. Secrets are never exposed in Read models."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi_users import schemas
from pydantic import BaseModel, field_validator, model_validator

from src.webapi.models import ROLE_USER
from src.types.stages import VALID_PRESETS


class UserRead(schemas.BaseUser[uuid.UUID]):
    role: str
    created_at: datetime


class UserCreate(schemas.BaseUserCreate):
    role: str = ROLE_USER


class ChangePassword(BaseModel):
    current_password: str
    new_password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AdminResetResult(BaseModel):
    reset_url: str
    email_sent: bool
    email_error: str | None = None


class UserUpdate(schemas.BaseUserUpdate):
    role: str | None = None


class CredentialCreate(BaseModel):
    kind: str
    label: str
    secret: str
    gitlab_base_url: str | None = None


class CredentialRead(BaseModel):
    id: uuid.UUID
    kind: str
    label: str
    gitlab_base_url: str | None
    created_at: datetime
    has_secret: bool


class AdminConfigRead(BaseModel):
    model_small: str
    model_medium: str
    model_large: str
    executor: str
    default_max_concurrent_pipelines: int
    global_concurrent_run_cap: int
    smtp_host: str | None
    smtp_from: str | None


class AdminConfigUpdate(BaseModel):
    model_small: str | None = None
    model_medium: str | None = None
    model_large: str | None = None
    executor: str | None = None
    default_max_concurrent_pipelines: int | None = None
    global_concurrent_run_cap: int | None = None
    smtp_host: str | None = None
    smtp_from: str | None = None


_SCAN_KEYS = {"description", "focus", "avoid"}


class RepositoryCreate(BaseModel):
    name: str
    source_type: Literal["upload", "gitlab"]
    gitlab_url: str | None = None
    gitlab_project_id: str | None = None
    default_credential_id: uuid.UUID | None = None
    is_private: bool = False
    scan_config: dict = {}
    # Convenience for the UI: a GitLab access token pasted at create time. The
    # server encrypts it as a per-user credential and links it as this repo's
    # default_credential_id (never stored in the clear). Use a write-scoped token
    # if you also enable push_patches.
    gitlab_token: str | None = None
    push_patches: bool = False

    @model_validator(mode="after")
    def _gitlab_needs_url(self):
        if self.source_type == "gitlab":
            if not self.gitlab_url:
                raise ValueError("gitlab_url is required when source_type='gitlab'")
            # Reject non-web schemes up front (file://, ext::, ssh://, …) — otherwise a
            # user could point the clone at a local repo or an internal host (SSRF/LFI).
            from urllib.parse import urlparse
            scheme = (urlparse(self.gitlab_url).scheme or "https").lower()
            if scheme not in ("https", "http"):
                raise ValueError(f"gitlab_url must be an http(s) URL (got {scheme!r})")
        return self

    @field_validator("scan_config")
    @classmethod
    def _scan_keys(cls, v):
        bad = set(v) - _SCAN_KEYS
        if bad:
            raise ValueError(f"unknown scan_config keys: {sorted(bad)}")
        return v


class RepositoryRead(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID
    name: str
    source_type: str
    gitlab_url: str | None
    gitlab_project_id: str | None
    default_credential_id: uuid.UUID | None
    has_webhook: bool
    is_private: bool
    upload_ready: bool
    push_patches: bool
    archived: bool
    ingestion_status: str = "idle"
    ingestion_error: str | None = None
    pipeline_config: dict
    scan_config: dict
    created_at: datetime


_CONFIG_KEYS = {"executor", "model_small", "model_medium", "model_large"}


class BulkDeleteRequest(BaseModel):
    ids: list[uuid.UUID]


class BulkDeleteResult(BaseModel):
    deleted: list[uuid.UUID] = []
    denied: list[uuid.UUID] = []   # exists but not owner/admin (or not visible)


class RepositoryUpdate(BaseModel):
    name: str | None = None
    default_credential_id: uuid.UUID | None = None
    is_private: bool | None = None
    push_patches: bool | None = None
    pipeline_config: dict | None = None
    scan_config: dict | None = None
    # Add/replace the GitLab access token (encrypted as a new credential + linked).
    gitlab_token: str | None = None

    @field_validator("pipeline_config")
    @classmethod
    def _known_keys(cls, v):
        if v is not None:
            bad = set(v) - _CONFIG_KEYS
            if bad:
                raise ValueError(f"unknown pipeline_config keys: {sorted(bad)}")
        return v

    @field_validator("scan_config")
    @classmethod
    def _scan_keys(cls, v):
        if v is not None:
            bad = set(v) - _SCAN_KEYS
            if bad:
                raise ValueError(f"unknown scan_config keys: {sorted(bad)}")
        return v


class AccessGrantCreate(BaseModel):
    user_id: uuid.UUID | None = None
    email: str | None = None

    @model_validator(mode="after")
    def _need_one(self):
        if not self.user_id and not self.email:
            raise ValueError("provide user_id or email")
        return self


class AccessGrantRead(BaseModel):
    user_id: uuid.UUID
    email: str
    created_at: datetime


class JobCreate(BaseModel):
    repository_id: uuid.UUID
    name: str
    stage_preset: str
    target_url: str | None = None
    notify_email: bool = False
    pipeline_overrides: dict = {}

    @field_validator("stage_preset")
    @classmethod
    def _valid_preset(cls, v):
        if v not in VALID_PRESETS:
            raise ValueError(f"stage_preset must be one of {VALID_PRESETS}")
        return v


class JobUpdate(BaseModel):
    notify_email: bool | None = None


class JobRead(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID
    repository_id: uuid.UUID
    name: str
    stage_preset: str
    target_url: str | None
    engine: str
    notify_email: bool = False
    pipeline_overrides: dict
    created_at: datetime


class RunRead(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    triggered_by: uuid.UUID | None
    trigger_type: str
    status: str
    current_phase: str | None
    session_id: str
    workflow_id: str | None
    total_cost_usd: float | None
    error_summary: str | None
    commit_sha: str | None = None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


class ScheduleCreate(BaseModel):
    job_id: uuid.UUID
    kind: Literal["once", "recurring", "gitlab_mr"]
    cron: str | None = None
    run_at: datetime | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def _kind_requirements(self):
        if self.kind == "recurring":
            if not self.cron:
                raise ValueError("cron is required when kind='recurring'")
            # Reject a syntactically invalid cron up front; otherwise the schedule
            # is stored but silently never fires (croniter raises at poll time).
            try:
                from croniter import croniter
                if not croniter.is_valid(self.cron):
                    raise ValueError(f"invalid cron expression: {self.cron!r}")
            except ImportError:  # optional dep; scheduler validates at runtime
                pass
        if self.kind == "once" and not self.run_at:
            raise ValueError("run_at is required when kind='once'")
        return self


class ScheduleUpdate(BaseModel):
    cron: str | None = None
    run_at: datetime | None = None
    enabled: bool | None = None

    @field_validator("cron")
    @classmethod
    def _valid_cron(cls, v):
        if v:
            try:
                from croniter import croniter
                if not croniter.is_valid(v):
                    raise ValueError(f"invalid cron expression: {v!r}")
            except ImportError:
                pass
        return v


class ScheduleRead(BaseModel):
    id: uuid.UUID
    job_id: uuid.UUID
    created_by: uuid.UUID
    kind: str
    cron: str | None
    run_at: datetime | None
    enabled: bool
    created_at: datetime


class InvitationCreate(BaseModel):
    email: str
    role: Literal["admin", "user"] = "user"


class InvitationRead(BaseModel):
    id: uuid.UUID
    email: str
    role: str
    accepted: bool
    created_at: datetime


class InvitationCreated(InvitationRead):
    # Returned ONLY on creation so the admin can share the link when SMTP isn't set.
    accept_url: str
    email_sent: bool
    # Why the email didn't send, if it didn't: "SMTP not configured" vs a real send
    # error (relay unreachable, auth failure, …). None when email_sent is True.
    email_error: str | None = None


class AcceptInvite(BaseModel):
    token: str
    password: str
