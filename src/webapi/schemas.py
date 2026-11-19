"""Pydantic API schemas. Secrets are never exposed in Read models."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi_users import schemas
from pydantic import BaseModel, field_validator, model_validator

from src.webapi.models import ROLE_USER
from src.types.config import RETRY_PRESETS as _RETRY_PRESETS, PipelineConfig
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
    # Forge credentials: the forge host the credential is bound to.
    forge_base_url: str | None = None
    # Deprecated name of ``forge_base_url``, still accepted.
    gitlab_base_url: str | None = None

    @model_validator(mode="after")
    def _forge_checks(self):
        self.forge_base_url = _merge_alias(
            self.forge_base_url, self.gitlab_base_url, "forge_base_url", "gitlab_base_url")
        self.gitlab_base_url = None
        from src.services.forges import forge_for_kind
        forge = forge_for_kind(self.kind)
        if forge is not None:
            forge.check_credential_secret(self.kind, self.secret, self.forge_base_url)
        return self


class CredentialRead(BaseModel):
    id: uuid.UUID
    kind: str
    label: str
    forge_base_url: str | None
    # Deprecated: same value as ``forge_base_url``.
    gitlab_base_url: str | None
    created_at: datetime
    has_secret: bool


def _merge_alias(new, old, new_name: str, old_name: str):
    """A field and its deprecated alias: either may be given, not two different values."""
    if old is not None and new is not None and old != new:
        raise ValueError(f"{old_name} is a deprecated name of {new_name}; give only one")
    return new if new is not None else old


class AdminConfigRead(BaseModel):
    model_small: str
    model_medium: str
    model_large: str
    executor: str
    default_max_concurrent_pipelines: int
    global_concurrent_run_cap: int
    smtp_host: str | None
    smtp_from: str | None


EXECUTORS = ("claude", "codex", "opencode")
_MODEL_MAX_LEN = 100


class AdminConfigUpdate(BaseModel):
    model_small: str | None = None
    model_medium: str | None = None
    model_large: str | None = None
    executor: str | None = None
    default_max_concurrent_pipelines: int | None = None
    global_concurrent_run_cap: int | None = None
    smtp_host: str | None = None
    smtp_from: str | None = None

    @field_validator("executor")
    @classmethod
    def _check_executor(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip().lower()
        if v not in EXECUTORS:
            raise ValueError(f"executor must be one of: {', '.join(EXECUTORS)}")
        return v

    @field_validator("model_small", "model_medium", "model_large")
    @classmethod
    def _check_model(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return ""  # clears the value: the worker's own default applies
        if len(v) > _MODEL_MAX_LEN:
            raise ValueError(f"model name must be at most {_MODEL_MAX_LEN} characters")
        if any(c.isspace() for c in v):
            raise ValueError("model name must not contain whitespace")
        return v


class ModelDefaultsRead(BaseModel):
    """Effective global executor/model defaults (non-secret; any signed-in user)."""

    executor: str
    model_small: str
    model_medium: str
    model_large: str


class ExecutorStatus(BaseModel):
    executor: str
    configured: bool
    mode: str | None = None  # e.g. "api key", "bedrock", "foundry", "gateway"
    present: list[str]  # names of env vars that are set (never values)
    missing: list[str]  # what to set to make it usable
    detail: str


class ExecutorStatusRead(BaseModel):
    executors: list[ExecutorStatus]


_SCAN_KEYS = {"description", "focus", "avoid"}


class GitHubAppIn(BaseModel):
    """A GitHub App to clone with (stored encrypted as a ``github_app`` credential)."""

    app_id: str
    private_key: str
    installation_id: str | None = None


# source_type -> the token fields that belong to it
_TOKEN_FIELDS = {"gitlab": ("gitlab_token",), "github": ("github_token", "github_app")}


def _check_token_fields(source_type: str | None, values: dict) -> None:
    """Token fields only for their own forge; at most one GitHub credential."""
    given = [f for fields in _TOKEN_FIELDS.values() for f in fields if values.get(f)]
    allowed = _TOKEN_FIELDS.get(source_type or "", ())
    wrong = [f for f in given if f not in allowed]
    if wrong:
        raise ValueError(f"{', '.join(wrong)} does not apply to a {source_type!r} repository")
    if len(given) > 1:
        raise ValueError(f"give only one of {', '.join(given)}")


class RepositoryCreate(BaseModel):
    name: str
    source_type: Literal["upload", "gitlab", "github"]
    # Forge sources: the repository URL (GitLab project or GitHub repository).
    remote_url: str | None = None
    forge_project_id: str | None = None
    # Deprecated names of ``remote_url`` / ``forge_project_id``, still accepted.
    gitlab_url: str | None = None
    gitlab_project_id: str | None = None
    default_credential_id: uuid.UUID | None = None
    is_private: bool = False
    scan_config: dict = {}
    # Convenience for the UI: a forge credential pasted at create time. The server
    # encrypts it as a per-user credential bound to the forge host and links it as
    # this repo's default_credential_id (never stored in the clear). Use a
    # write-scoped GitLab token if you also enable push_patches.
    gitlab_token: str | None = None
    github_token: str | None = None
    github_app: GitHubAppIn | None = None
    push_patches: bool = False

    @model_validator(mode="after")
    def _forge_needs_url(self):
        self.remote_url = _merge_alias(self.remote_url, self.gitlab_url,
                                       "remote_url", "gitlab_url")
        self.forge_project_id = _merge_alias(self.forge_project_id, self.gitlab_project_id,
                                             "forge_project_id", "gitlab_project_id")
        self.gitlab_url = self.gitlab_project_id = None
        _check_token_fields(self.source_type, {
            "gitlab_token": self.gitlab_token, "github_token": self.github_token,
            "github_app": self.github_app,
        })
        from src.services.forges import get_forge
        forge = get_forge(self.source_type)
        if forge is not None:
            if not self.remote_url:
                raise ValueError(f"remote_url is required when source_type={self.source_type!r}")
            forge.check_remote_url(self.remote_url)
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
    forge: str | None = None
    remote_url: str | None
    forge_project_id: str | None
    # Deprecated: same values as ``remote_url`` / ``forge_project_id``.
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
    # Add/replace the repository's forge credential (encrypted as a new credential
    # and linked); only the field of the repository's own forge applies.
    gitlab_token: str | None = None
    github_token: str | None = None
    github_app: GitHubAppIn | None = None

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


# Per-job tuning forwarded to the workflow as ``pipeline_config``: key -> (min, max)
# for integer knobs; ``retry_preset`` is an enum.
# One source of truth: the workflow's own bounds (it clamps to these), so the API
# rejects what the workflow would silently change.
PIPELINE_INT_BOUNDS: dict[str, tuple[int, int]] = dict(PipelineConfig.BOUNDS)
RETRY_PRESETS = _RETRY_PRESETS
PIPELINE_OVERRIDE_KEYS = frozenset(PIPELINE_INT_BOUNDS) | {"retry_preset"}


def validate_pipeline_overrides(v: dict | None) -> dict:
    """Reject unknown keys / wrong types / out-of-range values."""
    if not v:
        return {}
    if not isinstance(v, dict):
        raise ValueError("pipeline_overrides must be an object")
    bad = set(v) - PIPELINE_OVERRIDE_KEYS
    if bad:
        raise ValueError(f"unknown pipeline_overrides keys: {sorted(bad)}")
    out: dict = {}
    for key, val in v.items():
        if val is None:
            continue
        if key == "retry_preset":
            if val not in RETRY_PRESETS:
                raise ValueError(f"retry_preset must be one of {RETRY_PRESETS}")
        else:
            lo, hi = PIPELINE_INT_BOUNDS[key]
            if isinstance(val, bool) or not isinstance(val, int) or not lo <= val <= hi:
                raise ValueError(f"{key} must be an integer between {lo} and {hi}")
        out[key] = val
    return out


class JobCreate(BaseModel):
    repository_id: uuid.UUID
    name: str
    stage_preset: str
    target_url: str | None = None
    # One of the caller's cookie_header credentials: the run's agents (except the
    # planner) test the live target logged in with it. Requires target_url.
    target_credential_id: uuid.UUID | None = None
    notify_email: bool = False
    pipeline_overrides: dict = {}
    # Deprecated and ignored (kept so older clients that send it still validate).
    engine: str | None = None

    @field_validator("pipeline_overrides")
    @classmethod
    def _valid_overrides(cls, v):
        return validate_pipeline_overrides(v)

    @field_validator("stage_preset")
    @classmethod
    def _valid_preset(cls, v):
        if v not in VALID_PRESETS:
            raise ValueError(f"stage_preset must be one of {VALID_PRESETS}")
        return v


class JobUpdate(BaseModel):
    # Send null to clear the cookie credential (omit to leave it unchanged).
    target_credential_id: uuid.UUID | None = None
    notify_email: bool | None = None
    pipeline_overrides: dict | None = None

    @field_validator("pipeline_overrides")
    @classmethod
    def _valid_overrides(cls, v):
        return None if v is None else validate_pipeline_overrides(v)


class JobRead(BaseModel):
    id: uuid.UUID
    created_by: uuid.UUID
    repository_id: uuid.UUID
    name: str
    stage_preset: str
    target_url: str | None
    target_credential_id: uuid.UUID | None = None
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
