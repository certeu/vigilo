"""Application settings, loaded from environment (prefix VIGILO_)."""
from __future__ import annotations

from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VIGILO_", env_file=".env", extra="ignore")

    database_url: str = "sqlite+aiosqlite:///./vigilo_platform.db"
    jwt_secret: str = "CHANGE_ME"
    jwt_lifetime_seconds: int = 3600
    fernet_key: str = ""  # base64 32-byte key; required in prod (see security/vault.py)
    first_admin_email: str | None = None
    first_admin_password: str | None = None
    serve_ui: bool = False
    run_migrations_on_start: bool = True       # alembic upgrade head on boot (prod)

    # Execution engine
    execution_engine: str = "docker"          # "docker" (prod) | "fake" (local/dev)
    jobs_data_dir: str = "/data/jobs"          # per-run workspaces live here
    uploads_dir: str = "/data/uploads"         # uploaded source archives: {repo_id}.zip
    max_upload_mb: int = 2048                   # per-upload size cap (default 2 GiB)
    worker_image: str = "vigilo-worker:latest"  # generic pipeline worker image
    temporal_address: str = "temporal:7233"
    temporal_task_queue: str = "vigilo-pipeline"  # shared queue the worker serves on
    global_concurrent_run_cap: int = 2         # max concurrent non-terminal runs

    # Notifications
    smtp_host: str | None = None               # None → notifications disabled (fake)
    smtp_from: str = "vigilo@example.com"
    smtp_port: int = 25
    smtp_user: str | None = None               # set → authenticated SMTP (LOGIN)
    smtp_password: str | None = None
    smtp_starttls: bool = False                # upgrade the connection with STARTTLS
    ui_base_url: str | None = None             # e.g. http://vigilo.internal (for links)

    # Login brute-force throttle (0 disables; used by LoginRateLimitMiddleware)
    login_max_failures: int = 10               # failed attempts per window before 429
    login_failure_window_s: int = 300          # sliding window length in seconds

    # Global pipeline defaults (seeded into admin_config on first boot; per-repo
    # overridable). Set these in .env so the admin page reflects the deployment.
    default_executor: str = "claude"
    default_model_small: str = "claude-haiku-4-5"
    default_model_medium: str = "claude-sonnet-4-6"
    default_model_large: str = "claude-opus-4-6"
    default_max_concurrent_pipelines: int = 8


    @field_validator("jwt_lifetime_seconds")
    @classmethod
    def _positive_lifetime(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("jwt_lifetime_seconds must be positive")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
