"""Application settings, loaded from environment (prefix VIGILO_)."""
from __future__ import annotations

import os
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
    # Public API listener (src/webapi/main.py). The grey-box scope guard refuses these
    # endpoints as targets, so keep them in sync with how the API is really bound.
    api_host: str = "0.0.0.0"
    api_port: int = 8080
    run_migrations_on_start: bool = True       # alembic upgrade head on boot (prod)

    # Execution engine
    # Engines (see engine/provider.py): "docker" (container per run, default),
    # "temporal" (persistent worker, used by deploy/docker-compose.full.yml),
    # "mock" (simulated scan, no Claude) | "fake" (in-memory, tests).
    execution_engine: str = "docker"
    jobs_data_dir: str = "/data/jobs"          # per-run workspaces live here
    uploads_dir: str = "/data/uploads"         # uploaded source archives: {repo_id}.zip
    max_upload_mb: int = 2048                   # per-upload size cap (default 2 GiB)
    worker_image: str = "vigilo-worker:latest"  # generic pipeline worker image
    docker_network: str = "vigilo_net"          # network worker containers join (docker engine)
    temporal_address: str = "temporal:7233"
    temporal_task_queue: str = "vigilo-pipeline"  # shared queue the worker serves on
    global_concurrent_run_cap: int = 2         # max concurrent non-terminal runs

    # Internal listener for per-run secret redemption (workers -> API). A SEPARATE port
    # from the public API, never published and never proxied by the UI's nginx.
    internal_host: str = "0.0.0.0"
    internal_port: int = 8081
    # URL the workers use to reach that listener; handed to per-run worker containers.
    internal_api_url: str = "http://api:8081"
    secret_max_age_hours: int = 168            # a run's secret record expires after this
    redeem_max_per_minute: int = 60            # redemption attempts per run per minute

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
    # Comma-separated IPs/CIDRs of reverse proxies whose X-Forwarded-For is believed
    # (login throttle client address). Default none: the TCP peer is the client.
    trusted_proxies: str = ""

    # Security hardening
    # Dev/test only: accept a weak/default JWT secret and expose /docs, /redoc and
    # /openapi.json. Production refuses to start with the default or a <32-char secret.
    dev_mode: bool = False
    # Interactive API docs: None -> follow dev_mode (on in dev, off in production).
    api_docs_enabled: bool | None = None
    # Send Strict-Transport-Security (only set when the API is served over https).
    hsts_enabled: bool = False

    # Repository (white-box) SSRF guard: hosts a repository URL may use even though they
    # resolve to private addresses (your GitLab), comma-separated. The host of the
    # worker's GITLAB_URL is allowed too. Dev/test: repo_allow_private_hosts lifts the
    # private-range deny for every host (never metadata/link-local/multicast/reserved).
    gitlab_allowed_hosts: str = ""
    repo_allow_private_hosts: bool = False

    # Global pipeline defaults, seeded into admin_config on first boot (and then
    # editable in Admin -> Models & executor; per-repo overridable). Only values set
    # explicitly are used: unset executor = auto-detect from the worker's provider
    # variables, unset model = the worker's tier variable or the executor's built-in.
    default_executor: str = ""
    default_model_small: str = ""
    default_model_medium: str = ""
    default_model_large: str = ""
    default_max_concurrent_pipelines: int = 8

    # Grey-box web platform. Off by default:
    # when false every /greybox/* route except GET /greybox/config returns 404 and
    # /analyses lists white-box runs only.
    greybox_web_enabled: bool = False
    greybox_executor: str = "worker"            # worker | inprocess | off
    # Dev/test only: allow loopback/private targets (127.0.0.0/8, RFC1918, ...).
    greybox_allow_private_targets: bool = False
    # Comma-separated EXTRA hostnames always refused as targets. The built-in platform
    # names (api, web, db, postgres, temporal, surrealdb, localhost.localdomain and the
    # host of internal_api_url) are always refused too, whatever this is set to.
    greybox_blocked_hosts: str = ""
    # Comma-separated EXTRA "host:port" endpoints always refused ("private:PORT" = that
    # port on any loopback/private address). The API ports (api_port, the default 8080, internal_port) and the
    # database port are always included.
    greybox_blocked_endpoints: str = ""
    # Opt-in egress proxies. When false the /greybox/egress-proxies routes
    # return 404 and a target cannot select a proxy. The engine never reads *_proxy
    # environment variables whatever this is set to.
    greybox_egress_proxies_enabled: bool = False
    greybox_max_active_runs_per_user: int = 2
    greybox_worker_max_runs: int = 2
    greybox_lease_ttl_s: int = 60
    greybox_heartbeat_s: int = 10

    # Grey-box exploration agent: the model
    # backends/credentials are the SAME ones white-box uses (ANTHROPIC_*, CODEX_*, see
    # src/webapi/engine); only the per-run bounds live here.
    greybox_agent_max_calls: int = 300         # enforced per run
    greybox_agent_max_tokens: int = 6_000_000  # enforced per run (input + output)
    greybox_agent_timeout_s: int = 60

    @field_validator("greybox_executor")
    @classmethod
    def _greybox_executor(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in ("worker", "inprocess", "off"):
            raise ValueError("greybox_executor must be worker, inprocess or off")
        return v


    @field_validator("trusted_proxies")
    @classmethod
    def _trusted_proxies(cls, v: str) -> str:
        import ipaddress
        for p in (v or "").split(","):
            if p.strip():
                ipaddress.ip_network(p.strip(), strict=False)   # ValueError -> invalid
        return v

    @field_validator("jwt_lifetime_seconds")
    @classmethod
    def _positive_lifetime(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("jwt_lifetime_seconds must be positive")
        return v


@lru_cache
def get_settings() -> Settings:
    # VIGILO_IGNORE_DOTENV (hermetic test runs, as in modelsel.load_env): read only the
    # process environment, never a developer's repo-root .env, whose values (e.g.
    # feature flags turned on locally) would otherwise change test outcomes.
    if os.environ.get("VIGILO_IGNORE_DOTENV", "").lower() in ("1", "true", "yes"):
        return Settings(_env_file=None)
    return Settings()


MIN_JWT_SECRET_LENGTH = 32
_DEFAULT_JWT_SECRET = "CHANGE_ME"


def assert_secure_jwt_secret(s: Settings | None = None) -> None:
    """Refuse to run with the shipped default or a short signing secret (token forgery),
    unless VIGILO_DEV_MODE is set. Called when the app is built."""
    s = s or get_settings()
    if s.dev_mode:
        return
    if s.jwt_secret == _DEFAULT_JWT_SECRET or len(s.jwt_secret) < MIN_JWT_SECRET_LENGTH:
        raise RuntimeError(
            "VIGILO_JWT_SECRET is the default or shorter than "
            f"{MIN_JWT_SECRET_LENGTH} characters. Set a long random value "
            "(e.g. `openssl rand -hex 32`), or VIGILO_DEV_MODE=true for local development."
        )
