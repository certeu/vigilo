# Vigilo Web Platform — configuration reference

All platform settings are environment variables with the `VIGILO_` prefix (read by
`src/webapi/settings.py`). Copy the ones you need into your `.env` — `env.sample` is a
ready-to-edit starting point; this file is the exhaustive reference. See the
[main README](../README.md#configuration-reference) for the essentials.

## Required

| Variable | Meaning |
|---|---|
| `VIGILO_JWT_SECRET` | JWT signing secret (use ≥32 random bytes) |
| `VIGILO_FERNET_KEY` | base64 Fernet key encrypting credential secrets. Generate: `python -c "from src.webapi.security.vault import generate_key; print(generate_key())"` |
| `VIGILO_DATABASE_URL` | `postgresql+asyncpg://user:pass@host:5432/vigilo` (**Postgres is the only supported runtime datastore**; SQLite is used only by the test suite) |

## First-admin bootstrap (first boot only)

| Variable | Meaning |
|---|---|
| `VIGILO_FIRST_ADMIN_EMAIL` | creates an initial admin if no user with this email exists |
| `VIGILO_FIRST_ADMIN_PASSWORD` | its password |

## Execution

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_EXECUTION_ENGINE` | `docker` | `temporal` (persistent worker on the shared task queue — used by `docker-compose.full.yml`), `docker` (ephemeral container-per-job + Temporal), `mock` (demo, emits sample deliverables), `fake` (tests) |
| `VIGILO_JOBS_DATA_DIR` | `/data/jobs` | per-run workspaces |
| `VIGILO_WORKER_IMAGE` | `vigilo-worker:latest` | generic pipeline worker image (docker engine) |
| `VIGILO_TEMPORAL_ADDRESS` | `temporal:7233` | Temporal server (docker engine) |
| `VIGILO_GLOBAL_CONCURRENT_RUN_CAP` | `2` | max simultaneously-running scans (admission control) |

## Global pipeline defaults (seeded into admin_config on first boot; per-repo overridable)

| Variable | Default |
|---|---|
| `VIGILO_DEFAULT_EXECUTOR` | `claude` |
| `VIGILO_DEFAULT_MODEL_SMALL` | `claude-haiku-4-5` |
| `VIGILO_DEFAULT_MODEL_MEDIUM` | `claude-sonnet-4-6` |
| `VIGILO_DEFAULT_MODEL_LARGE` | `claude-opus-4-6` |
| `VIGILO_DEFAULT_MAX_CONCURRENT_PIPELINES` | `8` |

## Notifications (email)

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_SMTP_HOST` | (unset → no email) | SMTP server. In the full compose this is `mailhog` |
| `VIGILO_SMTP_PORT` | `25` | (MailHog uses `1025`) |
| `VIGILO_SMTP_FROM` | `vigilo@example.com` | sender |
| `VIGILO_UI_BASE_URL` | (unset) | public UI URL — used in invite + completion email links |

## Other

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_JWT_LIFETIME_SECONDS` | `3600` | access-token TTL (must be > 0) |
| `VIGILO_UPLOADS_DIR` | `/data/uploads` | uploaded source archives |
| `VIGILO_MAX_UPLOAD_MB` | `2048` | per-upload size cap (streamed to disk; 413 over cap) |
| `VIGILO_TEMPORAL_TASK_QUEUE` | `vigilo-pipeline` | queue the worker serves / API submits to |
| `VIGILO_RUN_MIGRATIONS_ON_START` | `true` | run Alembic `upgrade head` on API boot |

## Authenticated SMTP (real providers)

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_SMTP_USER` | (unset) | set → authenticated SMTP (LOGIN) |
| `VIGILO_SMTP_PASSWORD` | (unset) | SMTP password |
| `VIGILO_SMTP_STARTTLS` | `false` | upgrade the connection with STARTTLS |

## Reverse proxy / TLS (`docker-compose.full.yml`)

The full stack runs behind **Traefik**, which terminates TLS and is the only service
with published host ports (`80` → redirects to `443`, and `443`). The UI is the sole
public router; the API, Postgres, Temporal and MailHog have no router and no published
port — they are reachable only on the internal Docker network. The UI's nginx proxies
`/api` to the API internally, so the API is never exposed directly.

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_HOSTNAME` | `vigilo.example.com` | Public hostname for the UI. Used in the Traefik `Host()` router rule and as the default for `VIGILO_UI_BASE_URL`. Set it — the placeholder default will not match your traffic. |
| `ACME_EMAIL` | `admin@example.com` | Contact email registered with the ACME CA. Must be a real address: Let's Encrypt rejects `@example.com`. |
| `ACME_CASERVER` | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL. Defaults to Let's Encrypt; point it at your own CA to use an internal/corporate ACME server. |

Certificates are issued via the **HTTP-01 challenge** on port 80 and persisted in the
`acme_data` Docker volume (so they are not re-requested on restart). This requires the
ACME CA (`ACME_CASERVER`) to reach this host on port 80 at `VIGILO_HOSTNAME`; ensure DNS
and firewall allow that before first boot. Security headers (HSTS, `X-Content-Type-Options`,
`X-Frame-Options: DENY`, `Referrer-Policy`) are applied by a Traefik middleware.

Traefik is optional. To run without it — no TLS, UI published directly on a host port —
layer `deploy/docker-compose.plain.yml` on top of the full stack; see
[Deployment options](../README.md#deployment-options) in the main README.

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_HTTP_PORT` | `8080` | Host port the UI is published on when using `docker-compose.plain.yml`. Ignored otherwise. |

## Database migrations (Alembic)

**Postgres is the only runtime datastore.** Schema is managed by Alembic (not
`create_all`). The API runs `alembic upgrade head` automatically on boot
(`VIGILO_RUN_MIGRATIONS_ON_START=true`), so an existing DB safely takes new columns.

Deploy command (also runs automatically on API start):

    python -m scripts.run_migrations upgrade      # apply all pending migrations

Other: `... run_migrations current | downgrade <rev> | stamp head`. Migrations live in
`src/webapi/alembic/versions/`. A migration failure (e.g. the DB is ahead of the code)
raises and the API refuses to start.
