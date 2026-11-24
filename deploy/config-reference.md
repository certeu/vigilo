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
| `VIGILO_FIRST_ADMIN_EMAIL` | creates an initial admin if no user with this email exists; must pass standard email validation (reserved domains such as `.local` are rejected), or be blank to skip bootstrap |
| `VIGILO_FIRST_ADMIN_PASSWORD` | its password |

## Execution

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_EXECUTION_ENGINE` | `docker` | `temporal` (persistent worker on the shared task queue — used by `docker-compose.full.yml`), `docker` (ephemeral container-per-job + Temporal), `mock` (demo, emits sample deliverables), `fake` (tests) |
| `VIGILO_JOBS_DATA_DIR` | `/data/jobs` | per-run workspaces |
| `VIGILO_WORKER_IMAGE` | `vigilo-worker:latest` | generic pipeline worker image (docker engine) |
| `VIGILO_TEMPORAL_ADDRESS` | `temporal:7233` | Temporal server (docker engine) |
| `VIGILO_GLOBAL_CONCURRENT_RUN_CAP` | `2` | max simultaneously-running scans (admission control) |
| `VIGILO_DOCKER_NETWORK` | `vigilo_net` | Docker network the per-run worker containers join (docker engine) |

## Patch push-back (GitLab)

There is no global GitLab token. Pushing is configured **per repository** in the UI
(repository from GitLab + credential + "push patches"). For such a run, after the
remediation agent has written and Vigilo has verified the fix branches, Vigilo pushes each
`fix/*` branch to the repository's remote as recorded in the repository settings and opens one
merge request per fix branch (target = the project's default branch). The agent itself never
holds the token.

- The token is decrypted by the API and stored encrypted in the `run_secrets` table under a
  random per-run redemption key. Only a reference (`secrets: {ref, key}`), the flags
  `push.enabled` / `auth.cookie` and the non-secret `source: {remote_url, commit}` go into the
  workflow input. Workers redeem the token just in time from the API's **internal listener**
  (separate port, not published, not proxied by the UI's nginx), keep it in memory for the call
  and pass it to git via `GIT_ASKPASS` — it is never in a URL, `.git/config`, argv, a file,
  workflow history or logs. Redemption is refused for any other run and once the run has ended;
  the record is deleted on terminal state, cancel or failed start.
- With `VIGILO_EXECUTION_ENGINE=docker` the API starts the run's workflow itself, so nothing
  secret goes into the container's environment.
- Push and MR target come from the repository record, never from files in the checkout. The MR
  API base URL is derived from that remote. Failures are non-fatal and
  recorded per branch in `remediation_manifest.json` (`pushed`, `mr_url`, `push_error`,
  `mr_error`); the report shows **Delivered** only for pushed branches and **Patch available
  (local)** otherwise. Uploaded sources have no remote: nothing is pushed.

| Variable | Default | Meaning |
|---|---|---|
| `GITLAB_URL` | _unset_ | Fallback/hint for the MR API base only when it cannot be derived from the remote (GitLab served from a sub-path, e.g. `https://host/gitlab`). Set on the worker. |
| `GIT_PUSH_USER` | `oauth2` | Basic-auth user paired with the token for `git push`. Set on the worker. |

## Internal secret redemption

Per-run secrets (the GitLab push token, the job's session cookie) are redeemed by workers from
a separate API listener. Never publish or proxy its port.

| Variable | Default | Meaning |
|---|---|---|
| `VIGILO_INTERNAL_PORT` | `8081` | API: port of the internal secret-redemption listener. |
| `VIGILO_INTERNAL_HOST` | `0.0.0.0` | API: bind address of that listener. |
| `VIGILO_INTERNAL_API_URL` | `http://api:8081` | Workers: URL used to redeem secrets (the API passes it to per-run containers). |
| `VIGILO_SECRET_MAX_AGE_HOURS` | `168` | A run's secret record expires after this. |
| `VIGILO_REDEEM_MAX_PER_MINUTE` | `60` | Redemption attempts per run per minute (0 disables the limit). |


## Global pipeline defaults (seeded into admin_config on first boot; per-repo overridable)

| Variable | Default |
|---|---|
| `VIGILO_DEFAULT_EXECUTOR` | _unset_ — auto-detected from the provider variables (`VIGILO_EXECUTOR`, Codex/OpenCode credentials), else `claude` |
| `VIGILO_DEFAULT_MODEL_SMALL` | _unset_ — "worker default": the executor's tier variable (e.g. `CODEX_SMALL_MODEL`) or its built-in |
| `VIGILO_DEFAULT_MODEL_MEDIUM` | _unset_ — "worker default" (as above) |
| `VIGILO_DEFAULT_MODEL_LARGE` | _unset_ — "worker default" (as above) |
| `VIGILO_DEFAULT_MAX_CONCURRENT_PIPELINES` | `8` (agents run in parallel per stage; a job's `pipeline_overrides` can change it) |

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
| `VIGILO_LOGIN_MAX_FAILURES` | `10` | failed logins per window before the API answers 429 (`0` disables the throttle) |
| `VIGILO_LOGIN_FAILURE_WINDOW_S` | `300` | length of that sliding window, in seconds |

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
