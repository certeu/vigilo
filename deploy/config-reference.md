# Vigilo Web Platform — configuration reference

All platform settings are environment variables with the `VIGILO_` prefix (read by
`src/webapi/settings.py`). Copy the ones you need into your `.env` — `env.sample` is a
ready-to-edit starting point; this file is the exhaustive reference. See the
[main README](../README.md#configuration-reference) for the essentials.

## Required

| Variable | Meaning |
|---|---|
| `VIGILO_JWT_SECRET` | JWT signing secret, **at least 32 characters** (e.g. `openssl rand -hex 32`). The API refuses to start with the default `CHANGE_ME` or a shorter value unless `VIGILO_DEV_MODE=true` |
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
| `VIGILO_DOCKER_NETWORK` | `vigilo_net` | Docker network the per-run worker containers join (docker engine) |

## Grey-box web platform

The grey-box (black-box web scanning) feature is **off by default**. It runs a deterministic,
scope-guarded engine (no LLM, no shell): every request goes through one guarded HTTP client that
enforces the target scope, pins DNS, refuses platform/metadata/private addresses and enforces the
budgets. Operator options: `docs/assessment-options.md`.

| Variable | Default | Meaning / security note |
|---|---|---|
| `VIGILO_GREYBOX_WEB_ENABLED` | `false` | Feature flag. When false every `/greybox/*` route except `GET /greybox/config` answers 404 and `/analyses` lists white-box runs only. Set it on the **API and the worker** |
| `VIGILO_GREYBOX_EXECUTOR` | `worker` | Who executes queued runs. `worker`: a separate process, `python -m src.greybox_web.worker` (compose service `greybox-worker`, see below). `inprocess`: the API runs the worker loop itself (**development and tests only**: no isolation from the API process, runs die with it). `off`: runs are queued but nothing executes them (API-only/testing) |
| `VIGILO_GREYBOX_ALLOW_PRIVATE_TARGETS` | `false` | Allow loopback/RFC1918/ULA targets (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, ...). **Keep `false` in production**: with `true` an authenticated user can aim the scanner at internal systems. Cloud-metadata and link-local addresses are refused regardless. Only for the synthetic target and lab setups |
| `VIGILO_GREYBOX_BLOCKED_HOSTS` | (empty) | Comma-separated **extra** hostnames always refused as targets. Built in and always refused: `api`, `web`, `db`, `postgres`, `temporal`, `surrealdb`, `localhost.localdomain` and the host of `VIGILO_INTERNAL_API_URL`. Add your own internal service names (e.g. `vault`, `registry`) |
| `VIGILO_GREYBOX_BLOCKED_ENDPOINTS` | (empty) | Comma-separated **extra** `host:port` endpoints always refused. `private:PORT` means that port on any loopback/private address (e.g. `private:9200,10.0.0.5:6379`). Always included automatically: the API port (`VIGILO_API_PORT`) and the default 8080, `VIGILO_INTERNAL_PORT`, the database port taken from `VIGILO_DATABASE_URL`, and the API's own bind address when `VIGILO_API_HOST` is a specific address |
| `VIGILO_API_PORT` / `VIGILO_API_HOST` | `8080` / `0.0.0.0` | Where the public API binds (see *Other*). **They must have the same values in the API and the worker, and match the real deployment**: the guard derives the platform's own endpoint from them, so a mismatch leaves the platform's real port scannable on private addresses. In the full stack keep the API on 8080 (the UI's nginx proxies there) |
| `VIGILO_GREYBOX_EGRESS_PROXIES_ENABLED` | `false` | Opt-in **egress proxies** for targets only reachable through the organisation's forward proxy (e.g. Squid chosen by a PAC file). When false, `/greybox/egress-proxies*` answer 404 and a target cannot select a proxy. When true, **administrators** define named proxies (URL, optional Basic credentials stored Fernet-encrypted, and the hosts each may be used for) and users pick one per target. Through a proxy the engine cannot pin DNS: the proxy's own resolution is authoritative, so the proxy's ACLs must keep it away from platform and metadata services. The engine never reads `HTTP_PROXY`/`HTTPS_PROXY`/PAC regardless of this setting. Set it on the **API and the worker**. |
| `VIGILO_GREYBOX_MAX_ACTIVE_RUNS_PER_USER` | `2` | Concurrent non-terminal grey-box runs per user (start answers 429 above it). There is also **one active run per target**, enforced by a unique index |
| `VIGILO_GREYBOX_WORKER_MAX_RUNS` | `2` | Runs one worker process executes concurrently (also `--max-runs`). Total capacity is this times the number of worker replicas. Each run is also bounded by its own target limits (requests, duration, rate, concurrency, ...), enforced by the client and shown in the UI |
| `VIGILO_GREYBOX_LEASE_TTL_S` | `60` | A claimed run carries a lease that expires this many seconds after the last heartbeat. When the lease expires (worker crashed or lost the DB) the reaper marks the run `failed`; it is **never** retried automatically, so a target is never scanned twice. Lower = faster failure detection, higher = more tolerance to DB stalls. Keep it several times the heartbeat |
| `VIGILO_GREYBOX_HEARTBEAT_S` | `10` | How often a worker renews its leases (and polls for cancel requests, so it is also the worst-case cancel latency of an idle worker). Must be comfortably below `VIGILO_GREYBOX_LEASE_TTL_S` (default ratio 1:6) |
| `VIGILO_GREYBOX_SANDBOX_ISOLATION` | `auto` | OS isolation for **analysis tools the agent writes** (`tool.compose`). `auto`: bubblewrap (no network, read-only system image, no `/etc`/`/home`, cleared environment) if it can create namespaces, else `unshare` (network namespace only), else **agent-written code is refused**. `bwrap` / `unshare`: require that mechanism. `process`: interpreter-level guards + rlimits only — an explicit operator acceptance that a determined escape could reach the worker's network and files. The shipped Compose services apply worker-only seccomp/AppArmor namespace allowances and drop all capabilities except `SETUID`/`SETGID`; keep equivalent isolation when deploying without Compose rather than choosing `process` in production. Worker only |
| `VIGILO_GREYBOX_BROWSER_LIB_DIR` | (empty) | Extra shared-library directory passed (as `LD_LIBRARY_PATH`) to the headless browser only — for hosts where Chromium's system packages cannot be installed. The worker image installs them (`playwright install --with-deps`); build it with `--build-arg GREYBOX_BROWSER=0` to omit the browser, which is then never offered to the agent. Worker only |
| `VIGILO_GREYBOX_SKILLS` | `on` | Investigation skills (methodology playbooks with a definition of done, `src/greybox_web/skills/`). `off` removes the skill index from the agent's instructions and `skill.read` from its tools — used to evaluate the agent without skills. Worker only |
| `VIGILO_GREYBOX_SESSION_MAX_AGE_S` | `43200` | How old (seconds since last change) a run's encrypted identity state (sessions established by `auth.login`, browser cookie jars) may be and still be restored when the run is resumed. Older state is discarded and the agent re-authenticates. `0` never restores. Worker only |
| `VIGILO_GREYBOX_AGENT_MAX_CALLS` / `_MAX_TOKENS` / `_TIMEOUT_S` | `40` / `400000` / `60` | Per-run bounds of the AI exploration agent: model calls, total tokens (input + output) and the timeout of one call. Grey-box is AI-only: there is no rule-based fallback |

#### AI model for grey-box exploration

Grey-box has **no variables of its own for providers**: it reuses the white-box backends and their
variables (read from the process environment, overlaid on the repo-root `.env` when the API/worker
is started from the repo root, so a working `.env` is enough). `GET /greybox/config` lists them under
`agent.backends` (id, label, models, availability and the reason it is unavailable; never keys), and
each target stores the user's choice (`model_backend`, `model`; empty = default). A run snapshots it at
start and is refused with **409 "No AI model configured for grey-box exploration..."** when the
selected (or default) backend is unusable.

| Backend id | Usable when | Models offered (medium first) |
|---|---|---|
| `claude` | `ANTHROPIC_API_KEY`/`ANTHROPIC_AUTH_TOKEN`, or Foundry: `ANTHROPIC_FOUNDRY_API_KEY` + `ANTHROPIC_FOUNDRY_BASE_URL` (or `ANTHROPIC_FOUNDRY_RESOURCE`). Bedrock is not supported | `ANTHROPIC_MEDIUM_MODEL`, `_LARGE_MODEL`, `_SMALL_MODEL` (or the built-in defaults) |
| `codex` | `CODEX_API_KEY` (or `OPENAI_API_KEY`), optional `CODEX_BASE_URL`, and `CODEX_WIRE_API=chat` (the default `responses` is not supported by the grey-box client yet) | `CODEX_MEDIUM_MODEL`, `_LARGE_MODEL`, `_SMALL_MODEL` |
| `opencode` | `LITELLM_BASE_URL` + `LITELLM_API_KEY` | `OPENCODE_MEDIUM_MODEL`, `_LARGE_MODEL`, `_SMALL_MODEL` |
| `fake` | only with `VIGILO_DEV_MODE=true`; deterministic, for tests and E2E | `fake-explorer` |

**`CODEX_TLS_BRIDGE`** (default `false`, white-box worker). Some model endpoints drop the TLS handshake of the Codex CLI (its Rust TLS stack offers post-quantum/X25519 key shares only), so every scan fails with `stream disconnected before completion: error sending request`. With `CODEX_TLS_BRIDGE=true` the worker entrypoint starts `src/ai/tls_bridge.py`: the CLI talks plain HTTP to `127.0.0.1:${CODEX_TLS_BRIDGE_PORT:-18443}` inside the container, and the bridge forwards to `CODEX_BASE_URL` over TLS with OpenSSL (verification on; key exchange pinned to P-256 if the handshake is rejected). It listens on loopback only and forwards only to that one endpoint.

The default (target without a choice) is the white-box executor (`VIGILO_EXECUTOR` or auto-detection)
when usable, else the first usable backend. Set `VIGILO_IGNORE_DOTENV=true` to skip the `.env` overlay.

Per-target limits (requests, duration, requests/s, concurrency, ...), scope (hosts, ports, path
prefixes, exclusions, schemes, redirect policy) and the cookie credential are set in the UI/API per
target, not by environment; the environment only supplies the platform-wide guard rails above.
The cookie credential is decrypted in the worker (it needs `VIGILO_FERNET_KEY`) and registered with
the redactor before anything is persisted.

### Deploying the executor (`greybox-worker`)

With the default `VIGILO_GREYBOX_EXECUTOR=worker` the API only **queues** runs; without a worker
process they stay `queued` until the reaper fails them. Both compose files define a `greybox-worker`
service (profile `greybox`, so it is not started unless asked):

    # full stack
    docker compose --env-file .env --profile greybox -f deploy/docker-compose.full.yml up --build -d
    # API-only stack
    docker compose --env-file .env --profile api --profile greybox -f deploy/docker-compose.api.yml up --build -d

and `VIGILO_GREYBOX_WEB_ENABLED=true` in `.env` (the service defaults it to `true`; the API defaults
it to `false`). The service reuses the API image (`deploy/Dockerfile.api`) and the same database; it
runs `python -m src.greybox_web.worker`, restarts `unless-stopped`, publishes no port and needs only
egress to the targets and to Postgres. It does not read the repo-root `.env` and gets neither the JWT
secret nor model/SMTP credentials; it needs `VIGILO_FERNET_KEY` to decrypt a target's cookie credential.
It does not run migrations (`VIGILO_RUN_MIGRATIONS_ON_START=false`): the API owns them and the worker
waits for it to start. The shipped service grants the seccomp/AppArmor namespace allowances needed by
bubblewrap only to this worker and drops all other Linux capabilities. On a hardened host that forbids
nested user namespaces globally, generated tools remain fail-closed unless the host policy permits them.

- **Scaling**: `docker compose ... up -d --scale greybox-worker=N`. Several workers are safe: a run is
  claimed with a conditional `UPDATE` (no double claim), leases and heartbeats detect lost workers, and
  the one-active-run-per-target index prevents two runs on one target. Capacity is
  `N x VIGILO_GREYBOX_WORKER_MAX_RUNS`.
- **Egress**: put the worker on a network that can reach the targets you are authorised to test and
  nothing else; the guard is application-level and a network policy is the second layer. Do not give
  it a route to the platform's own services beyond Postgres.
- **Standalone use**: `python -m src.greybox_web.worker [--once] [--worker-id ID] [--max-runs N]`
  (`--once` claims and runs a single queued run, then exits; useful for debugging).
- **In-process mode** (`VIGILO_GREYBOX_EXECUTOR=inprocess`): the API starts the loop in its lifespan,
  no extra service. Use it for local development and the E2E suite only; do not run it together with
  workers on the same database unless you want the API to compete for runs.

## GitHub and GitHub Enterprise

A repository on github.com or a GitHub Enterprise Server host (`source_type: "github"`,
`remote_url: https://<host>/<owner>/<repo>`) is cloned with one of two credentials, bound to
that host:

- `github_token`: a personal access token (fine-grained or classic); read access to the
  repository's contents is enough. Paste it when adding the repository in the UI.
- `github_app`: a GitHub App (`{"app_id", "private_key", "installation_id"?}`, via the API as
  `github_app` on `POST /repositories`, or `POST /credentials` with `forge_base_url`). Each time
  access is needed, Vigilo mints a short-lived installation token limited to that one
  repository and `contents: read`; it is never stored. A fixed `installation_id` must be the
  App's installation on the repository's owner (organisation or user); leave it empty to have
  Vigilo look up the installation for the repository. The token requests go to the vetted
  address of the API host directly, without an HTTP(S) proxy from the environment.

A GitHub Enterprise Server host on a private address must be listed in
`VIGILO_GITLAB_ALLOWED_HOSTS`, like an internal GitLab. Pushing fixes back and webhooks are
GitLab only for now.

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
| `VIGILO_JWT_LIFETIME_SECONDS` | `3600` | access-token TTL (must be > 0). One hour is kept on purpose: the UI has no refresh-token flow, so a shorter TTL would sign users out mid-session. Tokens are revocable before expiry (logout, password change/reset and deactivation bump the user's `session_epoch`) |
| `VIGILO_UPLOADS_DIR` | `/data/uploads` | uploaded source archives |
| `VIGILO_MAX_UPLOAD_MB` | `2048` | per-upload size cap (streamed to disk; 413 over cap) |
| `VIGILO_TEMPORAL_TASK_QUEUE` | `vigilo-pipeline` | queue the worker serves / API submits to |
| `VIGILO_RUN_MIGRATIONS_ON_START` | `true` | run Alembic `upgrade head` on API boot |
| `VIGILO_LOGIN_MAX_FAILURES` | `10` | failed logins per window before the API answers 429 (`0` disables the throttle) |
| `VIGILO_LOGIN_FAILURE_WINDOW_S` | `300` | length of that sliding window, in seconds |
| `VIGILO_TRUSTED_PROXIES` | (empty) | comma-separated IPs/CIDRs of reverse proxies whose `X-Forwarded-For` the API believes. Empty = the TCP peer is the client (a client-sent `X-Forwarded-For` is ignored). The login throttle counts failures per client IP **and** per account (normalised email), both with the limits above. docker-compose.full.yml sets the private ranges (the UI's nginx); narrow them to your `vigilo_net` subnet if you can |
| `VIGILO_DEV_MODE` | `false` | local development only: accept a weak/default JWT secret and serve `/docs`, `/redoc`, `/openapi.json` |
| `VIGILO_API_DOCS_ENABLED` | (follows `VIGILO_DEV_MODE`) | `true`/`false` forces the interactive API docs and OpenAPI schema on/off |
| `VIGILO_HSTS_ENABLED` | `false` | send `Strict-Transport-Security` from the API (set only when it is served over https; Traefik already sends it in the full stack) |
| `VIGILO_GITLAB_ALLOWED_HOSTS` | (empty) | comma-separated hostnames a repository URL may use even though they resolve to private addresses (your GitLab or GitHub Enterprise Server). The host of the worker's `GITLAB_URL` is allowed too. Any other host resolving to loopback/private/link-local/metadata/multicast/reserved addresses is refused (`git ls-remote`/clone and the GitHub App token requests are pinned to the vetted address and do not follow redirects; metadata/link-local are refused even for allowlisted hosts) |
| `VIGILO_REPO_ALLOW_PRIVATE_HOSTS` | `false` | dev/test only: lift the private-range deny for every repository host |
| `VIGILO_API_HOST` / `VIGILO_API_PORT` | `0.0.0.0` / `8080` | where the public API binds. The grey-box scope guard refuses these endpoints (and 8080) as targets |

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
