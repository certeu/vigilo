# API reference

The platform is API-first (`src/webapi/`); the UI consumes only this API. The API serves
interactive OpenAPI docs at `/docs` (internal in the full stack; on the local fake-engine dev
server it's `http://localhost:8080/docs`, only when `VIGILO_DEV_MODE` or `VIGILO_API_DOCS_ENABLED` is set). Selected endpoints:

**Auth / users / credentials / admin**
- `GET /health`, `GET /version`
- `POST /auth/jwt/login` (form: `username`, `password`) → `{access_token}`; `POST /auth/jwt/logout` (204; revokes the caller's tokens by bumping the user's `session_epoch`, i.e. all of their sessions)
- `POST /auth/forgot-password`, `POST /auth/reset-password`, `POST /auth/accept-invite`
- `GET /users/me`, `POST /users/me/change-password`
- Admin: `POST /users`, `GET /users`, `PATCH /users/{id}`, `DELETE /users/{id}`, `POST /users/{id}/reset-password`
- Credentials (owner-private, secrets never returned): `POST`/`GET`/`DELETE /credentials`
- Admin config: `GET /admin/config`, `PUT /admin/config`
- Invitations: `POST`/`GET /invitations`, `DELETE /invitations/{id}`

**Repositories / jobs / runs**
- Repositories: `POST`/`GET /repositories`, `GET`/`PATCH`/`DELETE /repositories/{id}`,
  `POST /repositories/{id}/upload`, `POST /repositories/{id}/webhook`,
  `GET`/`POST`/`DELETE /repositories/{id}/access`
- Jobs: `POST`/`GET /jobs`, `GET`/`PATCH`/`DELETE /jobs/{id}`, `POST /jobs/{id}/run`
- Runs: `GET /runs`, `GET`/`DELETE /runs/{id}`, `POST /runs/{id}/cancel`
- Logs: `GET /runs/{id}/logs?offset=` (paged), `GET /runs/{id}/logs/stream` (SSE)
- Reports & artifacts: `GET /runs/{id}/report`, `GET /runs/{id}/artifacts[/{kind}]`

**Scheduling & webhooks**
- Schedules: `POST`/`GET /schedules`, `PATCH`/`DELETE /schedules/{id}` (`once` / `recurring` / `gitlab_mr`)
- `POST /webhooks/gitlab` (unauthenticated, `X-Gitlab-Token` verified) — MR events trigger matching schedules.

**Dashboards & metrics**
- `GET /dashboard/metrics`, `GET /runs/{id}/metrics`, `GET /repositories/{id}/metrics/timeline`

**Unified analyses**
- `GET /analyses?mode=all|whitebox|greybox&status=&q=&limit=&cursor=` merges white-box runs (existing repository ACL) and grey-box runs (owner/admin). It returns `{items, next_cursor}`.

**Grey-box** (behind `VIGILO_GREYBOX_WEB_ENABLED`, default off)
- `GET /greybox/config` is always mounted and reports `enabled`.
- Targets (owner/admin; others get 404): `POST /greybox/targets/validate`, `POST`/`GET /greybox/targets`,
  `GET`/`PATCH`/`DELETE /greybox/targets/{id}`.
- Preflight (M2): `POST /greybox/targets/{id}/preflight` — 200 `{ok, status_code, final_url, blocked_reason,
  resolved_ips, elapsed_ms}` from one guarded GET (nothing persisted); 429 more than once per 5 s per target.
- Runs (owner/admin; others get 404): `POST /greybox/targets/{id}/runs` — 201 `RunRead` (new), 200 `RunRead` for a
  repeated `idempotency_key`; 422 without `authorization_confirmed: true` or with an invalid credential;
  409 `run_id` when the target already has an active run; 429 over the per-user active-run cap; 503 executor off.
  `GET /greybox/runs?target_id=&status=&limit=&cursor=` (comma-separated status list), `GET /greybox/runs/{id}`
  (`RunRead` with live counters), `POST /greybox/runs/{id}/cancel` — 202 `RunRead` (`cancelling`/`cancelled`), `POST /greybox/runs/{id}/resume` — 202 `RunRead` (`queued`; body optional `{max_requests, max_duration_s}` that may only raise the budget; 409 when active or another run of the target is active; continues from the persisted state),
  409 when already finished — and `DELETE /greybox/runs/{id}` — 204 terminal only, 409 otherwise.
- Report: `GET /greybox/runs/{id}/report` → `{status, markdown, generated_at, error}`; `GET
  /greybox/runs/{id}/report/download` → `text/markdown` attachment `greybox-report-<run8>.md`, 404 before ready.
- Findings (owner/admin; others get 404): `GET /greybox/runs/{id}/findings?status=&severity=` → `{items: [FindingSummary]}`
  ordered critical→info then `created_at`; `GET /greybox/runs/{id}/findings/{finding_id}` → `Finding` (evidence,
  verification, detection hints, references, `provenance` with `node_id` and `first_event_seq`). Additive fields:
  `defense_count` (summary) and `defense_ids` (detail).
- Traffic: `GET /greybox/runs/{id}/traffic?method=&status_code=&host=&path_prefix=&agent_id=&work_order_id=&finding_id=&blocked=&limit=(1..200, default 50)&after_id=`
  → `{items: [ExchangeSummary], next_after_id: int|null, capture: "enabled"}` ordered by id; `GET
  /greybox/runs/{id}/traffic/{exchange_id}` → `Exchange` (headers and bodies as stored, already redacted, with truncation flags).
- Defenses: `GET /greybox/runs/{id}/defenses?finding_id=&kind=&format=` → `{items: [Defense]}`; `GET
  /greybox/runs/{id}/defenses/download?format=modsecurity|sigma|nginx|apache|all` (zip for `all`, 404 when empty).
- Hints: `POST /greybox/runs/{id}/hints` (201 `Hint`; 409 terminal run, 422, 429 above 10/min) and `GET
  /greybox/runs/{id}/hints` → `{items: [Hint]}` oldest first.
- When the flag is off, every `/greybox/*` route except `/greybox/config` returns 404.
