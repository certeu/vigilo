# Grey-box E2E suite

Reproducible browser tests of the grey-box web platform (and one white-box mock run).
The suite boots everything itself and leaves nothing behind.

```
cd web && npm run test:e2e:greybox      # = npx playwright test -c playwright.greybox.config.ts
```

Run one spec: `npm run test:e2e:greybox -- steering`. HTML report: `playwright-report/greybox/`;
failure screenshots and traces: `test-results/greybox/` (both git-ignored).

## What it starts (Playwright `webServer`, see `playwright.greybox.config.ts`)

| Port  | Process |
|-------|---------|
| 18581 | synthetic target `python -m tests.greybox_web.fixtures.target_app` |
| 18580 | API `uvicorn src.webapi.app:create_app --factory` on a fresh temp SQLite DB (migrations run at boot), admin bootstrapped, in-process grey-box executor, `VIGILO_EXECUTION_ENGINE=mock` for white-box, `VIGILO_GREYBOX_HEARTBEAT_S=2`, private targets allowed, random 48-char JWT secret and Fernet key |
| 18590 | vite dev server proxying `/api` to the API |

`e2e/greybox/serve.sh` sets the API environment and removes the temp dir on exit. Override ports with
`GB_API_PORT`, `GB_TARGET_PORT`, `GB_UI_PORT`. The user's vite on 5173/5174 is never touched.

## Prerequisites

- repo `.venv` with the backend dependencies (override interpreter: `VIGILO_E2E_PYTHON`)
- `npm install` in `web/`
- a Chromium. Browsers are not downloaded: the config uses `E2E_CHROMIUM=/path/to/chrome` if set, else the
  locally cached headless shell, else Playwright's own (`npx playwright install chromium`)
- the three ports above are free (the suite fails rather than reusing a running server)

## Specs

| File | Covers |
|------|--------|
| `happy-path.spec.ts` | login, New analysis, Grey-box, run completes; planted findings; Show in graph; Defenses (copy, ModSecurity/Sigma download); report view and download |
| `realtime.spec.ts` | slowed run: Live badge, events/graph nodes/header counters grow with no reload |
| `steering.spec.ts` | Run chat: focus, skip_check, out-of-scope seed; status ticks, hint node, operator-skipped work orders |
| `lifecycle.spec.ts` | cancel within 5 s; unreachable target fails readably; long-run heartbeat regression |
| `whitebox.spec.ts` | upload repo, job, mock run, results |
| `isolation.spec.ts` | second user gets 404 / empty lists for user A's targets and runs |

No IDs are hard-coded: every spec creates its own data (unique names) through the UI or API, so specs do not
depend on order. Timings are tolerant (`expect.poll`); the suite runs with one worker.
