# Vigilo Web UI

Minimalist SPA (React + Vite + TS + Tailwind) for the Vigilo platform. Consumes only
the API. Design language: Stripe-minimalism, cobalt accent, Space Grotesk + IBM Plex,
Heroicons, and the **Trace Rail** signature element.

For running the whole platform, see the [main README](../README.md). This document covers
the UI on its own for frontend development.

## Run (dev)

```bash
# 1) Start the API with the fake engine + a seeded admin (no Docker/Temporal needed):
cd ..   # repo root
export VIGILO_JWT_SECRET=dev-secret VIGILO_EXECUTION_ENGINE=fake
export VIGILO_FERNET_KEY=$(.venv-webapi/bin/python -c "from src.webapi.security.vault import generate_key; print(generate_key())")
export VIGILO_FIRST_ADMIN_EMAIL=admin@example.com VIGILO_FIRST_ADMIN_PASSWORD=change-me-now
.venv-webapi/bin/python -m src.webapi.main   # :8080

# 2) Start the SPA (proxies /api -> :8080):
cd web
npm install
npm run dev        # http://localhost:5173
```

Sign in with the seeded admin. Create a repository → a job → **Run** it. With the fake
engine the run goes "running" and the Trace Rail + log pane render immediately.

## Screens

- **Login** — email + password.
- **Dashboard / Runs** — control board: status dot · repository · preset · phase · cost.
- **Run detail** — the **Trace Rail** phase spine + live SSE log/evidence pane.
- **Jobs** — create a job (repo + stage preset + optional target URL) and run it.
- **Repositories** — attach upload/GitLab sources.
- **Admin** (admin role) — view model/executor/concurrency/SMTP config.

## Tests (Playwright)

```bash
npx playwright install --with-deps chromium
npm run test:e2e     # logs in, drives create→run, writes screenshots to e2e/artifacts/
```

## §17 visual critique checklist (do before calling the UI done)

Load each screen, screenshot, and check: spacing/alignment; CSS specificity bugs
(e.g. two component classes cancelling padding); responsive breakage; and that the
**Trace Rail stands alone** — nothing else competes for attention. Fix, then re-shoot.
