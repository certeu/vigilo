#!/usr/bin/env bash
# Launcher used by playwright.greybox.config.ts (Playwright's webServer array).
#   serve.sh target <port>        synthetic grey-box target
#   serve.sh api <port> <tgtport> API on a throwaway SQLite DB (migrations run at boot)
# Everything created here (temp dir, DB, jobs/uploads) is removed when the process
# is stopped, which Playwright does when the run ends.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
PY="${VIGILO_E2E_PYTHON:-$ROOT/.venv/bin/python}"
cd "$ROOT"

PID=""; TMP=""
cleanup() {
  [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null
  [ -n "$TMP" ] && rm -rf "$TMP"
}
trap 'cleanup; exit 0' TERM INT
trap cleanup EXIT

case "${1:-}" in
  target)
    "$PY" -m tests.greybox_web.fixtures.target_app --port "$2" &
    PID=$!
    ;;
  api)
    TMP="$(mktemp -d "${TMPDIR:-/tmp}/vigilo-gb-e2e.XXXXXX")"
    mkdir -p "$TMP/jobs" "$TMP/uploads"
    export VIGILO_JWT_SECRET="$("$PY" -c 'import secrets;print(secrets.token_urlsafe(48))')"
    export VIGILO_FERNET_KEY="$("$PY" -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')"
    export VIGILO_DATABASE_URL="sqlite+aiosqlite:///$TMP/app.db"
    export VIGILO_FIRST_ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@example.com}"
    export VIGILO_FIRST_ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-E2e-Passw0rd-xyz}"
    # "mock" completes a white-box run synchronously with sample deliverables.
    export VIGILO_EXECUTION_ENGINE=mock
    export VIGILO_GREYBOX_WEB_ENABLED=true VIGILO_GREYBOX_EXECUTOR=inprocess
    export VIGILO_GREYBOX_ALLOW_PRIVATE_TARGETS=true   # the target is on loopback
    # AI exploration runs on the fake model backend (listed only in dev mode); never
    # on real providers, so ignore the repo .env and any provider keys in the shell.
    export VIGILO_DEV_MODE=true VIGILO_IGNORE_DOTENV=true
    unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN ANTHROPIC_FOUNDRY_API_KEY \
          CODEX_API_KEY OPENAI_API_KEY LITELLM_API_KEY
    export VIGILO_GREYBOX_HEARTBEAT_S="${VIGILO_GREYBOX_HEARTBEAT_S:-2}"
    export VIGILO_GREYBOX_MAX_ACTIVE_RUNS_PER_USER=20
    export VIGILO_JOBS_DATA_DIR="$TMP/jobs" VIGILO_UPLOADS_DIR="$TMP/uploads"
    "$PY" -m uvicorn src.webapi.app:create_app --factory --host 127.0.0.1 --port "$2" &
    PID=$!
    ;;
  *) echo "usage: serve.sh target <port> | api <port>" >&2; exit 2 ;;
esac
wait "$PID"
