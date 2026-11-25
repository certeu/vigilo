#!/usr/bin/env bash
# Start Vigilo locally for grey-box evaluation: API + grey-box worker (+ optional UI).
# The local-development topology: the same
# code paths as production, SQLite, the sandbox under bubblewrap on the host (Docker's
# default seccomp profile would block it; see deploy/config-reference.md).
#
#   scripts/greybox_local_stack.sh start [--ui] [--route FILE]   # FILE: model-route env
#   scripts/greybox_local_stack.sh stop
#
# Secrets come from .env (read by the application itself) and the shell; nothing
# is written by this script. State lives in $VIGILO_E2E_DIR (default ~/.cache/vigilo-e2e).
set -euo pipefail
cd "$(dirname "$0")/.."
DIR="${VIGILO_E2E_DIR:-$HOME/.cache/vigilo-e2e}"
mkdir -p "$DIR"
cmd="${1:-start}"; shift || true

if [ "$cmd" = "stop" ]; then
  for p in api worker ui; do
    [ -f "$DIR/$p.pid" ] && kill "$(cat "$DIR/$p.pid")" 2>/dev/null || true
    rm -f "$DIR/$p.pid"
  done
  echo "stopped"; exit 0
fi

UI=0; ROUTE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --ui) UI=1 ;;
    --route) ROUTE="$2"; shift ;;
  esac; shift
done
[ -n "$ROUTE" ] && source "$ROUTE"

export VIGILO_DATABASE_URL="${VIGILO_DATABASE_URL:-sqlite+aiosqlite:///$DIR/vigilo.db}"
export VIGILO_UPLOADS_DIR="${VIGILO_UPLOADS_DIR:-$DIR/uploads}"
mkdir -p "$VIGILO_UPLOADS_DIR"
export VIGILO_GREYBOX_WEB_ENABLED=true
export VIGILO_GREYBOX_EXECUTOR=worker
# the synthetic target listens on loopback: lab setting, never in production
export VIGILO_GREYBOX_ALLOW_PRIVATE_TARGETS=true
export VIGILO_GREYBOX_AGENT_MAX_CALLS="${VIGILO_GREYBOX_AGENT_MAX_CALLS:-80}"
export VIGILO_GREYBOX_AGENT_MAX_TOKENS="${VIGILO_GREYBOX_AGENT_MAX_TOKENS:-3000000}"
export VIGILO_GREYBOX_AGENT_TIMEOUT_S="${VIGILO_GREYBOX_AGENT_TIMEOUT_S:-150}"
if [ -d "$HOME/.cache/vigilo-browser-libs/root/usr/lib/x86_64-linux-gnu" ]; then
  export VIGILO_GREYBOX_BROWSER_LIB_DIR="${VIGILO_GREYBOX_BROWSER_LIB_DIR:-$HOME/.cache/vigilo-browser-libs/root/usr/lib/x86_64-linux-gnu}"
fi
PORT="${VIGILO_API_PORT:-8080}"

uv run --frozen --all-extras python -m uvicorn src.webapi.app:create_app --factory \
  --host 127.0.0.1 --port "$PORT" > "$DIR/api.log" 2>&1 &
echo $! > "$DIR/api.pid"
for i in $(seq 1 60); do
  curl -sf --noproxy '*' "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break
  curl -sf --noproxy '*' "http://127.0.0.1:$PORT/greybox/config" >/dev/null 2>&1 && break
  sleep 1
done
uv run --frozen --all-extras python -m src.greybox_web.worker > "$DIR/worker.log" 2>&1 &
echo $! > "$DIR/worker.pid"
if [ "$UI" = 1 ]; then
  VITE="$PWD/web/node_modules/.bin/vite"
  if command -v node >/dev/null 2>&1 && [ -x "$VITE" ]; then
    (cd web && VIGILO_API_URL="http://127.0.0.1:$PORT" "$VITE" --host 127.0.0.1 \
      --port 5173 > "$DIR/ui.log" 2>&1 & echo $! > "$DIR/ui.pid")
  elif command -v npx >/dev/null 2>&1; then
    (cd web && VIGILO_API_URL="http://127.0.0.1:$PORT" npx vite --host 127.0.0.1 \
      --port 5173 > "$DIR/ui.log" 2>&1 & echo $! > "$DIR/ui.pid")
  else
    echo "UI not started: install web dependencies with npm ci" >&2
    UI=0
  fi
fi
echo "API    http://127.0.0.1:$PORT   (log $DIR/api.log)"
echo "worker pid $(cat "$DIR/worker.pid")   (log $DIR/worker.log)"
if [ "$UI" = 1 ]; then echo "UI     http://127.0.0.1:5173   (log $DIR/ui.log)"; fi
