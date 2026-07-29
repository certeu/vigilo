#!/bin/bash
set -euo pipefail

TARGET_UID="${VIGILO_HOST_UID:-}"
TARGET_GID="${VIGILO_HOST_GID:-}"
CURRENT_UID=$(id -u scanner 2>/dev/null || echo "")

if [ -n "$TARGET_UID" ] && [ "$TARGET_UID" != "$CURRENT_UID" ]; then
  deluser scanner 2>/dev/null || true
  delgroup scanner 2>/dev/null || true

  addgroup -g "${TARGET_GID:-$TARGET_UID}" scanner 2>/dev/null || true
  adduser -u "$TARGET_UID" -G scanner -s /bin/bash -D scanner 2>/dev/null ||
    adduser -u "$TARGET_UID" -s /bin/bash -D scanner

  chown -R scanner:scanner /repos /app /tmp/.claude 2>/dev/null || true
  chmod -R 777 /repos /tmp/.cache /tmp/.config /tmp/.npm /tmp/.codex 2>/dev/null || true
fi

# Codex executor: map generic OPENAI_* creds onto CODEX_* (so an OpenAI-style
# .env works unchanged), trust a custom/internal CA (codex uses the system trust
# store, not NODE_EXTRA_CA_CERTS), then render $CODEX_HOME/config.toml.
# No-op for the claude/opencode backends.
if [ "${VIGILO_EXECUTOR:-}" = "codex" ]; then
  # Fallback mapping: only fills CODEX_* when unset (explicit CODEX_* win).
  : "${CODEX_API_KEY:=${OPENAI_API_KEY:-}}"; export CODEX_API_KEY
  : "${CODEX_MEDIUM_MODEL:=${OPENAI_MODEL:-}}"; export CODEX_MEDIUM_MODEL
  : "${CODEX_LARGE_MODEL:=${OPENAI_MODEL:-}}"; export CODEX_LARGE_MODEL
  : "${CODEX_SMALL_MODEL:=${OPENAI_MODEL:-}}"; export CODEX_SMALL_MODEL
  if [ -z "${CODEX_BASE_URL:-}" ]; then
    CODEX_BASE_URL="${OPENAI_BASE_URL:-${OPENAI_ENDPOINT:-}}"
  fi
  # Base-URL normalisation (whitespace trim + /v1 version path) is owned by
  # config-codex, the single point that renders config.toml — so a stray space
  # can't be baked into the URL. Just export the (possibly OPENAI_*-derived)
  # value so config-codex sees it.
  export CODEX_BASE_URL

  CA_SRC="${CODEX_EXTRA_CA_CERT:-${NODE_EXTRA_CA_CERTS:-}}"
  if [ -n "$CA_SRC" ] && [ -f "$CA_SRC" ]; then
    mkdir -p /usr/local/share/ca-certificates
    cp "$CA_SRC" /usr/local/share/ca-certificates/codex-extra-ca.crt 2>/dev/null || true
    update-ca-certificates >/dev/null 2>&1 || cat "$CA_SRC" >> /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true
    export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    export SSL_CERT_DIR=/etc/ssl/certs
    echo "Codex: installed custom CA from $CA_SRC" >&2
  fi
  config-codex || echo "WARN: config-codex failed" >&2
  # config-codex runs here as root; the agent runs codex as the (possibly remapped)
  # scanner user, which must be able to READ the generated config. Without this the
  # CLI dies with "config.toml: Permission denied (os error 13)".
  chmod -R a+rX "${CODEX_HOME:-/tmp/.codex}" 2>/dev/null || true
fi

exec su -m scanner -c "exec $*"
