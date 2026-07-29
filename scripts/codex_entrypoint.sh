#!/usr/bin/env bash
# Wrapper entrypoint for the Codex executor (grey-box).
# Renders config.toml from env vars, then launches the grey-box worker.
# All arguments are forwarded to the worker.
set -e

config-codex
exec python3 -m src.greybox.temporal.worker "$@"
