#!/usr/bin/env bash
# Wrapper entrypoint for OpenCode executor.
# Generates opencode.json from env vars, then launches the grey-box worker.
# All arguments are forwarded to the worker.
set -e

config-opencode
exec python3 -m src.greybox.temporal.worker "$@"
