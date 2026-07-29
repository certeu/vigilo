"""Executor abstraction layer.

Dispatches agent execution to the configured backend (Claude Code or OpenCode)
based on the VIGILO_EXECUTOR environment variable.

    VIGILO_EXECUTOR=claude   -> claude_executor.py  (default)
    VIGILO_EXECUTOR=opencode -> opencode_executor.py
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import aiofiles

logger = logging.getLogger(__name__)

ExecutorType = Literal["claude", "opencode", "codex"]

StreamCallback = Callable[[str, int, str], Awaitable[None]]


@dataclass
class ExecutorResult:
    """Outcome of a single CLI executor invocation."""

    success: bool
    duration_ms: int
    cost_usd: float
    num_turns: int
    model: str | None
    input_tokens: int
    output_tokens: int
    result_text: str | None
    error: str | None = None


def _handle_file_not_found(
    e: FileNotFoundError,
    cli_name: str,
    cwd: str,
    agent_name: str,
    start: float,
    model: str,
) -> ExecutorResult:
    duration_ms = int((time.monotonic() - start) * 1000)
    if cwd and not os.path.isdir(cwd):
        err_msg = f"cwd does not exist: {cwd!r} (agent={agent_name}): {e}"
    else:
        err_msg = f"'{cli_name}' CLI not found on PATH (agent={agent_name}): {e}"
    return ExecutorResult(
        success=False,
        duration_ms=duration_ms,
        cost_usd=0.0,
        num_turns=0,
        model=model,
        input_tokens=0,
        output_tokens=0,
        result_text=None,
        error=err_msg,
    )


async def _write_error_log(
    cwd: str,
    agent_name: str,
    executor_label: str,
    error_msg: str,
    duration_ms: int,
    turn_count: int,
    cost_usd: float,
) -> None:
    error_log_path = Path(cwd) / "error.log"
    try:
        async with aiofiles.open(error_log_path, mode="a", encoding="utf-8") as f:
            log_entry = json.dumps({
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "agent": agent_name,
                "executor": executor_label,
                "error": error_msg[:500],
                "duration_ms": duration_ms,
                "turns": turn_count,
                "cost": cost_usd,
            })
            await f.write(log_entry + "\n")
    except Exception:
        pass


def _parse_stream_line(raw: str) -> dict | None:
    line = raw.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        logger.debug("Skipping malformed stream line: %s", line[:200])
        return None


_OPENCODE_SIGNAL_VARS = (
    "LITELLM_BASE_URL",
    "OPENCODE_SMALL_MODEL",
    "OPENCODE_MEDIUM_MODEL",
    "OPENCODE_LARGE_MODEL",
)

_CODEX_SIGNAL_VARS = (
    "CODEX_API_KEY",
    "CODEX_BASE_URL",
    "CODEX_SMALL_MODEL",
    "CODEX_MEDIUM_MODEL",
    "CODEX_LARGE_MODEL",
)


def get_executor_type() -> ExecutorType:
    """Determine which executor backend to use.

    Resolution order:
      1. Explicit ``VIGILO_EXECUTOR`` env var (``claude`` / ``opencode`` / ``codex``);
         any other value falls through to ``claude``.
      2. Auto-detect: Codex signal vars → ``codex``; else OpenCode/LiteLLM signal
         vars → ``opencode``. Codex vars are checked first because they are
         backend-specific (low collision risk).
      3. Default: ``claude``
    """
    explicit = os.environ.get("VIGILO_EXECUTOR", "").strip().lower()
    if explicit:
        if explicit == "opencode":
            return "opencode"
        if explicit == "codex":
            return "codex"
        return "claude"

    if any(os.environ.get(v) for v in _CODEX_SIGNAL_VARS):
        logger.info(
            "Auto-detected codex executor (signal env vars: %s)",
            [v for v in _CODEX_SIGNAL_VARS if os.environ.get(v)],
        )
        return "codex"

    if any(os.environ.get(v) for v in _OPENCODE_SIGNAL_VARS):
        logger.info(
            "Auto-detected opencode executor (signal env vars: %s)",
            [v for v in _OPENCODE_SIGNAL_VARS if os.environ.get(v)],
        )
        return "opencode"

    return "claude"


async def execute(
    prompt: str,
    agent_name: str,
    model_tier: str,
    cwd: str,
    max_turns: int = 10_000,
    on_stream: StreamCallback | None = None,
    extra_env: dict[str, str] | None = None,
    idle_timeout_s: float | None = None,
) -> ExecutorResult:
    """Dispatch execution to the configured backend."""
    executor_type = get_executor_type()

    if executor_type == "opencode":
        from src.ai.opencode_executor import execute as _execute
    elif executor_type == "codex":
        from src.ai.codex_executor import execute as _execute
    else:
        from src.ai.claude_executor import execute as _execute

    return await _execute(
        prompt=prompt,
        agent_name=agent_name,
        model_tier=model_tier,
        cwd=cwd,
        max_turns=max_turns,
        on_stream=on_stream,
        extra_env=extra_env,
        idle_timeout_s=idle_timeout_s,
    )


def resolve_model(tier: str) -> str:
    """Resolve a model tier name to a concrete model ID via the active backend."""
    executor_type = get_executor_type()
    if executor_type == "opencode":
        from src.ai.opencode_executor import resolve_model as _resolve
    elif executor_type == "codex":
        from src.ai.codex_executor import resolve_model as _resolve
    else:
        from src.ai.claude_executor import resolve_model as _resolve
    return _resolve(tier)


def build_env() -> dict[str, str]:
    """Build environment dict for the active executor's subprocess."""
    executor_type = get_executor_type()
    if executor_type == "opencode":
        from src.ai.opencode_executor import _build_env
    elif executor_type == "codex":
        from src.ai.codex_executor import _build_env
    else:
        from src.ai.claude_executor import _build_env
    return _build_env()


def get_preflight_cmd() -> list[str]:
    """Return a minimal CLI command to validate credentials at preflight."""
    executor_type = get_executor_type()
    if executor_type == "opencode":
        return [
            "opencode", "run",
            "--format", "json",
            "--dangerously-skip-permissions",
            "--dir", "/tmp",
            "hi",
        ]
    if executor_type == "codex":
        return [
            "codex", "exec", "--json", "--skip-git-repo-check",
            "--dangerously-bypass-approvals-and-sandbox", "hi",
        ]
    return [
        "claude", "-p", "hi", "--output-format", "json",
        "--max-turns", "1", "--dangerously-skip-permissions",
    ]


def get_cli_name() -> str:
    executor_type = get_executor_type()
    if executor_type == "opencode":
        return "opencode"
    if executor_type == "codex":
        return "codex"
    return "claude"


async def validate_agent_output(agent_name: str, repo_path: str) -> bool:
    """Check whether the agent's expected deliverable file exists on disk."""
    from src.session_manager import AGENTS

    definition = AGENTS.get(agent_name)  # type: ignore[arg-type]
    if definition is None:
        logger.warning(
            "No registry entry for agent '%s' -- skipping validation", agent_name
        )
        return True

    deliverable = Path(repo_path) / "deliverables" / definition.deliverable_filename
    if not deliverable.exists():
        logger.error(
            "Validation failed for agent '%s': missing %s",
            agent_name,
            deliverable,
        )
        return False

    if deliverable.stat().st_size == 0:
        logger.error(
            "Validation failed for agent '%s': %s is empty",
            agent_name,
            deliverable,
        )
        return False

    logger.info("Validation passed for agent '%s': %s", agent_name, deliverable)
    return True
