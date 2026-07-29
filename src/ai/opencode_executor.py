"""OpenCode CLI executor for agent pipeline.

Asyncio subprocess wrapper for OpenCode (https://opencode.ai).
Spawns ``opencode run`` in non-interactive mode and streams stdout
to collect execution metrics.

OpenCode connects to models through a LiteLLM gateway configured in
``$XDG_CONFIG_HOME/opencode/opencode.json``.  Model tiers resolve to
LiteLLM aliases (e.g. ``qwen3.6``) and are passed as
``litellm/<alias>`` on the CLI.

``--format json`` output schema (one JSON object per line)::

    {"type": "step_start", "part": {"type": "step-start", ...}}
    {"type": "text",       "part": {"type": "text", "text": "...", ...}}
    {"type": "tool_use",   "part": {"type": "tool", "tool": "bash", "state": {...}, ...}}
    {"type": "step_finish", "part": {"type": "step-finish", "reason": "stop"|"tool-calls",
                                     "tokens": {...}, "cost": ...}}

When ``--format json`` is unavailable (older versions), raw stdout is
captured as plain text and synthesised into a result.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from src.ai.executor import (
    ExecutorResult,
    StreamCallback,
    _handle_file_not_found,
    _parse_stream_line,
    _write_error_log,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Model tier resolution — LiteLLM aliases
# ---------------------------------------------------------------------------

MODEL_DEFAULTS: dict[str, str] = {
    "small": "qwen3.6",
    "medium": "qwen3.6",
    "large": "qwen3.6",
}

_TIER_ENV_MAP: dict[str, str] = {
    "small": "OPENCODE_SMALL_MODEL",
    "medium": "OPENCODE_MEDIUM_MODEL",
    "large": "OPENCODE_LARGE_MODEL",
}

LITELLM_PROVIDER_PREFIX = "litellm"


def resolve_model(tier: str) -> str:
    """Resolve tier to ``litellm/<alias>`` for OpenCode CLI.

    If *tier* is not a known tier name (small/medium/large), it is treated
    as a concrete model identifier.  The ``litellm/`` prefix is added if
    not already present.
    """
    if tier not in _TIER_ENV_MAP and tier not in MODEL_DEFAULTS:
        if tier.startswith(f"{LITELLM_PROVIDER_PREFIX}/"):
            return tier
        return f"{LITELLM_PROVIDER_PREFIX}/{tier}"
    env_var = _TIER_ENV_MAP.get(tier, "")
    alias = os.environ.get(env_var)
    if not alias:
        alias = MODEL_DEFAULTS.get(tier, MODEL_DEFAULTS["medium"])
    if alias.startswith(f"{LITELLM_PROVIDER_PREFIX}/"):
        return alias
    return f"{LITELLM_PROVIDER_PREFIX}/{alias}"


def _build_env() -> dict[str, str]:
    """Build the environment dict for the OpenCode subprocess."""
    env = os.environ.copy()
    return env


_DEFAULT_IDLE_TIMEOUT_S = float(
    os.environ.get("OPENCODE_IDLE_TIMEOUT_S", "900")
)


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
    """Run a prompt through OpenCode CLI and stream-collect metrics."""
    if idle_timeout_s is None:
        idle_timeout_s = _DEFAULT_IDLE_TIMEOUT_S
    model = resolve_model(model_tier)
    env = _build_env()
    if extra_env:
        env.update(extra_env)

    cmd = [
        "opencode", "run",
        "--model", model,
        "--format", "json",
        "--dangerously-skip-permissions",
        "--dir", cwd,
        prompt,
    ]

    env_status = {
        k: ("set" if env.get(k) else "unset")
        for k in ["LITELLM_BASE_URL", "LITELLM_API_KEY"]
    }
    logger.info(
        "Executing agent=%s model=%s tier=%s cwd=%s executor=opencode env=%s",
        agent_name,
        model,
        model_tier,
        cwd,
        env_status,
    )

    start = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=10 * 1024 * 1024,
        )
    except FileNotFoundError as e:
        return _handle_file_not_found(e, "opencode", cwd, agent_name, start, model)

    # -- Stream stdout and collect metrics --
    turn_count = 0
    text_chunks: list[str] = []
    cost_usd = 0.0
    input_tokens = 0
    output_tokens = 0
    resolved_model: str | None = model
    last_error: str | None = None
    plain_lines: list[str] = []
    is_stream_json = True

    prefix = f"[{agent_name}]"

    assert proc.stdout is not None
    while True:
        try:
            raw_line = await asyncio.wait_for(
                proc.stdout.readline(), timeout=idle_timeout_s
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Agent=%s idle for %.0fs with no stdout — killing subprocess",
                agent_name, idle_timeout_s,
            )
            print(
                f"{prefix} IDLE TIMEOUT: no output for {int(idle_timeout_s)}s, "
                f"killing subprocess"
            )
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            last_error = (
                f"idle timeout: no stdout for {int(idle_timeout_s)}s "
                f"(tool call likely hung)"
            )
            break
        if not raw_line:
            break

        decoded = raw_line.decode("utf-8", errors="replace")
        msg = _parse_stream_line(decoded)

        if msg is None:
            stripped = decoded.strip()
            if stripped:
                plain_lines.append(stripped)
                is_stream_json = False
            continue

        msg_type = msg.get("type")
        part = msg.get("part") or {}
        part_type = part.get("type", "")

        # -- OpenCode event: step_start (new LLM turn) --
        if msg_type == "step_start":
            turn_count += 1
            if on_stream:
                await on_stream(agent_name, turn_count, "[step_start]")

        # -- OpenCode event: text (LLM text output) --
        elif msg_type == "text" and part_type == "text":
            text = part.get("text", "")
            if text.strip():
                text_chunks.append(text)
                for line in text.strip().split("\n"):
                    print(f"{prefix} {line}")
                if on_stream:
                    await on_stream(agent_name, turn_count, text)

        # -- OpenCode event: tool_use (tool call + result) --
        elif msg_type == "tool_use" and part_type == "tool":
            tool_name = part.get("tool", "unknown")
            state = part.get("state") or {}
            status = state.get("status", "")
            title = state.get("title", "")
            label = title or tool_name
            if status == "completed":
                print(f"{prefix} <- {label}")
            else:
                print(f"{prefix} -> {label}")
            if on_stream:
                await on_stream(
                    agent_name, turn_count,
                    json.dumps({"tool": tool_name, "status": status},
                               separators=(",", ":")),
                )

        # -- OpenCode event: step_finish (turn complete, has tokens/cost) --
        elif msg_type == "step_finish" and part_type == "step-finish":
            tokens = part.get("tokens") or {}
            step_cost = part.get("cost", 0) or 0
            cost_usd += step_cost
            input_tokens += tokens.get("input", 0) + tokens.get("cache", {}).get("read", 0)
            output_tokens += tokens.get("output", 0) + tokens.get("reasoning", 0)
            reason = part.get("reason", "")
            total_tok = tokens.get("total", input_tokens + output_tokens)
            print(
                f"{prefix} step done ({reason}) — "
                f"{total_tok} tokens this step"
            )

        # -- Fallback: error events --
        elif msg_type == "error":
            last_error = part.get("error") or part.get("message") or msg.get("error") or str(msg)
            print(f"{prefix} ERROR: {last_error}")
            logger.warning(
                "Stream error from agent=%s: %s", agent_name, last_error
            )

    # -- Wait for process exit --
    stderr_bytes = b""
    if proc.stderr is not None:
        stderr_bytes = await proc.stderr.read()
    return_code = await proc.wait()

    duration_ms = int((time.monotonic() - start) * 1000)

    result_text = "\n".join(text_chunks) if text_chunks else None

    if not is_stream_json and plain_lines and result_text is None:
        result_text = "\n".join(plain_lines)
        turn_count = max(turn_count, 1)

    logger.info(
        "Agent=%s finished rc=%d duration=%dms turns=%d cost=$%.4f "
        "in=%d out=%d executor=opencode",
        agent_name,
        return_code,
        duration_ms,
        turn_count,
        cost_usd,
        input_tokens,
        output_tokens,
    )

    if return_code != 0:
        stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
        error_msg = last_error or stderr_text or f"opencode exited with code {return_code}"

        await _write_error_log(cwd, agent_name, "opencode", error_msg, duration_ms, turn_count, cost_usd)

        return ExecutorResult(
            success=False,
            duration_ms=duration_ms,
            cost_usd=cost_usd,
            num_turns=turn_count,
            model=resolved_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            result_text=result_text,
            error=error_msg,
        )

    print(
        f"{prefix} done -- {turn_count} turns, "
        f"${cost_usd:.4f}, {input_tokens + output_tokens} tokens"
    )

    return ExecutorResult(
        success=True,
        duration_ms=duration_ms,
        cost_usd=cost_usd,
        num_turns=turn_count,
        model=resolved_model,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        result_text=result_text,
        error=last_error,
    )
