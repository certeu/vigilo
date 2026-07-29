"""Claude Code CLI executor for agent pipeline.

Asyncio subprocess for Claude Agent SDK. Streams stdout in
stream-json format and collects execution metrics (cost, tokens, turns).
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
# Model tier resolution
# ---------------------------------------------------------------------------

MODEL_DEFAULTS: dict[str, str] = {
    "small": "claude-haiku-4-5",
    "medium": "claude-sonnet-4-6",
    "large": "claude-opus-4-6",
}

_BEDROCK_MODELS: dict[str, str] = {
    "small": "anthropic.claude-haiku-4-5-20251001-v1:0",
    "medium": "anthropic.claude-sonnet-4-6",
    "large": "anthropic.claude-opus-4-7",
}

_TIER_ENV_MAP: dict[str, str] = {
    "small": "ANTHROPIC_SMALL_MODEL",
    "medium": "ANTHROPIC_MEDIUM_MODEL",
    "large": "ANTHROPIC_LARGE_MODEL",
}


def _bedrock_geo_prefix() -> str:
    region = os.environ.get("AWS_REGION", "us-east-1")
    return region.split("-")[0]


def resolve_model(tier: str) -> str:
    """Resolve a model tier name to a concrete model ID.

    Environment variables (ANTHROPIC_SMALL_MODEL, ANTHROPIC_MEDIUM_MODEL,
    ANTHROPIC_LARGE_MODEL) override the built-in defaults so operators can
    swap models without code changes.  Empty strings are treated as unset.

    When CLAUDE_CODE_USE_BEDROCK is set, defaults use Bedrock cross-region
    inference profile IDs (geo prefix derived from AWS_REGION).

    If *tier* is not a known tier name (small/medium/large), it is treated
    as a concrete model identifier and returned as-is.
    """
    if tier not in _TIER_ENV_MAP and tier not in MODEL_DEFAULTS:
        return tier
    env_var = _TIER_ENV_MAP.get(tier, "")
    value = os.environ.get(env_var)
    if value:
        return value
    if os.environ.get("CLAUDE_CODE_USE_BEDROCK"):
        base = _BEDROCK_MODELS.get(tier)
        if base:
            return f"{_bedrock_geo_prefix()}.{base}"
    return MODEL_DEFAULTS.get(tier, MODEL_DEFAULTS["medium"])

def _build_env() -> dict[str, str]:
    """Build the environment dict for the Claude subprocess.

    Starts from the current process environment (so the CLI gets all
    system variables it needs — USER, LANG, TERM, etc.) and then
    ensures our known-required variables are present.
    """
    env = os.environ.copy()
    env["CLAUDE_CODE_MAX_OUTPUT_TOKENS"] = os.environ.get(
        "CLAUDE_CODE_MAX_OUTPUT_TOKENS", "64000"
    )
    return env


def _is_spending_cap_behavior(turns: int, cost: float, result_text: str) -> bool:
    """Detect spending cap behavior from Claude API.

    Heuristic: very few turns with zero cost and a short/apologetic result
    suggests the API hit a spending cap.
    """
    if turns > 3 or cost > 0.0:
        return False

    cap_indicators = [
        "spending limit",
        "spending cap",
        "rate limit",
        "quota exceeded",
        "billing",
        "usage limit",
    ]
    result_lower = result_text.lower()
    return any(indicator in result_lower for indicator in cap_indicators)


_DEFAULT_IDLE_TIMEOUT_S = float(
    os.environ.get("CLAUDE_IDLE_TIMEOUT_S", "900")  # 15 min
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
    """Run a prompt through the Claude CLI and stream-collect metrics.

    Parameters
    ----------
    prompt:
        The full prompt text (already rendered with variable substitution).
    agent_name:
        Agent identifier (for logging).
    model_tier:
        One of ``"small"``, ``"medium"``, ``"large"``.
    cwd:
        Working directory the CLI runs in (repo checkout).
    max_turns:
        Maximum agentic turns before the CLI self-terminates.
    extra_env:
        Additional environment variables to set for the subprocess.
    idle_timeout_s:
        Kill Claude if no stdout line arrives within this many seconds.
        Defaults to CLAUDE_IDLE_TIMEOUT_S env var or 900s. Protects against
        a hung shell tool call (e.g. curl against a WebSocket endpoint that
        never closes) stalling the whole activity.

    Returns
    -------
    ExecutorResult with success flag, metrics, and either result_text or error.
    """
    if idle_timeout_s is None:
        idle_timeout_s = _DEFAULT_IDLE_TIMEOUT_S
    model = resolve_model(model_tier)
    env = _build_env()
    if extra_env:
        env.update(extra_env)

    cmd = [
        "claude",
        "-p",
        prompt,
        "--model",
        model,
        "--max-turns",
        str(max_turns),
        "--output-format",
        "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
    ]

    # Log API-related env vars for debugging connectivity issues
    api_vars = [
        "ANTHROPIC_API_KEY", "CLAUDE_CODE_USE_FOUNDRY",
        "ANTHROPIC_FOUNDRY_RESOURCE", "ANTHROPIC_FOUNDRY_API_KEY",
        "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
        "ANTHROPIC_BASE_URL",
    ]
    env_status = {k: ("set" if env.get(k) else "unset") for k in api_vars}
    logger.info(
        "Executing agent=%s model=%s tier=%s cwd=%s max_turns=%d executor=claude env=%s",
        agent_name,
        model,
        model_tier,
        cwd,
        max_turns,
        env_status,
    )

    start = time.monotonic()

    try:
        # Use a large buffer limit (10 MB) for stdout — Claude's stream-json
        # output can produce lines >64KB (the default) when tool results
        # contain large file contents or screenshots.
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            limit=10 * 1024 * 1024,
        )
    except FileNotFoundError as e:
        return _handle_file_not_found(e, "claude", cwd, agent_name, start, model)

    # -- Stream stdout and collect metrics --
    turn_count = 0
    result_text: str | None = None
    cost_usd = 0.0
    input_tokens = 0
    output_tokens = 0
    resolved_model: str | None = model
    last_error: str | None = None

    prefix = f"[{agent_name}]"

    assert proc.stdout is not None  # guaranteed by PIPE
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

        msg = _parse_stream_line(raw_line.decode("utf-8", errors="replace"))
        if msg is None:
            continue

        msg_type = msg.get("type")

        if msg_type == "assistant":
            turn_count += 1
            # Extract content for logging — log every block type
            # (thinking, tool_use, text all appear as individual JSON entries).
            message = msg.get("message", {})
            content_blocks = message.get("content", [])
            for block in content_blocks:
                block_type = block.get("type", "")
                if block_type == "thinking":
                    thinking = block.get("thinking", "")
                    if thinking:
                        print(f"{prefix} [thinking]")
                    if on_stream:
                        content_str = json.dumps(block, separators=(",", ":"))
                        await on_stream(agent_name, turn_count, content_str)
                elif block_type == "text":
                    text = block.get("text", "")
                    if text.strip():
                        for line in text.strip().split("\n"):
                            print(f"{prefix} {line}")
                    if on_stream and text:
                        await on_stream(agent_name, turn_count, text)
                elif block_type == "tool_use":
                    tool_name = block.get("name", "unknown")
                    print(f"{prefix} -> {tool_name}")
                    if on_stream:
                        content_str = json.dumps(block, separators=(",", ":"))
                        await on_stream(agent_name, turn_count, content_str)

        elif msg_type == "result":
            # Final summary message with cumulative metrics.
            result_text = msg.get("result")
            cost_usd = msg.get("total_cost_usd", 0.0) or msg.get("cost_usd", 0.0) or msg.get("total_cost", 0.0)
            turn_count = msg.get("num_turns", turn_count)
            # Tokens live under `usage` in stream-json; older shapes had them
            # at the top level. Support both.
            usage = msg.get("usage") or {}
            input_tokens = usage.get("input_tokens", msg.get("input_tokens", 0)) or 0
            output_tokens = usage.get("output_tokens", msg.get("output_tokens", 0)) or 0
            resolved_model = msg.get("model") or model
            print(
                f"{prefix} done -- {turn_count} turns, "
                f"${cost_usd:.4f}, {input_tokens + output_tokens} tokens"
            )

        elif msg_type == "error":
            last_error = msg.get("error") or msg.get("message") or str(msg)
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

    logger.info(
        "Agent=%s finished rc=%d duration=%dms turns=%d cost=$%.4f "
        "in=%d out=%d executor=claude",
        agent_name,
        return_code,
        duration_ms,
        turn_count,
        cost_usd,
        input_tokens,
        output_tokens,
    )

    # -- Non-zero exit code means failure --
    if return_code != 0:
        stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
        error_msg = last_error or stderr_text or f"claude exited with code {return_code}"

        await _write_error_log(cwd, agent_name, "claude", error_msg, duration_ms, turn_count, cost_usd)

        return ExecutorResult(
            success=False,
            duration_ms=duration_ms,
            cost_usd=cost_usd,
            num_turns=turn_count,
            model=resolved_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            result_text=None,
            error=error_msg,
        )

    # Spending cap safeguard: detect billing cap that slipped through
    if _is_spending_cap_behavior(turn_count, cost_usd, result_text or ""):
        return ExecutorResult(
            success=False,
            duration_ms=duration_ms,
            cost_usd=cost_usd,
            num_turns=turn_count,
            model=resolved_model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            result_text=result_text,
            error=f"Spending cap likely reached (turns={turn_count}, cost=${cost_usd})",
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
