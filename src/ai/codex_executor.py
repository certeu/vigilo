"""OpenAI Codex CLI executor for the agent pipeline.

Asyncio subprocess wrapper for the Codex CLI (https://github.com/openai/codex).
Spawns ``codex exec`` in non-interactive mode with ``--json`` and stream-collects
execution metrics (turns, tokens, estimated cost).

Codex reaches models through an OpenAI-compatible endpoint configured in
``$CODEX_HOME/config.toml`` (``[model_providers.*]``). This works identically for
OpenAI direct, Azure Foundry, and a LiteLLM gateway. Model tiers resolve to the
deployment/model name passed via ``--model``.

``--json`` emits one JSON object per line. Relevant event types::

    {"type": "thread.started", "thread_id": "..."}
    {"type": "turn.started"}
    {"type": "item.completed", "item": {"type": "agent_message", "text": "..."}}
      (Codex >=0.140 renamed this from "assistant_message"; both are handled)
    {"type": "item.completed", "item": {"type": "reasoning", "text": "..."}}
    {"type": "item.started",   "item": {"type": "command_execution", "command": "..."}}
    {"type": "turn.completed", "usage": {"input_tokens": N, "cached_input_tokens": N,
                                          "output_tokens": N, "reasoning_output_tokens": N}}
    {"type": "turn.failed", "error": {...}}

The event stream carries NO cost field, so cost is estimated from a per-model
price table (env-overridable). When ``--json`` is unavailable or the schema
drifts, non-JSON stdout is captured as plain text and synthesised into a result.

On-stream content shape mirrors ``claude_executor``: raw ``str`` for assistant
text, ``json.dumps(block)`` for tool-use and thinking blocks — so ``workflow.log``
and ``agents/*.log`` stay structurally identical across backends.
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
    "small": "gpt-5-mini",
    "medium": "gpt-5-codex",
    "large": "gpt-5-codex",
}

_TIER_ENV_MAP: dict[str, str] = {
    "small": "CODEX_SMALL_MODEL",
    "medium": "CODEX_MEDIUM_MODEL",
    "large": "CODEX_LARGE_MODEL",
}


def resolve_model(tier: str) -> str:
    """Resolve a tier name to a concrete Codex model / Azure deployment name.

    Env vars (CODEX_SMALL_MODEL, CODEX_MEDIUM_MODEL, CODEX_LARGE_MODEL) override
    the built-in defaults. If *tier* is not a known tier name it is treated as a
    concrete model identifier and returned unchanged (no provider prefix — the
    provider is configured in config.toml, unlike OpenCode's ``litellm/`` prefix).
    """
    if tier not in _TIER_ENV_MAP and tier not in MODEL_DEFAULTS:
        return tier
    env_var = _TIER_ENV_MAP.get(tier, "")
    value = os.environ.get(env_var)
    if value:
        return value
    return MODEL_DEFAULTS.get(tier, MODEL_DEFAULTS["medium"])


# ---------------------------------------------------------------------------
# Cost estimation — Codex emits token usage but no cost
# ---------------------------------------------------------------------------

# USD per 1M tokens. Rough public list prices; override via env for accuracy.
_PRICE_TABLE: dict[str, tuple[float, float]] = {
    "gpt-5-codex": (1.25, 10.0),
    "gpt-5-mini": (0.25, 2.0),
    "gpt-5-nano": (0.05, 0.40),
    "gpt-5": (1.25, 10.0),
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Estimate USD cost from token counts.

    Resolution order: explicit env prices (CODEX_PRICE_INPUT_PER_MTOK /
    CODEX_PRICE_OUTPUT_PER_MTOK) -> built-in price table (prefix match) -> 0.0.
    Returns 0.0 with a WARNING when the model is unknown and no env price is set,
    so a silent zero cannot masquerade as a real "free" run.
    """
    env_in = os.environ.get("CODEX_PRICE_INPUT_PER_MTOK")
    env_out = os.environ.get("CODEX_PRICE_OUTPUT_PER_MTOK")
    if env_in and env_out:
        in_price, out_price = float(env_in), float(env_out)
    else:
        # Longest-prefix match so "gpt-5-codex" wins over "gpt-5".
        match = None
        for key in sorted(_PRICE_TABLE, key=len, reverse=True):
            if model and model.startswith(key):
                match = _PRICE_TABLE[key]
                break
        if match is None:
            logger.warning(
                "No price for Codex model %r and no CODEX_PRICE_* env override; "
                "reporting cost=0.0 (token counts still tracked)",
                model,
            )
            return 0.0
        in_price, out_price = match
    return (input_tokens / 1_000_000) * in_price + (output_tokens / 1_000_000) * out_price


def _build_env() -> dict[str, str]:
    """Build the environment dict for the Codex subprocess."""
    env = os.environ.copy()
    env.setdefault("CODEX_HOME", os.path.join(env.get("HOME", "/tmp"), ".codex"))
    return env


# Proxy env vars codex (a Rust/reqwest binary) honours for its HTTPS egress.
# Surfaced at startup so "requests route through a proxy" is obvious in the logs —
# a stalled/dropped SSE stream through a proxy is otherwise indistinguishable from
# a model hang.
_PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
               "https_proxy", "http_proxy", "no_proxy")


def _redact_proxy(url: str) -> str:
    """Strip embedded credentials from a proxy URL for safe logging."""
    if "://" in url and "@" in url:
        scheme, rest = url.split("://", 1)
        return f"{scheme}://{rest.rsplit('@', 1)[-1]}"
    return url


_DEFAULT_IDLE_TIMEOUT_S = float(os.environ.get("CODEX_IDLE_TIMEOUT_S", "900"))


# Codex item types that map to a tool-use style event, with the tool label used
# in prints and the on_stream block. Field probed for the human-readable detail.
_TOOL_ITEMS: dict[str, str] = {
    "command_execution": "bash",
    "web_search": "web_search",
    "mcp_tool_call": "mcp",
    "file_change": "edit",
}

# Codex renamed the assistant-text item to "agent_message" (>=0.140); older builds
# emitted "assistant_message". Accept both, else the agent's narration/summary is
# silently dropped — it never reaches result_text or workflow.log / agents/*.log,
# which makes a working run look frozen (only tool calls show).
_ASSISTANT_ITEM_TYPES = ("agent_message", "assistant_message")
_REASONING_ITEM_TYPES = ("reasoning", "agent_reasoning")


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
    """Run a prompt through the Codex CLI and stream-collect metrics."""
    if idle_timeout_s is None:
        idle_timeout_s = _DEFAULT_IDLE_TIMEOUT_S
    model = resolve_model(model_tier)
    env = _build_env()
    if extra_env:
        env.update(extra_env)

    cmd = [
        "codex", "exec",
        "--model", model,
        "--json",
        "--skip-git-repo-check",
        "--dangerously-bypass-approvals-and-sandbox",
        prompt,
    ]

    env_status = {
        k: ("set" if env.get(k) else "unset")
        for k in ["CODEX_API_KEY", "CODEX_BASE_URL", "CODEX_HOME", "OPENAI_API_KEY"]
    }
    proxy_status = {k: _redact_proxy(env[k]) for k in _PROXY_VARS if env.get(k)}
    logger.info(
        "Executing agent=%s model=%s tier=%s cwd=%s executor=codex env=%s proxy=%s",
        agent_name, model, model_tier, cwd, env_status, proxy_status or "none",
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
        return _handle_file_not_found(e, "codex", cwd, agent_name, start, model)

    turn_count = 0
    text_chunks: list[str] = []
    input_tokens = 0
    output_tokens = 0
    last_error: str | None = None
    plain_lines: list[str] = []
    is_stream_json = True

    prefix = f"[{agent_name}]"

    # Poll on a short interval so a stall is reported progressively rather than as
    # dead silence until the full idle_timeout_s elapses. Any output resets the
    # counter; only cumulative silence >= idle_timeout_s kills the subprocess.
    idle_log_interval_s = min(
        float(os.environ.get("CODEX_IDLE_LOG_INTERVAL_S", "30")), idle_timeout_s
    )
    idle_elapsed = 0.0

    assert proc.stdout is not None
    while True:
        try:
            raw_line = await asyncio.wait_for(
                proc.stdout.readline(), timeout=idle_log_interval_s
            )
        except asyncio.TimeoutError:
            idle_elapsed += idle_log_interval_s
            if idle_elapsed >= idle_timeout_s:
                logger.warning(
                    "Agent=%s idle for %.0fs with no stdout — killing subprocess",
                    agent_name, idle_elapsed,
                )
                print(f"{prefix} IDLE TIMEOUT: no output for {int(idle_elapsed)}s, "
                      f"killing subprocess")
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                last_error = (f"idle timeout: no stdout for {int(idle_elapsed)}s "
                              f"(tool call or model stream likely hung)")
                break
            logger.warning(
                "Agent=%s: no codex output for %.0fs (idle limit %.0fs) — upstream "
                "may be slow/rate-limited or the streaming connection stalled%s",
                agent_name, idle_elapsed, idle_timeout_s,
                " (proxy configured)" if proxy_status else "",
            )
            print(f"{prefix} ...waiting on model ({int(idle_elapsed)}s idle)")
            continue
        if not raw_line:
            break
        idle_elapsed = 0.0

        decoded = raw_line.decode("utf-8", errors="replace")
        msg = _parse_stream_line(decoded)
        if msg is None:
            stripped = decoded.strip()
            if stripped:
                plain_lines.append(stripped)
                is_stream_json = False
            continue

        msg_type = msg.get("type", "")

        if msg_type == "thread.started":
            logger.debug("codex thread started: %s", msg.get("thread_id"))

        elif msg_type == "turn.started":
            turn_count += 1
            if on_stream:
                await on_stream(agent_name, turn_count, "[turn.started]")

        elif msg_type in ("item.started", "item.updated", "item.completed"):
            item = msg.get("item") or {}
            item_type = item.get("type", "")
            if item_type in _ASSISTANT_ITEM_TYPES and msg_type == "item.completed":
                text = item.get("text") or item.get("message") or ""
                if text.strip():
                    text_chunks.append(text)
                    for line in text.strip().split("\n"):
                        print(f"{prefix} {line}")
                    if on_stream:
                        await on_stream(agent_name, turn_count, text)
            elif item_type in _REASONING_ITEM_TYPES and msg_type == "item.completed":
                text = item.get("text") or ""
                if text.strip():
                    print(f"{prefix} [thinking]")
                    if on_stream:
                        block = {"type": "thinking", "thinking": text}
                        await on_stream(
                            agent_name, turn_count,
                            json.dumps(block, separators=(",", ":")),
                        )
            elif item_type in _TOOL_ITEMS:
                tool = _TOOL_ITEMS[item_type]
                if item_type == "mcp_tool_call":
                    tool = item.get("server") or "mcp"
                detail = (item.get("command") or item.get("query")
                          or item.get("path") or "")
                arrow = "<-" if msg_type == "item.completed" else "->"
                print(f"{prefix} {arrow} {tool} {detail}".rstrip())
                if on_stream:
                    block = {"type": "tool_use", "name": tool, "input": detail}
                    await on_stream(
                        agent_name, turn_count,
                        json.dumps(block, separators=(",", ":")),
                    )

        elif msg_type == "turn.completed":
            usage = msg.get("usage") or {}
            input_tokens += (usage.get("input_tokens", 0)
                             + usage.get("cached_input_tokens", 0))
            output_tokens += (usage.get("output_tokens", 0)
                              + usage.get("reasoning_output_tokens", 0))

        elif msg_type in ("turn.failed", "error"):
            err = msg.get("error") or msg.get("message") or {}
            if isinstance(err, dict):
                msg_error = err.get("message") or json.dumps(err, separators=(",", ":"))
            else:
                msg_error = str(err)
            msg_error = msg_error or json.dumps(msg, separators=(",", ":"))
            print(f"{prefix} ERROR: {msg_error}")
            lowered = msg_error.lower()
            # "Reconnecting… N/5" is a transient retry codex recovers from; don't
            # latch it as the definitive error, else a recovered run reports a
            # spurious failure. Only non-retry messages become last_error.
            is_transient_retry = "reconnecting" in lowered
            if not is_transient_retry:
                last_error = msg_error
            if "rate limit" in lowered or "exceeded rate" in lowered or " 429" in lowered:
                logger.warning(
                    "Agent=%s RATE LIMITED by upstream: %s — lower concurrency or "
                    "raise the deployment's TPM/RPM quota", agent_name, msg_error,
                )
            elif any(s in lowered for s in
                     ("reconnecting", "disconnected", "response.failed")):
                logger.warning(
                    "Agent=%s stream interruption%s: %s%s", agent_name,
                    " (retrying)" if is_transient_retry else " (gave up)", msg_error,
                    " [proxy configured — may be dropping SSE]" if proxy_status else "",
                )
            else:
                logger.warning("Stream error from agent=%s: %s", agent_name, msg_error)

    stderr_bytes = b""
    if proc.stderr is not None:
        stderr_bytes = await proc.stderr.read()
    return_code = await proc.wait()

    duration_ms = int((time.monotonic() - start) * 1000)
    result_text = "\n".join(text_chunks) if text_chunks else None
    if not is_stream_json and plain_lines and result_text is None:
        result_text = "\n".join(plain_lines)
        turn_count = max(turn_count, 1)

    cost_usd = _estimate_cost(model, input_tokens, output_tokens)

    logger.info(
        "Agent=%s finished rc=%d duration=%dms turns=%d cost=$%.4f "
        "in=%d out=%d executor=codex",
        agent_name, return_code, duration_ms, turn_count, cost_usd,
        input_tokens, output_tokens,
    )

    if return_code != 0:
        stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
        error_msg = last_error or stderr_text or f"codex exited with code {return_code}"
        await _write_error_log(cwd, agent_name, "codex", error_msg,
                               duration_ms, turn_count, cost_usd)
        return ExecutorResult(
            success=False, duration_ms=duration_ms, cost_usd=cost_usd,
            num_turns=turn_count, model=model, input_tokens=input_tokens,
            output_tokens=output_tokens, result_text=result_text, error=error_msg,
        )

    print(f"{prefix} done -- {turn_count} turns, ${cost_usd:.4f}, "
          f"{input_tokens + output_tokens} tokens")

    return ExecutorResult(
        success=True, duration_ms=duration_ms, cost_usd=cost_usd,
        num_turns=turn_count, model=model, input_tokens=input_tokens,
        output_tokens=output_tokens, result_text=result_text, error=last_error,
    )
