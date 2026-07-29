"""Agent Logger.

Per-agent JSON event logs and prompt snapshots.

Each agent attempt gets its own log file with format:
    agents/{timestamp}_{agent_name}_attempt-{N}.log

This isolates retries so you can diff attempts and see exactly what changed.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone

import aiofiles


def _ts() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_log_filename(agent_name: str, attempt: int) -> str:
    """Generate a log filename: ``{timestamp}_{agent}_attempt-{N}.log``."""
    ts = int(time.time() * 1000)
    return f"{ts}_{agent_name}_attempt-{attempt}.log"


class AgentLogger:
    """Manages append-only, per-agent event logs and prompt snapshots."""

    def __init__(self, log_dir: str) -> None:
        self.log_dir = log_dir
        # Track current log file path per agent (set by start_agent_log)
        self._active_logs: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Agent log lifecycle
    # ------------------------------------------------------------------

    async def start_agent_log(
        self,
        agent_name: str,
        attempt: int,
        session_id: str = "",
        web_url: str = "",
    ) -> None:
        """Create a new log file for an agent attempt and write the header banner.

        Log files with metadata header.
        """
        agents_dir = os.path.join(self.log_dir, "agents")
        os.makedirs(agents_dir, exist_ok=True)

        filename = _make_log_filename(agent_name, attempt)
        log_path = os.path.join(agents_dir, filename)
        self._active_logs[agent_name] = log_path

        # Write header banner
        header = "\n".join([
            "=" * 40,
            f"Agent: {agent_name}",
            f"Attempt: {attempt}",
            f"Started: {_ts()}",
            f"Session: {session_id}",
            f"Web URL: {web_url}",
            "=" * 40,
            "",
        ])
        async with aiofiles.open(log_path, mode="w") as f:
            await f.write(header)

    # ------------------------------------------------------------------
    # Event logging
    # ------------------------------------------------------------------

    async def log_event(
        self,
        agent_name: str,
        event_type: str,
        data: dict,
    ) -> None:
        """Append a single JSON event to the agent's active log file.

        Each line in the file is a self-contained JSON object so the file
        can be streamed and parsed incrementally.

        Falls back to ``agents/{agent_name}.log`` if no active log was started.
        """
        log_path = self._active_logs.get(agent_name)
        if not log_path:
            # Fallback for events logged before start_agent_log
            agents_dir = os.path.join(self.log_dir, "agents")
            os.makedirs(agents_dir, exist_ok=True)
            log_path = os.path.join(agents_dir, f"{agent_name}.log")

        # Include timestamp in event data
        ts = _ts()
        data_with_ts = {**data, "timestamp": ts}

        event = {
            "type": event_type,
            "timestamp": ts,
            "data": data_with_ts,
        }
        line = json.dumps(event, separators=(",", ":")) + "\n"

        async with aiofiles.open(log_path, mode="a") as f:
            await f.write(line)

    # ------------------------------------------------------------------
    # Prompt snapshots
    # ------------------------------------------------------------------

    async def save_prompt(
        self,
        agent_name: str,
        prompt: str,
        session_id: str = "",
        web_url: str = "",
    ) -> None:
        """Save a prompt snapshot to ``prompts/{agent_name}.md``."""
        prompts_dir = os.path.join(self.log_dir, "prompts")
        os.makedirs(prompts_dir, exist_ok=True)

        prompt_path = os.path.join(prompts_dir, f"{agent_name}.md")
        header = "\n".join([
            f"# Prompt Snapshot: {agent_name}",
            "",
            f"**Session:** {session_id}",
            f"**Web URL:** {web_url}",
            f"**Saved:** {_ts()}",
            "",
            "---",
            "",
        ])
        content = header + prompt

        async with aiofiles.open(prompt_path, mode="w") as f:
            await f.write(content)
