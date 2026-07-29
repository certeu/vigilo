"""Workflow Logger.

Human-readable log file writer optimized for ``tail -f`` viewing during
concurrent workflow execution.
"""

from __future__ import annotations

from datetime import datetime, timezone

import aiofiles


def _ts() -> str:
    """Return a UTC timestamp formatted for log lines."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _format_duration(ms: int) -> str:
    """Human-readable duration from milliseconds."""
    if ms < 1_000:
        return f"{ms}ms"
    seconds = ms / 1_000
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    remaining = seconds - minutes * 60
    return f"{minutes}m{remaining:.0f}s"


class WorkflowLogger:
    """Manages the unified ``workflow.log`` file for a session."""

    def __init__(self, log_path: str) -> None:
        self.log_path = log_path

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(self, web_url: str, session_id: str) -> None:
        """Write the header banner to workflow.log."""
        header = "\n".join([
            "=" * 80,
            "Vigilo - Workflow Log",
            "=" * 80,
            f"Session: {session_id}",
            f"Target:  {web_url}",
            f"Started: {_ts()}",
            "=" * 80,
            "",
        ])
        await self._write(header)

    # ------------------------------------------------------------------
    # Phase events
    # ------------------------------------------------------------------

    async def log_phase_start(self, phase: str) -> None:
        """Log the start of a pipeline phase."""
        # Blank line before phase start for readability
        await self._write("")
        await self._write(f"[{_ts()}] [PHASE] Starting: {phase}")

    async def log_phase_complete(self, phase: str) -> None:
        """Log the completion of a pipeline phase."""
        await self._write(f"[{_ts()}] [PHASE] Completed: {phase}")

    # ------------------------------------------------------------------
    # Agent events
    # ------------------------------------------------------------------

    async def log_agent_start(self, agent_name: str, attempt: int) -> None:
        """Log that an agent has started execution."""
        await self._write(
            f"[{_ts()}] [AGENT] {agent_name}: Starting (attempt {attempt})"
        )

    async def log_agent_complete(
        self,
        agent_name: str,
        duration_s: float,
        cost: float,
    ) -> None:
        """Log that an agent has completed successfully."""
        await self._write(
            f"[{_ts()}] [AGENT] {agent_name}: Completed "
            f"({duration_s:.1f}s ${cost:.4f})"
        )

    async def log_agent_error(self, agent_name: str, error: str) -> None:
        """Log an agent-level error."""
        await self._write(f"[{_ts()}] [ERROR] {agent_name}: {error}")

    async def log_llm_response(
        self, agent_name: str, turn: int, content: str
    ) -> None:
        """Log a single LLM response turn."""
        escaped = content.replace("\n", "\\n")
        await self._write(
            f"[{_ts()}] [{agent_name}] [LLM] Turn {turn}: {escaped}"
        )

    # ------------------------------------------------------------------
    # Workflow lifecycle
    # ------------------------------------------------------------------

    async def log_workflow_complete(self, summary: dict) -> None:
        """Write the completion banner with summary statistics.

        Expected *summary* keys:
        - ``status`` (str): ``"completed"`` or ``"failed"``
        - ``total_duration_ms`` (int)
        - ``total_cost_usd`` (float)
        - ``completed_agents`` (list[str])
        - ``agent_metrics`` (dict[str, dict]): per-agent ``duration_ms``, ``cost_usd``
        - ``error`` (str | None, optional)
        """
        status_label = summary.get("status", "unknown").upper()
        duration = _format_duration(summary.get("total_duration_ms", 0))
        cost = summary.get("total_cost_usd", 0.0)
        completed: list[str] = summary.get("completed_agents", [])
        agent_metrics: dict = summary.get("agent_metrics", {})
        error: str | None = summary.get("error")

        lines: list[str] = [
            "",
            "=" * 80,
            f"Workflow {status_label}",
            "\u2500" * 40,
            f"Status:      {summary.get('status', 'unknown')}",
            f"Duration:    {duration}",
            f"Total Cost:  ${cost:.4f}",
            f"Agents:      {len(completed)} completed",
        ]

        if error:
            lines.append(f"Error:       {error}")

        lines.append("")
        lines.append("Agent Breakdown:")

        for agent_name in completed:
            metrics = agent_metrics.get(agent_name)
            if metrics:
                dur = _format_duration(metrics.get("duration_ms", 0))
                c = metrics.get("cost_usd")
                cost_str = f"${c:.4f}" if c is not None else "N/A"
                lines.append(f"  - {agent_name} ({dur}, {cost_str})")
            else:
                lines.append(f"  - {agent_name}")

        lines.append("=" * 80)

        # Single atomic write to avoid interleaved output in log tailers
        await self._write("\n".join(lines))

    async def log_resume_header(self, info: dict) -> None:
        """Write a resume header when a workflow is continued from a checkpoint.

        Expected *info* keys:
        - ``previous_workflow_id`` (str)
        - ``new_workflow_id`` (str)
        - ``checkpoint_hash`` (str)
        - ``completed_agents`` (list[str])
        """
        completed: list[str] = info.get("completed_agents", [])
        header = "\n".join([
            "",
            "=" * 80,
            "RESUMED",
            "=" * 80,
            f"Previous Workflow ID: {info.get('previous_workflow_id', '')}",
            f"New Workflow ID:      {info.get('new_workflow_id', '')}",
            f"Resumed At:           {_ts()}",
            f"Checkpoint:           {info.get('checkpoint_hash', '')}",
            f"Completed:            {len(completed)} agents ({', '.join(completed)})",
            "=" * 80,
            "",
        ])
        await self._write(header)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _write(self, line: str) -> None:
        """Append a line (with trailing newline) to the log file."""
        async with aiofiles.open(self.log_path, mode="a") as f:
            await f.write(line + "\n")
