"""Audit trail writer for the grey-box pipeline.

Writes to the volume-mounted workspace directory so all data survives
container shutdown. Three output files:

  {workspace}/workflow.log        — human-readable, tail-friendly
  {workspace}/session.json        — machine-readable cumulative metrics
  {workspace}/deliverables/agents/{agent}.json  — per-agent result summaries
  {workspace}/deliverables/prompts/{agent}.md   — rendered prompts
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiofiles

logger = logging.getLogger(__name__)

_lock = asyncio.Lock()


def _ts() -> str:
    """ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _ts_iso() -> str:
    """ISO-8601 UTC timestamp with timezone."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# workflow.log — human-readable append-only log
# ---------------------------------------------------------------------------


async def append_workflow_log(workspace: str, line: str) -> None:
    """Append a line to workflow.log. Creates the file if needed."""
    log_path = Path(workspace) / "workflow.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiofiles.open(log_path, mode="a", encoding="utf-8") as f:
        await f.write(line + "\n")


async def log_workflow_header(
    workspace: str,
    session_id: str,
    target_url: str,
    identities: list[str],
) -> None:
    """Write the workflow.log header banner, preserving any prior content.

    If the log file already has content (e.g. an audit event fired before
    init_workspace), prepend the banner rather than clobbering. This keeps
    phase/agent events visible while still showing the session header.
    """
    log_path = Path(workspace) / "workflow.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    banner = "\n".join([
        "=" * 80,
        f"  Vigilo Grey-Box Pipeline — {session_id}",
        f"  Target: {target_url}",
        f"  Identities: {', '.join(identities)}",
        f"  Started: {_ts()}",
        "=" * 80,
        "",
    ]) + "\n"

    existing = ""
    if log_path.exists() and log_path.stat().st_size > 0:
        async with aiofiles.open(log_path, mode="r", encoding="utf-8") as f:
            existing = await f.read()
        if existing.startswith("=" * 10):  # banner already present — no-op
            return

    async with aiofiles.open(log_path, mode="w", encoding="utf-8") as f:
        await f.write(banner + existing)


async def log_phase_start(workspace: str, phase: str) -> None:
    """Log a phase start event."""
    await append_workflow_log(
        workspace, f"[{_ts()}] [PHASE] Starting: {phase}"
    )


async def log_phase_complete(workspace: str, phase: str) -> None:
    """Log a phase completion event."""
    await append_workflow_log(
        workspace, f"[{_ts()}] [PHASE] Completed: {phase}"
    )


async def log_agent_start(workspace: str, agent_name: str) -> None:
    """Log an agent start event."""
    await append_workflow_log(
        workspace, f"[{_ts()}] [AGENT] {agent_name}: Starting"
    )


async def log_agent_complete(
    workspace: str,
    agent_name: str,
    duration_s: float,
    cost_usd: float,
    findings_count: int = 0,
) -> None:
    """Log an agent completion event."""
    findings_str = f" findings={findings_count}" if findings_count else ""
    await append_workflow_log(
        workspace,
        f"[{_ts()}] [AGENT] {agent_name}: Completed "
        f"({duration_s:.1f}s ${cost_usd:.4f}{findings_str})",
    )


async def log_agent_error(
    workspace: str, agent_name: str, error: str
) -> None:
    """Log an agent error event."""
    await append_workflow_log(
        workspace,
        f"[{_ts()}] [AGENT] {agent_name}: FAILED — {error[:500]}",
    )


async def log_managed_scan(
    workspace: str,
    scan_type: str,
    items_found: int,
    nodes_added: int,
    duration_ms: int,
) -> None:
    """Log a managed scan completion."""
    await append_workflow_log(
        workspace,
        f"[{_ts()}] [SCAN] {scan_type}: {items_found} items, "
        f"{nodes_added} nodes ({duration_ms}ms)",
    )


async def log_workflow_complete(
    workspace: str,
    status: str,
    total_cost: float,
    total_duration_ms: int,
    findings_count: int,
    agents_completed: int,
    error: str | None = None,
) -> None:
    """Write workflow completion summary to workflow.log."""
    lines = [
        "",
        "-" * 80,
        f"  Pipeline {status.upper()}",
        f"  Duration: {total_duration_ms // 1000}s",
        f"  Cost: ${total_cost:.4f}",
        f"  Findings: {findings_count}",
        f"  Agents completed: {agents_completed}",
    ]
    if error:
        lines.append(f"  Error: {error[:500]}")
    lines.extend(["-" * 80, ""])

    for line in lines:
        await append_workflow_log(workspace, line)


# ---------------------------------------------------------------------------
# session.json — machine-readable atomic metrics
# ---------------------------------------------------------------------------


async def init_session_json(
    workspace: str,
    session_id: str,
    target_url: str,
    identities: list[str],
) -> None:
    """Write the initial session.json."""
    data = {
        "session_id": session_id,
        "pipeline_type": "greybox",
        "target_url": target_url,
        "identities": identities,
        "status": "running",
        "started_at": _ts_iso(),
        "phases_completed": [],
        "agents": {},
        "managed_scans": {},
        "total_cost_usd": 0.0,
        "total_duration_ms": 0,
        "findings_count": 0,
        "agents_spawned": 0,
        "agents_completed": 0,
    }
    await _write_session_json(workspace, data)


async def update_session_phase(workspace: str, phase: str) -> None:
    """Mark a phase as completed in session.json."""
    async with _lock:
        data = await _read_session_json(workspace)
        if phase not in data.get("phases_completed", []):
            data.setdefault("phases_completed", []).append(phase)
        await _write_session_json(workspace, data)


async def update_session_agent(
    workspace: str,
    agent_name: str,
    duration_ms: int,
    cost_usd: float,
    input_tokens: int,
    output_tokens: int,
    num_turns: int,
    model: str,
    findings_count: int = 0,
    success: bool = True,
) -> None:
    """Record an agent's results in session.json."""
    async with _lock:
        data = await _read_session_json(workspace)
        data.setdefault("agents", {})[agent_name] = {
            "duration_ms": duration_ms,
            "cost_usd": cost_usd,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "num_turns": num_turns,
            "model": model,
            "findings_count": findings_count,
            "success": success,
            "completed_at": _ts_iso(),
        }
        data["agents_completed"] = sum(
            1 for a in data["agents"].values() if a.get("success")
        )
        data["total_cost_usd"] = sum(
            a.get("cost_usd", 0) for a in data["agents"].values()
        )
        data["findings_count"] = sum(
            a.get("findings_count", 0) for a in data["agents"].values()
        )
        await _write_session_json(workspace, data)


async def update_session_managed_scan(
    workspace: str,
    scan_type: str,
    items_found: int,
    nodes_added: int,
    duration_ms: int,
    success: bool = True,
) -> None:
    """Record a managed scan's results in session.json."""
    async with _lock:
        data = await _read_session_json(workspace)
        data.setdefault("managed_scans", {})[scan_type] = {
            "items_found": items_found,
            "nodes_added": nodes_added,
            "duration_ms": duration_ms,
            "success": success,
            "completed_at": _ts_iso(),
        }
        await _write_session_json(workspace, data)


async def update_session_spawned(workspace: str) -> None:
    """Increment agents_spawned counter."""
    async with _lock:
        data = await _read_session_json(workspace)
        data["agents_spawned"] = data.get("agents_spawned", 0) + 1
        await _write_session_json(workspace, data)


async def finalize_session(
    workspace: str,
    status: str,
    total_duration_ms: int,
    error: str | None = None,
) -> None:
    """Mark the session as completed/failed in session.json."""
    async with _lock:
        data = await _read_session_json(workspace)
        data["status"] = status
        data["completed_at"] = _ts_iso()
        data["total_duration_ms"] = total_duration_ms
        if error:
            data["error"] = error[:2000]
        await _write_session_json(workspace, data)


async def _read_session_json(workspace: str) -> dict[str, Any]:
    """Read session.json, returning empty dict if missing."""
    path = Path(workspace) / "session.json"
    if not path.exists():
        return {}
    try:
        async with aiofiles.open(path, encoding="utf-8") as f:
            return json.loads(await f.read())
    except (json.JSONDecodeError, OSError):
        return {}


async def _write_session_json(workspace: str, data: dict[str, Any]) -> None:
    """Atomic write session.json via tempfile + rename."""
    path = Path(workspace) / "session.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(data, indent=2, default=str)
    # Write to tempfile then rename for atomicity
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=str(path.parent), suffix=".tmp", prefix="session_"
    )
    try:
        async with aiofiles.open(tmp_fd, mode="w", encoding="utf-8", closefd=True) as f:
            await f.write(content)
        Path(tmp_path).replace(path)
    except Exception:
        Path(tmp_path).unlink(missing_ok=True)
        raise


# ---------------------------------------------------------------------------
# Per-agent artifacts — deliverables/agents/ and deliverables/prompts/
# ---------------------------------------------------------------------------


async def save_agent_prompt(
    workspace: str, agent_name: str, prompt: str
) -> None:
    """Save a rendered prompt to deliverables/prompts/{agent_name}.md."""
    prompts_dir = Path(workspace) / "deliverables" / "prompts"
    prompts_dir.mkdir(parents=True, exist_ok=True)
    path = prompts_dir / f"{agent_name}.md"
    async with aiofiles.open(path, mode="w", encoding="utf-8") as f:
        await f.write(f"# Prompt: {agent_name}\n")
        await f.write(f"<!-- generated {_ts_iso()} -->\n\n")
        await f.write(prompt)


async def save_agent_result(
    workspace: str, agent_name: str, result: dict[str, Any]
) -> None:
    """Save an agent result summary to deliverables/agents/{agent_name}.json."""
    agents_dir = Path(workspace) / "deliverables" / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    path = agents_dir / f"{agent_name}.json"
    async with aiofiles.open(path, mode="w", encoding="utf-8") as f:
        await f.write(json.dumps(result, indent=2, default=str))
