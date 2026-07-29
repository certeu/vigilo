"""Metrics Tracker.

Manages ``session.json`` with atomic writes and an asyncio lock for
concurrent-write safety
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone

import aiofiles

from src.types.audit import SessionMetadata


def _ts() -> str:
    """Return an ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class MetricsTracker:
    """Manages the ``session.json`` file for a pentest session."""

    def __init__(self, session_path: str) -> None:
        self.session_path = session_path
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(
        self,
        metadata: SessionMetadata,
        workflow_id: str = "",
    ) -> None:
        """Create or load ``session.json`` with the initial structure."""
        async with self._lock:
            if os.path.exists(self.session_path):
                data = await self._read_unsafe()
            else:
                data = {
                    "session": {
                        "id": metadata.id,
                        "webUrl": metadata.web_url,
                        "status": "in-progress",
                        "createdAt": _ts(),
                    },
                    "metrics": {
                        "total_duration_ms": 0,
                        "total_cost_usd": 0.0,
                        "phases": {},
                        "agents": {},
                    },
                }
                if metadata.repo_path:
                    data["session"]["repoPath"] = metadata.repo_path
                if workflow_id:
                    data["session"]["originalWorkflowId"] = workflow_id
                await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    async def start_agent(self, agent_name: str, attempt: int) -> None:
        """Record that an agent execution has started."""
        async with self._lock:
            data = await self._read_unsafe()
            agents = data["metrics"].setdefault("agents", {})
            if agent_name not in agents:
                agents[agent_name] = {
                    "status": "in-progress",
                    "attempts": [],
                    "final_duration_ms": 0,
                    "total_cost_usd": 0.0,
                }
            else:
                agents[agent_name]["status"] = "in-progress"
            await self._write_unsafe(data)

    async def end_agent(
        self,
        agent_name: str,
        attempt: int,
        duration_ms: int,
        cost_usd: float,
        status: str,
        model: str | None = None,
        checkpoint: str | None = None,
    ) -> None:
        """Record agent completion with metrics."""
        async with self._lock:
            data = await self._read_unsafe()
            agents = data["metrics"].setdefault("agents", {})
            agent = agents.setdefault(agent_name, {
                "status": "in-progress",
                "attempts": [],
                "final_duration_ms": 0,
                "total_cost_usd": 0.0,
            })

            # Append attempt record
            attempt_record: dict = {
                "attempt_number": attempt,
                "duration_ms": duration_ms,
                "cost_usd": cost_usd,
                "success": status == "success",
                "timestamp": _ts(),
            }
            if model:
                attempt_record["model"] = model
            agent["attempts"].append(attempt_record)

            # Recalculate total cost across all attempts
            agent["total_cost_usd"] = sum(
                a["cost_usd"] for a in agent["attempts"]
            )

            # Update status and metadata on success
            agent["status"] = status
            if status == "success":
                agent["final_duration_ms"] = duration_ms
                if model:
                    agent["model"] = model
                if checkpoint:
                    agent["checkpoint"] = checkpoint

            # Recalculate session-level aggregations
            self._recalculate(data)

            await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Session status
    # ------------------------------------------------------------------

    async def update_status(self, status: str) -> None:
        """Update the top-level session status."""
        async with self._lock:
            data = await self._read_unsafe()
            data["session"]["status"] = status
            if status in ("completed", "failed"):
                data["session"]["completedAt"] = _ts()
            await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Resume tracking
    # ------------------------------------------------------------------

    async def add_resume_attempt(
        self,
        workflow_id: str,
        terminated: list[str],
        checkpoint: str,
    ) -> None:
        """Record a workflow resume attempt in session.json."""
        async with self._lock:
            data = await self._read_unsafe()
            session = data["session"]

            # Backfill originalWorkflowId if missing
            if "originalWorkflowId" not in session:
                session["originalWorkflowId"] = session.get("id", "")

            resume_attempts: list[dict] = session.setdefault(
                "resumeAttempts", []
            )
            entry: dict = {
                "workflowId": workflow_id,
                "timestamp": _ts(),
            }
            if terminated:
                entry["terminatedPrevious"] = ",".join(terminated)
            if checkpoint:
                entry["resumedFromCheckpoint"] = checkpoint

            resume_attempts.append(entry)
            await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_data(self) -> dict:
        """Return the current contents of session.json."""
        async with self._lock:
            return await self._read_unsafe()

    # ------------------------------------------------------------------
    # Internal I/O (must be called while holding ``_lock``)
    # ------------------------------------------------------------------

    async def _read_unsafe(self) -> dict:
        """Read session.json without acquiring the lock."""
        async with aiofiles.open(self.session_path, mode="r") as f:
            raw = await f.read()
        return json.loads(raw)

    async def _write_unsafe(self, data: dict) -> None:
        """Atomic write: write to a temp file in the same directory, then rename."""
        dir_name = os.path.dirname(self.session_path)
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
        os.close(fd)
        try:
            async with aiofiles.open(tmp_path, mode="w") as f:
                await f.write(json.dumps(data, indent=2))
            os.replace(tmp_path, self.session_path)
        except BaseException:
            # Clean up the temp file on failure
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
            raise

    # Convenience aliases expected by the public API
    async def _read(self) -> dict:
        async with self._lock:
            return await self._read_unsafe()

    async def _write(self, data: dict) -> None:
        async with self._lock:
            await self._write_unsafe(data)

    # ------------------------------------------------------------------
    # Aggregation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _recalculate(data: dict) -> None:
        """Recalculate session-level totals from agent metrics."""
        agents: dict = data["metrics"].get("agents", {})
        successful = {
            name: info
            for name, info in agents.items()
            if info.get("status") == "success"
        }

        total_duration = sum(
            info.get("final_duration_ms", 0) for info in successful.values()
        )
        total_cost = sum(
            info.get("total_cost_usd", 0.0) for info in successful.values()
        )

        data["metrics"]["total_duration_ms"] = total_duration
        data["metrics"]["total_cost_usd"] = total_cost
