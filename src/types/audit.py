"""Audit system type definitions.

Models for session metadata, structured log events, per-agent attempt
records, and the top-level session.json structure.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class SessionMetadata(BaseModel):
    """Cross-cutting session metadata used by services, temporal, and audit."""

    id: str
    web_url: str
    repo_path: str
    output_path: str | None = None


class LogEvent(BaseModel):
    """Single structured log entry for workflow.log or agent logs."""

    timestamp: str
    level: str
    agent: str | None = None
    phase: str | None = None
    message: str
    context: dict | None = None


class AgentAttempt(BaseModel):
    """Record of a single agent execution attempt."""

    attempt: int
    duration_ms: int
    cost_usd: float
    status: str
    model: str | None = None


class AgentRecord(BaseModel):
    """Aggregate record of an agent across all attempts."""

    status: str
    attempts: list[AgentAttempt] = Field(default_factory=list)
    checkpoint: str | None = None
    total_cost_usd: float = 0.0
    final_duration_ms: int = 0
    model: str | None = None


class SessionData(BaseModel):
    """Top-level structure for session.json.

    Uses flexible dicts to match Shannon's session.json format, which
    allows arbitrary nesting under ``session`` and ``metrics`` keys.
    """

    session: dict = Field(default_factory=dict)
    metrics: dict = Field(default_factory=dict)
