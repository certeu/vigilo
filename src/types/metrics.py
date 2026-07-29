"""Metrics type definitions for agent and pipeline tracking.

Used across services, activities, and audit system to record cost, duration,
token usage, and overall pipeline state.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class AgentMetrics(BaseModel):
    """Metrics collected from a single agent execution."""

    duration_ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None
    num_turns: int | None = None
    model: str | None = None


class PipelineSummary(BaseModel):
    """Aggregated metrics across all agents in a pipeline run."""

    total_cost_usd: float = 0.0
    total_duration_ms: int = 0
    total_turns: int = 0
    agent_count: int = 0


class PipelineState(BaseModel):
    """Mutable pipeline state tracked by the workflow."""

    status: Literal["running", "completed", "failed"] = "running"
    current_phase: str | None = None
    current_agent: str | None = None
    completed_agents: list[str] = Field(default_factory=list)
    failed_agent: str | None = None
    error: str | None = None
    start_time: float
    # Temporal activities return plain dicts (JSON-deserialized), not AgentMetrics.
    # The workflow also handles both forms in _compute_summary.
    agent_metrics: dict[str, AgentMetrics | dict[str, Any]] = Field(default_factory=dict)
    summary: PipelineSummary | None = None


class PipelineProgress(PipelineState):
    """Pipeline state enriched with runtime info, returned by workflow query."""

    workflow_id: str = ""
    elapsed_ms: int = 0
