"""Audit Session facade.

Coordinates :class:`WorkflowLogger`, :class:`MetricsTracker`, and
:class:`AgentLogger` behind a single entry point.
audit-session.ts.
"""

from __future__ import annotations

import os

from src.types.audit import SessionMetadata
from src.types.metrics import AgentMetrics

from .agent_logger import AgentLogger
from .metrics_tracker import MetricsTracker
from .workflow_logger import WorkflowLogger


def get_workspace_path(
    session_id: str,
    repo_path: str,
    output_path: str | None = None,
) -> str:
    """Return the workspace directory for *session_id*.

    Uses *output_path* as the base when provided, otherwise defaults to
    ``{repo_path}/.vigilo``.  This places all scan artefacts inside the
    target repository so users find results where they expect them.
    """
    base = output_path or os.path.join(repo_path, ".vigilo")
    return os.path.join(base, session_id)


class AuditSession:
    """Main audit system facade for a pentest session.

    Usage::

        session = AuditSession(metadata)
        await session.initialize(workflow_id="wf-123")
        await session.log_phase_start("pre-recon")
        await session.start_agent("recon", attempt=1)
        # ... agent runs ...
        await session.end_agent("recon", metrics, checkpoint="abc123")
        await session.log_phase_complete("pre-recon")
        await session.log_workflow_complete(summary)
    """

    def __init__(self, metadata: SessionMetadata) -> None:
        self.metadata = metadata
        self._initialized = False

        # Sub-components (created in ``initialize``)
        self._workflow_logger: WorkflowLogger | None = None
        self._metrics_tracker: MetricsTracker | None = None
        self._agent_logger: AgentLogger | None = None

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    async def initialize(self, workflow_id: str = "") -> None:
        """Set up the audit directory structure and initialise sub-components.

        Creates:
        - ``{repo_path}/.vigilo/{session_id}/``
        - ``{repo_path}/.vigilo/{session_id}/agents/``
        - ``{repo_path}/.vigilo/{session_id}/prompts/``
        - ``{repo_path}/.vigilo/{session_id}/deliverables/``
        """
        if self._initialized:
            return

        workspace = get_workspace_path(
            self.metadata.id,
            self.metadata.repo_path,
            self.metadata.output_path,
        )

        # Create directory tree
        for subdir in ("agents", "prompts", "deliverables"):
            os.makedirs(os.path.join(workspace, subdir), exist_ok=True)

        # Workflow logger
        log_path = os.path.join(workspace, "workflow.log")
        self._workflow_logger = WorkflowLogger(log_path)
        await self._workflow_logger.initialize(
            self.metadata.web_url,
            self.metadata.id,
        )

        # Metrics tracker
        session_json_path = os.path.join(workspace, "session.json")
        self._metrics_tracker = MetricsTracker(session_json_path)
        await self._metrics_tracker.initialize(self.metadata, workflow_id)

        # Agent logger
        self._agent_logger = AgentLogger(workspace)

        self._initialized = True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _ensure_initialized(self) -> None:
        if not self._initialized:
            await self.initialize()

    # ------------------------------------------------------------------
    # Agent lifecycle
    # ------------------------------------------------------------------

    async def start_agent(self, agent_name: str, attempt: int) -> None:
        """Record the start of an agent execution."""
        await self._ensure_initialized()
        assert self._workflow_logger is not None
        assert self._metrics_tracker is not None
        assert self._agent_logger is not None

        await self._workflow_logger.log_agent_start(agent_name, attempt)
        await self._metrics_tracker.start_agent(agent_name, attempt)

        # Create per-attempt log file with header banner
        await self._agent_logger.start_agent_log(
            agent_name,
            attempt,
            session_id=self.metadata.id,
            web_url=self.metadata.web_url,
        )
        await self._agent_logger.log_event(
            agent_name,
            "agent_start",
            {"agentName": agent_name, "attemptNumber": attempt},
        )

    async def end_agent(
        self,
        agent_name: str,
        metrics: AgentMetrics,
        checkpoint: str | None = None,
    ) -> None:
        """Record agent completion with collected metrics."""
        await self._ensure_initialized()
        assert self._workflow_logger is not None
        assert self._metrics_tracker is not None
        assert self._agent_logger is not None

        duration_s = metrics.duration_ms / 1_000
        cost = metrics.cost_usd or 0.0
        status = "success"  # Caller is responsible for not calling on failure

        await self._workflow_logger.log_agent_complete(
            agent_name, duration_s, cost
        )
        await self._metrics_tracker.end_agent(
            agent_name=agent_name,
            attempt=1,
            duration_ms=metrics.duration_ms,
            cost_usd=cost,
            status=status,
            model=metrics.model,
            checkpoint=checkpoint,
        )
        await self._agent_logger.log_event(
            agent_name,
            "agent_end",
            {
                "duration_ms": metrics.duration_ms,
                "cost_usd": cost,
                "model": metrics.model,
            },
        )

    # ------------------------------------------------------------------
    # Phase events
    # ------------------------------------------------------------------

    async def log_phase_start(self, phase: str) -> None:
        await self._ensure_initialized()
        assert self._workflow_logger is not None
        await self._workflow_logger.log_phase_start(phase)

    async def log_phase_complete(self, phase: str) -> None:
        await self._ensure_initialized()
        assert self._workflow_logger is not None
        await self._workflow_logger.log_phase_complete(phase)

    # ------------------------------------------------------------------
    # Workflow lifecycle
    # ------------------------------------------------------------------

    async def log_workflow_complete(self, summary: dict) -> None:
        await self._ensure_initialized()
        assert self._workflow_logger is not None
        await self._workflow_logger.log_workflow_complete(summary)

    async def update_session_status(self, status: str) -> None:
        await self._ensure_initialized()
        assert self._metrics_tracker is not None
        await self._metrics_tracker.update_status(status)

    # ------------------------------------------------------------------
    # Resume support
    # ------------------------------------------------------------------

    async def add_resume_attempt(
        self,
        workflow_id: str,
        terminated: list[str],
        checkpoint: str,
    ) -> None:
        await self._ensure_initialized()
        assert self._metrics_tracker is not None
        await self._metrics_tracker.add_resume_attempt(
            workflow_id, terminated, checkpoint
        )

    async def log_resume_header(self, info: dict) -> None:
        await self._ensure_initialized()
        assert self._workflow_logger is not None
        await self._workflow_logger.log_resume_header(info)

    # ------------------------------------------------------------------
    # Read-only access
    # ------------------------------------------------------------------

    async def get_metrics(self) -> dict:
        await self._ensure_initialized()
        assert self._metrics_tracker is not None
        return await self._metrics_tracker.get_data()
