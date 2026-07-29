"""In-memory execution engine for tests and local UI evaluation.

Does not launch containers or Temporal workflows — it just advances Run state so
the API, run lifecycle, and UI can be exercised end-to-end without infrastructure.
"""
from __future__ import annotations

from src.webapi.models import (
    RUN_CANCELLED,
    RUN_RUNNING,
    RUN_TERMINAL,
    Job,
    Repository,
    Run,
)


class FakeEngine:
    """Records calls and advances Run state deterministically."""

    durable = False  # runs cannot survive/resume across an API restart

    def __init__(self) -> None:
        self.started: list[str] = []
        self.cancelled: list[str] = []

    async def start(self, run: Run, job: Job, repo: Repository) -> None:
        self.started.append(str(run.id))
        run.workflow_id = f"fake-wf-{run.id.hex[:8]}"
        run.container_id = f"fake-container-{run.id.hex[:8]}"
        run.status = RUN_RUNNING
        run.current_phase = "preflight"

    async def cancel(self, run: Run) -> None:
        self.cancelled.append(str(run.id))
        if run.status not in RUN_TERMINAL:
            run.status = RUN_CANCELLED

    async def refresh(self, run: Run) -> None:
        # No-op: fake runs stay in whatever state start()/cancel() left them.
        return None
