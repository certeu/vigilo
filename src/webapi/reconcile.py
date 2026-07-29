"""Startup reconciliation of non-terminal runs after a crash/restart.

Guarantees a job is never silently lost or stuck "running" forever:

- **Durable engine (Temporal):** re-poll each non-terminal run's status
  (``engine.refresh``). Workflows survive an API restart and resume from the last
  completed activity, so a still-running run stays running and a finished one is
  updated. Nothing is failed just because the API bounced.
- **Non-durable engine (mock/fake):** a run left non-terminal by a crash cannot
  recover, so it is marked ``failed`` with a clear reason instead of hanging.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.engine.base import ExecutionEngine
from src.webapi.models import RUN_FAILED, RUN_TERMINAL, Run

logger = logging.getLogger(__name__)

_NON_TERMINAL = ("queued", "preparing", "running")


async def reconcile_runs(session: AsyncSession, engine: ExecutionEngine) -> dict:
    """Reconcile non-terminal runs on startup. Returns a small summary."""
    durable = getattr(engine, "durable", False)
    rows = (
        await session.scalars(select(Run).where(Run.status.in_(_NON_TERMINAL)))
    ).all()
    reattached = 0
    failed = 0
    for run in rows:
        if durable:
            try:
                await engine.refresh(run)
                reattached += 1
            except Exception as exc:  # pragma: no cover - best-effort
                logger.warning("reconcile refresh failed for run %s: %s", run.id, exc)
        if run.status not in RUN_TERMINAL and not durable:
            run.status = RUN_FAILED
            run.finished_at = datetime.now(timezone.utc)
            run.error_summary = (
                "Interrupted by a service restart and could not be resumed. "
                "Please start a new run."
            )
            failed += 1
    if rows:
        await session.commit()
    summary = {"non_terminal": len(rows), "reattached": reattached, "failed": failed}
    if rows:
        logger.info("Run reconciliation on startup: %s", summary)
    return summary
