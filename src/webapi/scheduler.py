"""In-process schedule runner.

Fires due schedules: ``once`` (run_at <= now, not yet fired) and ``recurring``
(cron due since the last fire, if croniter is installed). ``gitlab_mr`` schedules are
event-driven and ignored here. A background poller in the app lifespan calls
``run_due_schedules`` periodically; the function is also directly unit-testable.

Recurring uses croniter when available; if not installed, recurring schedules are
skipped (a warning is logged once) — one-off ``once`` scheduling works regardless.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.engine.base import ExecutionEngine
from src.webapi.models import RUN_TERMINAL, Job, Run, Schedule
from src.webapi.runsvc import create_and_maybe_start

logger = logging.getLogger(__name__)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(dt: datetime | None) -> datetime | None:
    """Coerce a possibly-naive datetime (SQLite drops tz) to aware UTC."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


async def _last_run_time(session: AsyncSession, sched: Schedule) -> datetime | None:
    if sched.last_run_id is None:
        return None
    run = await session.get(Run, sched.last_run_id)
    return _as_utc(run.created_at) if run else None


def _recurring_due(cron: str, last: datetime | None, now: datetime) -> bool:
    try:
        from croniter import croniter
    except ImportError:  # pragma: no cover - optional dependency
        logger.warning("croniter not installed; recurring schedules skipped")
        return False
    base = last or (now.replace(microsecond=0))
    nxt = croniter(cron, base).get_next(datetime)
    return nxt <= now


async def run_due_schedules(
    session: AsyncSession, engine: ExecutionEngine, now: datetime | None = None
) -> list[str]:
    """Fire all due time-based schedules; return the ids of runs started."""
    now = now or _now()
    started: list[str] = []
    scheds = (
        await session.scalars(
            select(Schedule).where(Schedule.enabled == True)  # noqa: E712
        )
    ).all()
    for sched in scheds:
        due = False
        if sched.kind == "once":
            already = sched.last_run_id is not None
            run_at = _as_utc(sched.run_at)
            due = (not already) and run_at is not None and run_at <= now
        elif sched.kind == "recurring" and sched.cron:
            last = await _last_run_time(session, sched)
            due = _recurring_due(sched.cron, last, now)
        if not due:
            continue
        job = await session.get(Job, sched.job_id)
        if job is None:
            continue
        run = await create_and_maybe_start(
            session, engine, job, triggered_by=sched.created_by, trigger_type="schedule"
        )
        sched.last_run_id = run.id
        if sched.kind == "once":
            sched.enabled = False  # one-shot
        await session.commit()
        started.append(str(run.id))
    return started


async def scheduler_loop(session_factory, engine, interval_s: int = 30) -> None:
    """Background poller. Best-effort; never crashes the app."""
    while True:
        try:
            async with session_factory() as session:
                await run_due_schedules(session, engine)
        except Exception as exc:  # pragma: no cover
            logger.warning("scheduler tick failed: %s", exc)
        await asyncio.sleep(interval_s)


# Re-export for callers that want the terminal set (avoids an extra import).
__all__ = ["run_due_schedules", "scheduler_loop", "RUN_TERMINAL"]
