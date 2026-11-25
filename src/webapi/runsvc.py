"""Shared run-creation service.

Used by manual runs (POST /jobs/{id}/run), the GitLab MR webhook, and (later)
recurring schedules — so every trigger path creates and admits runs identically.
"""
from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)
_BACKGROUND_TASKS: set[asyncio.Task] = set()
import os
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from src.webapi.db import _session_maker

# Serializes the admission-control window (count active → decide → start) so
# concurrent run requests can't all pass the cap check at once. Correct for the
# single-process API; a Postgres advisory lock is the multi-process upgrade.
# Bound lazily to the running loop (a module-level Lock would bind to the wrong
# loop across test cases / restarts).
_admission_lock: asyncio.Lock | None = None
_admission_loop = None


def _get_admission_lock() -> asyncio.Lock:
    global _admission_lock, _admission_loop
    loop = asyncio.get_running_loop()
    if _admission_lock is None or _admission_loop is not loop:
        _admission_lock = asyncio.Lock()
        _admission_loop = loop
    return _admission_lock

import logging

from src.webapi.engine.base import ExecutionEngine, new_run_identity
from src.webapi.models import (
    RUN_FAILED,
    RUN_PREPARING,
    RUN_QUEUED,
    RUN_RUNNING,
    AdminConfig,
    Job,
    Repository,
    Run,
)
from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)


async def create_and_maybe_start(
    session: AsyncSession,
    engine: ExecutionEngine,
    job: Job,
    *,
    triggered_by: uuid.UUID | None,
    trigger_type: str,
    gitlab_mr_iid: str | None = None,
) -> Run:
    """Create a Run for ``job`` and start it if under the concurrency cap; otherwise
    leave it queued. Returns the (committed, refreshed) Run."""
    repo = await session.get(Repository, job.repository_id)
    run_id, session_id, task_queue = new_run_identity()
    data_dir = os.path.join(get_settings().jobs_data_dir, str(run_id))
    run = Run(
        id=run_id, job_id=job.id, triggered_by=triggered_by, trigger_type=trigger_type,
        status=RUN_QUEUED, session_id=session_id, task_queue=task_queue,
        data_dir=data_dir, gitlab_mr_iid=gitlab_mr_iid,
    )
    session.add(run)
    await session.commit()

    async with _get_admission_lock():
        if await _active_count(session) < await _effective_cap(session):
            # Do NOT wait for engine.start (clone/extract can take a while): the run is
            # already committed as "queued", so the caller (API/UI) can redirect to the
            # run page right away. The launch continues in a background task.
            # The run is claimed (queued -> preparing) INSIDE the admission lock: otherwise
            # it stays "queued" for the whole clone, is not counted by _active_count, and
            # N simultaneous requests exceed the global concurrency cap.
            if await _claim_for_launch(session, run):
                task = asyncio.create_task(
                    _launch_bg(run.id, engine, job.id, repo.id if repo else None)
                )
                _BACKGROUND_TASKS.add(task)
                task.add_done_callback(_BACKGROUND_TASKS.discard)
    await session.refresh(run)
    return run


async def _effective_cap(session: AsyncSession) -> int:
    """Return the live concurrency cap from the admin_config DB row.

    The row is seeded from ``VIGILO_GLOBAL_CONCURRENT_RUN_CAP`` on first boot
    (see ``seed_admin_config``) and is editable at runtime via the admin API,
    so operators can change the cap without a restart. Falls back to the env
    setting if the row is somehow absent."""
    cfg = await session.get(AdminConfig, 1)
    if cfg is not None:
        return cfg.global_concurrent_run_cap
    return get_settings().global_concurrent_run_cap


async def _active_count(session: AsyncSession) -> int:
    return await session.scalar(
        select(func.count()).select_from(Run).where(
            Run.status.in_((RUN_PREPARING, RUN_RUNNING))
        )
    )




async def _claim_for_launch(session: AsyncSession, run: Run) -> bool:
    """Atomically transition a run from queued to preparing (False if already claimed).

    The ORM only flushes the new status after engine.start() returns, which can take
    minutes of cloning. Claiming up front makes the run visible to the concurrency cap
    and stops a concurrent drain_queue tick from launching it a second time.
    """
    started = datetime.now(timezone.utc)
    res = await session.execute(
        update(Run)
        .where(Run.id == run.id, Run.status == RUN_QUEUED)
        .values(status=RUN_PREPARING, started_at=started)
    )
    await session.commit()
    if res.rowcount == 0:
        logger.info("run %s already claimed by another launcher, skipping", run.id)
        return False
    run.status = RUN_PREPARING
    run.started_at = started
    return True


async def _launch_bg(run_id: uuid.UUID, engine: ExecutionEngine, job_id: uuid.UUID,
                     repo_id: uuid.UUID | None) -> None:
    """Start a run via the engine in a DEDICATED session (the request's session is
    closed by the time this background task runs). A launch failure must NOT leave
    the run stuck 'queued' — mark it failed with a user-facing summary."""
    async with _session_maker()() as session:
        run = await session.get(Run, run_id)
        if run is None:
            return
        job = await session.get(Job, job_id)
        repo = await session.get(Repository, repo_id) if repo_id else None
        # Normally already claimed (preparing) by create_and_maybe_start under the
        # admission lock; a still-queued run (direct caller) is claimed here.
        if run.status == RUN_QUEUED and not await _claim_for_launch(session, run):
            return
        if run.status != RUN_PREPARING:
            return  # cancelled/finished in the meantime
        try:
            await engine.start(run, job, repo)
        except Exception as exc:
            logger.warning("engine.start failed for run %s: %s", run.id, exc)
            run.status = RUN_FAILED
            run.finished_at = datetime.now(timezone.utc)
            run.error_summary = f"Failed to start scan: {str(exc)[:400]}"
            from src.webapi.secret_store import revoke
            await revoke(session, run.id)
        await session.commit()


async def _launch(session: AsyncSession, engine: ExecutionEngine, run: Run,
                  job: Job, repo: Repository | None) -> None:
    run.started_at = datetime.now(timezone.utc)
    try:
        await engine.start(run, job, repo)
    except Exception as exc:
        logger.warning("engine.start failed for run %s: %s", run.id, exc)
        run.status = RUN_FAILED
        run.finished_at = datetime.now(timezone.utc)
        run.error_summary = f"Failed to start scan: {str(exc)[:400]}"
        from src.webapi.secret_store import revoke
        await revoke(session, run.id)
    await session.commit()


async def drain_queue(session: AsyncSession, engine: ExecutionEngine) -> int:
    """Promote queued runs (oldest first) until the concurrency cap is reached.

    Without this, a run created over the cap stays 'queued' forever — freeing a
    slot never starts it. Called periodically by ``run_queue_loop`` and safe to
    run concurrently with new submissions (both hold the admission lock)."""
    started = 0
    async with _get_admission_lock():
        cap = await _effective_cap(session)
        while await _active_count(session) < cap:
            nxt = await session.scalar(
                select(Run).where(Run.status == RUN_QUEUED)
                .order_by(Run.created_at).limit(1)
            )
            if nxt is None:
                break
            job = await session.get(Job, nxt.job_id)
            if job is None:  # orphaned queued run → don't wedge the queue
                nxt.status = RUN_FAILED
                nxt.finished_at = datetime.now(timezone.utc)
                nxt.error_summary = "Job no longer exists"
                await session.commit()
                continue
            repo = await session.get(Repository, job.repository_id)
            await _launch(session, engine, nxt, job, repo)
            started += 1
    return started


async def run_queue_loop(session_factory, engine, interval_s: int = 5) -> None:
    """Background poller that drains the run queue as slots free up. Best-effort."""
    while True:
        try:
            async with session_factory() as session:
                await drain_queue(session, engine)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("queue drain tick failed: %s", exc)
        await asyncio.sleep(interval_s)
