"""Cascading deletion of runs and repositories, with disk cleanup.

FKs here have no ON DELETE CASCADE, so children must be removed in dependency
order. These helpers also reclaim on-disk artifacts (per-run workspaces, uploaded
source, the browse-only tree cache) so deleting from the UI doesn't leak files.
Disk removal is bounded to the configured jobs/uploads dirs (never escapes them).
"""
from __future__ import annotations

import logging
import os
import shutil

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.engine.base import ExecutionEngine
from src.webapi.models import (
    RUN_TERMINAL,
    Job,
    Repository,
    RepositoryAccess,
    Run,
    RunMetrics,
    Schedule,
)
from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)


def _rm_within(path: str | None, root: str) -> None:
    """Remove a file/dir only if it lives inside ``root`` (defensive)."""
    if not path:
        return
    root_abs = os.path.abspath(root)
    p = os.path.abspath(path)
    if p != root_abs and not p.startswith(root_abs + os.sep):
        logger.warning("deletion refused: %s outside %s", p, root_abs)
        return
    try:
        if os.path.islink(p):
            os.unlink(p)
        elif os.path.isdir(p):
            shutil.rmtree(p, ignore_errors=True)
        elif os.path.exists(p):
            os.remove(p)
    except OSError as exc:  # pragma: no cover - best-effort
        logger.warning("deletion failed for %s: %s", p, exc)


async def delete_run(session: AsyncSession, engine: ExecutionEngine, run: Run) -> None:
    """Cancel (if still active), then delete a run: metrics row, schedule back-refs,
    the DB row, and its on-disk workspace."""
    if run.status not in RUN_TERMINAL:
        try:
            await engine.cancel(run)
        except Exception as exc:  # pragma: no cover - best-effort
            logger.warning("cancel during delete failed for run %s: %s", run.id, exc)
    await session.execute(delete(RunMetrics).where(RunMetrics.run_id == run.id))
    # A schedule may point at this run as its last_run_id — null it, don't orphan-block.
    await session.execute(
        update(Schedule).where(Schedule.last_run_id == run.id).values(last_run_id=None)
    )
    data_dir = run.data_dir
    await session.delete(run)
    await session.flush()
    _rm_within(data_dir, get_settings().jobs_data_dir)


async def delete_job(session: AsyncSession, engine: ExecutionEngine, job: Job) -> None:
    """Delete a job and its runs (+metrics+workspaces) and schedules."""
    runs = (await session.scalars(select(Run).where(Run.job_id == job.id))).all()
    for run in runs:
        await delete_run(session, engine, run)
    await session.execute(delete(Schedule).where(Schedule.job_id == job.id))
    await session.delete(job)
    await session.flush()


async def delete_repository(
    session: AsyncSession, engine: ExecutionEngine, repo_id
) -> None:
    """Delete a repository and everything under it: runs (+metrics+workspaces),
    schedules, jobs, access grants, uploaded source + tree cache, then the repo row."""
    jobs = (await session.scalars(select(Job).where(Job.repository_id == repo_id))).all()
    for job in jobs:
        runs = (await session.scalars(select(Run).where(Run.job_id == job.id))).all()
        for run in runs:
            await delete_run(session, engine, run)
        await session.execute(delete(Schedule).where(Schedule.job_id == job.id))
        await session.delete(job)
    await session.execute(
        delete(RepositoryAccess).where(RepositoryAccess.repository_id == repo_id)
    )
    # Any run_metrics keyed directly by repository (defensive; also covered per-run).
    await session.execute(delete(RunMetrics).where(RunMetrics.repository_id == repo_id))
    repo = await session.get(Repository, repo_id)
    if repo is not None:
        await session.delete(repo)
    await session.flush()

    # Reclaim uploaded source + browse tree (bounded to uploads_dir).
    uploads = get_settings().uploads_dir
    rid = str(repo_id)
    _rm_within(os.path.join(uploads, f"{rid}.zip"), uploads)
    _rm_within(os.path.join(uploads, rid), uploads)
    _rm_within(os.path.join(uploads, f"{rid}.tree.json"), uploads)
