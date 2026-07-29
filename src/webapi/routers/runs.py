"""Runs: executions of a job. Team-visible; cancel restricted to owner/admin."""
from __future__ import annotations

import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import accessible_repo_ids, require_run_access
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.engine.base import ExecutionEngine
from src.webapi.engine.provider import get_engine
from src.webapi.mailer_provider import get_mailer
from src.webapi.models import (
    ROLE_ADMIN,
    RUN_FAILED,
    RUN_SUCCEEDED,
    RUN_TERMINAL,
    Job,
    Run,
    User,
)
from src.webapi.notifications import Mailer, build_completion_message
from src.webapi.reports import read_report
from src.webapi.schemas import RunRead
from src.webapi.settings import get_settings

router = APIRouter(tags=["runs"])
logger = logging.getLogger(__name__)

_NOTIFY_STATES = frozenset({RUN_SUCCEEDED, RUN_FAILED})
_MAX_NOTIFY_ATTEMPTS = 5


async def _maybe_notify(run: Run, session: AsyncSession, mailer: Mailer) -> None:
    """Send a completion email once when a run reaches success/failure.

    Retries a failed send only up to _MAX_NOTIFY_ATTEMPTS (attempts are naturally
    spaced by the caller's status polling) so a broken SMTP server can't cause an
    unbounded send storm on every GET."""
    if run.notified or run.status not in _NOTIFY_STATES:
        return
    # Per-job opt-in: only email when the job requested it (default off). Also gives us
    # the job for the owner fallback below.
    job = await session.get(Job, run.job_id)
    if job is None or not job.notify_email:
        run.notified = True  # nothing to send for this run; don't re-check every poll
        return
    if run.notify_attempts >= _MAX_NOTIFY_ATTEMPTS:
        run.notified = True  # give up cleanly; stop retrying
        return
    run.notify_attempts += 1
    recipient = None
    if run.triggered_by is not None:
        user = await session.get(User, run.triggered_by)
        recipient = user.email if user else None
    if recipient is None:  # fall back to the job/repo owner
        owner = await session.get(User, job.created_by)
        recipient = owner.email if owner else None
    if recipient is None:
        return
    from src.webapi.reports import report_path
    rpath = report_path(run.data_dir, run.session_id)
    report_exists = os.path.isfile(rpath)
    msg = build_completion_message(
        run, recipient, report_exists, get_settings().ui_base_url
    )
    try:
        # Attach the actual report when present, so the body's "attached" is true.
        mailer.send(msg["to"], msg["subject"], msg["body"],
                    rpath if report_exists else None)
        run.notified = True
    except Exception as exc:  # never let a mail failure break the request, but log why
        logger.warning(
            "Completion email for run %s to %s failed (attempt %d/%d): %s",
            run.id, recipient, run.notify_attempts, _MAX_NOTIFY_ATTEMPTS, exc,
        )
        return


async def _notify_sweep(session: AsyncSession, engine: ExecutionEngine, mailer: Mailer) -> None:
    """One pass: refresh in-flight runs from the engine and fire completion emails."""
    active = (await session.scalars(
        select(Run).where(Run.status.in_(("preparing", "running")))
    )).all()
    for run in active:
        try:
            await engine.refresh(run)
            await _maybe_notify(run, session, mailer)
            await session.commit()
        except Exception as exc:  # isolate one bad run from the rest
            await session.rollback()
            logger.warning("run status sweep: run %s failed: %s", run.id, exc)


async def run_status_loop(session_factory, engine, interval_s: int = 15) -> None:
    """Background sweep: refresh in-flight runs from the engine and fire completion
    notifications — WITHOUT anyone opening the run detail. Without this, an unattended
    run (e.g. a scheduled one) would never refresh its status or send its report email,
    because those only happened on GET /runs/{id}. Best-effort; never crashes the app."""
    while True:
        try:
            async with session_factory() as session:
                await _notify_sweep(session, engine, get_mailer())
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("run status sweep tick failed: %s", exc)
        await asyncio.sleep(interval_s)


def run_to_read(r: Run) -> RunRead:
    return RunRead(
        id=r.id, job_id=r.job_id, triggered_by=r.triggered_by,
        trigger_type=r.trigger_type, status=r.status, current_phase=r.current_phase,
        session_id=r.session_id, workflow_id=r.workflow_id,
        total_cost_usd=r.total_cost_usd, error_summary=r.error_summary,
        commit_sha=r.commit_sha,
        started_at=r.started_at, finished_at=r.finished_at, created_at=r.created_at,
    )


async def _may_control(run: Run, user: User, session: AsyncSession) -> bool:
    if user.role == ROLE_ADMIN or run.triggered_by == user.id:
        return True
    job = await session.get(Job, run.job_id)
    return job is not None and job.created_by == user.id


@router.get("/runs", response_model=list[RunRead])
async def list_runs(
    job_id: uuid.UUID | None = None,
    repository_id: uuid.UUID | None = None,
    status_filter: str | None = None,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[RunRead]:
    stmt = select(Run).order_by(Run.created_at.desc())
    if job_id is not None:
        stmt = stmt.where(Run.job_id == job_id)
    if status_filter is not None:
        stmt = stmt.where(Run.status == status_filter)
    rows = (await session.scalars(stmt)).all()

    allowed = await accessible_repo_ids(session, user)
    # Map job_id -> repository_id to filter by repo access (and optional repo filter).
    job_repo = {
        j.id: j.repository_id for j in (await session.scalars(select(Job))).all()
    }
    out: list[RunRead] = []
    for r in rows:
        repo_id = job_repo.get(r.job_id)
        if allowed is not None and repo_id not in allowed:
            continue
        if repository_id is not None and repo_id != repository_id:
            continue
        out.append(run_to_read(r))
    return out


@router.get("/runs/{run_id}", response_model=RunRead)
async def get_run(
    run_id: uuid.UUID,
    _: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
    mailer: Mailer = Depends(get_mailer),
) -> RunRead:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, _, run)
    if run.status not in RUN_TERMINAL:
        try:
            await engine.refresh(run)
        except Exception:  # best-effort; never fail a read on refresh
            await session.rollback()
    await _maybe_notify(run, session, mailer)
    await session.commit()
    # Compute + store metrics once the run has succeeded (best-effort).
    if run.status == RUN_SUCCEEDED:
        try:
            from src.webapi.metrics_service import upsert_run_metrics
            await upsert_run_metrics(session, run)
        except Exception:
            await session.rollback()
    # Reclaim disk from the source checkout once terminal (keeps .vigilo outputs).
    if run.status in RUN_TERMINAL:
        try:
            from src.webapi.cleanup import cleanup_run_source
            cleanup_run_source(run.data_dir)
        except Exception:
            pass
    return run_to_read(run)


@router.post("/runs/{run_id}/cancel", response_model=RunRead)
async def cancel_run(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
) -> RunRead:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, user, run)
    if not await _may_control(run, user, session):
        raise HTTPException(status_code=403, detail="Not permitted to cancel this run")
    if run.status not in RUN_TERMINAL:
        await engine.cancel(run)
        await session.commit()
        await session.refresh(run)
    return run_to_read(run)


@router.delete("/runs/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_run(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
) -> None:
    """Delete a run (cancels it first if still active), its metrics, and its on-disk
    workspace. Same authorization as cancel: run owner / job owner / admin."""
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, user, run)  # 404 if repo not visible
    if not await _may_control(run, user, session):
        raise HTTPException(status_code=403, detail="Not permitted to delete this run")
    from src.webapi.deletion import delete_run as _delete_run
    await _delete_run(session, engine, run)
    await session.commit()
