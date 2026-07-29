"""Dashboard metrics: per-run, per-repository timeline, and global aggregation."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import (
    accessible_repo_ids,
    require_repo_access,
    require_run_access,
)
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.metrics_service import (
    global_dashboard,
    metrics_to_dict,
    repo_timeline,
)
from src.webapi.models import Run, RunMetrics, User

router = APIRouter(tags=["dashboard"])


@router.get("/runs/{run_id}/metrics")
async def run_metrics(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, user, run)
    m = await session.scalar(select(RunMetrics).where(RunMetrics.run_id == run_id))
    if m is None:
        raise HTTPException(status_code=404, detail="No metrics for this run")
    return metrics_to_dict(m)


@router.get("/repositories/{repository_id}/metrics/timeline")
async def repository_timeline(
    repository_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    await require_repo_access(session, user, repository_id)
    return {"timeline": await repo_timeline(session, repository_id)}


@router.get("/dashboard/metrics")
async def dashboard_metrics(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    allowed = await accessible_repo_ids(session, user)
    return await global_dashboard(session, allowed)
