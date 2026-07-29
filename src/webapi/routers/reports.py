"""Report + artifact access for a run."""
from __future__ import annotations

import os
import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import require_run_access
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import Run, User
from src.webapi.reports import (
    artifact_path,
    available_artifacts,
    read_report,
)

router = APIRouter(tags=["reports"])


async def _run_or_404(run_id: uuid.UUID, session: AsyncSession, user: User) -> Run:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, user, run)
    return run


@router.get("/runs/{run_id}/report")
async def get_report(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await _run_or_404(run_id, session, user)
    markdown = read_report(run.data_dir, run.session_id)
    return {"exists": markdown is not None, "markdown": markdown or ""}


@router.get("/runs/{run_id}/artifacts")
async def list_artifacts(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await _run_or_404(run_id, session, user)
    return {"artifacts": available_artifacts(run.data_dir, run.session_id)}


@router.get("/runs/{run_id}/artifacts/{kind}")
async def download_artifact(
    run_id: uuid.UUID,
    kind: str,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> FileResponse:
    run = await _run_or_404(run_id, session, user)
    path = artifact_path(run.data_dir, run.session_id, kind)
    if path is None or not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(path, filename=os.path.basename(path))
