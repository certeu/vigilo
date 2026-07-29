"""Run log access: paginated read + Server-Sent-Events live stream."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import require_run_access
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.logs import log_path_for, read_from, stream_lines
from src.webapi.models import RUN_TERMINAL, Run, User

router = APIRouter(tags=["logs"])


async def _get_run_or_404(run_id: uuid.UUID, session: AsyncSession, user: User) -> Run:
    run = await session.get(Run, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    await require_run_access(session, user, run)
    return run


@router.get("/runs/{run_id}/logs")
async def get_logs(
    run_id: uuid.UUID,
    offset: int = 0,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    """Paginated read of the run's workflow.log from a byte offset."""
    run = await _get_run_or_404(run_id, session, user)
    path = log_path_for(run.data_dir, run.session_id)
    lines, new_offset = read_from(path, offset)
    return {"lines": lines, "offset": new_offset, "status": run.status}


@router.get("/runs/{run_id}/logs/stream")
async def stream_logs(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> StreamingResponse:
    """Live SSE stream of new log lines until the run reaches a terminal state."""
    run = await _get_run_or_404(run_id, session, user)
    path = log_path_for(run.data_dir, run.session_id)

    async def _is_done() -> bool:
        await session.refresh(run)
        return run.status in RUN_TERMINAL

    return StreamingResponse(
        stream_lines(path, _is_done, poll_seconds=0.2),
        media_type="text/event-stream",
    )
