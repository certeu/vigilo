"""Report + artifact access for a run."""
from __future__ import annotations

import asyncio
import uuid

import jwt
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import require_run_access
from src.webapi.auth.backend import get_jwt_strategy
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import Run, User
from src.webapi.reports import (
    BUNDLE_KIND,
    PATCHES_KIND,
    PATCHES_ZIP_NAME,
    open_artifact,
    available_artifacts,
    build_bundle_zip,
    build_patches_zip,
    read_report,
    resolve_deliverable_file,
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


async def _user_from_query_token(token: str | None, session: AsyncSession) -> User:
    """Authenticate from a ``?token=`` query param (for <img> tags, which cannot
    send an Authorization header). Same validation as the Bearer flow, including
    the session-epoch revocation check."""
    if not token:
        raise HTTPException(status_code=401, detail="Token required")
    strategy = get_jwt_strategy()
    try:
        payload = jwt.decode(
            token,
            strategy.decode_key,
            audience=strategy.token_audience,
            algorithms=[strategy.algorithm],
        )
        user_id = payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await session.get(User, uuid.UUID(str(user_id)))
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid token")
    if int(payload.get("epoch", 0) or 0) != int(getattr(user, "session_epoch", 0) or 0):
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


@router.get("/runs/{run_id}/files/{rel_path:path}")
async def get_run_file(
    run_id: uuid.UUID,
    rel_path: str,
    token: str | None = None,
    session: AsyncSession = Depends(get_async_session),
) -> FileResponse:
    """Serve a file from the run's deliverables dir (report screenshots).

    Auth is via ``?token=<jwt>`` because ``<img>`` requests cannot attach a
    Bearer header. Path traversal outside deliverables/ is rejected."""
    user = await _user_from_query_token(token, session)
    run = await _run_or_404(run_id, session, user)
    path = resolve_deliverable_file(run.data_dir, run.session_id, rel_path)
    if path is None:
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(path)


@router.get("/runs/{run_id}/artifacts")
async def list_artifacts(
    run_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> dict:
    run = await _run_or_404(run_id, session, user)
    return {"artifacts": available_artifacts(run.data_dir, run.session_id)}


@router.get("/runs/{run_id}/artifacts/{kind}", response_model=None)
async def download_artifact(
    run_id: uuid.UUID,
    kind: str,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> FileResponse | StreamingResponse:
    run = await _run_or_404(run_id, session, user)
    if kind in (PATCHES_KIND, BUNDLE_KIND):
        if kind == PATCHES_KIND:
            buf = await asyncio.to_thread(build_patches_zip, run.data_dir, run.session_id)
            zip_name = PATCHES_ZIP_NAME
        else:
            buf = await asyncio.to_thread(build_bundle_zip, run.data_dir, run.session_id)
            zip_name = f"vigilo-deliverables-{str(run.id)[:8]}.zip"
        if buf is None:
            raise HTTPException(status_code=404, detail="Artifact not found")

        def _chunks():
            try:
                while chunk := buf.read(64 * 1024):
                    yield chunk
            finally:
                buf.close()

        return StreamingResponse(
            _chunks(), media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{zip_name}"'},
        )
    opened = open_artifact(run.data_dir, run.session_id, kind)
    if opened is None:
        raise HTTPException(status_code=404, detail="Artifact not found")
    fh, name, media_type = opened

    def _file_chunks():
        try:
            while chunk := fh.read(64 * 1024):
                yield chunk
        finally:
            fh.close()

    return StreamingResponse(
        _file_chunks(), media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )
