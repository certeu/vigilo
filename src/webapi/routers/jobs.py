"""Jobs: saved run configurations. Team-visible; delete restricted to owner/admin."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import accessible_repo_ids, require_repo_access
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.engine.base import ExecutionEngine
from src.webapi.engine.provider import get_engine
from src.webapi.models import ROLE_ADMIN, Job, Repository, User
from src.webapi.routers.runs import run_to_read
from src.webapi.runsvc import create_and_maybe_start
from src.webapi.schemas import JobCreate, JobRead, JobUpdate, RunRead

router = APIRouter(tags=["jobs"])


def _to_read(j: Job) -> JobRead:
    return JobRead(
        id=j.id, created_by=j.created_by, repository_id=j.repository_id, name=j.name,
        stage_preset=j.stage_preset, target_url=j.target_url, engine=j.engine,
        notify_email=j.notify_email, pipeline_overrides=j.pipeline_overrides,
        created_at=j.created_at,
    )


@router.post("/jobs", response_model=JobRead, status_code=status.HTTP_201_CREATED)
async def create_job(
    payload: JobCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> JobRead:
    await require_repo_access(session, user, payload.repository_id)
    repo = await session.get(Repository, payload.repository_id)
    if repo is None:
        raise HTTPException(status_code=400, detail="Unknown repository")
    job = Job(
        created_by=user.id, repository_id=payload.repository_id, name=payload.name,
        stage_preset=payload.stage_preset, target_url=payload.target_url,
        engine="whitebox", notify_email=payload.notify_email,
        pipeline_overrides=payload.pipeline_overrides or {},
    )
    session.add(job)
    await session.commit()
    await session.refresh(job)
    return _to_read(job)


@router.get("/jobs", response_model=list[JobRead])
async def list_jobs(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[JobRead]:
    allowed = await accessible_repo_ids(session, user)
    rows = (await session.scalars(select(Job))).all()
    return [_to_read(j) for j in rows if allowed is None or j.repository_id in allowed]


@router.get("/jobs/{job_id}", response_model=JobRead)
async def get_job(
    job_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> JobRead:
    job = await session.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    await require_repo_access(session, user, job.repository_id)
    return _to_read(job)


@router.patch("/jobs/{job_id}", response_model=JobRead)
async def update_job(
    job_id: uuid.UUID,
    payload: JobUpdate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> JobRead:
    """Update a job's settings (currently the report-email opt-in). Owner/admin only."""
    job = await session.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    await require_repo_access(session, user, job.repository_id)  # 404 if repo not visible
    if job.created_by != user.id and user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Not your job")
    data = payload.model_dump(exclude_unset=True)
    if "notify_email" in data:
        job.notify_email = bool(data["notify_email"])
    await session.commit()
    await session.refresh(job)
    return _to_read(job)


@router.delete("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_job(
    job_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
) -> None:
    job = await session.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    await require_repo_access(session, user, job.repository_id)  # 404 if repo not visible
    if job.created_by != user.id and user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Not your job")
    # Cascade: delete the job's runs (+metrics+workspaces) and schedules first, else
    # the FK would block. Running runs are cancelled inside delete_run.
    from src.webapi.deletion import delete_job as _delete_job
    await _delete_job(session, engine, job)
    await session.commit()


@router.post("/jobs/{job_id}/run", response_model=RunRead,
             status_code=status.HTTP_201_CREATED)
async def run_job(
    job_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    engine: ExecutionEngine = Depends(get_engine),
) -> RunRead:
    job = await session.get(Job, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    await require_repo_access(session, user, job.repository_id)
    run = await create_and_maybe_start(
        session, engine, job, triggered_by=user.id, trigger_type="manual"
    )
    return run_to_read(run)
