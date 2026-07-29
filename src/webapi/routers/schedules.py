"""Schedules: recurring (cron) or GitLab-MR-triggered job runs.

CRUD here manages the schedule records. Recurring execution is driven by a Temporal
Schedule (integration; created when temporal is reachable); the MR path is handled by
the GitLab webhook router. Team-visible; mutate restricted to owner/admin.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.acl import accessible_repo_ids, require_repo_access
from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import ROLE_ADMIN, Job, Schedule, User
from src.webapi.schemas import ScheduleCreate, ScheduleRead, ScheduleUpdate

router = APIRouter(tags=["schedules"])


def _to_read(s: Schedule) -> ScheduleRead:
    return ScheduleRead(
        id=s.id, job_id=s.job_id, created_by=s.created_by, kind=s.kind,
        cron=s.cron, run_at=s.run_at, enabled=s.enabled, created_at=s.created_at,
    )


@router.post("/schedules", response_model=ScheduleRead, status_code=status.HTTP_201_CREATED)
async def create_schedule(
    payload: ScheduleCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ScheduleRead:
    job = await session.get(Job, payload.job_id)
    if job is None:
        raise HTTPException(status_code=400, detail="Unknown job")
    await require_repo_access(session, user, job.repository_id)
    sched = Schedule(
        job_id=payload.job_id, created_by=user.id, kind=payload.kind,
        cron=payload.cron, run_at=payload.run_at, enabled=payload.enabled,
    )
    session.add(sched)
    await session.commit()
    await session.refresh(sched)
    return _to_read(sched)


@router.get("/schedules", response_model=list[ScheduleRead])
async def list_schedules(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[ScheduleRead]:
    allowed = await accessible_repo_ids(session, user)
    job_repo = {j.id: j.repository_id for j in (await session.scalars(select(Job))).all()}
    rows = (await session.scalars(select(Schedule))).all()
    return [
        _to_read(s) for s in rows
        if allowed is None or job_repo.get(s.job_id) in allowed
    ]


@router.patch("/schedules/{schedule_id}", response_model=ScheduleRead)
async def patch_schedule(
    schedule_id: uuid.UUID,
    payload: ScheduleUpdate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ScheduleRead:
    sched = await session.get(Schedule, schedule_id)
    if sched is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    job = await session.get(Job, sched.job_id)
    if job is not None:
        await require_repo_access(session, user, job.repository_id)
    if sched.created_by != user.id and user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Not your schedule")
    data = payload.model_dump(exclude_unset=True)
    if "cron" in data:
        sched.cron = data["cron"]
    if "run_at" in data:
        sched.run_at = data["run_at"]
    if data.get("enabled") is not None:
        sched.enabled = data["enabled"]
    await session.commit()
    await session.refresh(sched)
    return _to_read(sched)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_schedule(
    schedule_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> None:
    sched = await session.get(Schedule, schedule_id)
    if sched is None:
        return
    job = await session.get(Job, sched.job_id)
    if job is not None:
        await require_repo_access(session, user, job.repository_id)
    if sched.created_by != user.id and user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Not your schedule")
    await session.delete(sched)
    await session.commit()
