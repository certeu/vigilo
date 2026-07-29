"""Repository access control.

Visibility model:
- Admins see everything.
- A repository owner sees their own repos.
- Non-private repos are team-visible (all authenticated users).
- Private repos are visible only to the owner, explicitly-granted users, and admins.

Jobs, runs, reports, metrics and schedules inherit their repository's access. These
helpers are the single source of truth used by every router.
"""
from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.models import (
    ROLE_ADMIN,
    Job,
    Repository,
    RepositoryAccess,
    Run,
    User,
)


async def accessible_repo_ids(session: AsyncSession, user: User) -> set[uuid.UUID] | None:
    """Return the set of repo ids the user may access, or None meaning ALL (admin)."""
    if user.role == ROLE_ADMIN:
        return None
    repos = (await session.scalars(select(Repository))).all()
    granted = set(
        (await session.scalars(
            select(RepositoryAccess.repository_id).where(
                RepositoryAccess.user_id == user.id
            )
        )).all()
    )
    allowed: set[uuid.UUID] = set()
    for r in repos:
        if (not r.is_private) or r.created_by == user.id or r.id in granted:
            allowed.add(r.id)
    return allowed


async def can_access_repo(session: AsyncSession, user: User, repo: Repository) -> bool:
    if user.role == ROLE_ADMIN or repo.created_by == user.id or not repo.is_private:
        return True
    grant = await session.scalar(
        select(RepositoryAccess).where(
            RepositoryAccess.repository_id == repo.id,
            RepositoryAccess.user_id == user.id,
        )
    )
    return grant is not None


async def require_repo_access(
    session: AsyncSession, user: User, repository_id: uuid.UUID
) -> Repository:
    repo = await session.get(Repository, repository_id)
    if repo is None or not await can_access_repo(session, user, repo):
        # 404 (not 403) for private repos the user can't see → no existence leak.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found")
    return repo


def is_owner_or_admin(user: User, repo: Repository) -> bool:
    return user.role == ROLE_ADMIN or repo.created_by == user.id


async def repo_id_for_job(session: AsyncSession, job_id: uuid.UUID) -> uuid.UUID | None:
    job = await session.get(Job, job_id)
    return job.repository_id if job else None


async def require_run_access(
    session: AsyncSession, user: User, run: Run
) -> Repository:
    repo_id = await repo_id_for_job(session, run.job_id)
    if repo_id is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return await require_repo_access(session, user, repo_id)
