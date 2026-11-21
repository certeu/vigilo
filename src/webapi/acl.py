"""Repository access control.

Visibility model:
- Admins see everything.
- A repository owner sees their own repos.
- Non-private repos are team-visible (all authenticated users).
- Private repos are visible only to the owner, explicitly-granted users, and admins.
- ARCHIVED repos are hidden from everyone (admins included) unless the caller
  explicitly asks for them (``include_archived``) — the archive is a soft hide,
  never a delete: runs, jobs and artifacts stay on disk and unarchiving restores
  full visibility.

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


async def accessible_repo_ids(
    session: AsyncSession, user: User, include_archived: bool = False
) -> set[uuid.UUID] | None:
    """Return the set of repo ids the user may access, or None meaning ALL (admin).

    Archived repos are excluded unless ``include_archived`` is set; an admin then
    gets the ALL sentinel only when archived repos are requested, otherwise an
    explicit set of the non-archived ones so the archive filter always applies.
    """
    repos = (await session.scalars(select(Repository))).all()
    if user.role == ROLE_ADMIN and include_archived:
        return None
    granted = set(
        (await session.scalars(
            select(RepositoryAccess.repository_id).where(
                RepositoryAccess.user_id == user.id
            )
        )).all()
    )
    allowed: set[uuid.UUID] = set()
    for r in repos:
        if r.archived and not include_archived:
            continue
        if (
            user.role == ROLE_ADMIN
            or (not r.is_private)
            or r.created_by == user.id
            or r.id in granted
        ):
            allowed.add(r.id)
    return allowed


async def can_access_repo(session: AsyncSession, user: User, repo: Repository) -> bool:
    if repo.archived:
        return False  # archived → invisible (require_repo_access → 404), unarchive to restore
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
