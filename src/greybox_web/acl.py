"""Owner/admin access control for grey-box targets and runs.

A target or run is visible to its ``owner_id`` and to admins. Anyone else gets
**404** ``{"detail": "Not found"}`` (no existence leak). Mutations (PATCH, DELETE,
start, cancel) are allowed for the same principals.
"""
from __future__ import annotations

import uuid

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.greybox_web.models import GreyboxRun, GreyboxTarget
from src.webapi.models import ROLE_ADMIN, User

NOT_FOUND = "Not found"


def is_admin(user: User) -> bool:
    return user.role == ROLE_ADMIN


def may_access(user: User, owner_id: uuid.UUID) -> bool:
    return is_admin(user) or owner_id == user.id


# Mutations follow the same rule as visibility (owner or admin).
may_control = may_access


def not_found() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=NOT_FOUND)


async def get_target_or_404(session: AsyncSession, user: User,
                            target_id: uuid.UUID) -> GreyboxTarget:
    target = await session.get(GreyboxTarget, target_id)
    if target is None or not may_access(user, target.owner_id):
        raise not_found()
    return target


async def get_run_or_404(session: AsyncSession, user: User, run_id: uuid.UUID) -> GreyboxRun:
    run = await session.get(GreyboxRun, run_id)
    if run is None or not may_access(user, run.owner_id):
        raise not_found()
    return run
