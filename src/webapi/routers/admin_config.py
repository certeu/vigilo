"""Global admin config (models, executor, concurrency, SMTP). Admin-only in M1."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.auth.deps import require_admin
from src.webapi.db import get_async_session
from src.webapi.models import AdminConfig, User
from src.webapi.schemas import AdminConfigRead, AdminConfigUpdate

router = APIRouter(tags=["admin"])


async def _get_or_create(session: AsyncSession) -> AdminConfig:
    cfg = await session.get(AdminConfig, 1)
    if cfg is None:
        cfg = AdminConfig(id=1)
        session.add(cfg)
        await session.commit()
        await session.refresh(cfg)
    return cfg


@router.get("/admin/config", response_model=AdminConfigRead)
async def get_config(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> AdminConfig:
    return await _get_or_create(session)


@router.put("/admin/config", response_model=AdminConfigRead)
async def put_config(
    payload: AdminConfigUpdate,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> AdminConfig:
    cfg = await _get_or_create(session)
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(cfg, field, value)
    await session.commit()
    await session.refresh(cfg)
    return cfg
