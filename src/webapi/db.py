"""Async SQLAlchemy engine/session and declarative base."""
from __future__ import annotations

from collections.abc import AsyncGenerator
from functools import lru_cache

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from src.webapi.settings import get_settings


class Base(DeclarativeBase):
    pass


@lru_cache
def get_engine():
    return create_async_engine(get_settings().database_url, future=True)


@lru_cache
def _session_maker():
    return async_sessionmaker(get_engine(), expire_on_commit=False, class_=AsyncSession)


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    async with _session_maker()() as session:
        yield session


async def create_all() -> None:
    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
