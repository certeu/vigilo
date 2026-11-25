"""Write transactions for the grey-box engine (portable SQLite/Postgres).

Every engine write (event + state change) runs in one short transaction. On Postgres
the ``UPDATE greybox_runs ... RETURNING last_seq`` row lock serialises emitters across
processes. SQLite has a single database-wide writer and fails fast (instead of
waiting) when a read transaction tries to upgrade to a write while another writer is
active, so on SQLite every in-process write is additionally serialised through one
per-event-loop lock, and a "database is locked" error from another process is retried.
"""
from __future__ import annotations

import asyncio
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import TypeVar

from sqlalchemy.exc import OperationalError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

T = TypeVar("T")
SessionFactory = async_sessionmaker[AsyncSession]

_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = (
    weakref.WeakKeyDictionary())


def _loop_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _locks.get(loop)
    if lock is None:
        lock = _locks[loop] = asyncio.Lock()
    return lock


def is_sqlite_session(session: AsyncSession) -> bool:
    return session.get_bind().dialect.name == "sqlite"


def _factory_is_sqlite(factory: SessionFactory) -> bool:
    bind = factory.kw.get("bind")
    return bind is not None and bind.dialect.name == "sqlite"


@asynccontextmanager
async def sqlite_write_lock(session: AsyncSession) -> AsyncIterator[None]:
    """Hold the in-process SQLite writer lock (no-op on other dialects). Used by API
    routes that write grey-box state through the request session."""
    if is_sqlite_session(session):
        async with _loop_lock():
            yield
    else:
        yield


def _is_locked(exc: OperationalError) -> bool:
    return "locked" in str(exc).lower() or "busy" in str(exc).lower()


async def write(factory: SessionFactory, fn: Callable[[AsyncSession], Awaitable[T]],
                *, retries: int = 6) -> T:
    """Run ``fn(session)`` in one committed transaction and return its result."""
    sqlite = _factory_is_sqlite(factory)
    attempt = 0
    while True:
        try:
            if sqlite:
                async with _loop_lock():
                    return await _once(factory, fn)
            return await _once(factory, fn)
        except OperationalError as exc:
            attempt += 1
            if not sqlite or not _is_locked(exc) or attempt > retries:
                raise
            await asyncio.sleep(0.05 * (2 ** attempt))


async def _once(factory: SessionFactory, fn: Callable[[AsyncSession], Awaitable[T]]) -> T:
    async with factory() as session:
        async with session.begin():
            return await fn(session)


async def read(factory: SessionFactory, fn: Callable[[AsyncSession], Awaitable[T]]) -> T:
    async with factory() as session:
        return await fn(session)
