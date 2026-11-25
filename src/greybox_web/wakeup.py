"""In-process wake-up for a run's supervisor (hint latency).

The API and the worker may be different processes, so the supervisor still polls the
database for open hints (``RunSupervisor.POLL_S``). When both live in one process (the
in-process executor, tests) the hints endpoint calls :func:`notify` after it commits and
the supervisor's wait returns at once instead of at the next poll tick.
"""
from __future__ import annotations

import asyncio
import uuid

_waiters: dict[uuid.UUID, list[tuple[asyncio.AbstractEventLoop, asyncio.Event]]] = {}


def register(run_id: uuid.UUID, event: asyncio.Event) -> None:
    _waiters.setdefault(run_id, []).append((asyncio.get_running_loop(), event))


def unregister(run_id: uuid.UUID, event: asyncio.Event) -> None:
    rest = [w for w in _waiters.get(run_id, []) if w[1] is not event]
    if rest:
        _waiters[run_id] = rest
    else:
        _waiters.pop(run_id, None)


def notify(run_id: uuid.UUID) -> None:
    """Wake the supervisor(s) of ``run_id`` running in this process (thread-safe)."""
    for loop, event in list(_waiters.get(run_id, [])):
        try:
            loop.call_soon_threadsafe(event.set)
        except RuntimeError:           # that loop is closed
            pass
