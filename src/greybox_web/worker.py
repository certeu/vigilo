"""Grey-box worker: claims queued runs and supervises them.

Run as a separate process (``python -m src.greybox_web.worker``) or in-process
(``VIGILO_GREYBOX_EXECUTOR=inprocess`` starts :func:`worker_loop` in the API
lifespan). The claim is a conditional ``UPDATE`` on SQLite and Postgres alike, so
two workers can never claim the same run; heartbeats renew the lease and detect
a lost claim ("claim lost": stop writing, the reaper owns the run). Runs are
never auto-retried: a crashed worker's run is failed by the reaper and the user
starts a new one — duplicate scanning is impossible by construction.

Tests use :func:`run_once` (claim one run, run it to completion) and call the
supervisor directly.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession

# Register the platform tables (users, credentials) in the shared metadata: grey-box
# rows reference them by foreign key, and the API process imports them implicitly
# but a standalone worker does not (every flush failed with NoReferencedTableError).
import src.webapi.models  # noqa: F401,E402
from src.greybox_web import events
from src.greybox_web.models import (
    GB_CANCELLING,
    GB_PREPARING,
    GB_QUEUED,
    GB_RUNNING,
    GB_TERMINAL,
    GreyboxRun,
)
from src.greybox_web.supervisor import RunSupervisor
from src.greybox_web.txn import write as tx_write


def new_worker_id() -> str:
    host = getattr(os.uname(), "nodename", "unknown")
    return f"{host}:{os.getpid()}:{uuid.uuid4().hex[:8]}"[:128]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def claim_next_run(factory: async_sessionmaker, worker_id: str) -> uuid.UUID | None:
    """Claim the oldest queued run. Returns None when the queue is empty or the
    conditional update lost the race (T10: no double claim)."""

    async def fn(session: AsyncSession) -> uuid.UUID | None:
        from src.greybox_web import settings as gb_settings
        ttl = int(gb_settings.settings().greybox_lease_ttl_s)
        run_id = (await session.scalars(
            select(GreyboxRun.id).where(GreyboxRun.status == GB_QUEUED)
            .order_by(GreyboxRun.created_at, GreyboxRun.id).limit(1))).first()
        if run_id is None:
            return None
        now = utcnow()
        res = await session.execute(
            update(GreyboxRun)
            .where(GreyboxRun.id == run_id, GreyboxRun.status == GB_QUEUED)
            .values(status=GB_PREPARING, lease_owner=worker_id,
                    lease_expires_at=now + timedelta(seconds=ttl),
                    attempts=GreyboxRun.attempts + 1,
                    started_at=func.coalesce(GreyboxRun.started_at, now))
            .execution_options(synchronize_session=False))
        return run_id if res.rowcount == 1 else None

    return await tx_write(factory, fn)


async def heartbeat(factory: async_sessionmaker, run_id: uuid.UUID, worker_id: str,
                    ttl_s: int) -> tuple[bool, bool]:
    """Renew the lease. Returns (still_ours, cancel_requested)."""
    if isinstance(run_id, str):
        run_id = uuid.UUID(run_id)

    async def fn(session: AsyncSession) -> tuple[bool, bool]:
        res = await session.execute(
            update(GreyboxRun)
            .where(GreyboxRun.id == run_id, GreyboxRun.lease_owner == worker_id)
            .values(lease_expires_at=utcnow() + timedelta(seconds=ttl_s),
                    heartbeat_at=utcnow())
            .returning(GreyboxRun.cancel_requested_at)
            .execution_options(synchronize_session=False))
        row = res.first()
        if row is None:                           # claim lost: not ours any more
            return (False, False)
        return (True, row[0] is not None)

    return await tx_write(factory, fn)


async def run_once(factory: async_sessionmaker, worker_id: str | None = None,
                   **supervisor_kwargs) -> uuid.UUID | None:
    """Claim one queued run and run it to completion. Test entry point."""
    wid = worker_id or new_worker_id()
    run_id = await claim_next_run(factory, wid)
    if run_id is None:
        return None
    # An explicitly injected planner factory (tests) wins.
    pf = supervisor_kwargs.pop("planner_factory", None) \
        or await planner_factory_for(factory, run_id)
    supervisor = RunSupervisor(factory, run_id, wid, planner_factory=pf,
                               **supervisor_kwargs)
    await supervisor.run_to_completion()
    return run_id


async def planner_factory_for(factory: async_sessionmaker,
                             run_id: uuid.UUID) -> "Callable":
    """The proposer for a run: always the LLM proposer fed by the supervisor's
    explorer. There is no rule-based alternative; a run with no model backend fails
    fast in the supervisor with a clear error. The proposer shares the run's
    dynamic-tool registry (batch E) so findings from run-defined checks get their
    ``verify.<dyn id>`` replay work orders."""
    from src.greybox_web.exploration.proposer import LlmProposer
    return lambda state: LlmProposer(state.dynamic_tools)


async def worker_loop(factory: async_sessionmaker, *, worker_id: str | None = None,
                      max_runs: int | None = None, poll_s: float = 1.0,
                      **supervisor_kwargs) -> None:
    """The worker main loop: reap, claim, run; at most ``max_runs`` at a time."""
    from src.greybox_web import settings as gb_settings
    from src.greybox_web.service import reap_expired_leases

    wid = worker_id or new_worker_id()
    limit = max_runs if max_runs is not None \
        else int(gb_settings.settings().greybox_worker_max_runs)
    semaphore = asyncio.Semaphore(max(1, limit))

    async def _one(run_id: uuid.UUID) -> None:
        async with semaphore:
            # An explicitly injected planner factory (tests) wins; it stays in the
            # kwargs for the next run too (get, not pop).
            pf = supervisor_kwargs.get("planner_factory") \
                or await planner_factory_for(factory, run_id)
            supervisor = RunSupervisor(
                factory, run_id, wid,
                planner_factory=pf,
                **{k: v for k, v in supervisor_kwargs.items()
                   if k != "planner_factory"})
            await supervisor.run_to_completion()

    tasks: set[asyncio.Task] = set()
    try:
        while True:
            try:
                await reap_expired_leases(factory, wid)
            except Exception:                     # noqa: BLE001 — keep looping
                pass
            if not semaphore.locked():            # capacity free: claim one more
                run_id = await claim_next_run(factory, wid)
                if run_id is not None:
                    t = asyncio.create_task(_one(run_id), name=f"gb-run-{run_id}")
                    tasks.add(t)
                    t.add_done_callback(tasks.discard)
                    continue                       # claim again immediately
            await asyncio.sleep(poll_s)
    finally:
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="python -m src.greybox_web.worker",
        description="Vigilo grey-box web worker: claim queued runs and execute them "
                    "through the scope-guarded engine (no shell, no subprocess).")
    parser.add_argument("--once", action="store_true",
                        help="claim and run a single queued run, then exit")
    parser.add_argument("--worker-id", default=None,
                        help="override the worker identity (lease owner)")
    parser.add_argument("--max-runs", type=int, default=None,
                        help="concurrent runs per worker process "
                             "(default: VIGILO_GREYBOX_WORKER_MAX_RUNS)")
    args = parser.parse_args(argv)

    async def _amain() -> None:
        from src.webapi.db import _session_maker
        factory = _session_maker()
        if args.once:
            run_id = await run_once(factory, worker_id=args.worker_id)
            print("no queued run" if run_id is None else f"finished run {run_id}")
            return
        await worker_loop(factory, worker_id=args.worker_id, max_runs=args.max_runs)

    asyncio.run(_amain())


if __name__ == "__main__":
    main()
