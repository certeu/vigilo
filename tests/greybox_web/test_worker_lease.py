"""Claim fencing, heartbeat ("claim lost") and the lease reaper. Runs are never
auto-retried: a crashed worker's run is failed by the reaper with end_reason=lease_expired."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from src.greybox_web.models import GB_FAILED, GreyboxRun
from src.greybox_web.service import reap_expired_leases
from src.greybox_web.worker import claim_next_run, heartbeat, new_worker_id
from tests.greybox_web.conftest import LIMITS_USE, create_target, h, target_body


async def _queued_run(client, token, url):
    from tests.greybox_web.conftest import start_run
    t = await create_target(client, token, base_url=url, limits=LIMITS_USE)
    r = await start_run(client, token, t["id"])
    assert r.status_code == 201, r.text
    return r.json()


async def test_two_workers_never_claim_the_same_run(client, user_token,
                                                    session_maker, target_server):
    run = await _queued_run(client, user_token, target_server.url)
    a, b = new_worker_id(), new_worker_id()
    got_a = await claim_next_run(session_maker, a)
    got_b = await claim_next_run(session_maker, b)
    assert str(got_a) == run["id"]
    assert got_b is None                        # the queue is empty for B


async def test_heartbeat_detects_lost_claim(client, user_token, session_maker,
                                            target_server):
    run = await _queued_run(client, user_token, target_server.url)
    owner = new_worker_id()
    await claim_next_run(session_maker, owner)
    ok, cancel = await heartbeat(session_maker, uuid.UUID(run["id"]), owner,
                                 ttl_s=60)
    assert ok and not cancel
    # a different worker cannot renew someone else's lease
    ok2, _ = await heartbeat(session_maker, run["id"], new_worker_id(), ttl_s=60)
    assert ok2 is False


async def test_reaper_fails_expired_leases_without_retry(client, user_token,
                                                         session_maker,
                                                         target_server):
    run = await _queued_run(client, user_token, target_server.url)
    owner = new_worker_id()
    await claim_next_run(session_maker, owner)
    run_id = uuid.UUID(run["id"])
    # simulate a dead worker: lease in the past
    async with session_maker() as s:
        await s.execute(update(GreyboxRun).where(GreyboxRun.id == run_id)
                        .values(lease_expires_at=datetime.now(timezone.utc)
                                - timedelta(seconds=1)))
        await s.commit()
    reaped = await reap_expired_leases(session_maker)
    assert reaped == 1
    async with session_maker() as s:
        row = await s.get(GreyboxRun, run_id)
        assert row.status == GB_FAILED
        assert row.end_reason == "lease_expired"
        assert row.finished_at is not None
        assert row.lease_owner is None
    # terminal now: reaping again does nothing
    assert await reap_expired_leases(session_maker) == 0


async def test_reaper_finishes_cancelled_runs(client, user_token, session_maker,
                                              target_server):
    run = await _queued_run(client, user_token, target_server.url)
    owner = new_worker_id()
    await claim_next_run(session_maker, owner)
    run_id = uuid.UUID(run["id"])
    async with session_maker() as s:
        await s.execute(update(GreyboxRun).where(GreyboxRun.id == run_id)
                        .values(status="cancelling",
                                lease_expires_at=datetime.now(timezone.utc)
                                - timedelta(seconds=1)))
        await s.commit()
    await reap_expired_leases(session_maker)
    async with session_maker() as s:
        row = await s.get(GreyboxRun, run_id)
        assert row.status == "cancelled"
        assert row.end_reason == "lease_expired"


async def test_lease_never_reaped_while_heartbeat_alive(client, user_token,
                                                        session_maker,
                                                        target_server):
    run = await _queued_run(client, user_token, target_server.url)
    owner = new_worker_id()
    await claim_next_run(session_maker, owner)
    await heartbeat(session_maker, uuid.UUID(run["id"]), owner, ttl_s=60)
    assert await reap_expired_leases(session_maker) == 0

async def test_reaper_settles_graph_nodes_of_a_dead_run(client, user_token,
                                                        session_maker, target_server):
    """A reaped run must not leave action nodes "running" or the objective "active"."""
    import asyncio

    from src.greybox_web.models import GreyboxGraphNode
    from src.greybox_web.worker import run_once
    from tests.greybox_web.conftest import start_run

    t = await create_target(client, user_token, base_url=target_server.url + "slow",
                            limits={**LIMITS_USE, "request_timeout_s": 30})
    r = await start_run(client, user_token, t["id"])
    run_id = uuid.UUID(r.json()["id"])
    worker = asyncio.create_task(run_once(session_maker))

    async def live_nodes() -> list[GreyboxGraphNode]:
        async with session_maker() as s:
            return list((await s.scalars(select(GreyboxGraphNode).where(
                GreyboxGraphNode.run_id == run_id,
                GreyboxGraphNode.status.in_(("running", "active"))))).all())

    for _ in range(200):                       # fetch_root is blocked on /slow
        if any(n.kind == "action" for n in await live_nodes()):
            break
        await asyncio.sleep(0.05)
    assert any(n.kind == "action" for n in await live_nodes())
    worker.cancel()                            # the worker "dies" without finalizing
    await asyncio.gather(worker, return_exceptions=True)
    async with session_maker() as s:
        await s.execute(update(GreyboxRun).where(GreyboxRun.id == run_id)
                        .values(lease_expires_at=datetime.now(timezone.utc)
                                - timedelta(seconds=1)))
        await s.commit()
    assert await reap_expired_leases(session_maker) == 1
    assert await live_nodes() == []
    async with session_maker() as s:
        nodes = (await s.scalars(select(GreyboxGraphNode).where(
            GreyboxGraphNode.run_id == run_id))).all()
        by_kind = {n.kind: n for n in nodes if n.kind == "objective"}
        assert by_kind["objective"].status == "done"
        assert all(n.status == "cancelled" for n in nodes if n.kind == "action")
        assert all(n.status == "cancelled" for n in nodes if n.kind == "work_order")
