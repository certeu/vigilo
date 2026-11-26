"""T9: cancelling a run stuck on /slow reaches
`cancelled` within 5 s, the in-flight request is aborted, and no exchange is
recorded after the terminal acknowledgement event."""
from __future__ import annotations

import asyncio
import time
import uuid

from sqlalchemy import func, select

from src.greybox_web.models import GreyboxEvent, GreyboxHttpExchange
from tests.greybox_web.conftest import FAST_LIMITS, create_target, h, start_run


async def _wait_status(client, token, run_id, statuses, timeout=15.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = await client.get(f"/greybox/runs/{run_id}", headers=h(token))
        body = r.json()
        if body["status"] in statuses:
            return body
        await asyncio.sleep(0.1)
    raise AssertionError(f"run never reached {statuses}: {body['status']}")


async def test_cancel_during_slow_endpoint(client, user_token, session_maker,
                                           target_server):
    # The run's base URL is the /slow endpoint: fetch_root blocks on it for 30 s.
    t = await create_target(client, user_token,
                            base_url=target_server.url + "slow",
                            limits={**FAST_LIMITS, "request_timeout_s": 30})
    r = await start_run(client, user_token, t["id"])
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]

    from src.greybox_web.worker import run_once
    worker = asyncio.create_task(run_once(session_maker))
    try:
        await _wait_status(client, user_token, run_id, {"running", "cancelling"})
        await asyncio.sleep(0.2)                 # let the request reach /slow
        target_server.reset()                    # count only from here on
        t0 = time.monotonic()
        r = await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token),
                              json={"reason": "too slow"})
        assert r.status_code == 202
        assert r.json()["status"] == "cancelling"
        body = await _wait_status(client, user_token, run_id, {"cancelled"},
                                  timeout=5.0)
        elapsed = time.monotonic() - t0
        assert elapsed < 5.0, f"cancellation took {elapsed:.1f}s"
        assert body["status"] == "cancelled"
        assert body["end_reason"] == "cancelled"
        assert body["cancel_requested"] is True
    finally:
        await asyncio.wait_for(worker, timeout=20)

    run = uuid.UUID(run_id)
    async with session_maker() as s:
        # The terminal acknowledgement is the last event of the run.
        ack = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run, GreyboxEvent.kind == "run.cancelled")
        )).one()
        last = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run)
            .order_by(GreyboxEvent.seq.desc()))).first()
        assert last.seq == ack.seq
        # No exchange recorded after the acknowledgement timestamp.
        late = (await s.scalars(select(GreyboxHttpExchange).where(
            GreyboxHttpExchange.run_id == run,
            GreyboxHttpExchange.ts > ack.ts).limit(1))).first()
        assert late is None
        # The work order never completed: it is cancelled.
        from src.greybox_web.models import GreyboxWorkOrder
        wos = (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run))).all()
        assert all(w.status == "cancelled" for w in wos), \
            [w.status for w in wos]
    # /slow was requested once before the reset (the aborted attempt) and
    # NOTHING after it: no second attempt, no retries.
    counts = target_server.counts()
    assert counts.get("/slow", 0) == 0


async def test_cancel_before_worker_claims(client, user_token, target_server,
                                           session_maker):
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits=FAST_LIMITS)
    r = await start_run(client, user_token, t["id"])
    run_id = r.json()["id"]
    r = await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token))
    assert r.status_code == 202
    assert r.json()["status"] == "cancelled"
    # a later worker claim finds nothing to do
    from src.greybox_web.worker import claim_next_run
    assert await claim_next_run(session_maker, "w-late") is None
