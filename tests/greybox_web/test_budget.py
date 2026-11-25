"""Request-budget exhaustion ends the run as ``succeeded`` with
``end_reason=budget_requests`` — open work orders are skipped with reason
``budget``, a ``run.budget_exhausted`` event is emitted, exactly ``max_requests``
exchanges are recorded, and the report is still generated (the budget path
reports). Plus unit coverage of the ``Budget`` guard: wall-clock deadline,
cancellation priority and request counting.
"""
from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import func, select

from src.greybox_web.models import GreyboxEvent, GreyboxHttpExchange, GreyboxRun
from tests.greybox_web.conftest import (
    FAST_LIMITS,
    create_target,
    h,
    run_worker_once,
    start_run,
)


async def test_budget_requests_e2e(client, user_token, target_server, session_maker):
    # A full crawl of the synthetic app needs >= 20 requests, so a 6-request
    # budget is guaranteed to stop the run mid-flight, never to complete it.
    t = await create_target(client, user_token, base_url=target_server.url,
                            limits={**FAST_LIMITS, "max_requests": 6})
    r = await start_run(client, user_token, t["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = uuid.UUID(r.json()["id"])
    assert await run_worker_once(session_maker) == run_id

    async with session_maker() as s:
        run = await s.get(GreyboxRun, run_id)
        assert run.status == "succeeded"
        assert run.end_reason == "budget_requests"
        assert run.requests_made == 6
        # Every consumed attempt is recorded and nothing beyond the budget:
        # the 7th consume() raises before an exchange row can be created.
        n = await s.scalar(select(func.count()).select_from(GreyboxHttpExchange)
                           .where(GreyboxHttpExchange.run_id == run_id))
        assert n == 6

        budget_ev = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id,
            GreyboxEvent.kind == "run.budget_exhausted"))).one()
        assert budget_ev.data["budget"] == "requests"

        skipped = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id,
            GreyboxEvent.kind == "work_order.skipped"))).all()
        assert any(ev.data.get("reason") == "budget" for ev in skipped), \
            [ev.data.get("reason") for ev in skipped]

        completed = (await s.scalars(select(GreyboxEvent).where(
            GreyboxEvent.run_id == run_id,
            GreyboxEvent.kind == "run.completed"))).one()
        assert completed.data["end_reason"] == "budget_requests"

    # The budget path still reports, and the API counters agree with the DB.
    r = await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "succeeded"
    assert body["end_reason"] == "budget_requests"
    assert body["report_status"] == "ready"
    assert body["counters"]["requests"] == 6


async def test_budget_unit():
    from src.greybox_web.netguard import Budget, BudgetExhausted, RunCancelled

    # Wall-clock budget: the deadline elapses while the caller sleeps.
    b = Budget(max_requests=100, max_duration_s=0.01)
    await asyncio.sleep(0.05)                 # far past the 0.01 s deadline
    with pytest.raises(BudgetExhausted) as ei:
        b.check()
    assert ei.value.budget == "time"
    assert b.exhausted == "time"

    # Cancellation wins over every other stop reason, even an elapsed deadline.
    c = Budget(max_requests=100, max_duration_s=0.01)
    await asyncio.sleep(0.05)
    c.cancelled = True
    with pytest.raises(RunCancelled):
        c.check()

    # consume() counts requests: three fit, the fourth is refused and, having
    # been refused by check(), is not counted.
    r = Budget(max_requests=3, max_duration_s=60)
    r.consume()
    r.consume()
    r.consume()
    assert r.used == 3
    with pytest.raises(BudgetExhausted) as ei:
        r.consume()
    assert ei.value.budget == "requests"
    assert r.used == 3
