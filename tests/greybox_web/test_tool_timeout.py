"""A tool that never returns must not freeze the run.

Regression for a live run where one ``browser.visit`` wedged: discovery has a single
general slot, so every other discovery work order queued behind it, the agent's
plans (including its answer to an operator message) waited on that discovery, and
the run stayed "running" with no events while its heartbeat kept it alive.
"""
from __future__ import annotations

import asyncio
import dataclasses
import uuid
from datetime import timedelta

from sqlalchemy import delete, select

from src.greybox_web import supervisor, tools
from src.greybox_web.models import GreyboxEvent, GreyboxWorkOrder
from tests.greybox_web.conftest import run_worker_once, start_run

HUNG_TOOL = "discovery.robots"     # an early discovery work order in every web run


def test_tool_timeouts():
    assert supervisor.tool_timeout_s("discovery.crawl") == supervisor.TOOL_TIMEOUT_S
    assert supervisor.tool_timeout_s("browser.visit") == supervisor.BROWSER_TOOL_TIMEOUT_S
    assert supervisor.tool_timeout_s("discovery.crawl", {"tool_timeout_s": 30}) == 30
    # the run-level override never loosens the browser bound
    assert supervisor.tool_timeout_s("browser.act", {"tool_timeout_s": 9999}) == \
        supervisor.BROWSER_TOOL_TIMEOUT_S
    assert supervisor.tool_timeout_s("discovery.scripts") == \
        supervisor.SCRIPT_TOOL_TIMEOUT_S


def test_scheduler_isolates_browser_and_ages_pending_work():
    browser = next(slot for slot in supervisor.SLOTS if slot.name == "browser-1")
    local = next(slot for slot in supervisor.SLOTS if slot.name == "analysis-1")
    general = next(slot for slot in supervisor.SLOTS if slot.name == "discovery-1")
    interactive = next(slot for slot in supervisor.SLOTS if slot.name == "discovery-2")

    assert supervisor.slot_accepts(browser, "browser.visit", 40)
    assert not supervisor.slot_accepts(browser, "discovery.scripts", 40)
    assert supervisor.slot_accepts(local, "skill.read", 40)
    assert supervisor.slot_accepts(local, "netview.reexamine", 40)
    assert supervisor.slot_accepts(local, "tool.compose", 40)
    assert not supervisor.slot_accepts(local, "discovery.scripts", 40)
    assert supervisor.slot_accepts(general, "discovery.scripts", 40)
    assert not supervisor.slot_accepts(general, "browser.visit", 40)
    assert not supervisor.slot_accepts(general, "skill.read", 40)
    assert supervisor.slot_accepts(interactive, "discovery.crawl", 5)
    assert not supervisor.slot_accepts(interactive, "browser.visit", 5)
    assert not supervisor.slot_accepts(interactive, "discovery.routes", 5)


async def test_disjoint_scheduler_queries_select_each_lane_and_age_old_work(
        client, user_token, session_maker, live_target):
    response = await start_run(client, user_token, live_target["id"],
                               key=uuid.uuid4().hex)
    run_id = uuid.UUID(response.json()["id"])
    now = supervisor.utcnow()
    orders = [
        ("browser.visit", 5, now, "browser"),
        ("discovery.scripts", 5, now, "remote"),
        ("skill.read", 5, now, "fresh-local"),
        ("netview.reexamine", 90,
         now - timedelta(seconds=supervisor.PENDING_STARVATION_S + 1), "old-local"),
    ]
    async with session_maker() as session:
        await session.execute(delete(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == run_id))
        for seq, (tool, priority, created, key) in enumerate(orders, 1):
            session.add(GreyboxWorkOrder(
                run_id=run_id, dedup_key=key, kind="discovery", tool=tool,
                title=key, reason="test", params={}, priority=priority,
                created_seq=seq, created_at=created))
        await session.commit()

    worker = supervisor.RunSupervisor(session_maker, run_id, "test-worker")
    browser = next(slot for slot in supervisor.SLOTS if slot.name == "browser-1")
    local = next(slot for slot in supervisor.SLOTS if slot.name == "analysis-1")
    general = next(slot for slot in supervisor.SLOTS if slot.name == "discovery-1")
    assert (await worker._next_pending(browser))["tool"] == "browser.visit"
    assert (await worker._next_pending(local))["tool"] == "netview.reexamine"
    assert (await worker._next_pending(general))["tool"] == "discovery.scripts"


async def test_a_hung_tool_times_out_and_the_run_completes(
        client, user_token, session_maker, live_target, monkeypatch):
    real_get = tools.get
    entered = asyncio.Event()

    async def hang(ctx):
        entered.set()
        await asyncio.Event().wait()           # never returns, like the wedged page

    def get(tool_id):
        spec = real_get(tool_id)
        if spec is not None and tool_id == HUNG_TOOL:
            return dataclasses.replace(spec, run=hang)
        return spec

    monkeypatch.setattr(tools, "get", get)
    monkeypatch.setattr(supervisor, "TOOL_TIMEOUT_S", 1.0)

    r = await start_run(client, user_token, live_target["id"], key=uuid.uuid4().hex)
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    # bounded: before the fix this never returned
    assert str(await asyncio.wait_for(run_worker_once(session_maker), 240)) == run_id
    assert entered.is_set()

    async with session_maker() as s:
        wo = (await s.scalars(select(GreyboxWorkOrder).where(
            GreyboxWorkOrder.run_id == uuid.UUID(run_id),
            GreyboxWorkOrder.tool == HUNG_TOOL))).first()
        kinds = [e.kind for e in (await s.scalars(
            select(GreyboxEvent).where(GreyboxEvent.run_id == uuid.UUID(run_id))
            .order_by(GreyboxEvent.seq))).all()]
    assert wo is not None and wo.status == "failed"
    assert "timeout" in (wo.error or "") and HUNG_TOOL in wo.error
    # the run carried on: other work completed and the run finished normally
    assert "work_order.completed" in kinds
    assert kinds[-1] == "run.completed"


async def test_a_page_that_will_not_close_cannot_hold_its_caller(monkeypatch):
    """The browser tools close their page in ``finally``, which also runs when the
    supervisor's timeout cancels them: that close must be bounded, and a page that
    will not close takes its identity's context with it."""
    from types import SimpleNamespace

    from src.greybox_web.tools import browser

    monkeypatch.setattr(browser, "PAGE_CLOSE_TIMEOUT_S", 0.2)

    class Wedged:
        closed = False

        async def close(self):
            await asyncio.Event().wait()

    class Ctx(Wedged):
        pass

    sess = browser.BrowserSession()
    sess._contexts["provided-cookie"] = Ctx()
    ctx = SimpleNamespace(run_id=uuid.uuid4(), scope=None)
    monkeypatch.setitem(browser._SESSIONS, ctx.run_id, sess)

    await asyncio.wait_for(browser._close_page(Wedged(), ctx, "provided-cookie"), 3)
    assert "provided-cookie" not in sess._contexts     # recreated on next use
