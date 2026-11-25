"""The in-process executor (``VIGILO_GREYBOX_EXECUTOR=inprocess`` starts
``worker_loop`` in the API process) runs the AI exploration agent on the fake backend
exactly like the standalone worker, and still respects an injected planner_factory."""
from __future__ import annotations

import asyncio
import uuid

import pytest
from sqlalchemy import select

from src.greybox_web.models import GB_TERMINAL, GreyboxEvent, GreyboxRun
from tests.greybox_web.conftest import create_target, h
from tests.greybox_web.test_exploration_acceptance import (
    LIMITS,
    build_ticketing_api,
    serve,
)


async def _queue_run(client, token, **target_over) -> tuple[dict, uuid.UUID]:
    target_over.setdefault("model_backend", "fake")
    target = await create_target(client, token, **target_over)
    r = await client.post(f"/greybox/targets/{target['id']}/runs", headers=h(token),
                          json={"authorization_confirmed": True,
                                "idempotency_key": uuid.uuid4().hex})
    assert r.status_code == 201, r.text
    return target, uuid.UUID(r.json()["id"])


async def test_inprocess_worker_loop_runs_the_agent(
        client, user_token, session_maker):
    from src.greybox_web.worker import worker_loop
    server, url = serve(build_ticketing_api())
    try:
        _, run_id = await _queue_run(client, user_token, base_url=url,
                                     limits=dict(LIMITS))
        loop = asyncio.create_task(worker_loop(session_maker, poll_s=0.05))
        try:
            for _ in range(600):
                async with session_maker() as s:
                    run = await s.get(GreyboxRun, run_id)
                    if run.status in GB_TERMINAL:
                        break
                await asyncio.sleep(0.1)
        finally:
            loop.cancel()
            await asyncio.gather(loop, return_exceptions=True)
        async with session_maker() as s:
            run = await s.get(GreyboxRun, run_id)
            assert run.status == "succeeded", run.end_reason
            kinds = set((await s.scalars(select(GreyboxEvent.kind).where(
                GreyboxEvent.run_id == run_id))).all())
        assert "llm.request" in kinds and "llm.response" in kinds
    finally:
        server.should_exit = True


async def test_injected_planner_factory_wins(
        client, user_token, session_maker):
    from src.greybox_web import worker as w
    _, run_id = await _queue_run(client, user_token,
                                 name="explorer-app")
    seen = {}

    class FakeSupervisor:
        def __init__(self, factory, rid, wid, **kw):
            seen.update(kw)

        async def run_to_completion(self):
            return None

    sentinel = lambda state: None  # noqa: E731
    orig = w.RunSupervisor
    w.RunSupervisor = FakeSupervisor
    try:
        await w.run_once(session_maker, planner_factory=sentinel)
    finally:
        w.RunSupervisor = orig
    assert seen["planner_factory"] is sentinel


async def test_run_snapshots_the_model_choice(client, user_token):
    _, run_id = await _queue_run(client, user_token)
    r = await client.get(f"/greybox/runs/{run_id}", headers=h(user_token))
    assert r.status_code == 200, r.text
    assert (r.json()["model_backend"], r.json()["model"]) == ("fake", "fake-explorer")
