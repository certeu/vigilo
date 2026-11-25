"""Run lifecycle hardening: worker --once (A), DB guard for one active run per
target (B), idempotency key bound to a target (C), conditional cancel and the
reaper's NULL-lease defence (D)."""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from src.greybox_web import service as gb_service
from src.greybox_web.models import (
    GB_ACTIVE,
    GB_CANCELLED,
    GB_CANCELLING,
    GB_PREPARING,
    GB_SUCCEEDED,
    GreyboxRun,
    GreyboxTarget,
)
from src.greybox_web.service import RunStartError, cancel_run, reap_expired_leases
from src.greybox_web.worker import claim_next_run, new_worker_id, run_once
from tests.greybox_web.conftest import (
    create_target,
    h,
    start_run,
    target_body,
    user_id,
)


async def _status(session_maker, run_id) -> str:
    async with session_maker() as s:
        return (await s.scalars(select(GreyboxRun.status).where(
            GreyboxRun.id == uuid.UUID(str(run_id))))).one()


# ------------------------------------------------------------------------- A


async def test_run_once_executes_claimed_run_to_completion(
        client, user_token, session_maker, live_target, target_server):
    r = await start_run(client, user_token, live_target["id"])
    assert r.status_code == 201, r.text
    run_id = r.json()["id"]
    got = await run_once(session_maker)            # no supervisor kwargs at all
    assert str(got) == run_id
    assert await _status(session_maker, run_id) == GB_SUCCEEDED
    assert target_server.counts                   # it really hit the synthetic app


async def test_run_once_empty_queue_returns_none(session_maker):
    assert await run_once(session_maker) is None


async def test_worker_cli_once_runs_the_claimed_run(
        client, user_token, session_maker, live_target, target_server,
        engine, monkeypatch, capsys):
    """``python -m src.greybox_web.worker --once`` used to raise TypeError
    (max_runs forwarded to RunSupervisor) after claiming, stranding the run."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from src.greybox_web import worker
    import src.webapi.db as webdb

    r = await start_run(client, user_token, live_target["id"])
    run_id = r.json()["id"]
    url = engine.url

    def _maker():
        eng = create_async_engine(url, connect_args={"timeout": 10})
        return async_sessionmaker(eng, expire_on_commit=False, class_=AsyncSession)

    monkeypatch.setattr(webdb, "_session_maker", _maker)
    await asyncio.to_thread(worker.main, ["--once"])
    assert f"finished run {run_id}" in capsys.readouterr().out
    assert await _status(session_maker, run_id) == GB_SUCCEEDED


# ------------------------------------------------------------------------- B


async def test_partial_unique_index_rejects_second_active_run(
        client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"])
    assert r.status_code == 201
    async with session_maker() as s:
        first = await s.get(GreyboxRun, uuid.UUID(r.json()["id"]))
        first_id = first.id
        cols = dict(target_id=first.target_id, owner_id=first.owner_id,
                    status="queued", base_url=first.base_url, scope=first.scope,
                    limits=first.limits, checks=first.checks,
                    initiated_by=first.initiated_by)
        s.add(GreyboxRun(id=uuid.uuid4(), **cols))
        with pytest.raises(IntegrityError):
            await s.flush()
        await s.rollback()
        # a terminal run does not count: finish the first, a new one is fine
        await s.execute(update(GreyboxRun).where(GreyboxRun.id == first_id)
                        .values(status=GB_SUCCEEDED))
        s.add(GreyboxRun(id=uuid.uuid4(), **cols))
        await s.flush()
        await s.rollback()


class _StaleActive:
    """Makes the select-then-insert pre-checks see no active run (the race
    window), then behaves normally for the post-conflict lookup."""

    def __init__(self) -> None:
        self.calls = 0

    def __iter__(self):
        self.calls += 1
        return iter(() if self.calls <= 2 else tuple(GB_ACTIVE))


async def test_integrity_error_maps_to_409_with_winner_run_id(
        client, user_token, session_maker, live_target, monkeypatch):
    r = await start_run(client, user_token, live_target["id"])
    winner = r.json()["id"]
    monkeypatch.setattr(gb_service, "GB_ACTIVE", _StaleActive())
    r2 = await start_run(client, user_token, live_target["id"])
    assert r2.status_code == 409, r2.text
    assert r2.json() == {"detail": "A run for this target is already active",
                         "run_id": winner}
    async with session_maker() as s:
        n = len((await s.scalars(select(GreyboxRun.id).where(
            GreyboxRun.target_id == uuid.UUID(live_target["id"])))).all())
    assert n == 1


async def test_concurrent_starts_yield_one_run(client, user_token, live_target):
    rs = await asyncio.gather(*[start_run(client, user_token, live_target["id"])
                                for _ in range(4)])
    codes = sorted(x.status_code for x in rs)
    assert codes == [201, 409, 409, 409]


# ------------------------------------------------------------------------- C


async def test_idempotency_key_of_another_target_is_409_not_that_run(
        client, user_token, live_target):
    key = f"key-{uuid.uuid4().hex[:12]}"
    other = await create_target(client, user_token, name="second-app")
    r1 = await start_run(client, user_token, live_target["id"], key=key)
    assert r1.status_code == 201
    r2 = await start_run(client, user_token, other["id"], key=key)
    assert r2.status_code == 409, r2.text
    assert "run_id" not in r2.json()
    assert r1.json()["id"] not in r2.text
    # same target + same key is still the idempotent 200
    r3 = await start_run(client, user_token, live_target["id"], key=key)
    assert r3.status_code == 200 and r3.json()["id"] == r1.json()["id"]


# ------------------------------------------------------------------------- D


async def test_cancel_does_not_resurrect_a_run_that_went_terminal(
        client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"])
    run_id = uuid.UUID(r.json()["id"])
    uid = await user_id(session_maker, "user@example.com")
    async with session_maker() as stale_session:
        stale = await stale_session.get(GreyboxRun, run_id)      # loaded as queued
        assert stale.status == "queued"
        # meanwhile: claimed, then finished (terminal, lease cleared)
        assert await claim_next_run(session_maker, new_worker_id()) == run_id
        async with session_maker() as s:
            await s.execute(update(GreyboxRun).where(GreyboxRun.id == run_id)
                            .values(status=GB_SUCCEEDED, lease_owner=None,
                                    lease_expires_at=None,
                                    finished_at=datetime.now(timezone.utc)))
            await s.commit()
        with pytest.raises(RunStartError) as ei:
            await cancel_run(stale_session, stale, user_id=uid, reason=None)
        assert ei.value.status_code == 409
        await stale_session.rollback()
    assert await _status(session_maker, run_id) == GB_SUCCEEDED


async def test_cancel_stale_preparing_run_that_finished_is_409(
        client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"])
    run_id = uuid.UUID(r.json()["id"])
    uid = await user_id(session_maker, "user@example.com")
    await claim_next_run(session_maker, new_worker_id())
    async with session_maker() as stale_session:
        stale = await stale_session.get(GreyboxRun, run_id)
        assert stale.status == GB_PREPARING
        async with session_maker() as s:
            await s.execute(update(GreyboxRun).where(GreyboxRun.id == run_id)
                            .values(status="failed", lease_owner=None,
                                    lease_expires_at=None))
            await s.commit()
        with pytest.raises(RunStartError) as ei:
            await cancel_run(stale_session, stale, user_id=uid, reason="x")
        assert ei.value.status_code == 409
        await stale_session.rollback()
    assert await _status(session_maker, run_id) == "failed"


async def test_cancel_claimed_run_sets_cancelling_and_keeps_lease(
        client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"])
    run_id = r.json()["id"]
    await claim_next_run(session_maker, new_worker_id())
    rc = await client.post(f"/greybox/runs/{run_id}/cancel", headers=h(user_token),
                           json={})
    assert rc.status_code == 202 and rc.json()["status"] == GB_CANCELLING
    async with session_maker() as s:
        run = await s.get(GreyboxRun, uuid.UUID(run_id))
        assert run.lease_expires_at is not None
        assert run.cancel_requested_at is not None


async def test_reaper_finishes_cancelling_run_with_null_lease(
        client, user_token, session_maker, live_target):
    r = await start_run(client, user_token, live_target["id"])
    run_id = uuid.UUID(r.json()["id"])
    async with session_maker() as s:        # the legacy stuck state
        await s.execute(update(GreyboxRun).where(GreyboxRun.id == run_id)
                        .values(status=GB_CANCELLING, lease_owner=None,
                                lease_expires_at=None,
                                cancel_requested_at=datetime.now(timezone.utc)))
        await s.commit()
    assert await reap_expired_leases(session_maker, "w") == 1
    assert await _status(session_maker, run_id) == GB_CANCELLED


def test_migration_0012_creates_and_drops_the_partial_index(tmp_path):
    import sqlalchemy as sa
    from alembic import command

    from scripts.run_migrations import build_config

    url = f"sqlite:///{tmp_path / 'm.db'}"
    cfg = build_config(url)
    command.upgrade(cfg, "head")
    name = "ux_greybox_runs_one_active_per_target"

    def idx():
        return {i["name"]: i for i in
                sa.inspect(sa.create_engine(url)).get_indexes("greybox_runs")}

    assert idx()[name]["unique"]
    command.downgrade(cfg, "0011_greybox_graph_fields")
    assert name not in idx()
    command.upgrade(cfg, "head")
    assert name in idx()


# Full end-to-end runs: excluded from CI (pytest -m 'not slow'), run locally.
pytestmark = pytest.mark.slow
