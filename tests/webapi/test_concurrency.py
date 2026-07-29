from __future__ import annotations

import asyncio

from src.webapi.models import RUN_PREPARING, RUN_RUNNING


async def _repo_job(client, token, preset="vuln"):
    h = {"Authorization": f"Bearer {token}"}
    repo = (await client.post("/repositories", headers=h,
            json={"name": "conc", "source_type": "upload"})).json()
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": preset})).json()
    return job


class TestConcurrencyCap:
    async def test_parallel_runs_respect_global_cap(self, client, user_token, monkeypatch):
        # Cap at 2; fire 10 runs concurrently → at most 2 running, rest queued.
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "2")
        settings_mod.get_settings.cache_clear()

        job = await _repo_job(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}

        async def fire():
            return await client.post(f"/jobs/{job['id']}/run", headers=h)

        results = await asyncio.gather(*[fire() for _ in range(10)])
        assert all(r.status_code == 201 for r in results)
        statuses = [r.json()["status"] for r in results]
        running = sum(1 for s in statuses if s in (RUN_RUNNING, RUN_PREPARING))
        queued = sum(1 for s in statuses if s == "queued")
        assert running <= 2, f"cap exceeded: {statuses}"
        assert running + queued == 10
        assert queued >= 8
        settings_mod.get_settings.cache_clear()

    async def test_runs_all_created_and_listable(self, client, user_token, monkeypatch):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "3")
        settings_mod.get_settings.cache_clear()
        job = await _repo_job(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        await asyncio.gather(*[client.post(f"/jobs/{job['id']}/run", headers=h) for _ in range(6)])
        listed = (await client.get("/runs", headers=h)).json()
        assert len(listed) == 6
        settings_mod.get_settings.cache_clear()

    async def test_queue_drains_when_slot_frees(self, client, user_token, session_maker,
                                                fake_engine, monkeypatch):
        # Regression: over-cap runs must not stay queued forever. Freeing a slot
        # (a run finishing) + the drainer must promote the oldest queued run.
        from sqlalchemy import select
        from src.webapi import settings as settings_mod
        from src.webapi.models import Run, RUN_RUNNING, RUN_QUEUED, RUN_SUCCEEDED
        from src.webapi.runsvc import drain_queue
        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "1")
        settings_mod.get_settings.cache_clear()

        job = await _repo_job(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        for _ in range(3):
            await client.post(f"/jobs/{job['id']}/run", headers=h)

        async with session_maker() as s:
            runs = (await s.scalars(select(Run).order_by(Run.created_at))).all()
            statuses = [r.status for r in runs]
            assert statuses.count(RUN_RUNNING) == 1 and statuses.count(RUN_QUEUED) == 2, statuses

            # finish the running one, then drain → exactly one queued promoted
            running = next(r for r in runs if r.status == RUN_RUNNING)
            running.status = RUN_SUCCEEDED
            await s.commit()
            promoted = await drain_queue(s, fake_engine)
            assert promoted == 1, promoted

            after = [r.status for r in (await s.scalars(select(Run))).all()]
            assert after.count(RUN_RUNNING) == 1 and after.count(RUN_QUEUED) == 1, after
        settings_mod.get_settings.cache_clear()
