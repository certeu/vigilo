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
        # sqlite :memory: est par-connexion: patcher _launch AVANT les POST pour que le
        # background task démarre via le fake_engine sur la même factory de session
        # le lancement part en tâche de fond (_launch_bg, session dédiée). En test sqlite
        # :memory:, on la remplace par un lancement direct via le fake_engine.
        from src.webapi import runsvc
        async def _launch_inline(run_id, engine, job_id, repo_id):
            async with session_maker() as s:
                from src.webapi.models import Run, Job, Repository
                run = await s.get(Run, run_id); job = await s.get(Job, job_id)
                repo = await s.get(Repository, repo_id) if repo_id else None
                await fake_engine.start(run, job, repo)
                await s.commit()
        monkeypatch.setattr(runsvc, "_launch_bg", _launch_inline)
        for _ in range(3):
            await client.post(f"/jobs/{job['id']}/run", headers=h)
        if runsvc._BACKGROUND_TASKS:
            await asyncio.gather(*list(runsvc._BACKGROUND_TASKS), return_exceptions=True)

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


    async def test_run_endpoint_answers_before_engine_start(
        self, client, user_token, session_maker, monkeypatch
    ):
        """POST /jobs/{id}/run must return as soon as the run row is committed,
        NOT after engine.start (the clone can take seconds). The launch continues
        in a background task."""
        import time
        from src.webapi import runsvc, settings as settings_mod
        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "3")
        settings_mod.get_settings.cache_clear()
        job = await _repo_job(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}

        started = asyncio.Event()
        release = asyncio.Event()
        class SlowEngine:
            async def start(self, run, job, repo):
                started.set()
                await release.wait()  # simule un clone long
                run.status = RUN_RUNNING
        monkeypatch.setattr("src.webapi.runsvc._launch_bg", self._wrap_slow(SlowEngine(), started, release, session_maker))
        t0 = time.monotonic()
        r = await client.post(f"/jobs/{job['id']}/run", headers=h)
        elapsed = time.monotonic() - t0
        assert r.status_code == 201 and r.json()["status"] in ("queued", "preparing")
        assert elapsed < 1.0, f"endpoint blocked {elapsed:.2f}s on engine.start"
        # laisser la tâche de fond se terminer proprement
        release.set()
        if runsvc._BACKGROUND_TASKS:
            await asyncio.gather(*list(runsvc._BACKGROUND_TASKS), return_exceptions=True)

    def _wrap_slow(self, engine, started, release, session_maker):
        from src.webapi.models import Run, Job, Repository
        async def _launch_bg(run_id, _engine, job_id, repo_id):
            async with session_maker() as s:
                run = await s.get(Run, run_id); job = await s.get(Job, job_id)
                repo = await s.get(Repository, repo_id) if repo_id else None
                await engine.start(run, job, repo)
                await s.commit()
        return _launch_bg


class TestAdmissionWithBackgroundLaunch:
    async def test_cap_holds_while_launches_are_still_running(
        self, client, user_token, monkeypatch, settle
    ):
        """engine.start runs in the background and can take minutes (clone). Runs being
        launched must already count against the cap, otherwise N simultaneous requests
        all pass the admission check and the global cap is exceeded."""
        from sqlalchemy import select
        from src.webapi import settings as settings_mod
        from src.webapi.engine.provider import get_engine
        from src.webapi.models import Run

        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "2")
        settings_mod.get_settings.cache_clear()
        release = asyncio.Event()
        started: list[str] = []

        class SlowEngine:
            async def start(self, run, job, repo):
                started.append(str(run.id))
                await release.wait()  # simulates a long clone
                run.status = RUN_RUNNING

            async def cancel(self, run):
                return None

            async def refresh(self, run):
                return None

        client._app.dependency_overrides[get_engine] = lambda: SlowEngine()
        job = await _repo_job(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        results = await asyncio.gather(
            *[client.post(f"/jobs/{job['id']}/run", headers=h) for _ in range(8)]
        )
        assert all(r.status_code == 201 for r in results)
        # Let the background launches reach engine.start (poll: runner speed varies).
        for _ in range(100):
            if len(started) >= 2:
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(0.2)  # grace period: a 3rd launch would show up here

        statuses = [r["status"] for r in (await client.get("/runs", headers=h)).json()]
        active = sum(1 for s in statuses if s in ("preparing", "running"))
        assert active <= 2, f"cap exceeded while launches were in flight: {statuses}"
        assert statuses.count("queued") == 6
        assert len(started) == 2

        release.set()
        await settle()
        settings_mod.get_settings.cache_clear()
