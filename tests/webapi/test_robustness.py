from __future__ import annotations

import uuid

from src.webapi.engine.base import new_run_identity
from src.webapi.engine.provider import get_engine
from src.webapi.models import RUN_RUNNING, Job, Repository, Run, User
from src.webapi.reconcile import reconcile_runs


class _FailingEngine:
    """Engine whose start() always fails (simulates bad clone URL / docker error)."""
    durable = False

    async def start(self, run, job, repo):
        raise RuntimeError("git clone failed: could not read from remote")

    async def cancel(self, run):
        return None

    async def refresh(self, run):
        return None


class TestStartFailure:
    async def test_failed_start_marks_run_failed_not_500(self, client, user_token):
        # Swap in an engine that fails to launch.
        client._app.dependency_overrides[get_engine] = lambda: _FailingEngine()
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h,
                json={"name": "r", "source_type": "upload"})).json()
        job = (await client.post("/jobs", headers=h, json={
            "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
        resp = await client.post(f"/jobs/{job['id']}/run", headers=h)
        # graceful: 201 with a failed run + user-facing error, NOT a 500 or stuck queued
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["status"] == "failed"
        assert "Failed to start scan" in (body["error_summary"] or "")
        # report endpoint reports no report (not a broken/partial one)
        rep = await client.get(f"/runs/{body['id']}/report", headers=h)
        assert rep.json()["exists"] is False


class TestReconciliation:
    async def test_nondurable_stuck_runs_failed_on_startup(self, session_maker):
        from src.webapi.engine.fake import FakeEngine
        # Seed a run stuck in 'running' (as if the API crashed mid-run).
        async with session_maker() as s:
            u = User(id=uuid.uuid4(), email="r@x.eu", hashed_password="h",
                     role="user", is_active=True, is_superuser=False, is_verified=True)
            repo = Repository(id=uuid.uuid4(), created_by=u.id, name="r", source_type="upload")
            job = Job(id=uuid.uuid4(), created_by=u.id, repository_id=repo.id, name="j",
                      stage_preset="vuln", engine="whitebox", pipeline_overrides={})
            rid, sid, tq = new_run_identity()
            run = Run(id=rid, job_id=job.id, trigger_type="manual", status=RUN_RUNNING,
                      session_id=sid, task_queue=tq, data_dir="/x")
            s.add_all([u, repo, job, run])
            await s.commit()
            run_id = run.id
        # Reconcile with a non-durable engine → stuck run becomes failed.
        async with session_maker() as s:
            summary = await reconcile_runs(s, FakeEngine())
            assert summary["failed"] == 1
            got = await s.get(Run, run_id)
            assert got.status == "failed"
            assert "Interrupted by a service restart" in got.error_summary

    async def test_durable_engine_reattaches_not_fails(self, session_maker):
        # A durable engine leaves still-running runs running (Temporal resume).
        class _Durable:
            durable = True
            async def refresh(self, run):
                return None  # still running
            async def start(self, run, job, repo):
                return None
            async def cancel(self, run):
                return None
        async with session_maker() as s:
            u = User(id=uuid.uuid4(), email="d@x.eu", hashed_password="h",
                     role="user", is_active=True, is_superuser=False, is_verified=True)
            repo = Repository(id=uuid.uuid4(), created_by=u.id, name="r", source_type="upload")
            job = Job(id=uuid.uuid4(), created_by=u.id, repository_id=repo.id, name="j",
                      stage_preset="vuln", engine="whitebox", pipeline_overrides={})
            rid, sid, tq = new_run_identity()
            run = Run(id=rid, job_id=job.id, trigger_type="manual", status=RUN_RUNNING,
                      session_id=sid, task_queue=tq, data_dir="/x")
            s.add_all([u, repo, job, run])
            await s.commit()
            run_id = run.id
        async with session_maker() as s:
            summary = await reconcile_runs(s, _Durable())
            assert summary["failed"] == 0
            assert summary["reattached"] == 1
            assert (await s.get(Run, run_id)).status == "running"
