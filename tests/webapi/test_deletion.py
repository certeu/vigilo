"""Deleting runs and repositories: cascade, disk cleanup, and access control."""
from __future__ import annotations

import os
import uuid

from sqlalchemy import select

from src.webapi.models import Job, Repository, Run, RunMetrics, Schedule
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


async def _user(client, session_maker, email, role="user"):
    await _make_user(session_maker, email, PW, role)
    return await _token(client, email, PW)


def _h(t):
    return {"Authorization": f"Bearer {t}"}


async def _repo(client, tok, name="r", private=True):
    return (await client.post("/repositories", headers=_h(tok),
            json={"name": name, "source_type": "upload", "is_private": private})).json()["id"]


async def _run(client, tok, repo_id):
    jid = (await client.post("/jobs", headers=_h(tok),
           json={"repository_id": repo_id, "name": "j", "stage_preset": "vuln"})).json()["id"]
    return jid, (await client.post(f"/jobs/{jid}/run", headers=_h(tok))).json()["id"]


class TestDeleteRun:
    async def test_delete_run_cascades_and_cleans_disk(self, client, session_maker):
        tok = await _user(client, session_maker, "a@example.com")
        rid = await _repo(client, tok)
        jid, run_id = await _run(client, tok, rid)
        # give the run an on-disk workspace + a metrics row + a schedule back-ref
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id))
            os.makedirs(run.data_dir, exist_ok=True)
            marker = os.path.join(run.data_dir, "marker.txt")
            open(marker, "w").write("x")
            s.add(RunMetrics(run_id=run.id, repository_id=uuid.UUID(rid), total_findings=0,
                             critical=0, high=0, medium=0, low=0, informational=0,
                             exploited=0, supply_chain=0, data={}))
            sched = Schedule(id=uuid.uuid4(), job_id=uuid.UUID(jid), kind="once",
                             enabled=False, created_by=run.triggered_by, last_run_id=run.id)
            s.add(sched)
            await s.commit()
            data_dir, sched_id = run.data_dir, sched.id

        r = await client.delete(f"/runs/{run_id}", headers=_h(tok))
        assert r.status_code == 204, r.text
        async with session_maker() as s:
            assert await s.get(Run, uuid.UUID(run_id)) is None
            assert (await s.scalar(select(RunMetrics).where(RunMetrics.run_id == uuid.UUID(run_id)))) is None
            sched = await s.get(Schedule, sched_id)
            assert sched is not None and sched.last_run_id is None  # back-ref nulled, not orphaned
        assert not os.path.exists(data_dir)  # workspace reclaimed

    async def test_delete_run_requires_permission(self, client, session_maker):
        owner = await _user(client, session_maker, "owner@example.com")
        intruder = await _user(client, session_maker, "intruder@example.com")
        rid = await _repo(client, owner, private=True)
        _, run_id = await _run(client, owner, rid)
        r = await client.delete(f"/runs/{run_id}", headers=_h(intruder))
        assert r.status_code == 404  # private repo -> not even existence leaks
        async with session_maker() as s:
            assert await s.get(Run, uuid.UUID(run_id)) is not None  # still there


class TestDeleteRepository:
    async def test_delete_repo_cascades_everything(self, client, session_maker, monkeypatch):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(__import__("pathlib").Path(os.environ.get("VIGILO_JOBS_DATA_DIR", "/tmp")) / "up"))
        settings_mod.get_settings.cache_clear()
        tok = await _user(client, session_maker, "a@example.com")
        rid = await _repo(client, tok)
        jid, run_id = await _run(client, tok, rid)
        # seed uploaded source + tree cache + run workspace
        uploads = settings_mod.get_settings().uploads_dir
        os.makedirs(uploads, exist_ok=True)
        open(os.path.join(uploads, f"{rid}.zip"), "w").write("z")
        open(os.path.join(uploads, f"{rid}.tree.json"), "w").write("{}")
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id))
            os.makedirs(run.data_dir, exist_ok=True)
            data_dir = run.data_dir

        r = await client.delete(f"/repositories/{rid}", headers=_h(tok))
        assert r.status_code == 204, r.text
        async with session_maker() as s:
            assert await s.get(Repository, uuid.UUID(rid)) is None
            assert await s.get(Job, uuid.UUID(jid)) is None
            assert await s.get(Run, uuid.UUID(run_id)) is None
        assert not os.path.exists(os.path.join(uploads, f"{rid}.zip"))
        assert not os.path.exists(os.path.join(uploads, f"{rid}.tree.json"))
        assert not os.path.exists(data_dir)
        settings_mod.get_settings.cache_clear()

    async def test_delete_repo_requires_owner(self, client, session_maker):
        owner = await _user(client, session_maker, "owner@example.com")
        intruder = await _user(client, session_maker, "intruder@example.com")
        rid = await _repo(client, owner, private=True)
        r = await client.delete(f"/repositories/{rid}", headers=_h(intruder))
        assert r.status_code == 404  # private -> no existence leak
        async with session_maker() as s:
            assert await s.get(Repository, uuid.UUID(rid)) is not None

    async def test_admin_can_delete_any_repo(self, client, session_maker):
        admin = await _user(client, session_maker, "admin@example.com", role="admin")
        owner = await _user(client, session_maker, "owner@example.com")
        rid = await _repo(client, owner, private=True)
        r = await client.delete(f"/repositories/{rid}", headers=_h(admin))
        assert r.status_code == 204


class TestDeleteJob:
    async def test_delete_job_cascades_runs(self, client, session_maker):
        tok = await _user(client, session_maker, "a@example.com")
        rid = await _repo(client, tok)
        jid, run_id = await _run(client, tok, rid)
        r = await client.delete(f"/jobs/{jid}", headers=_h(tok))
        assert r.status_code == 204, r.text
        async with session_maker() as s:
            assert await s.get(Job, uuid.UUID(jid)) is None
            assert await s.get(Run, uuid.UUID(run_id)) is None  # cascaded
        # repo itself remains
        assert (await client.get(f"/repositories/{rid}", headers=_h(tok))).status_code == 200

    async def test_delete_job_requires_owner(self, client, session_maker):
        owner = await _user(client, session_maker, "owner@example.com")
        intruder = await _user(client, session_maker, "intruder@example.com")
        rid = await _repo(client, owner, private=True)
        jid, _ = await _run(client, owner, rid)
        assert (await client.delete(f"/jobs/{jid}", headers=_h(intruder))).status_code == 404


class TestBulkDeleteRepos:
    async def test_bulk_delete_owned_and_denies_others(self, client, session_maker):
        alice = await _user(client, session_maker, "alice@example.com")
        bob = await _user(client, session_maker, "bob@example.com")
        a1 = await _repo(client, alice, "a1")
        a2 = await _repo(client, alice, "a2")
        b1 = await _repo(client, bob, "b1", private=True)  # alice must NOT delete this
        r = await client.post("/repositories/bulk-delete", headers=_h(alice),
                              json={"ids": [a1, a2, b1]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body["deleted"]) == {a1, a2}
        assert body["denied"] == [b1]
        async with session_maker() as s:
            assert await s.get(Repository, uuid.UUID(a1)) is None
            assert await s.get(Repository, uuid.UUID(a2)) is None
            assert await s.get(Repository, uuid.UUID(b1)) is not None  # untouched
