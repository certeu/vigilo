from __future__ import annotations

import asyncio

from src.webapi.models import RUN_PREPARING, RUN_RUNNING, ROLE_USER
from tests.webapi.conftest import _make_user, _token


async def _user_with_private_repo_job(client, session_maker, email):
    await _make_user(session_maker, email, "passpass123", ROLE_USER)
    tok = await _token(client, email, "passpass123")
    h = {"Authorization": f"Bearer {tok}"}
    repo = (await client.post("/repositories", headers=h, json={
        "name": f"{email}-repo", "source_type": "upload", "is_private": True})).json()
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
    return tok, repo["id"], job["id"]


class TestMultiUserConcurrency:
    async def test_three_users_concurrent_runs_cap_and_isolation(
        self, client, user_token, monkeypatch, session_maker
    ):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "2")
        settings_mod.get_settings.cache_clear()

        # three distinct users, each with their own PRIVATE repo + job
        u = {}
        for email in ("alice@example.com", "bob@example.com", "carol@example.com"):
            u[email] = await _user_with_private_repo_job(client, session_maker, email)

        # all three fire a run at the same time
        async def fire(email):
            tok, _repo, job = u[email]
            return await client.post(f"/jobs/{job}/run",
                                     headers={"Authorization": f"Bearer {tok}"})

        results = await asyncio.gather(*[fire(e) for e in u])
        assert all(r.status_code == 201 for r in results)
        statuses = [r.json()["status"] for r in results]
        running = sum(1 for s in statuses if s in (RUN_RUNNING, RUN_PREPARING))
        # global cap holds across DIFFERENT users, not just one user
        assert running <= 2, f"cap exceeded across users: {statuses}"
        assert statuses.count("queued") >= 1

        # ACL under load: alice cannot see bob's or carol's private runs
        atok = u["alice@example.com"][0]
        alice_runs = (await client.get("/runs",
                      headers={"Authorization": f"Bearer {atok}"})).json()
        alice_repo = u["alice@example.com"][1]
        # every run alice sees must belong to alice's repo (via her job)
        alice_jobs = {j["id"] for j in (await client.get("/jobs",
                      headers={"Authorization": f"Bearer {atok}"})).json()}
        assert all(r["job_id"] in alice_jobs for r in alice_runs)
        # and she sees only her own repo
        alice_repos = (await client.get("/repositories",
                       headers={"Authorization": f"Bearer {atok}"})).json()
        assert {r["id"] for r in alice_repos} == {alice_repo}

        # admin sees everyone's runs (oversight)
        admin_runs = (await client.get("/runs",
                      headers={"Authorization": f"Bearer {user_token}"})).json()
        # user_token is a 'user', not admin; use the admin fixture instead
        settings_mod.get_settings.cache_clear()

    async def test_admin_sees_all_users_runs(self, client, admin_token, session_maker):
        u = await _user_with_private_repo_job(client, session_maker, "dave@example.com")
        tok, _repo, job = u
        await client.post(f"/jobs/{job}/run", headers={"Authorization": f"Bearer {tok}"})
        # admin sees the private run despite not owning it
        admin_runs = (await client.get("/runs",
                      headers={"Authorization": f"Bearer {admin_token}"})).json()
        assert any(r["job_id"] == job for r in admin_runs)
