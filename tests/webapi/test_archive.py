"""Archiving a repository soft-hides it (and everything under it) everywhere,
without deleting anything; unarchiving restores full visibility."""
from __future__ import annotations

from tests.webapi.conftest import _make_user, _token
from src.webapi.models import ROLE_USER


async def _repo(client, token, name="repo-a"):
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post("/repositories", headers=h,
                          json={"name": name, "source_type": "upload"})
    assert r.status_code == 201
    return r.json()


async def _other_user(client, session_maker, email="other@example.com"):
    await _make_user(session_maker, email, "otherpass123", ROLE_USER)
    return await _token(client, email, "otherpass123")


class TestArchive:
    async def test_archive_hides_and_unarchive_restores(self, client, user_token, admin_token):
        repo = await _repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        ha = {"Authorization": f"Bearer {admin_token}"}
        r = await client.patch(f"/repositories/{repo['id']}", headers=h,
                               json={"archived": True})
        assert r.status_code == 200
        assert r.json()["archived"] is True
        # hidden from the owner's and the admin's default lists
        assert repo["id"] not in {x["id"] for x in (await client.get("/repositories", headers=h)).json()}
        assert repo["id"] not in {x["id"] for x in (await client.get("/repositories", headers=ha)).json()}
        # direct access 404s (same no-existence-leak behaviour as private repos)
        assert (await client.get(f"/repositories/{repo['id']}", headers=ha)).status_code == 404
        # visible again with include_archived=true
        shown = (await client.get("/repositories?include_archived=true", headers=ha)).json()
        assert repo["id"] in {x["id"] for x in shown}
        assert all(x["archived"] is False or x["id"] == repo["id"] for x in shown)
        # unarchive restores everything
        r = await client.patch(f"/repositories/{repo['id']}", headers=h,
                               json={"archived": False})
        assert r.status_code == 200 and r.json()["archived"] is False
        assert repo["id"] in {x["id"] for x in (await client.get("/repositories", headers=ha)).json()}
        assert (await client.get(f"/repositories/{repo['id']}", headers=ha)).status_code == 200

    async def test_archived_repo_hides_jobs_and_blocks_runs(self, client, user_token):
        repo = await _repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        job = (await client.post("/jobs", headers=h, json={
            "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
        await client.patch(f"/repositories/{repo['id']}", headers=h, json={"archived": True})
        # job disappears from the list and cannot be run anymore
        assert job["id"] not in {j["id"] for j in (await client.get("/jobs", headers=h)).json()}
        assert (await client.get(f"/jobs/{job['id']}", headers=h)).status_code == 404
        assert (await client.post(f"/jobs/{job['id']}/run", headers=h)).status_code == 404
        # and comes back after unarchive
        await client.patch(f"/repositories/{repo['id']}", headers=h, json={"archived": False})
        assert job["id"] in {j["id"] for j in (await client.get("/jobs", headers=h)).json()}

    async def test_non_owner_cannot_archive(self, client, user_token, session_maker):
        other = await _other_user(client, session_maker)
        ho = {"Authorization": f"Bearer {other}"}
        # team-visible repo: other user may see it but not archive it (403)
        repo = await _repo(client, user_token, name="not-yours")
        r = await client.patch(f"/repositories/{repo['id']}", headers=ho,
                               json={"archived": True})
        assert r.status_code == 403
        fresh = await client.get(f"/repositories/{repo['id']}",
                                 headers={"Authorization": f"Bearer {user_token}"})
        assert fresh.json()["archived"] is False
        # private repo: invisible to the other user → no existence leak
        h = {"Authorization": f"Bearer {user_token}"}
        priv = (await client.post("/repositories", headers=h, json={
            "name": "hidden", "source_type": "upload", "is_private": True})).json()
        assert (await client.patch(f"/repositories/{priv['id']}", headers=ho,
                                   json={"archived": True})).status_code in (403, 404)

    async def test_admin_can_archive_anyones_repo(self, client, user_token, admin_token):
        repo = await _repo(client, user_token, name="theirs")
        ha = {"Authorization": f"Bearer {admin_token}"}
        r = await client.patch(f"/repositories/{repo['id']}", headers=ha,
                               json={"archived": True})
        assert r.status_code == 200 and r.json()["archived"] is True

    async def test_archive_blocked_while_run_in_progress(self, client, user_token, session_maker):
        import uuid as _uuid  # noqa: F401
        from src.webapi.models import Run, RUN_RUNNING
        repo = await _repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        job = (await client.post("/jobs", headers=h, json={
            "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
        async with session_maker() as s:
            s.add(Run(job_id=_uuid.UUID(job["id"]), session_id="s-guard",
                      data_dir="/tmp/guard", status=RUN_RUNNING))
            await s.commit()
        # archiving is refused while the run is in flight
        r = await client.patch(f"/repositories/{repo['id']}", headers=h,
                               json={"archived": True})
        assert r.status_code == 409
        assert "in progress" in r.json()["detail"]
        assert (await client.get(f"/repositories/{repo['id']}", headers=h)).json()["archived"] is False
        # unarchiving never needs this check
        assert (await client.patch(f"/repositories/{repo['id']}", headers=h,
                                   json={"archived": False})).status_code == 200
