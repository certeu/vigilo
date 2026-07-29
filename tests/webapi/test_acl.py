from __future__ import annotations

from src.webapi.models import ROLE_USER
from tests.webapi.conftest import _make_user, _token


async def _other_user(client, session_maker, email="other@example.com"):
    await _make_user(session_maker, email, "otherpass123", ROLE_USER)
    return await _token(client, email, "otherpass123")


async def _private_repo(client, owner_token):
    h = {"Authorization": f"Bearer {owner_token}"}
    return (await client.post("/repositories", headers=h, json={
        "name": "secret", "source_type": "upload", "is_private": True})).json()


class TestPrivateRepoVisibility:
    async def test_owner_sees_admin_sees_others_dont(self, client, user_token, admin_token, session_maker):
        repo = await _private_repo(client, user_token)
        other = await _other_user(client, session_maker)
        # owner sees it
        owner_list = await client.get("/repositories", headers={"Authorization": f"Bearer {user_token}"})
        assert repo["id"] in {r["id"] for r in owner_list.json()}
        # admin sees it
        admin_list = await client.get("/repositories", headers={"Authorization": f"Bearer {admin_token}"})
        assert repo["id"] in {r["id"] for r in admin_list.json()}
        # other user does NOT see it
        other_list = await client.get("/repositories", headers={"Authorization": f"Bearer {other}"})
        assert repo["id"] not in {r["id"] for r in other_list.json()}
        # other user gets 404 on direct access (no existence leak)
        direct = await client.get(f"/repositories/{repo['id']}", headers={"Authorization": f"Bearer {other}"})
        assert direct.status_code == 404

    async def test_grant_gives_access_and_revoke_removes_it(self, client, user_token, session_maker):
        repo = await _private_repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        # discover the other user's id (admin creates via /users would need admin; use DB)
        await _make_user(session_maker, "grantee@example.com", "grantpass123", ROLE_USER)
        grantee = await _token(client, "grantee@example.com", "grantpass123")
        from sqlalchemy import select
        from src.webapi.models import User
        async with session_maker() as s:
            uid = str((await s.scalars(select(User).where(User.email == "grantee@example.com"))).first().id)
        # before grant: no access
        assert (await client.get(f"/repositories/{repo['id']}",
                headers={"Authorization": f"Bearer {grantee}"})).status_code == 404
        # grant
        g = await client.post(f"/repositories/{repo['id']}/access", headers=h,
                              json={"user_id": uid})
        assert g.status_code == 201
        assert (await client.get(f"/repositories/{repo['id']}",
                headers={"Authorization": f"Bearer {grantee}"})).status_code == 200
        # revoke
        await client.delete(f"/repositories/{repo['id']}/access/{uid}", headers=h)
        assert (await client.get(f"/repositories/{repo['id']}",
                headers={"Authorization": f"Bearer {grantee}"})).status_code == 404

    async def test_private_jobs_runs_hidden_from_others(self, client, user_token, session_maker):
        repo = await _private_repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        job = (await client.post("/jobs", headers=h, json={
            "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
        other = await _other_user(client, session_maker)
        ho = {"Authorization": f"Bearer {other}"}
        # other cannot see the job in the list or by id
        assert job["id"] not in {j["id"] for j in (await client.get("/jobs", headers=ho)).json()}
        assert (await client.get(f"/jobs/{job['id']}", headers=ho)).status_code == 404
        # other cannot run it
        assert (await client.post(f"/jobs/{job['id']}/run", headers=ho)).status_code == 404

    async def test_only_owner_admin_can_grant(self, client, user_token, session_maker):
        repo = await _private_repo(client, user_token)
        other = await _other_user(client, session_maker)
        import uuid
        resp = await client.post(f"/repositories/{repo['id']}/access",
                                 headers={"Authorization": f"Bearer {other}"},
                                 json={"user_id": str(uuid.uuid4())})
        # other can't even see the repo → 404
        assert resp.status_code in (403, 404)


class TestNonPrivateStillTeamVisible:
    async def test_public_repo_visible_to_all(self, client, user_token, session_maker):
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h, json={
            "name": "shared", "source_type": "upload"})).json()  # is_private defaults False
        other = await _other_user(client, session_maker)
        seen = await client.get("/repositories", headers={"Authorization": f"Bearer {other}"})
        assert repo["id"] in {r["id"] for r in seen.json()}
