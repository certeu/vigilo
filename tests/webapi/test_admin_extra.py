from __future__ import annotations

from datetime import datetime, timedelta, timezone


class TestInvitations:
    async def test_user_cannot_invite(self, client, user_token):
        resp = await client.post("/invitations",
                                 headers={"Authorization": f"Bearer {user_token}"},
                                 json={"email": "x@example.com", "role": "user"})
        assert resp.status_code == 403

    async def test_admin_invites_and_email_sent(self, client, admin_token, fake_mailer):
        h = {"Authorization": f"Bearer {admin_token}"}
        resp = await client.post("/invitations", headers=h,
                                 json={"email": "New@Example.com", "role": "user"})
        assert resp.status_code == 201, resp.text
        assert resp.json()["email"] == "new@example.com"
        assert resp.json()["accepted"] is False
        assert any(m["to"] == "new@example.com" for m in fake_mailer.sent)

    async def test_accept_invite_creates_user_and_can_login(
        self, client, admin_token, session_maker
    ):
        from sqlalchemy import select
        from src.webapi.models import Invitation
        h = {"Authorization": f"Bearer {admin_token}"}
        await client.post("/invitations", headers=h,
                          json={"email": "invitee@example.com", "role": "user"})
        async with session_maker() as s:
            inv = (await s.scalars(select(Invitation))).first()
            token = inv.token
        # accept with the token → user created
        acc = await client.post("/auth/accept-invite",
                                json={"token": token, "password": "longenough1"})
        assert acc.status_code == 200, acc.text
        # the new user can log in
        login = await client.post("/auth/jwt/login",
                                  data={"username": "invitee@example.com",
                                        "password": "longenough1"})
        assert login.status_code == 200
        # token can't be reused
        again = await client.post("/auth/accept-invite",
                                  json={"token": token, "password": "longenough1"})
        assert again.status_code == 400

    async def test_reject_bad_token(self, client):
        bad = await client.post("/auth/accept-invite",
                                json={"token": "nope", "password": "longenough1"})
        assert bad.status_code == 400


class TestRepoConfigOverride:
    async def test_set_and_read_pipeline_config(self, client, user_token):
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h,
                json={"name": "r", "source_type": "upload"})).json()
        assert repo["pipeline_config"] == {}
        patched = await client.patch(f"/repositories/{repo['id']}", headers=h,
                                     json={"pipeline_config": {"executor": "codex",
                                                               "model_large": "claude-opus-4-8"}})
        assert patched.status_code == 200
        assert patched.json()["pipeline_config"]["executor"] == "codex"

    async def test_unknown_config_key_rejected(self, client, user_token):
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h,
                json={"name": "r2", "source_type": "upload"})).json()
        resp = await client.patch(f"/repositories/{repo['id']}", headers=h,
                                  json={"pipeline_config": {"bogus": "x"}})
        assert resp.status_code == 422


class TestOnceSchedule:
    async def test_once_requires_run_at(self, client, user_token):
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h,
                json={"name": "r", "source_type": "upload"})).json()
        job = (await client.post("/jobs", headers=h, json={
            "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
        bad = await client.post("/schedules", headers=h,
                                json={"job_id": job["id"], "kind": "once"})
        assert bad.status_code == 422
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        ok = await client.post("/schedules", headers=h, json={
            "job_id": job["id"], "kind": "once", "run_at": future})
        assert ok.status_code == 201
        assert ok.json()["run_at"] is not None
