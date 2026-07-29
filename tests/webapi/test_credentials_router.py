from __future__ import annotations


class TestCredentials:
    async def test_create_hides_secret(self, client, user_token):
        h = {"Authorization": f"Bearer {user_token}"}
        resp = await client.post("/credentials", headers=h, json={
            "kind": "gitlab_token", "label": "my tok", "secret": "glpat-xyz",
            "gitlab_base_url": "https://gitlab.internal"})
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["has_secret"] is True
        assert "secret" not in body and "secret_enc" not in body

    async def test_list_only_own(self, client, user_token, admin_token):
        hu = {"Authorization": f"Bearer {user_token}"}
        ha = {"Authorization": f"Bearer {admin_token}"}
        await client.post("/credentials", headers=hu, json={
            "kind": "gitlab_token", "label": "u", "secret": "s"})
        await client.post("/credentials", headers=ha, json={
            "kind": "gitlab_token", "label": "a", "secret": "s"})
        got = await client.get("/credentials", headers=hu)
        labels = {c["label"] for c in got.json()}
        assert labels == {"u"}

    async def test_secret_is_encrypted_at_rest(self, client, user_token, session_maker):
        from sqlalchemy import select
        from src.webapi.models import Credential
        h = {"Authorization": f"Bearer {user_token}"}
        await client.post("/credentials", headers=h, json={
            "kind": "gitlab_token", "label": "e", "secret": "glpat-plaintext"})
        async with session_maker() as s:
            row = (await s.scalars(select(Credential))).first()
        assert b"glpat-plaintext" not in row.secret_enc
