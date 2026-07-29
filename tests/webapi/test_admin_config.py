from __future__ import annotations


class TestAdminConfig:
    async def test_user_cannot_read(self, client, user_token):
        resp = await client.get("/admin/config",
                                headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 403

    async def test_admin_get_returns_defaults(self, client, admin_token):
        resp = await client.get("/admin/config",
                                headers={"Authorization": f"Bearer {admin_token}"})
        assert resp.status_code == 200
        assert resp.json()["executor"] == "claude"

    async def test_admin_put_updates(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        resp = await client.put("/admin/config", headers=h,
                                json={"executor": "codex", "global_concurrent_run_cap": 4})
        assert resp.status_code == 200
        assert resp.json()["executor"] == "codex"
        again = await client.get("/admin/config", headers=h)
        assert again.json()["global_concurrent_run_cap"] == 4
