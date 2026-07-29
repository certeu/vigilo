from __future__ import annotations


class TestUsersRouter:
    async def test_user_cannot_list(self, client, user_token):
        resp = await client.get("/users", headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 403

    async def test_admin_can_create_and_list(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        create = await client.post("/users", headers=h, json={
            "email": "new@example.com", "password": "newpass123", "role": "user"})
        assert create.status_code == 201, create.text
        assert create.json()["email"] == "new@example.com"
        lst = await client.get("/users", headers=h)
        assert lst.status_code == 200
        emails = {u["email"] for u in lst.json()}
        assert {"admin@example.com", "new@example.com"} <= emails

    async def test_admin_can_patch_role(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        created = (await client.post("/users", headers=h, json={
            "email": "p@example.com", "password": "pass123456", "role": "user"})).json()
        patched = await client.patch(f"/users/{created['id']}", headers=h,
                                     json={"role": "admin"})
        assert patched.status_code == 200
        assert patched.json()["role"] == "admin"

    async def test_admin_can_delete(self, client, admin_token):
        h = {"Authorization": f"Bearer {admin_token}"}
        created = (await client.post("/users", headers=h, json={
            "email": "d@example.com", "password": "pass123456", "role": "user"})).json()
        resp = await client.delete(f"/users/{created['id']}", headers=h)
        assert resp.status_code == 204
