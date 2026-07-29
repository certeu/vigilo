from __future__ import annotations


class TestPushPatches:
    async def test_defaults_false(self, client, user_token):
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h, json={
            "name": "gl", "source_type": "gitlab", "gitlab_url": "https://gl/x.git"})).json()
        assert repo["push_patches"] is False

    async def test_enable_on_gitlab_repo(self, client, user_token):
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h, json={
            "name": "gl", "source_type": "gitlab", "gitlab_url": "https://gl/x.git"})).json()
        patched = await client.patch(f"/repositories/{repo['id']}", headers=h,
                                     json={"push_patches": True})
        assert patched.status_code == 200
        assert patched.json()["push_patches"] is True

    async def test_reject_on_upload_repo(self, client, user_token):
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h, json={
            "name": "up", "source_type": "upload"})).json()
        resp = await client.patch(f"/repositories/{repo['id']}", headers=h,
                                  json={"push_patches": True})
        assert resp.status_code == 400
