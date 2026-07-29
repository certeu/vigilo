from __future__ import annotations


async def _repo_gitlab(client, token, project_id="4242"):
    h = {"Authorization": f"Bearer {token}"}
    repo = (await client.post("/repositories", headers=h, json={
        "name": "gl", "source_type": "gitlab",
        "gitlab_url": "https://gitlab.internal/g/p.git",
        "gitlab_project_id": project_id})).json()
    secret = (await client.post(f"/repositories/{repo['id']}/webhook", headers=h)).json()["secret"]
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": "vuln"})).json()
    return repo, secret, job


def _mr_payload(project_id="4242", action="open", iid=7):
    return {
        "object_kind": "merge_request",
        "project": {"id": int(project_id)},
        "object_attributes": {"iid": iid, "action": action, "target_branch": "main"},
    }


class TestScheduleCrud:
    async def test_recurring_requires_cron(self, client, user_token):
        _, _, job = await _repo_gitlab(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        bad = await client.post("/schedules", headers=h, json={
            "job_id": job["id"], "kind": "recurring"})
        assert bad.status_code == 422
        ok = await client.post("/schedules", headers=h, json={
            "job_id": job["id"], "kind": "recurring", "cron": "0 3 * * *"})
        assert ok.status_code == 201
        assert ok.json()["cron"] == "0 3 * * *"

    async def test_toggle_and_delete(self, client, user_token):
        _, _, job = await _repo_gitlab(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        s = (await client.post("/schedules", headers=h, json={
            "job_id": job["id"], "kind": "gitlab_mr"})).json()
        patched = await client.patch(f"/schedules/{s['id']}", headers=h,
                                     json={"enabled": False})
        assert patched.json()["enabled"] is False
        assert (await client.delete(f"/schedules/{s['id']}", headers=h)).status_code == 204

    async def test_non_owner_cannot_delete(self, client, user_token, admin_token, session_maker):
        from src.webapi.models import ROLE_USER
        from tests.webapi.conftest import _make_user, _token
        _, _, job = await _repo_gitlab(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        s = (await client.post("/schedules", headers=h, json={
            "job_id": job["id"], "kind": "gitlab_mr"})).json()
        await _make_user(session_maker, "z9@example.com", "zpass12345", ROLE_USER)
        other = await _token(client, "z9@example.com", "zpass12345")
        resp = await client.delete(f"/schedules/{s['id']}",
                                   headers={"Authorization": f"Bearer {other}"})
        assert resp.status_code == 403


class TestGitlabWebhook:
    async def test_invalid_token_rejected(self, client, user_token):
        _, secret, job = await _repo_gitlab(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        await client.post("/schedules", headers=h, json={
            "job_id": job["id"], "kind": "gitlab_mr"})
        resp = await client.post("/webhooks/gitlab",
                                 headers={"X-Gitlab-Token": "wrong"},
                                 json=_mr_payload())
        assert resp.status_code == 401

    async def test_valid_token_triggers_run(self, client, user_token, fake_engine):
        _, secret, job = await _repo_gitlab(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        await client.post("/schedules", headers=h, json={
            "job_id": job["id"], "kind": "gitlab_mr"})
        resp = await client.post("/webhooks/gitlab",
                                 headers={"X-Gitlab-Token": secret},
                                 json=_mr_payload(iid=11))
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "ok"
        assert len(body["runs_started"]) == 1
        assert body["mr_iid"] == "11"
        # the run is visible and tagged as gitlab_mr
        runs = (await client.get("/runs", headers=h)).json()
        assert any(r["trigger_type"] == "gitlab_mr" for r in runs)

    async def test_non_mr_event_ignored(self, client, user_token):
        _, secret, _ = await _repo_gitlab(client, user_token)
        resp = await client.post("/webhooks/gitlab",
                                 headers={"X-Gitlab-Token": secret},
                                 json={"object_kind": "push"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"
