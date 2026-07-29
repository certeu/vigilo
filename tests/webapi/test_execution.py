from __future__ import annotations

import pytest

from src.webapi.models import ROLE_USER
from tests.webapi.conftest import _make_user, _token


async def _make_repo(client, token, name="acme-api"):
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post("/repositories", headers=h, json={
        "name": name, "source_type": "upload"})
    assert r.status_code == 201, r.text
    return r.json()


async def _make_job(client, token, repo_id, preset="vuln", target=None):
    h = {"Authorization": f"Bearer {token}"}
    r = await client.post("/jobs", headers=h, json={
        "repository_id": repo_id, "name": "job1", "stage_preset": preset,
        "target_url": target})
    return r


class TestRepositories:
    async def test_create_and_team_visible(self, client, user_token, admin_token):
        repo = await _make_repo(client, user_token)
        assert repo["has_webhook"] is False
        # admin (different user) sees it — team-shared
        seen = await client.get("/repositories",
                                headers={"Authorization": f"Bearer {admin_token}"})
        assert repo["id"] in {r["id"] for r in seen.json()}

    async def test_non_owner_cannot_delete(self, client, user_token, admin_token, session_maker):
        repo = await _make_repo(client, user_token)
        await _make_user(session_maker, "other@example.com", "otherpass123", ROLE_USER)
        other = await _token(client, "other@example.com", "otherpass123")
        resp = await client.delete(f"/repositories/{repo['id']}",
                                   headers={"Authorization": f"Bearer {other}"})
        assert resp.status_code == 403

    async def test_gitlab_requires_url(self, client, user_token):
        resp = await client.post("/repositories",
                                 headers={"Authorization": f"Bearer {user_token}"},
                                 json={"name": "x", "source_type": "gitlab"})
        assert resp.status_code == 422

    async def test_issue_webhook(self, client, user_token):
        repo = await _make_repo(client, user_token)
        resp = await client.post(f"/repositories/{repo['id']}/webhook",
                                 headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 200
        assert len(resp.json()["secret"]) > 20


class TestJobs:
    async def test_invalid_preset_rejected(self, client, user_token):
        repo = await _make_repo(client, user_token)
        resp = await _make_job(client, user_token, repo["id"], preset="everything")
        assert resp.status_code == 422

    async def test_create_valid_presets(self, client, user_token):
        repo = await _make_repo(client, user_token)
        for preset in ("vuln", "vuln_patch", "full"):
            resp = await _make_job(client, user_token, repo["id"], preset=preset)
            assert resp.status_code == 201, resp.text
            assert resp.json()["engine"] == "whitebox"

    async def test_unknown_repo_rejected(self, client, user_token):
        import uuid
        resp = await client.post("/jobs",
                                 headers={"Authorization": f"Bearer {user_token}"},
                                 json={"repository_id": str(uuid.uuid4()),
                                       "name": "j", "stage_preset": "vuln"})
        # unknown/inaccessible repo → 404 (no existence leak)
        assert resp.status_code == 404


class TestRunLifecycle:
    async def test_run_starts_via_engine(self, client, user_token, fake_engine):
        repo = await _make_repo(client, user_token)
        job = (await _make_job(client, user_token, repo["id"])).json()
        h = {"Authorization": f"Bearer {user_token}"}
        run = await client.post(f"/jobs/{job['id']}/run", headers=h)
        assert run.status_code == 201, run.text
        body = run.json()
        assert body["status"] == "running"
        assert body["workflow_id"]
        assert body["id"] in fake_engine.started

    async def test_runs_team_visible_and_get(self, client, user_token, admin_token):
        repo = await _make_repo(client, user_token)
        job = (await _make_job(client, user_token, repo["id"])).json()
        run = (await client.post(f"/jobs/{job['id']}/run",
                                 headers={"Authorization": f"Bearer {user_token}"})).json()
        # admin sees it
        lst = await client.get("/runs", headers={"Authorization": f"Bearer {admin_token}"})
        assert run["id"] in {r["id"] for r in lst.json()}
        one = await client.get(f"/runs/{run['id']}",
                               headers={"Authorization": f"Bearer {admin_token}"})
        assert one.status_code == 200

    async def test_cancel_permissions(self, client, user_token, admin_token, session_maker):
        repo = await _make_repo(client, user_token)
        job = (await _make_job(client, user_token, repo["id"])).json()
        run = (await client.post(f"/jobs/{job['id']}/run",
                                 headers={"Authorization": f"Bearer {user_token}"})).json()
        # unrelated user cannot cancel
        await _make_user(session_maker, "nope@example.com", "noppass123", ROLE_USER)
        other = await _token(client, "nope@example.com", "noppass123")
        forbidden = await client.post(f"/runs/{run['id']}/cancel",
                                      headers={"Authorization": f"Bearer {other}"})
        assert forbidden.status_code == 403
        # admin can cancel
        ok = await client.post(f"/runs/{run['id']}/cancel",
                               headers={"Authorization": f"Bearer {admin_token}"})
        assert ok.status_code == 200
        assert ok.json()["status"] == "cancelled"

    async def test_admission_control_queues_when_at_cap(self, client, user_token, monkeypatch):
        # Force cap to 0 → run stays queued, engine not started.
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_GLOBAL_CONCURRENT_RUN_CAP", "0")
        settings_mod.get_settings.cache_clear()
        repo = await _make_repo(client, user_token)
        job = (await _make_job(client, user_token, repo["id"])).json()
        run = await client.post(f"/jobs/{job['id']}/run",
                                headers={"Authorization": f"Bearer {user_token}"})
        assert run.status_code == 201
        assert run.json()["status"] == "queued"
        settings_mod.get_settings.cache_clear()


class TestStagesPayload:
    def test_vuln_job_payload_enforces_invariants(self):
        from src.webapi.engine.base import build_stages_payload
        from src.webapi.models import Job
        job = Job(name="j", stage_preset="vuln", engine="whitebox", pipeline_overrides={})
        payload = build_stages_payload(job)
        assert payload["run_vuln"] is True
        assert payload["run_critique"] is True      # always
        assert payload["run_remediation"] is False
        assert payload["run_chain"] is False
        assert "run_exploit" not in payload          # exploit welded to vuln
