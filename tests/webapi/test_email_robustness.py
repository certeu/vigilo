from __future__ import annotations

import uuid

from src.webapi.mailer_provider import get_mailer
from src.webapi.models import RUN_SUCCEEDED, Run


class _FailingMailer:
    def __init__(self):
        self.calls = 0

    def send(self, to, subject, body, attachment_path):
        self.calls += 1
        raise RuntimeError("smtp down")


async def _make_succeeded_run(client, user_token, session_maker):
    h = {"Authorization": f"Bearer {user_token}"}
    repo = (await client.post("/repositories", headers=h,
            json={"name": "r", "source_type": "upload"})).json()
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": "vuln", "notify_email": True})).json()
    run = (await client.post(f"/jobs/{job['id']}/run", headers=h)).json()
    async with session_maker() as s:
        r = await s.get(Run, uuid.UUID(run["id"]))
        r.status = RUN_SUCCEEDED
        await s.commit()
    return run["id"]


class TestEmailFailure:
    async def test_retries_capped_and_run_usable(self, client, user_token, session_maker):
        failing = _FailingMailer()
        client._app.dependency_overrides[get_mailer] = lambda: failing
        h = {"Authorization": f"Bearer {user_token}"}
        run_id = await _make_succeeded_run(client, user_token, session_maker)
        # poll the run 8 times; email send fails every time
        for _ in range(8):
            resp = await client.get(f"/runs/{run_id}", headers=h)
            assert resp.status_code == 200
            assert resp.json()["status"] == "succeeded"  # run stays usable
        # retries capped at 5 (not 8) — no unbounded storm
        assert failing.calls == 5
        # run marked notified (gave up) so it stops retrying
        async with session_maker() as s:
            r = await s.get(Run, uuid.UUID(run_id))
            assert r.notified is True
            assert r.notify_attempts == 5


class TestSmtpAuthWiring:
    def test_mailer_built_with_auth(self, monkeypatch):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_SMTP_HOST", "smtp.internal")
        monkeypatch.setenv("VIGILO_SMTP_USER", "vigilo@example.com")
        monkeypatch.setenv("VIGILO_SMTP_PASSWORD", "secret")
        monkeypatch.setenv("VIGILO_SMTP_STARTTLS", "true")
        settings_mod.get_settings.cache_clear()
        from src.webapi.mailer_provider import _build_mailer
        _build_mailer.cache_clear()
        m = _build_mailer()
        assert m.user == "vigilo@example.com" and m.password == "secret" and m.starttls is True
        _build_mailer.cache_clear()
        settings_mod.get_settings.cache_clear()
