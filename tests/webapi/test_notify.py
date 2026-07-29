"""Per-job report-email opt-in: only send when the job requested it."""
from __future__ import annotations

import uuid

from src.webapi.models import RUN_SUCCEEDED, Run
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


async def _job_run(client, session_maker, notify_email: bool):
    await _make_user(session_maker, "u@example.com", PW, "user")
    tok = await _token(client, "u@example.com", PW)
    rid = (await client.post("/repositories", headers=_h(tok),
           json={"name": "r", "source_type": "upload", "is_private": True})).json()["id"]
    job = (await client.post("/jobs", headers=_h(tok), json={
        "repository_id": rid, "name": "j", "stage_preset": "vuln",
        "notify_email": notify_email})).json()
    assert job["notify_email"] is notify_email  # persisted + round-tripped
    run_id = (await client.post(f"/jobs/{job['id']}/run", headers=_h(tok))).json()["id"]
    # force the run terminal so the completion-notify path runs on the next GET
    async with session_maker() as s:
        run = await s.get(Run, uuid.UUID(run_id))
        run.status = RUN_SUCCEEDED
        await s.commit()
    return tok, run_id


class TestNotifyOptIn:
    async def test_unchecked_sends_nothing(self, client, session_maker, fake_mailer):
        tok, run_id = await _job_run(client, session_maker, notify_email=False)
        await client.get(f"/runs/{run_id}", headers=_h(tok))  # triggers _maybe_notify
        assert fake_mailer.sent == []

    async def test_checked_emails_the_triggering_user(self, client, session_maker, fake_mailer):
        tok, run_id = await _job_run(client, session_maker, notify_email=True)
        await client.get(f"/runs/{run_id}", headers=_h(tok))
        assert len(fake_mailer.sent) == 1
        msg = fake_mailer.sent[0]
        assert msg["to"] == "u@example.com"                 # the triggering user
        assert "succeeded" in msg["subject"].lower()

    async def test_only_sent_once(self, client, session_maker, fake_mailer):
        tok, run_id = await _job_run(client, session_maker, notify_email=True)
        await client.get(f"/runs/{run_id}", headers=_h(tok))
        await client.get(f"/runs/{run_id}", headers=_h(tok))  # second poll
        assert len(fake_mailer.sent) == 1                # notified flag prevents dupes


class TestJobNotifyPatch:
    """The Scheduler tab edits the SAME job.notify_email via PATCH /jobs/{id}."""

    async def test_owner_can_toggle_notify_email(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        rid = (await client.post("/repositories", headers=_h(tok),
               json={"name": "r", "source_type": "upload"})).json()["id"]
        job = (await client.post("/jobs", headers=_h(tok), json={
            "repository_id": rid, "name": "j", "stage_preset": "vuln"})).json()
        assert job["notify_email"] is False
        # turn it on
        r = await client.patch(f"/jobs/{job['id']}", headers=_h(tok), json={"notify_email": True})
        assert r.status_code == 200 and r.json()["notify_email"] is True
        assert (await client.get(f"/jobs/{job['id']}", headers=_h(tok))).json()["notify_email"] is True
        # and off again
        r = await client.patch(f"/jobs/{job['id']}", headers=_h(tok), json={"notify_email": False})
        assert r.json()["notify_email"] is False

    async def test_non_owner_cannot_patch(self, client, session_maker):
        await _make_user(session_maker, "owner@example.com", PW, "user")
        await _make_user(session_maker, "intruder@example.com", PW, "user")
        owner = await _token(client, "owner@example.com", PW)
        intruder = await _token(client, "intruder@example.com", PW)
        rid = (await client.post("/repositories", headers=_h(owner),
               json={"name": "sec", "source_type": "upload", "is_private": True})).json()["id"]
        job = (await client.post("/jobs", headers=_h(owner), json={
            "repository_id": rid, "name": "j", "stage_preset": "vuln"})).json()
        r = await client.patch(f"/jobs/{job['id']}", headers=_h(intruder), json={"notify_email": True})
        assert r.status_code == 404  # private repo -> not even visible


class TestBackgroundSweep:
    """Unattended (e.g. scheduled) runs must email WITHOUT anyone opening the run page."""

    async def test_sweep_notifies_completed_run_without_a_GET(self, client, session_maker, fake_mailer):
        # create an opted-in job + run, leave it 'running' (as an unattended run would be)
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        rid = (await client.post("/repositories", headers=_h(tok),
               json={"name": "r", "source_type": "upload", "is_private": True})).json()["id"]
        job = (await client.post("/jobs", headers=_h(tok), json={
            "repository_id": rid, "name": "j", "stage_preset": "vuln",
            "notify_email": True})).json()
        run_id = (await client.post(f"/jobs/{job['id']}/run", headers=_h(tok))).json()["id"]
        async with session_maker() as s:
            run = await s.get(Run, uuid.UUID(run_id))
            run.status = "running"
            await s.commit()

        # engine whose refresh transitions the run to succeeded (like Temporal finishing)
        class _FinishingEngine:
            async def refresh(self, run):
                run.status = RUN_SUCCEEDED

        from src.webapi.routers.runs import _notify_sweep
        async with session_maker() as s:
            await _notify_sweep(s, _FinishingEngine(), fake_mailer)

        # emailed even though NOBODY called GET /runs/{id}
        assert len(fake_mailer.sent) == 1
        assert fake_mailer.sent[0]["to"] == "u@example.com"
