from __future__ import annotations

import os
import uuid

from src.webapi.models import RUN_SUCCEEDED, Run
from src.webapi.reports import deliverables_dir, REPORT_FILENAME


async def _repo_job_run(client, token):
    h = {"Authorization": f"Bearer {token}"}
    repo = (await client.post("/repositories", headers=h,
            json={"name": "r", "source_type": "upload"})).json()
    job = (await client.post("/jobs", headers=h, json={
        "repository_id": repo["id"], "name": "j", "stage_preset": "vuln", "notify_email": True})).json()
    run = (await client.post(f"/jobs/{job['id']}/run", headers=h)).json()
    return run


def _write_report(data_dir: str, session_id: str, text: str) -> None:
    d = deliverables_dir(data_dir, session_id)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, REPORT_FILENAME), "w", encoding="utf-8") as fh:
        fh.write(text)


async def _set_status(session_maker, run_id: str, status: str) -> None:
    async with session_maker() as s:
        run = await s.get(Run, uuid.UUID(run_id))
        run.status = status
        await s.commit()


class TestReport:
    async def test_report_absent_then_present(self, client, user_token):
        from src.webapi.settings import get_settings
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        absent = await client.get(f"/runs/{run['id']}/report", headers=h)
        assert absent.status_code == 200 and absent.json()["exists"] is False

        data_dir = os.path.join(get_settings().jobs_data_dir, run["id"])
        _write_report(data_dir, run["session_id"], "# Report\nAll good.")
        present = await client.get(f"/runs/{run['id']}/report", headers=h)
        assert present.json()["exists"] is True
        assert "All good." in present.json()["markdown"]

    async def test_artifacts_list_and_download(self, client, user_token):
        from src.webapi.settings import get_settings
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        data_dir = os.path.join(get_settings().jobs_data_dir, run["id"])
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "findings_index.json"), "w") as fh:
            fh.write('{"total_vulnerabilities": 3}')
        listing = await client.get(f"/runs/{run['id']}/artifacts", headers=h)
        assert "findings_index" in listing.json()["artifacts"]
        dl = await client.get(f"/runs/{run['id']}/artifacts/findings_index", headers=h)
        assert dl.status_code == 200
        assert b"total_vulnerabilities" in dl.content

    async def test_unknown_artifact_404(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        resp = await client.get(f"/runs/{run['id']}/artifacts/nope", headers=h)
        assert resp.status_code == 404


class TestNotification:
    async def test_email_sent_once_on_terminal(self, client, user_token, session_maker, fake_mailer):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        await _set_status(session_maker, run["id"], RUN_SUCCEEDED)
        # first GET after completion → one email
        await client.get(f"/runs/{run['id']}", headers=h)
        assert len(fake_mailer.sent) == 1
        assert fake_mailer.sent[0]["to"] == "user@example.com"
        assert "succeeded" in fake_mailer.sent[0]["subject"]
        # subsequent GET → no duplicate
        await client.get(f"/runs/{run['id']}", headers=h)
        assert len(fake_mailer.sent) == 1


class TestBuildMessage:
    def test_message_fields(self):
        from src.webapi.notifications import build_completion_message

        run = Run(id=uuid.uuid4(), job_id=uuid.uuid4(), trigger_type="manual",
                  status=RUN_SUCCEEDED, session_id="web-abc", data_dir="/x")
        msg = build_completion_message(run, "u@example.com", True, "http://vigilo.internal")
        assert msg["to"] == "u@example.com"
        assert "succeeded" in msg["subject"]
        assert "http://vigilo.internal/runs/" in msg["body"]
        assert "attached" in msg["body"]
