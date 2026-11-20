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

    async def test_patches_zip_download(self, client, user_token):
        import io
        import zipfile

        from src.webapi.settings import get_settings
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        data_dir = os.path.join(get_settings().jobs_data_dir, run["id"])
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(os.path.join(d, "patches"), exist_ok=True)
        with open(os.path.join(d, "patches", "F-1.patch"), "w") as fh:
            fh.write("--- a\n+++ b\n")
        with open(os.path.join(d, "patches", "notes.txt"), "w") as fh:
            fh.write("ignored")
        with open(os.path.join(d, "remediation_manifest.json"), "w") as fh:
            fh.write("{}")
        outside = os.path.join(data_dir, "secret.patch")
        with open(outside, "w") as fh:
            fh.write("secret")
        os.symlink(outside, os.path.join(d, "patches", "evil.patch"))
        listing = await client.get(f"/runs/{run['id']}/artifacts", headers=h)
        assert "patches" in listing.json()["artifacts"]
        assert "remediation_manifest" in listing.json()["artifacts"]
        dl = await client.get(f"/runs/{run['id']}/artifacts/patches", headers=h)
        assert dl.status_code == 200
        assert dl.headers["content-type"] == "application/zip"
        names = sorted(zipfile.ZipFile(io.BytesIO(dl.content)).namelist())
        assert names == ["patches/F-1.patch", "remediation_manifest.json"]
        man = await client.get(f"/runs/{run['id']}/artifacts/remediation_manifest", headers=h)
        assert man.status_code == 200

    async def test_patches_404_when_none(self, client, user_token):
        run = await _repo_job_run(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        resp = await client.get(f"/runs/{run['id']}/artifacts/patches", headers=h)
        assert resp.status_code == 404

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


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16


def _write_screenshot(data_dir: str, session_id: str, name: str, data: bytes = PNG) -> str:
    d = os.path.join(deliverables_dir(data_dir, session_id), "screenshots")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, name)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


class TestReportScreenshots:
    async def _setup(self, client, user_token):
        from src.webapi.settings import get_settings
        run = await _repo_job_run(client, user_token)
        data_dir = os.path.join(get_settings().jobs_data_dir, run["id"])
        return run, data_dir

    async def test_screenshot_served_as_image(self, client, user_token):
        run, data_dir = await self._setup(client, user_token)
        _write_screenshot(data_dir, run["session_id"], "xss alert.png")
        r = await client.get(f"/runs/{run['id']}/files/screenshots/xss%20alert.png",
                             params={"token": user_token})
        assert r.status_code == 200 and r.content == PNG
        assert r.headers["content-type"] == "image/png"
        assert r.headers["x-content-type-options"] == "nosniff"

    async def test_only_raster_images_under_screenshots(self, client, user_token):
        run, data_dir = await self._setup(client, user_token)
        _write_screenshot(data_dir, run["session_id"], "poc.svg", b"<svg onload=alert(1)>")
        _write_screenshot(data_dir, run["session_id"], "poc.html", b"<script>alert(1)</script>")
        _write_report(data_dir, run["session_id"], "# Report")
        for rel in ("screenshots/poc.svg", "screenshots/poc.html", REPORT_FILENAME,
                    "screenshots/../" + REPORT_FILENAME, "screenshots/missing.png"):
            r = await client.get(f"/runs/{run['id']}/files/{rel}", params={"token": user_token})
            assert r.status_code == 404, rel

    async def test_symlinked_screenshot_or_directory_not_served(self, client, user_token, tmp_path):
        run, data_dir = await self._setup(client, user_token)
        outside = tmp_path / "secret.png"
        outside.write_bytes(b"secret-bytes")
        d = deliverables_dir(data_dir, run["session_id"])
        os.makedirs(os.path.join(d, "screenshots"))
        os.symlink(outside, os.path.join(d, "screenshots", "x.png"))
        r = await client.get(f"/runs/{run['id']}/files/screenshots/x.png", params={"token": user_token})
        assert r.status_code == 404 and b"secret-bytes" not in r.content
        # the whole deliverables directory replaced by a symlink to another tree
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "screenshots").mkdir(parents=True)
        (elsewhere / "screenshots" / "x.png").write_bytes(b"secret-bytes")
        os.remove(os.path.join(d, "screenshots", "x.png"))
        os.rmdir(os.path.join(d, "screenshots"))
        os.rmdir(d)
        os.symlink(elsewhere, d)
        r = await client.get(f"/runs/{run['id']}/files/screenshots/x.png", params={"token": user_token})
        assert r.status_code == 404 and b"secret-bytes" not in r.content
