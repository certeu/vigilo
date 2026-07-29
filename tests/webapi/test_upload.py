from __future__ import annotations

import io
import os
import zipfile


async def _upload_repo(client, token):
    h = {"Authorization": f"Bearer {token}"}
    return (await client.post("/repositories", headers=h,
            json={"name": "up", "source_type": "upload"})).json()


class TestUpload:
    async def test_repo_starts_not_ready(self, client, user_token):
        repo = await _upload_repo(client, user_token)
        assert repo["upload_ready"] is False

    async def test_upload_zip_marks_ready_and_stores(self, client, user_token, monkeypatch, tmp_path):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(tmp_path / "uploads"))
        settings_mod.get_settings.cache_clear()
        repo = await _upload_repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("app.py", "print('hi')")
        buf.seek(0)
        resp = await client.post(
            f"/repositories/{repo['id']}/upload", headers=h,
            files={"files": ("src.zip", buf.getvalue(), "application/zip")},
        )
        assert resp.status_code == 200, resp.text
        # Ingestion is backgrounded now: the upload response reports "importing" and
        # the archive is on disk (the bg task flips it to ready/failed).
        assert resp.json()["ingestion_status"] == "importing"
        archive = tmp_path / "uploads" / f"{repo['id']}.zip"
        assert archive.is_file()
        settings_mod.get_settings.cache_clear()

    async def test_upload_uncompressed_files(self, client, user_token, monkeypatch, tmp_path):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(tmp_path / "uploads2"))
        settings_mod.get_settings.cache_clear()
        repo = await _upload_repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        resp = await client.post(
            f"/repositories/{repo['id']}/upload", headers=h,
            files=[
                ("files", ("main.py", b"x=1", "text/x-python")),
                ("files", ("sub/util.py", b"y=2", "text/x-python")),
            ],
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["ingestion_status"] == "importing"
        tree = tmp_path / "uploads2" / repo["id"]
        assert (tree / "main.py").is_file()
        assert (tree / "sub" / "util.py").is_file()
        settings_mod.get_settings.cache_clear()

    async def test_upload_rejects_non_upload_repo(self, client, user_token, monkeypatch, tmp_path):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(tmp_path / "u3"))
        settings_mod.get_settings.cache_clear()
        h = {"Authorization": f"Bearer {user_token}"}
        repo = (await client.post("/repositories", headers=h, json={
            "name": "gl", "source_type": "gitlab",
            "gitlab_url": "https://gl/x.git"})).json()
        resp = await client.post(f"/repositories/{repo['id']}/upload", headers=h,
                                 files={"files": ("a.zip", b"x", "application/zip")})
        assert resp.status_code == 400
        settings_mod.get_settings.cache_clear()

    async def test_upload_exceeding_cap_rejected_413(self, client, user_token, monkeypatch, tmp_path):
        # Cap at 0 MiB → any non-empty upload is rejected and no partial file remains.
        from src.webapi import settings as settings_mod
        up = tmp_path / "u5"
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(up))
        monkeypatch.setenv("VIGILO_MAX_UPLOAD_MB", "0")
        settings_mod.get_settings.cache_clear()
        repo = await _upload_repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        resp = await client.post(
            f"/repositories/{repo['id']}/upload", headers=h,
            files=[("files", ("big.py", b"x" * 4096, "text/x-python"))],
        )
        assert resp.status_code == 413
        # no partial file left behind
        assert not os.path.isfile(up / repo["id"] / "big.py")
        settings_mod.get_settings.cache_clear()

    async def test_upload_traversal_filename_sanitized(self, client, user_token, monkeypatch, tmp_path):
        from src.webapi import settings as settings_mod
        up = tmp_path / "u4"
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(up))
        settings_mod.get_settings.cache_clear()
        repo = await _upload_repo(client, user_token)
        h = {"Authorization": f"Bearer {user_token}"}
        await client.post(
            f"/repositories/{repo['id']}/upload", headers=h,
            files=[("files", ("../../evil.py", b"bad", "text/x-python"))],
        )
        # nothing escaped the uploads tree
        assert not (tmp_path / "evil.py").exists()
        assert os.path.isfile(up / repo["id"] / "evil.py")
        settings_mod.get_settings.cache_clear()
