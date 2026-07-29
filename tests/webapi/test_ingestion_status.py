"""Repository ingestion status: validate_upload + the upload endpoint's importing state."""
import io
import os
import zipfile

import pytest

from src.webapi.ingestion import validate_upload
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


class TestValidateUpload:
    def test_valid_zip_returns_file_count(self, tmp_path):
        p = tmp_path / "src.zip"
        p.write_bytes(_zip_bytes({"main.py": "print(1)\n", "util.py": "x=1\n"}))
        assert validate_upload(str(p)) == 2

    def test_not_a_zip_raises(self, tmp_path):
        p = tmp_path / "bad.zip"
        p.write_bytes(b"this is not a zip file")
        with pytest.raises(ValueError):
            validate_upload(str(p))

    def test_empty_zip_raises(self, tmp_path):
        p = tmp_path / "empty.zip"
        p.write_bytes(_zip_bytes({}))
        with pytest.raises(ValueError):
            validate_upload(str(p))

    def test_unsafe_member_raises(self, tmp_path):
        p = tmp_path / "eviltar.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../etc/passwd", "root\n")
        p.write_bytes(buf.getvalue())
        with pytest.raises(ValueError):
            validate_upload(str(p))

    def test_folder_upload_counts_files(self, tmp_path):
        d = tmp_path / "tree"
        (d / "sub").mkdir(parents=True)
        (d / "a.py").write_text("a\n")
        (d / "sub" / "b.py").write_text("b\n")
        assert validate_upload(str(d)) == 2

    def test_empty_folder_raises(self, tmp_path):
        d = tmp_path / "empty"
        d.mkdir()
        with pytest.raises(ValueError):
            validate_upload(str(d))

    def test_unsupported_extension_raises(self, tmp_path):
        p = tmp_path / "src.rar"
        p.write_bytes(b"whatever")
        with pytest.raises(ValueError):
            validate_upload(str(p))


class TestUploadEndpointStatus:
    async def test_new_upload_repo_starts_idle(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        h = {"Authorization": f"Bearer {tok}"}
        r = await client.post("/repositories", headers=h,
                              json={"name": "up", "source_type": "upload", "is_private": True})
        assert r.json()["ingestion_status"] == "idle"

    async def test_gitlab_repo_starts_importing_pending_validation(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        h = {"Authorization": f"Bearer {tok}"}
        r = await client.post("/repositories", headers=h,
                              json={"name": "gl", "source_type": "gitlab",
                                    "gitlab_url": "https://gitlab.example.com/g/p.git"})
        # access is validated in the background -> starts "importing"
        assert r.json()["ingestion_status"] == "importing"

    async def test_upload_sets_importing_and_schedules_ingestion(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        h = {"Authorization": f"Bearer {tok}"}
        repo_id = (await client.post("/repositories", headers=h,
                   json={"name": "up", "source_type": "upload", "is_private": True})).json()["id"]
        resp = await client.post(
            f"/repositories/{repo_id}/upload", headers=h,
            files={"files": ("src.zip", _zip_bytes({"main.py": "print(1)\n"}), "application/zip")},
        )
        assert resp.status_code == 200
        # The response is built before the background task runs -> importing.
        assert resp.json()["ingestion_status"] == "importing"
