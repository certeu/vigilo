"""Repository ingestion status: validate_upload + the upload endpoint's importing state."""
import io
import os
import tarfile
import zipfile

import pytest

from src.webapi.ingestion import archive_kind, extract_archive, validate_upload
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


def _zip_bytes(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()


def _tar_bytes(files: dict[str, str], mode: str = "w:gz") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class TestArchiveDetectedByContent:
    """Uploads are stored as ``<repo id>.zip`` whatever their format: a .tar.gz the UI
    accepts used to fail with "not a valid .zip archive"."""

    @pytest.mark.parametrize("mode", ["w:gz", "w"])
    def test_tar_stored_under_a_zip_name_is_validated(self, tmp_path, mode):
        p = tmp_path / "repo-id.zip"
        p.write_bytes(_tar_bytes({"app/main.py": "print(1)\n", "app/util.py": "x=1\n"}, mode))
        assert archive_kind(str(p)) == "tar"
        assert validate_upload(str(p)) == 2

    def test_tar_stored_under_a_zip_name_is_extracted(self, tmp_path):
        p = tmp_path / "repo-id.zip"
        p.write_bytes(_tar_bytes({"proj/main.py": "print(1)\n", "proj/sub/b.py": "b\n"}))
        out = extract_archive(str(p), str(tmp_path / "out"))
        assert sorted(os.path.relpath(os.path.join(r, f), out)
                      for r, _d, fs in os.walk(out) for f in fs) == ["main.py", "sub/b.py"]

    def test_unsafe_tar_member_is_refused(self, tmp_path):
        p = tmp_path / "repo-id.zip"
        p.write_bytes(_tar_bytes({"../../escape.txt": "x\n"}))
        with pytest.raises(Exception):
            extract_archive(str(p), str(tmp_path / "out"))
        assert not (tmp_path / "escape.txt").exists()

    def test_macos_tar_sidecars_are_not_extracted(self, tmp_path):
        """A Mac's tar adds a "._name" AppleDouble file next to every file (and one
        for the wrapper dir); they are not source and must not hide the wrapper."""
        p = tmp_path / "repo-id.zip"
        p.write_bytes(_tar_bytes({"._proj": "x", "proj/main.py": "print(1)\n",
                                  "proj/._main.py": "x", "proj/sub/b.py": "b\n",
                                  "proj/sub/._b.py": "x"}))
        out = extract_archive(str(p), str(tmp_path / "out"))
        assert sorted(os.path.relpath(os.path.join(r, f), out)
                      for r, _d, fs in os.walk(out) for f in fs) == ["main.py", "sub/b.py"]

    def test_zip_is_still_a_zip(self, tmp_path):
        p = tmp_path / "repo-id.zip"
        p.write_bytes(_zip_bytes({"main.py": "x\n"}))
        assert archive_kind(str(p)) == "zip"


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
