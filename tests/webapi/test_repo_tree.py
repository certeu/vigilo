"""Browse-only repository file tree: capture, endpoint, access control, no contents."""
from __future__ import annotations

import io
import zipfile

import pytest

from src.webapi.repo_tree import capture_repo_tree, read_repo_tree, tree_cache_path
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


class TestCaptureTree:
    def test_capture_from_directory_skips_git_and_vigilo(self, tmp_path, monkeypatch):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(tmp_path / "uploads"))
        settings_mod.get_settings.cache_clear()
        src = tmp_path / "src"
        (src / "api").mkdir(parents=True)
        (src / ".git").mkdir()
        (src / "api" / "main.py").write_text("x")
        (src / "README.md").write_text("y")
        (src / ".git" / "config").write_text("z")
        n = capture_repo_tree("repo1", str(src))
        tree = read_repo_tree("repo1")
        assert n == 2 and tree["count"] == 2
        assert "api/main.py" in tree["paths"] and "README.md" in tree["paths"]
        assert not any(".git" in p for p in tree["paths"])  # internal dir excluded
        settings_mod.get_settings.cache_clear()

    def test_capture_from_zip(self, tmp_path, monkeypatch):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(tmp_path / "u2"))
        settings_mod.get_settings.cache_clear()
        z = tmp_path / "s.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("pkg/a.py", "1"); zf.writestr("b.txt", "2")
        z.write_bytes(buf.getvalue())
        capture_repo_tree("repo2", str(z))
        tree = read_repo_tree("repo2")
        assert sorted(tree["paths"]) == ["b.txt", "pkg/a.py"]
        settings_mod.get_settings.cache_clear()

    def test_read_missing_returns_none(self, tmp_path, monkeypatch):
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(tmp_path / "u3"))
        settings_mod.get_settings.cache_clear()
        assert read_repo_tree("nope") is None
        settings_mod.get_settings.cache_clear()


class TestTreeEndpoint:
    async def _repo(self, client, tok, name="r", private=True):
        h = {"Authorization": f"Bearer {tok}"}
        return (await client.post("/repositories", headers=h,
                json={"name": name, "source_type": "upload", "is_private": private})).json()["id"]

    async def test_owner_can_read_tree_names_only(self, client, session_maker, monkeypatch):
        from src.webapi import settings as settings_mod
        await _make_user(session_maker, "a@example.com", PW, "user")
        tok = await _token(client, "a@example.com", PW)
        rid = await self._repo(client, tok)
        # seed a tree cache for this repo
        settings_mod.get_settings.cache_clear()
        src = __import__("pathlib").Path(settings_mod.get_settings().uploads_dir)
        (src).mkdir(parents=True, exist_ok=True)
        import json
        (src / f"{rid}.tree.json").write_text(json.dumps({"paths": ["app/main.py", "README.md"], "truncated": False, "count": 2}))
        r = await client.get(f"/repositories/{rid}/tree", headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 200
        body = r.json()
        assert body["available"] is True
        assert body["paths"] == ["app/main.py", "README.md"]
        # no file-content field is ever returned
        assert "content" not in body and "contents" not in body

    async def test_no_access_gets_404(self, client, session_maker):
        await _make_user(session_maker, "owner@example.com", PW, "user")
        await _make_user(session_maker, "intruder@example.com", PW, "user")
        owner = await _token(client, "owner@example.com", PW)
        intruder = await _token(client, "intruder@example.com", PW)
        rid = await self._repo(client, owner, name="secret", private=True)
        r = await client.get(f"/repositories/{rid}/tree", headers={"Authorization": f"Bearer {intruder}"})
        assert r.status_code == 404   # private repo -> not even existence leaks

    async def test_endpoint_backfills_upload_when_cache_missing(self, client, session_maker, monkeypatch):
        # Self-heal: even if the tree cache is gone (e.g. repo predates the feature, or
        # after a scan cleaned the checkout), the endpoint rebuilds it from the persistent
        # uploaded source. This is the item-1 fix (files visible after a scan).
        import io, os, zipfile
        from src.webapi import settings as settings_mod
        monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(__import__("pathlib").Path(
            os.environ.get("VIGILO_JOBS_DATA_DIR", "/tmp")) / "up-heal"))
        settings_mod.get_settings.cache_clear()
        await _make_user(session_maker, "a@example.com", PW, "user")
        tok = await _token(client, "a@example.com", PW)
        h = {"Authorization": f"Bearer {tok}"}
        rid = (await client.post("/repositories", headers=h,
               json={"name": "heal", "source_type": "upload", "is_private": True})).json()["id"]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("app/main.py", "x"); zf.writestr("README.md", "y")
        await client.post(f"/repositories/{rid}/upload", headers=h,
                          files={"files": ("s.zip", buf.getvalue(), "application/zip")})
        # delete the cache to simulate a repo with no tree cache
        from src.webapi.repo_tree import tree_cache_path
        cache = tree_cache_path(rid)
        if os.path.isfile(cache):
            os.remove(cache)
        # endpoint rebuilds it from the still-present uploaded zip
        r = await client.get(f"/repositories/{rid}/tree", headers=h)
        assert r.status_code == 200
        body = r.json()
        assert body["available"] is True
        assert sorted(body["paths"]) == ["README.md", "app/main.py"]
        settings_mod.get_settings.cache_clear()

    async def test_no_content_endpoint_exists(self, client, session_maker):
        await _make_user(session_maker, "a@example.com", PW, "user")
        tok = await _token(client, "a@example.com", PW)
        rid = await self._repo(client, tok)
        h = {"Authorization": f"Bearer {tok}"}
        # there must be NO endpoint serving file contents (browse-only, enforced server-side)
        for p in (f"/repositories/{rid}/file?path=README.md",
                  f"/repositories/{rid}/tree/README.md",
                  f"/repositories/{rid}/blob?path=README.md"):
            assert (await client.get(p, headers=h)).status_code in (404, 405), p
