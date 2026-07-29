"""GitLab token attachment + access validation."""
import subprocess
import types

import pytest

from src.webapi.ingestion import validate_gitlab_access
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


def _fake_runner(returncode=0, stdout="", stderr=""):
    def run(cmd, capture_output=True, text=True, timeout=None, env=None):
        return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
    return run


class TestValidateGitlabAccess:
    def test_success_returns_ref_count(self):
        runner = _fake_runner(0, "abc123\trefs/heads/main\ndef456\trefs/heads/dev\n")
        assert validate_gitlab_access("https://gl.example.com/g/p.git", "glpat-x", runner) == 2

    def test_failure_raises_and_scrubs_token(self):
        # stderr echoes the tokenized URL; the raised message must not leak the token.
        runner = _fake_runner(128, stderr="fatal: could not read from https://oauth2:glpat-SECRET@gl/p.git")
        with pytest.raises(RuntimeError) as ei:
            validate_gitlab_access("https://gl.example.com/g/p.git", "glpat-SECRET", runner)
        assert "glpat-SECRET" not in str(ei.value)


class TestGitUrlSchemeAllowlist:
    """Reject non-web git URL schemes (file://, ext::, ssh://) — SSRF/LFI guard."""

    def test_build_clone_url_rejects_file_scheme(self):
        from src.webapi.ingestion import build_clone_url
        for bad in ("file:///srv/secret.git", "ext::sh -c id", "ssh://git@host/x.git",
                    "git://host/x.git"):
            with pytest.raises(ValueError):
                build_clone_url(bad, "tok")

    def test_build_clone_url_allows_https_and_http(self):
        from src.webapi.ingestion import build_clone_url
        assert build_clone_url("https://gl.example.com/g/p.git", "tok").startswith("https://")
        assert build_clone_url("http://gl.internal/g/p.git", "tok").startswith("http://")

    def test_validate_gitlab_access_rejects_file_scheme(self):
        from src.webapi.ingestion import validate_gitlab_access
        with pytest.raises(ValueError):
            validate_gitlab_access("file:///srv/secret.git", None, _fake_runner(0))

    async def test_create_gitlab_repo_with_file_url_is_422(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        r = await client.post("/repositories", headers={"Authorization": f"Bearer {tok}"},
                              json={"name": "evil", "source_type": "gitlab",
                                    "gitlab_url": "file:///srv/secret.git"})
        assert r.status_code == 422, r.text


class TestGitlabTokenAttachment:
    async def test_create_repo_with_token_makes_credential_and_importing(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        h = {"Authorization": f"Bearer {tok}"}
        resp = await client.post("/repositories", headers=h, json={
            "name": "gl-repo", "source_type": "gitlab",
            "gitlab_url": "https://gl.example.com/g/p.git",
            "gitlab_token": "glpat-mytoken", "push_patches": True,
        })
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["ingestion_status"] == "importing"   # validation scheduled
        assert body["push_patches"] is True
        assert body["default_credential_id"] is not None  # token linked
        # a credential now exists for the user, secret present, never returned in clear
        creds = (await client.get("/credentials", headers=h)).json()
        assert len(creds) == 1 and creds[0]["has_secret"] is True
        assert "glpat-mytoken" not in (await client.get("/credentials", headers=h)).text

    async def test_push_patches_requires_gitlab(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        h = {"Authorization": f"Bearer {tok}"}
        resp = await client.post("/repositories", headers=h, json={
            "name": "up", "source_type": "upload", "push_patches": True,
        })
        assert resp.status_code == 400

    async def test_update_repo_token_relinks_and_revalidates(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        tok = await _token(client, "u@example.com", PW)
        h = {"Authorization": f"Bearer {tok}"}
        rid = (await client.post("/repositories", headers=h, json={
            "name": "gl", "source_type": "gitlab",
            "gitlab_url": "https://gl.example.com/g/p.git"})).json()["id"]
        resp = await client.patch(f"/repositories/{rid}", headers=h,
                                  json={"gitlab_token": "glpat-new"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["default_credential_id"] is not None
        assert resp.json()["ingestion_status"] == "importing"
