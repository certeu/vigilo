"""GitHub (github.com / GitHub Enterprise Server) sources: PATs and GitHub Apps."""
import base64
import io
import json
import urllib.error
import uuid

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from src.services.forges import github_app as gh
from src.webapi.credential_guard import CredentialRejected, validate_repo_credential
from src.webapi.models import Credential
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def pem(rsa_key):
    return rsa_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()


def _secret(pem, installation_id=None):
    return gh.build_app_secret("12345", pem, installation_id)


def validate_github_credential(cred, owner, url):
    validate_repo_credential(cred, owner, "github", url)


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


# ── URLs ────────────────────────────────────────────────────────────────────


class TestRepoUrl:
    def test_github_com(self):
        r = gh.parse_repo_url("https://github.com/acme/app.git")
        assert (r.web_base, r.owner, r.name) == ("https://github.com", "acme", "app")
        assert r.api_base == "https://api.github.com"

    def test_ghe_uses_api_v3_on_same_host(self):
        r = gh.parse_repo_url("https://ghe.example.com/acme/app")
        assert r.web_base == "https://ghe.example.com"
        assert r.api_base == "https://ghe.example.com/api/v3"

    def test_ghe_keeps_port(self):
        r = gh.parse_repo_url("https://ghe.example.com:8443/acme/app")
        assert r.api_base == "https://ghe.example.com:8443/api/v3"

    @pytest.mark.parametrize("bad", [
        "http://github.com/acme/app",            # no cleartext
        "https://tok@github.com/acme/app",       # no credentials
        "https://github.com/acme",               # owner only
        "https://github.com/acme/app/extra",     # too deep
        "https://github.com/acme/app?x=1",       # query
        "file:///srv/x.git",
        "ssh://git@github.com/acme/app.git",
    ])
    def test_rejects(self, bad):
        with pytest.raises(ValueError):
            gh.parse_repo_url(bad)


# ── App secret + JWT ────────────────────────────────────────────────────────


class TestAppSecret:
    def test_roundtrip(self, pem):
        cfg = gh.parse_app_secret(_secret(pem, "678"))
        assert (cfg.app_id, cfg.installation_id) == ("12345", "678")

    def test_installation_optional(self, pem):
        assert gh.parse_app_secret(_secret(pem)).installation_id is None

    @pytest.mark.parametrize("app_id", ["", "abc", "12 3"])
    def test_bad_app_id(self, pem, app_id):
        with pytest.raises(ValueError):
            gh.build_app_secret(app_id, pem)

    def test_bad_installation_id(self, pem):
        with pytest.raises(ValueError):
            gh.build_app_secret("1", pem, "x1")

    def test_garbage_key(self):
        with pytest.raises(ValueError):
            gh.build_app_secret("1", "not a key")

    def test_non_rsa_key(self):
        ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        with pytest.raises(ValueError, match="RSA"):
            gh.build_app_secret("1", ec_pem)

    def test_not_json(self):
        with pytest.raises(ValueError):
            gh.parse_app_secret("glpat-x")


class TestJwt:
    def test_rs256_claims_and_signature(self, pem, rsa_key):
        cfg = gh.parse_app_secret(_secret(pem))
        jwt = gh.app_jwt(cfg, now=1_000_000)
        h, p, s = jwt.split(".")
        assert json.loads(_b64d(h)) == {"alg": "RS256", "typ": "JWT"}
        claims = json.loads(_b64d(p))
        assert claims == {"iat": 1_000_000 - 60, "exp": 1_000_000 + 540, "iss": "12345"}
        assert claims["exp"] - claims["iat"] <= 600  # GitHub's 10-minute ceiling
        rsa_key.public_key().verify(_b64d(s), f"{h}.{p}".encode(), padding.PKCS1v15(),
                                    hashes.SHA256())


# ── Installation token (REST calls stubbed) ─────────────────────────────────


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Opener:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def open(self, req, timeout=None):
        self.calls.append((req.get_method(), req.full_url, dict(req.header_items()),
                           json.loads(req.data) if req.data else None))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return _Resp(json.dumps(r).encode())


def _http_error(code, body=b'{"message": "Not Found"}'):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(body))


class TestInstallationToken:
    def test_discovers_installation_then_mints_scoped_token(self, pem):
        op = _Opener([{"id": 99}, {"token": "ghs_abc"}])
        tok = gh.installation_token(_secret(pem), "https://ghe.example.com/acme/app.git", opener=op)
        assert tok == "ghs_abc"
        (m1, u1, h1, _), (m2, u2, _h2, body) = op.calls
        assert (m1, u1) == ("GET", "https://ghe.example.com/api/v3/repos/acme/app/installation")
        assert h1["Authorization"].startswith("Bearer ey")
        assert (m2, u2) == ("POST", "https://ghe.example.com/api/v3/app/installations/99/access_tokens")
        assert body == {"repositories": ["app"], "permissions": {"contents": "read"}}

    def test_configured_installation_skips_lookup(self, pem):
        op = _Opener([{"token": "ghs_x"}])
        gh.installation_token(_secret(pem, "7"), "https://github.com/acme/app", opener=op)
        assert [c[1] for c in op.calls] == ["https://api.github.com/app/installations/7/access_tokens"]

    def test_not_installed(self, pem):
        op = _Opener([_http_error(404)])
        with pytest.raises(gh.GitHubAppError, match="404"):
            gh.installation_token(_secret(pem), "https://github.com/acme/app", opener=op)

    def test_redirect_refused(self, pem):
        op = _Opener([_http_error(302, b"")])
        with pytest.raises(gh.GitHubAppError, match="redirect"):
            gh.installation_token(_secret(pem), "https://github.com/acme/app", opener=op)

    def test_error_never_contains_jwt(self, pem):
        op = _Opener([_http_error(401, b'{"message": "Bad credentials"}')])
        with pytest.raises(gh.GitHubAppError) as ei:
            gh.installation_token(_secret(pem), "https://github.com/acme/app", opener=op)
        assert "Bad credentials" in str(ei.value)
        assert "eyJ" not in str(ei.value) and "Bearer" not in str(ei.value)


# ── Clone URL + credential guard ────────────────────────────────────────────


def test_clone_url_uses_the_forges_user_name():
    from src.services.forges import get_forge
    from src.webapi.ingestion import build_clone_url
    url = build_clone_url("https://ghe.example.com/acme/app.git", "ghs_t",
                          get_forge("github").clone_username)
    assert url == "https://x-access-token:ghs_t@ghe.example.com/acme/app.git"
    assert get_forge("gitlab").clone_username == "oauth2"
    assert get_forge("upload") is None


class TestGuard:
    def _cred(self, owner, kind="github_app", base="https://ghe.example.com"):
        return Credential(owner_id=owner, kind=kind, label="x", secret_enc=b"x",
                          forge_base_url=base)

    def test_ok(self):
        o = uuid.uuid4()
        validate_github_credential(self._cred(o), o, "https://ghe.example.com/a/b")

    def test_other_host(self):
        o = uuid.uuid4()
        with pytest.raises(CredentialRejected, match="different GitHub host"):
            validate_github_credential(self._cred(o), o, "https://github.com/a/b")

    def test_gitlab_token_not_accepted_for_github(self):
        o = uuid.uuid4()
        with pytest.raises(CredentialRejected):
            validate_repo_credential(self._cred(o, kind="gitlab_token"), o, "github",
                                       "https://ghe.example.com/a/b")

    def test_github_app_not_accepted_for_gitlab(self):
        o = uuid.uuid4()
        with pytest.raises(CredentialRejected):
            validate_repo_credential(self._cred(o), o, "gitlab", "https://ghe.example.com/a/b")

    def test_other_owner(self):
        with pytest.raises(CredentialRejected):
            validate_github_credential(self._cred(uuid.uuid4()), uuid.uuid4(),
                                       "https://ghe.example.com/a/b")


# ── API ─────────────────────────────────────────────────────────────────────


class TestApi:
    async def _h(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        return {"Authorization": f"Bearer {await _token(client, 'u@example.com', PW)}"}

    async def test_create_github_repo_with_app(self, client, session_maker, pem):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github",
            "remote_url": "https://ghe.example.com/acme/app.git",
            "github_app": {"app_id": "12345", "private_key": pem},
        })
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["source_type"] == "github"
        assert body["ingestion_status"] == "importing"
        creds = (await client.get("/credentials", headers=h)).json()
        assert [(c["kind"], c["forge_base_url"]) for c in creds] == [
            ("github_app", "https://ghe.example.com")]
        assert pem not in json.dumps(creds)

    async def test_bad_private_key_is_400(self, client, session_maker):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github",
            "remote_url": "https://github.com/acme/app",
            "github_app": {"app_id": "1", "private_key": "nope"},
        })
        assert r.status_code == 400, r.text

    @pytest.mark.parametrize("url", ["http://github.com/acme/app", "https://github.com/acme",
                                     "file:///x.git"])
    async def test_bad_url_is_422(self, client, session_maker, url):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github", "remote_url": url})
        assert r.status_code == 422, r.text

    async def test_push_patches_rejected_for_github(self, client, session_maker):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github", "remote_url": "https://github.com/a/b",
            "push_patches": True})
        assert r.status_code == 400, r.text

    async def test_github_app_on_gitlab_source_is_422(self, client, session_maker, pem):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gl", "source_type": "gitlab", "remote_url": "https://gl.example.com/g/p",
            "github_app": {"app_id": "1", "private_key": pem}})
        assert r.status_code == 422, r.text

    async def test_github_app_credential_via_credentials_api_is_validated(
            self, client, session_maker, pem):
        h = await self._h(client, session_maker)
        bad = await client.post("/credentials", headers=h, json={
            "kind": "github_app", "label": "x", "secret": "{}"})
        assert bad.status_code == 422, bad.text
        ok = await client.post("/credentials", headers=h, json={
            "kind": "github_app", "label": "x", "secret": _secret(pem),
            "forge_base_url": "https://ghe.example.com"})
        assert ok.status_code == 201, ok.text
        # an existing App credential can be linked to a GitHub repo on that host …
        r = await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github", "remote_url": "https://ghe.example.com/a/b",
            "default_credential_id": ok.json()["id"]})
        assert r.status_code == 201, r.text
        # … but not to one on another host
        r = await client.post("/repositories", headers=h, json={
            "name": "gh2", "source_type": "github", "remote_url": "https://github.com/a/b",
            "default_credential_id": ok.json()["id"]})
        assert r.status_code == 400, r.text

    async def test_webhook_refused_for_github(self, client, session_maker):
        h = await self._h(client, session_maker)
        repo = (await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github",
            "remote_url": "https://github.com/a/b"})).json()
        r = await client.post(f"/repositories/{repo['id']}/webhook", headers=h)
        assert r.status_code == 400, r.text


# ── Personal access tokens ──────────────────────────────────────────────────


class TestPersonalAccessToken:
    async def _h(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        return {"Authorization": f"Bearer {await _token(client, 'u@example.com', PW)}"}

    async def test_create_github_repo_with_token(self, client, session_maker):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github",
            "remote_url": "https://ghe.example.com/acme/app.git",
            "github_token": "ghp_secret",
        })
        assert r.status_code == 201, r.text
        assert r.json()["default_credential_id"] is not None
        creds = (await client.get("/credentials", headers=h)).json()
        assert [(c["kind"], c["forge_base_url"]) for c in creds] == [
            ("github_token", "https://ghe.example.com")]
        assert "ghp_secret" not in json.dumps(creds)

    async def test_token_and_app_together_is_422(self, client, session_maker, pem):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github", "remote_url": "https://github.com/a/b",
            "github_token": "ghp_x", "github_app": {"app_id": "1", "private_key": pem}})
        assert r.status_code == 422, r.text

    async def test_github_token_on_gitlab_source_is_422(self, client, session_maker):
        h = await self._h(client, session_maker)
        r = await client.post("/repositories", headers=h, json={
            "name": "gl", "source_type": "gitlab", "remote_url": "https://gl.example.com/g/p",
            "github_token": "ghp_x"})
        assert r.status_code == 422, r.text

    async def test_replace_token_via_patch(self, client, session_maker):
        h = await self._h(client, session_maker)
        repo = (await client.post("/repositories", headers=h, json={
            "name": "gh", "source_type": "github", "remote_url": "https://github.com/a/b",
            "github_token": "ghp_old"})).json()
        r = await client.patch(f"/repositories/{repo['id']}", headers=h,
                               json={"github_token": "ghp_new"})
        assert r.status_code == 200, r.text
        assert r.json()["default_credential_id"] != repo["default_credential_id"]
        assert r.json()["ingestion_status"] == "importing"

    def test_pat_is_used_as_is(self, monkeypatch):
        from src.webapi.credential_guard import repo_access_token

        class _Vault:
            def decrypt(self, b):
                return b.decode()

        monkeypatch.setattr("src.webapi.security.vault.build_vault", lambda s: _Vault())
        cred = Credential(owner_id=uuid.uuid4(), kind="github_token", label="x",
                          secret_enc=b"ghp_plain", forge_base_url="https://github.com")
        assert repo_access_token(cred, "github", "https://github.com/a/b") == "ghp_plain"

    def test_guard_accepts_pat(self):
        o = uuid.uuid4()
        cred = Credential(owner_id=o, kind="github_token", label="x", secret_enc=b"x",
                          forge_base_url="https://ghe.example.com")
        validate_repo_credential(cred, o, "github", "https://ghe.example.com/a/b")


class TestPushNotYetForGitHub:
    def test_github_forge_does_not_push(self):
        from src.services.forges import get_forge
        assert get_forge("github").supports_push is False
        assert get_forge("gitlab").supports_push is True
