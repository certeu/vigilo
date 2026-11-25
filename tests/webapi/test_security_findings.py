"""Regression tests for the authorised security assessment (login throttle, token
revocation, repo SSRF guard, weak secrets/passwords, headers, 404 consistency)."""
from __future__ import annotations

import socket

import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from src.webapi.ratelimit import LoginRateLimitMiddleware, client_ip, parse_trusted_proxies
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"
PATH = "/auth/jwt/login"


@pytest.fixture
def set_env(monkeypatch):
    from src.webapi.settings import get_settings

    def _set(name, value):
        monkeypatch.setenv(name, value)
        get_settings.cache_clear()
    return _set


def _h(t):
    return {"Authorization": f"Bearer {t}"}


# ---------------------------------------------------------------- 1. login throttle


def _login_app(max_failures=3, trusted=""):
    async def login(request):
        return JSONResponse({}, status_code=400)
    app = Starlette(routes=[Route(PATH, login, methods=["POST"])])
    app.add_middleware(LoginRateLimitMiddleware, max_failures=max_failures, window_s=300,
                       trusted_proxies=trusted)
    return app


class TestClientIp:
    def test_untrusted_peer_ignores_xff(self):
        assert client_ip("203.0.113.9", "1.2.3.4", []) == "203.0.113.9"
        assert client_ip("203.0.113.9", "1.2.3.4", parse_trusted_proxies("10.0.0.0/8")) == "203.0.113.9"

    def test_trusted_peer_takes_rightmost_untrusted(self):
        nets = parse_trusted_proxies("10.0.0.0/8, 172.18.0.5")
        # client-prepended junk on the left is never believed
        assert client_ip("10.0.0.2", "6.6.6.6, 198.51.100.7", nets) == "198.51.100.7"
        assert client_ip("10.0.0.2", "6.6.6.6, 198.51.100.7, 10.0.0.9", nets) == "198.51.100.7"
        assert client_ip("10.0.0.2", "garbage", nets) == "10.0.0.2"

    def test_bad_cidr_rejected(self):
        with pytest.raises(ValueError):
            parse_trusted_proxies("not-a-cidr")


class TestThrottle:
    def test_spoofed_xff_does_not_reset_ip_counter(self):
        c = TestClient(_login_app(max_failures=3), client=("203.0.113.9", 1))
        codes = [c.post(PATH, data={"username": f"u{i}@x.io", "password": "x"},
                        headers={"X-Forwarded-For": f"9.9.9.{i}"}).status_code
                 for i in range(5)]
        assert codes[:3] == [400] * 3 and codes[3:] == [429, 429]

    def test_per_account_counter_across_many_ips(self):
        app = _login_app(max_failures=3)
        for i in range(3):
            c = TestClient(app, client=(f"203.0.113.{i + 1}", 1))
            assert c.post(PATH, data={"username": "Victim@X.io", "password": "g"}).status_code == 400
        # a brand-new IP, same account (case/space-normalised) is locked out
        c = TestClient(app, client=("198.51.100.1", 1))
        r = c.post(PATH, data={"username": " victim@x.IO ", "password": "g"})
        assert r.status_code == 429 and r.headers.get("Retry-After")
        # another account from that IP is unaffected
        assert c.post(PATH, data={"username": "other@x.io", "password": "g"}).status_code == 400

    def test_trusted_proxy_xff_is_used_for_ip_bucket(self):
        app = _login_app(max_failures=2, trusted="203.0.113.0/24")
        c = TestClient(app, client=("203.0.113.5", 1))
        for _ in range(2):
            c.post(PATH, data={"username": "a@x.io"}, headers={"X-Forwarded-For": "198.51.100.1"})
        assert c.post(PATH, data={"username": "b@x.io"},
                      headers={"X-Forwarded-For": "198.51.100.1"}).status_code == 429
        assert c.post(PATH, data={"username": "c@x.io"},
                      headers={"X-Forwarded-For": "198.51.100.2"}).status_code == 400

    async def test_real_login_body_still_reaches_handler(self, client, session_maker, set_env):
        set_env("VIGILO_LOGIN_MAX_FAILURES", "2")
        from src.webapi.app import create_app
        from httpx import ASGITransport, AsyncClient
        from src.webapi.db import get_async_session
        app = create_app(run_lifespan=False)
        app.dependency_overrides[get_async_session] = client._app.dependency_overrides[get_async_session]
        await _make_user(session_maker, "t@example.com", PW, "user")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            ok = await c.post(PATH, data={"username": "t@example.com", "password": PW})
            assert ok.status_code == 200
            for _ in range(2):
                assert (await c.post(PATH, data={"username": "t@example.com", "password": "nope"})).status_code == 400
            assert (await c.post(PATH, data={"username": "t@example.com", "password": PW})).status_code == 429


# ---------------------------------------------------------------- 4/9. revocation


class TestRevocation:
    async def test_logout_revokes_token(self, client, user_token):
        assert (await client.get("/users/me", headers=_h(user_token))).status_code == 200
        assert (await client.post("/auth/jwt/logout", headers=_h(user_token))).status_code == 204
        assert (await client.get("/users/me", headers=_h(user_token))).status_code == 401

    async def test_deactivation_bumps_epoch(self, client, admin_token, session_maker):
        await _make_user(session_maker, "v@example.com", PW, "user")
        vt = await _token(client, "v@example.com", PW)
        users = (await client.get("/users", headers=_h(admin_token))).json()
        vid = next(u["id"] for u in users if u["email"] == "v@example.com")
        assert (await client.patch(f"/users/{vid}", headers=_h(admin_token),
                                   json={"is_active": False})).status_code == 200
        # re-activate: the OLD token must stay dead (epoch moved), not silently revive
        assert (await client.patch(f"/users/{vid}", headers=_h(admin_token),
                                   json={"is_active": True})).status_code == 200
        assert (await client.get("/users/me", headers=_h(vt))).status_code == 401
        assert (await client.get("/users/me", headers=_h(await _token(client, "v@example.com", PW)))).status_code == 200


# ---------------------------------------------------------------- 6. JWT secret


class TestJwtSecret:
    @pytest.mark.parametrize("secret", ["CHANGE_ME", "short", "x" * 31])
    def test_weak_secret_refuses_to_start(self, secret, set_env):
        set_env("VIGILO_JWT_SECRET", secret)
        set_env("VIGILO_DEV_MODE", "false")
        from src.webapi.app import create_app
        with pytest.raises(RuntimeError, match="VIGILO_JWT_SECRET"):
            create_app(run_lifespan=False)

    def test_dev_mode_allows_weak_secret_and_docs(self, set_env, monkeypatch):
        set_env("VIGILO_JWT_SECRET", "CHANGE_ME")
        set_env("VIGILO_DEV_MODE", "true")
        monkeypatch.delenv("VIGILO_API_DOCS_ENABLED", raising=False)
        from src.webapi.app import create_app
        assert create_app(run_lifespan=False).openapi_url == "/openapi.json"

    def test_strong_secret_ok_and_docs_off_by_default(self, set_env, monkeypatch):
        # the test's own premise: a strong secret (never whatever the developer's
        # environment happens to hold)
        set_env("VIGILO_JWT_SECRET", "s" * 48)
        set_env("VIGILO_DEV_MODE", "false")
        monkeypatch.delenv("VIGILO_API_DOCS_ENABLED", raising=False)
        from src.webapi.settings import get_settings
        get_settings.cache_clear()
        from src.webapi.app import create_app
        app = create_app(run_lifespan=False)
        assert app.openapi_url is None and app.docs_url is None and app.redoc_url is None


# ---------------------------------------------------------------- 7/8. passwords


class TestPasswords:
    async def test_create_user_weak_password_is_400_not_500(self, client, admin_token):
        r = await client.post("/users", headers=_h(admin_token),
                              json={"email": "n@example.com", "password": "short"})
        assert r.status_code == 400 and "10 characters" in r.text

    @pytest.mark.parametrize("pw", ["aaaaaaaaaaaa", "1234567890", "0987654321", "123456789012"])
    async def test_trivial_passwords_rejected(self, client, admin_token, pw):
        r = await client.post("/users", headers=_h(admin_token),
                              json={"email": "n@example.com", "password": pw})
        assert r.status_code == 400

    async def _invite(self, client, admin_token):
        r = await client.post("/invitations", headers=_h(admin_token),
                              json={"email": "inv@example.com", "role": "user"})
        assert r.status_code == 201, r.text
        return r.json()["accept_url"].split("token=")[1]

    async def test_accept_invite_uses_user_manager_rules(self, client, admin_token):
        tok = await self._invite(client, admin_token)
        for bad in ("short123", "aaaaaaaaaaaa", "1234567890", "xinv@example.comx"):
            r = await client.post("/auth/accept-invite", json={"token": tok, "password": bad})
            assert r.status_code == 422, (bad, r.text)
        r = await client.post("/auth/accept-invite", json={"token": tok, "password": PW})
        assert r.status_code == 200
        assert (await _token(client, "inv@example.com", PW))


# ---------------------------------------------------------------- 10. reset fingerprint


async def test_reset_token_carries_fingerprint_not_the_hash(client, admin_token, session_maker):
    import jwt as pyjwt
    from sqlalchemy import select

    from src.webapi.models import User
    await _make_user(session_maker, "r@example.com", PW, "user")
    users = (await client.get("/users", headers=_h(admin_token))).json()
    uid = next(u["id"] for u in users if u["email"] == "r@example.com")
    r = await client.post(f"/users/{uid}/reset-password", headers=_h(admin_token))
    token = r.json()["reset_url"].split("token=")[1]
    claims = pyjwt.decode(token, options={"verify_signature": False, "verify_aud": False})
    async with session_maker() as s:
        stored = (await s.scalars(select(User).where(User.email == "r@example.com"))).one().hashed_password
    assert claims["password_fgpt"] != stored          # a hash OF the hash, salted
    assert stored not in claims["password_fgpt"]


# ---------------------------------------------------------------- 11. headers, docs


class TestHeaders:
    async def test_api_security_headers(self, client):
        r = await client.get("/health")
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert "strict-transport-security" not in r.headers

    async def test_hsts_only_when_enabled(self, set_env, session_maker):
        set_env("VIGILO_HSTS_ENABLED", "true")
        from httpx import ASGITransport, AsyncClient
        from src.webapi.app import create_app
        app = create_app(run_lifespan=False)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            assert "max-age" in (await c.get("/health")).headers["strict-transport-security"]

    async def test_trace_rail_requires_auth(self, client, user_token):
        assert (await client.get("/pipeline/trace-rail")).status_code == 401
        assert (await client.get("/pipeline/trace-rail", headers=_h(user_token))).status_code == 200


# ---------------------------------------------------------------- 13. 404 consistency


class TestNotFoundConsistency:
    async def test_foreign_credential_delete_is_404(self, client, session_maker, user_token):
        await _make_user(session_maker, "o@example.com", PW, "user")
        ot = await _token(client, "o@example.com", PW)
        r = await client.post("/credentials", headers=_h(ot),
                              json={"kind": "cookie_header", "label": "c", "secret": "a=b"})
        assert r.status_code == 201, r.text
        cid = r.json()["id"]
        assert (await client.delete(f"/credentials/{cid}", headers=_h(user_token))).status_code == 404
        missing = "00000000-0000-0000-0000-000000000001"
        assert (await client.delete(f"/credentials/{missing}", headers=_h(user_token))).status_code == 404
        assert (await client.delete(f"/credentials/{cid}", headers=_h(ot))).status_code == 204

    async def test_private_repo_mutations_are_404_for_strangers(self, client, session_maker,
                                                                admin_token, user_token):
        r = await client.post("/repositories", headers=_h(admin_token),
                              json={"name": "priv", "source_type": "upload", "is_private": True})
        assert r.status_code == 201, r.text
        rid = r.json()["id"]
        other = "00000000-0000-0000-0000-000000000009"
        for method, path, body in [
            ("get", f"/repositories/{rid}", None),
            ("patch", f"/repositories/{rid}", {"name": "x"}),
            ("delete", f"/repositories/{rid}", None),
            ("get", f"/repositories/{rid}/access", None),
            ("post", f"/repositories/{rid}/access", {"email": "a@b.io"}),
            ("delete", f"/repositories/{rid}/access/{other}", None),
            ("post", f"/repositories/{rid}/webhook", None),
        ]:
            kw = {"json": body} if body is not None else {}
            resp = await getattr(client, method)(path, headers=_h(user_token), **kw)
            assert resp.status_code == 404, (method, path, resp.status_code)
