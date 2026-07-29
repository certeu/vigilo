from __future__ import annotations

from src.webapi.models import ROLE_USER
from tests.webapi.conftest import _make_user


class TestAuthFlow:
    async def test_login_returns_token(self, client, session_maker):
        await _make_user(session_maker, "z@example.com", "passpass123", ROLE_USER)
        resp = await client.post("/auth/jwt/login",
                                 data={"username": "z@example.com", "password": "passpass123"})
        assert resp.status_code == 200
        assert "access_token" in resp.json()

    async def test_me_requires_auth(self, client):
        resp = await client.get("/users/me")
        assert resp.status_code == 401

    async def test_me_returns_current_user(self, client, user_token):
        resp = await client.get("/users/me",
                                headers={"Authorization": f"Bearer {user_token}"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["email"] == "user@example.com"
        assert body["role"] == "user"
