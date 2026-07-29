"""Password change / admin reset / forgot-password: strength, session invalidation, ACL."""
from __future__ import annotations

from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"          # 12 chars, meets the >=10 rule
NEWPW = "Newpassw0rd!456"


def _h(t):
    return {"Authorization": f"Bearer {t}"}


async def _login(client, session_maker, email, role="user"):
    await _make_user(session_maker, email, PW, role)
    return await _token(client, email, PW)


class TestSelfChangePassword:
    async def test_wrong_current_password_rejected(self, client, session_maker):
        tok = await _login(client, session_maker, "u@example.com")
        r = await client.post("/users/me/change-password", headers=_h(tok),
                              json={"current_password": "wrong-one", "new_password": NEWPW})
        assert r.status_code == 400 and "current password" in r.text.lower()

    async def test_weak_new_password_rejected(self, client, session_maker):
        tok = await _login(client, session_maker, "u@example.com")
        r = await client.post("/users/me/change-password", headers=_h(tok),
                              json={"current_password": PW, "new_password": "short"})
        assert r.status_code == 400 and "10 characters" in r.text
        # and the raw password never echoed back
        assert "short" not in r.text

    async def test_change_invalidates_other_sessions_keeps_this_one(self, client, session_maker):
        # session A + session B are two independent logins for the same user.
        tokA = await _login(client, session_maker, "u@example.com")
        tokB = await _token(client, "u@example.com", PW)
        assert (await client.get("/users/me", headers=_h(tokA))).status_code == 200
        # change password using session B -> returns a fresh token for B
        r = await client.post("/users/me/change-password", headers=_h(tokB),
                              json={"current_password": PW, "new_password": NEWPW})
        assert r.status_code == 200
        newB = r.json()["access_token"]
        # OTHER session (A) is now invalidated; the stale B token is too; the fresh one works
        assert (await client.get("/users/me", headers=_h(tokA))).status_code == 401
        assert (await client.get("/users/me", headers=_h(tokB))).status_code == 401
        assert (await client.get("/users/me", headers=_h(newB))).status_code == 200

    async def test_new_password_actually_hashed_and_usable(self, client, session_maker):
        tok = await _login(client, session_maker, "u@example.com")
        await client.post("/users/me/change-password", headers=_h(tok),
                          json={"current_password": PW, "new_password": NEWPW})
        # old password no longer logs in; new one does
        assert (await client.post("/auth/jwt/login",
                data={"username": "u@example.com", "password": PW})).status_code == 400
        assert (await client.post("/auth/jwt/login",
                data={"username": "u@example.com", "password": NEWPW})).status_code == 200


class TestAdminReset:
    async def test_non_admin_cannot_reset_directly(self, client, session_maker):
        await _login(client, session_maker, "admin@example.com", role="admin")
        user = await _login(client, session_maker, "user@example.com")
        from sqlalchemy import select
        from src.webapi.models import User
        async with session_maker() as s:
            admin_id = (await s.scalars(select(User).where(User.email == "admin@example.com"))).first().id
        # a plain user hitting the endpoint directly -> 403 (not just hidden in UI)
        r = await client.post(f"/users/{admin_id}/reset-password", headers=_h(user))
        assert r.status_code == 403

    async def test_admin_reset_invalidates_sessions_and_link_works(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        member = await _login(client, session_maker, "member@example.com")
        from sqlalchemy import select
        from src.webapi.models import User
        async with session_maker() as s:
            member_id = (await s.scalars(select(User).where(User.email == "member@example.com"))).first().id
        assert (await client.get("/users/me", headers=_h(member))).status_code == 200
        # admin triggers reset
        r = await client.post(f"/users/{member_id}/reset-password", headers=_h(admin))
        assert r.status_code == 200
        reset_url = r.json()["reset_url"]
        assert "token=" in reset_url and PW not in r.text
        # member's existing session is now invalidated
        assert (await client.get("/users/me", headers=_h(member))).status_code == 401
        # the reset link works: set a new password via the public reset endpoint
        token = reset_url.split("token=")[1]
        rr = await client.post("/auth/reset-password", json={"token": token, "password": NEWPW})
        assert rr.status_code == 200, rr.text
        # member logs in with the new password
        assert (await client.post("/auth/jwt/login",
                data={"username": "member@example.com", "password": NEWPW})).status_code == 200


class TestForgotPassword:
    async def test_no_user_enumeration(self, client, session_maker):
        await _login(client, session_maker, "real@example.com")
        known = await client.post("/auth/forgot-password", json={"email": "real@example.com"})
        unknown = await client.post("/auth/forgot-password", json={"email": "ghost@example.com"})
        # identical response whether or not the email exists
        assert known.status_code == unknown.status_code == 202
        assert known.text == unknown.text
