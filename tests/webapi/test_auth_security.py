"""Auth hardening: password hashing + no login user-enumeration."""
from __future__ import annotations

from sqlalchemy import select

from src.webapi.models import User
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


class TestPasswordHashing:
    async def test_password_is_hashed_not_reversible(self, client, session_maker):
        await _make_user(session_maker, "u@example.com", PW, "user")
        async with session_maker() as s:
            u = (await s.scalars(select(User).where(User.email == "u@example.com"))).first()
        # stored hash must not be the plaintext and must be a modern KDF (argon2/bcrypt)
        assert u.hashed_password != PW
        assert PW not in u.hashed_password
        assert u.hashed_password.startswith(("$argon2", "$2b$", "$2a$")), u.hashed_password[:12]
        # and it verifies
        from fastapi_users.password import PasswordHelper
        ok, _ = PasswordHelper().verify_and_update(PW, u.hashed_password)
        assert ok is True


class TestNoUserEnumeration:
    async def test_unknown_email_and_wrong_password_are_indistinguishable(self, client, session_maker):
        await _make_user(session_maker, "real@example.com", PW, "user")
        wrong_pw = await client.post("/auth/jwt/login",
                                     data={"username": "real@example.com", "password": "totally-wrong"})
        unknown = await client.post("/auth/jwt/login",
                                    data={"username": "ghost@example.com", "password": "totally-wrong"})
        # identical status + identical body -> an attacker can't tell which emails exist
        assert wrong_pw.status_code == unknown.status_code
        assert wrong_pw.json() == unknown.json()
        # and neither leaks whether the account exists in the message
        assert "not found" not in wrong_pw.text.lower()
        assert "not found" not in unknown.text.lower()

    async def test_correct_login_still_works(self, client, session_maker):
        await _make_user(session_maker, "real@example.com", PW, "user")
        tok = await _token(client, "real@example.com", PW)
        assert tok
