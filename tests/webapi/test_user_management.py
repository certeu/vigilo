"""Admin user removal/deactivation: access control + last-admin lockout guard."""
from __future__ import annotations

import uuid

from sqlalchemy import select

from src.webapi.models import Repository, User
from tests.webapi.conftest import _make_user, _token

PW = "Passw0rd!123"


async def _login(client, session_maker, email, role="user"):
    await _make_user(session_maker, email, PW, role)
    return await _token(client, email, PW)


def _h(t):
    return {"Authorization": f"Bearer {t}"}


async def _uid(session_maker, email):
    async with session_maker() as s:
        u = (await s.scalars(select(User).where(User.email == email.lower()))).first()
        return str(u.id)


class TestAccessControl:
    async def test_non_admin_cannot_deactivate_or_delete_users(self, client, session_maker):
        await _login(client, session_maker, "admin@example.com", role="admin")
        user = await _login(client, session_maker, "user@example.com")
        victim_id = await _uid(session_maker, "admin@example.com")
        # a plain user hitting the admin endpoints directly is rejected server-side
        assert (await client.patch(f"/users/{victim_id}", headers=_h(user),
                                   json={"is_active": False})).status_code == 403
        assert (await client.delete(f"/users/{victim_id}", headers=_h(user))).status_code == 403


class TestDeactivation:
    async def test_admin_deactivates_accepted_user_keeps_their_data(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        member = await _login(client, session_maker, "member@example.com")
        # member owns a repo
        rid = (await client.post("/repositories", headers=_h(member),
               json={"name": "keep", "source_type": "upload"})).json()["id"]
        member_id = await _uid(session_maker, "member@example.com")

        r = await client.patch(f"/users/{member_id}", headers=_h(admin), json={"is_active": False})
        assert r.status_code == 200 and r.json()["is_active"] is False
        # data kept (owner reference intact), just under a disabled account
        async with session_maker() as s:
            assert await s.get(Repository, uuid.UUID(rid)) is not None
            assert (await s.get(User, uuid.UUID(member_id))).is_active is False
        # deactivated user can no longer log in
        bad = await client.post("/auth/jwt/login", data={"username": "member@example.com", "password": PW})
        assert bad.status_code == 400

    async def test_reactivate(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        await _login(client, session_maker, "m@example.com")
        mid = await _uid(session_maker, "m@example.com")
        await client.patch(f"/users/{mid}", headers=_h(admin), json={"is_active": False})
        r = await client.patch(f"/users/{mid}", headers=_h(admin), json={"is_active": True})
        assert r.json()["is_active"] is True


class TestLastAdminGuard:
    async def test_cannot_deactivate_last_admin(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        admin_id = await _uid(session_maker, "admin@example.com")
        r = await client.patch(f"/users/{admin_id}", headers=_h(admin), json={"is_active": False})
        assert r.status_code == 400

    async def test_cannot_demote_last_admin(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        admin_id = await _uid(session_maker, "admin@example.com")
        r = await client.patch(f"/users/{admin_id}", headers=_h(admin), json={"role": "user"})
        assert r.status_code == 400

    async def test_can_deactivate_admin_when_another_exists(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        await _login(client, session_maker, "admin2@example.com", role="admin")
        a2 = await _uid(session_maker, "admin2@example.com")
        r = await client.patch(f"/users/{a2}", headers=_h(admin), json={"is_active": False})
        assert r.status_code == 200


class TestHardDeleteGuards:
    async def test_delete_user_owning_repos_is_409(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        member = await _login(client, session_maker, "member@example.com")
        await client.post("/repositories", headers=_h(member),
                          json={"name": "owned", "source_type": "upload"})
        mid = await _uid(session_maker, "member@example.com")
        r = await client.delete(f"/users/{mid}", headers=_h(admin))
        assert r.status_code == 409  # steer to deactivation, don't orphan data

    async def test_delete_user_without_data_ok(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        await _login(client, session_maker, "nodata@example.com")
        nid = await _uid(session_maker, "nodata@example.com")
        assert (await client.delete(f"/users/{nid}", headers=_h(admin))).status_code == 204

    async def test_cannot_delete_last_admin(self, client, session_maker):
        admin = await _login(client, session_maker, "admin@example.com", role="admin")
        aid = await _uid(session_maker, "admin@example.com")
        assert (await client.delete(f"/users/{aid}", headers=_h(admin))).status_code == 400
