from __future__ import annotations

import pytest
from sqlalchemy import select

from src.webapi.bootstrap import create_first_admin
from src.webapi.models import ROLE_ADMIN, User
from src.webapi.settings import get_settings
from tests.webapi.conftest import _make_user


@pytest.fixture
def bootstrap_db(monkeypatch, session_maker):
    monkeypatch.setattr(
        "src.webapi.bootstrap._session_maker", lambda: session_maker
    )
    return session_maker


def _set_first_admin(monkeypatch, email: str, password: str = "password123") -> None:
    monkeypatch.setenv("VIGILO_FIRST_ADMIN_EMAIL", email)
    monkeypatch.setenv("VIGILO_FIRST_ADMIN_PASSWORD", password)
    get_settings.cache_clear()


class TestFirstAdminBootstrap:
    async def test_reject_special_use_email(self, monkeypatch, bootstrap_db):
        _set_first_admin(monkeypatch, "admin@vigilo.local")

        with pytest.raises(ValueError, match="VIGILO_FIRST_ADMIN_EMAIL"):
            await create_first_admin()

        async with bootstrap_db() as session:
            assert (await session.scalars(select(User))).all() == []

    @pytest.mark.parametrize("email", ["", "   "])
    async def test_blank_email_skips_bootstrap(self, monkeypatch, bootstrap_db, email):
        _set_first_admin(monkeypatch, email)

        await create_first_admin()

        async with bootstrap_db() as session:
            assert (await session.scalars(select(User))).all() == []

    async def test_stale_legacy_config_does_not_block_existing_admin(
        self, monkeypatch, bootstrap_db
    ):
        await _make_user(
            bootstrap_db, "admin@vigilo.local", "password123", ROLE_ADMIN
        )
        _set_first_admin(monkeypatch, "admin@vigilo.local")

        await create_first_admin()

        async with bootstrap_db() as session:
            assert len((await session.scalars(select(User))).all()) == 1

    async def test_valid_email_creates_admin(self, monkeypatch, bootstrap_db):
        _set_first_admin(monkeypatch, " Admin@Example.com ")

        await create_first_admin()
        await create_first_admin()

        async with bootstrap_db() as session:
            users = (await session.scalars(select(User))).all()
        assert len(users) == 1
        assert users[0].email == "admin@example.com"
        assert users[0].role == ROLE_ADMIN
