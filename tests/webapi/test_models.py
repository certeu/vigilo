from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.webapi.db import Base
from src.webapi.models import AdminConfig, Credential, ROLE_ADMIN, User


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with maker() as s:
        yield s
    await engine.dispose()


class TestModels:
    async def test_create_user_with_role(self, session):
        u = User(
            id=uuid.uuid4(), email="a@x.eu", hashed_password="h", role=ROLE_ADMIN,
            is_active=True, is_superuser=False, is_verified=True,
        )
        session.add(u)
        await session.commit()
        assert u.role == "admin"

    async def test_credential_stores_bytes(self, session):
        owner = uuid.uuid4()
        c = Credential(id=uuid.uuid4(), owner_id=owner, kind="gitlab_token",
                       label="tok", secret_enc=b"\x00\x01", gitlab_base_url="https://gl")
        session.add(c)
        await session.commit()
        assert c.secret_enc == b"\x00\x01"

    async def test_admin_config_singleton_id(self, session):
        cfg = AdminConfig(id=1, model_small="haiku", model_medium="sonnet",
                          model_large="opus", executor="claude")
        session.add(cfg)
        await session.commit()
        assert cfg.id == 1
