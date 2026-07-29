from __future__ import annotations

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.webapi.db import Base, get_async_session
from src.webapi.models import ROLE_ADMIN, ROLE_USER, User
from src.webapi.security.vault import generate_key


@pytest.fixture
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGILO_JWT_SECRET", "test-secret")
    monkeypatch.setenv("VIGILO_FERNET_KEY", generate_key())
    monkeypatch.setenv("VIGILO_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("VIGILO_JOBS_DATA_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("VIGILO_LOGIN_MAX_FAILURES", "0")  # disable login throttle in tests
    from src.webapi.settings import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def engine(_env):
    eng = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_maker(engine):
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@pytest.fixture
def fake_engine():
    from src.webapi.engine.fake import FakeEngine
    return FakeEngine()


@pytest.fixture
def fake_mailer():
    from src.webapi.notifications import FakeMailer
    return FakeMailer()


@pytest.fixture
async def client(engine, session_maker, fake_engine, fake_mailer):
    from src.webapi.app import create_app
    from src.webapi.engine.provider import get_engine
    from src.webapi.mailer_provider import get_mailer

    async def _get_session():
        async with session_maker() as s:
            yield s

    app = create_app(run_lifespan=False)
    app.dependency_overrides[get_async_session] = _get_session
    app.dependency_overrides[get_engine] = lambda: fake_engine
    app.dependency_overrides[get_mailer] = lambda: fake_mailer
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        c._app = app  # expose for tests that swap dependency overrides (e.g. engine)
        yield c


async def _make_user(session_maker, email: str, password: str, role: str) -> None:
    from fastapi_users.password import PasswordHelper
    helper = PasswordHelper()
    async with session_maker() as s:
        s.add(User(
            id=uuid.uuid4(), email=email.lower(),
            hashed_password=helper.hash(password),
            role=role, is_active=True, is_superuser=False, is_verified=True,
        ))
        await s.commit()


async def _token(client: AsyncClient, email: str, password: str) -> str:
    resp = await client.post(
        "/auth/jwt/login",
        data={"username": email, "password": password},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
async def admin_token(client, session_maker):
    await _make_user(session_maker, "admin@example.com", "adminpass123", ROLE_ADMIN)
    return await _token(client, "admin@example.com", "adminpass123")


@pytest.fixture
async def user_token(client, session_maker):
    await _make_user(session_maker, "user@example.com", "userpass123", ROLE_USER)
    return await _token(client, "user@example.com", "userpass123")
