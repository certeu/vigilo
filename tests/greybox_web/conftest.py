"""Grey-box web fixtures: platform API fixtures (ASGI client, admin/user tokens)
over a per-test FILE SQLite database, with the grey-box flag on and private
targets allowed. Only the synthetic 127.0.0.1 target is ever requested.
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest

from src.webapi.models import ROLE_USER
from src.webapi.security.vault import generate_key
from tests.webapi.conftest import (  # noqa: F401  (pytest fixtures)
    _make_user,
    _token,
    admin_token,
    fake_engine,
    fake_mailer,
    user_token,
)


@pytest.fixture(autouse=True)
def _sandbox_isolation_off_linux(monkeypatch):
    """OS isolation for agent-written code (bubblewrap / user namespaces) is
    Linux-only, and in ``auto`` mode the sandbox correctly REFUSES to run code
    without it. On a developer's macOS/Windows host that made every test that runs
    a generated tool fail with ``IsolationUnavailable``. There, use the
    interpreter-level ``process`` mode so tool behaviour (broker, quotas, prelude
    escape blocking) is still exercised; Linux/CI keeps ``auto`` and runs the real
    namespaces. An explicit VIGILO_GREYBOX_SANDBOX_ISOLATION, or a test's own
    monkeypatch (e.g. the refusal test), always wins."""
    from src.greybox_web import sandbox
    if sys.platform != "linux" and not os.environ.get(sandbox.ISOLATION_ENV):
        monkeypatch.setenv(sandbox.ISOLATION_ENV, "process")


# ------------------------------------------------------------------ engine/client
#
# The grey-box engine writes from concurrent tasks (supervisor, heartbeat,
# watcher, per-exchange recorder) while the API serves reads. The platform's
# in-memory SQLite uses StaticPool — ONE connection shared by every session —
# which cannot carry concurrent transactions, so grey-box tests use a
# per-test FILE database with one connection per session (like production
# Postgres) and WAL so readers never block the engine's short writes.


@pytest.fixture
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv("VIGILO_JWT_SECRET", "test-secret-0123456789-abcdefghijklmnopqrstuvwxyz")
    monkeypatch.setenv("VIGILO_FERNET_KEY", generate_key())
    monkeypatch.setenv("VIGILO_DATABASE_URL", "sqlite+aiosqlite:///:memory:")
    monkeypatch.setenv("VIGILO_JOBS_DATA_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("VIGILO_UPLOADS_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("VIGILO_LOGIN_MAX_FAILURES", "0")
    monkeypatch.setenv("VIGILO_GREYBOX_WEB_ENABLED", "true")
    monkeypatch.setenv("VIGILO_GREYBOX_ALLOW_PRIVATE_TARGETS", "true")
    # the grey-box engine is model-driven: tests run on the deterministic fake model
    # (never the real keys of a developer .env)
    monkeypatch.setenv("VIGILO_DEV_MODE", "true")
    monkeypatch.setenv("VIGILO_IGNORE_DOTENV", "1")
    # The whole suite runs on the fake model backend (dev mode only): no real keys,
    # and never the maintainer's repo .env / shell provider variables.
    monkeypatch.setenv("VIGILO_DEV_MODE", "true")
    from src.greybox_web import modelsel
    monkeypatch.setattr(modelsel, "load_env", lambda: {})
    from src.webapi.settings import get_settings
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
async def engine(_env, tmp_path):
    from sqlalchemy import event
    from sqlalchemy.ext.asyncio import create_async_engine
    from src.webapi.db import Base
    import src.webapi.models  # noqa: F401  (registers all models on Base)

    url = f"sqlite+aiosqlite:///{tmp_path / 'greybox-test.db'}"
    eng = create_async_engine(url, connect_args={"timeout": 10})

    @event.listens_for(eng.sync_engine, "connect")
    def _wal(dbapi_conn, _record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=10000")
        cursor.close()

    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture
def session_maker(engine):
    from sqlalchemy.ext.asyncio import async_sessionmaker, AsyncSession
    return async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


@pytest.fixture
async def client(engine, session_maker, fake_engine, fake_mailer):
    from httpx import ASGITransport, AsyncClient
    from src.webapi.app import create_app
    from src.webapi.db import get_async_session
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
        c._app = app
        yield c


@pytest.fixture
def set_env(monkeypatch):
    """Change a VIGILO_ setting mid-test (the settings cache is cleared)."""
    from src.webapi.settings import get_settings

    def _set(name: str, value: str) -> None:
        monkeypatch.setenv(name, value)
        get_settings.cache_clear()

    return _set


def h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def other_user_token(client, session_maker, email="other@example.com") -> str:
    await _make_user(session_maker, email, "otherpass123", ROLE_USER)
    return await _token(client, email, "otherpass123")


async def user_id(session_maker, email: str) -> uuid.UUID:
    from sqlalchemy import select

    from src.webapi.models import User
    async with session_maker() as s:
        return (await s.scalars(select(User).where(User.email == email))).one().id


TARGET_URL = "http://127.0.0.1:43123/"


def target_body(**over):
    body = {"name": "demo-app", "base_url": TARGET_URL}
    body.update(over)
    return body


async def create_target(client, token, **over) -> dict:
    r = await client.post("/greybox/targets", headers=h(token), json=target_body(**over))
    assert r.status_code == 201, r.text
    return r.json()


# ------------------------------------------------------------ live synthetic target


@pytest.fixture
def target_server():
    """The synthetic target on an ephemeral 127.0.0.1 port, with a
    per-path request counter. This is the only target tests ever request."""
    from types import SimpleNamespace

    from tests.greybox_web.fixtures import target_app
    target_app.reset_counts()
    server, url = target_app.serve()
    yield SimpleNamespace(server=server, url=url,
                          counts=target_app.counts,
                          reset=target_app.reset_counts)
    server.should_exit = True


@pytest.fixture
def spa_server():
    """The JavaScript-driven SPA fixture (``fixtures/spa_app.py``): pages, routes and
    API calls exist only after the bundle runs. The only target the SPA acceptance
    tests request."""
    from types import SimpleNamespace

    from tests.greybox_web.fixtures import spa_app
    spa_app.reset_counts()
    server, url = spa_app.serve()
    yield SimpleNamespace(server=server, url=url, counts=spa_app.counts,
                          reset=spa_app.reset_counts)
    server.should_exit = True


@pytest.fixture
def idp_server():
    """The SSO-protected application fixture (``fixtures/idp_app.py``): an invalid
    session is redirected to an out-of-scope identity provider."""
    from types import SimpleNamespace

    from tests.greybox_web.fixtures import idp_app
    idp_app.reset_counts()
    server, url = idp_app.serve()
    yield SimpleNamespace(server=server, url=url, counts=idp_app.counts,
                          reset=idp_app.reset_counts, idp_host=idp_app.IDP_HOST)
    server.should_exit = True


FAST_LIMITS = {"rate_limit_rps": 50, "max_requests": 400, "request_timeout_s": 5,
               "max_duration_s": 120, "max_pages": 50,
               "max_concurrency": 4}
LIMITS_USE = FAST_LIMITS   # alias used by lease tests (no run is executed)


@pytest.fixture
async def live_target(client, user_token, target_server):
    """A target pointing at the live synthetic app, with fast test limits."""
    body = target_body(base_url=target_server.url, limits=dict(FAST_LIMITS))
    r = await client.post("/greybox/targets", headers=h(user_token), json=body)
    assert r.status_code == 201, r.text
    return r.json()


async def start_run(client, token, target_id, *, key=None, checks=None,
                    base_url=None, scope=None, executor_ok=True) -> object:
    """POST .../runs helper returning the raw response."""
    if base_url is not None or checks is not None or scope is not None:
        body = {"name": "demo-app", "base_url": base_url or TARGET_URL}
        if checks is not None:
            body["checks"] = checks
        if scope is not None:
            body["scope"] = scope
        r = await client.post("/greybox/targets", headers=h(token), json=body)
        assert r.status_code == 201, r.text
        target_id = r.json()["id"]
    payload = {"authorization_confirmed": True}
    if key is not None:
        payload["idempotency_key"] = key
    return await client.post(f"/greybox/targets/{target_id}/runs",
                             headers=h(token), json=payload)


async def run_worker_once(session_maker, **kw):
    from src.greybox_web.worker import run_once
    return await run_once(session_maker, **kw)
