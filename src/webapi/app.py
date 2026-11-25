"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from src.webapi.auth.backend import auth_backend
from src.webapi.auth.deps import fastapi_users
from src.webapi.routers import (
    admin_config,
    credentials,
    dashboard,
    invitations,
    jobs,
    logs,
    reports,
    repositories,
    runs,
    schedules,
    system,
    users,
    webhooks,
)


def create_app(run_lifespan: bool = True) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        tasks: list = []
        if run_lifespan:
            import asyncio

            import asyncio as _asyncio

            from src.webapi.bootstrap import create_first_admin, seed_admin_config
            from src.webapi.db import _session_maker, create_all
            from src.webapi.engine.provider import get_engine
            from src.webapi.scheduler import scheduler_loop
            from src.webapi.runsvc import run_queue_loop
            from src.webapi.routers.runs import run_status_loop
            from src.webapi.settings import get_settings as _gs
            # Schema management: run Alembic migrations (prod) so an existing DB takes
            # schema changes safely; fall back to create_all only when disabled. A
            # migration failure (e.g. DB ahead of code) raises → the app refuses to start.
            if _gs().run_migrations_on_start:
                from scripts.run_migrations import main as _migrate
                await _asyncio.to_thread(_migrate, ["upgrade"])
            else:
                await create_all()
            await create_first_admin()
            await seed_admin_config()
            # Recover any runs left non-terminal by a previous crash/restart.
            from src.webapi.reconcile import reconcile_runs
            async with _session_maker()() as _s:
                await reconcile_runs(_s, get_engine())
            tasks.append(asyncio.create_task(
                scheduler_loop(_session_maker(), get_engine())
            ))
            tasks.append(asyncio.create_task(
                run_queue_loop(_session_maker(), get_engine())
            ))
            # Refresh in-flight runs + fire completion emails for unattended (e.g.
            # scheduled) runs, without needing anyone to open the run page.
            tasks.append(asyncio.create_task(
                run_status_loop(_session_maker(), get_engine())
            ))
            # Grey-box web platform: the optional in-process executor (dev).
            # Separate process (`python -m src.greybox_web.worker`) is the default.
            _s2 = _gs()
            if _s2.greybox_web_enabled and _s2.greybox_executor == "inprocess":
                from src.greybox_web.worker import worker_loop as _gb_loop
                tasks.append(asyncio.create_task(
                    _gb_loop(_session_maker()), name="greybox-worker"))
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()

    from src.webapi.settings import assert_secure_jwt_secret
    from src.webapi.settings import get_settings as _get_settings
    _s = _get_settings()
    assert_secure_jwt_secret(_s)   # refuse the default / short signing secret

    # Interactive docs + OpenAPI schema: on in dev, off in production unless
    # VIGILO_API_DOCS_ENABLED=true.
    _docs = _s.dev_mode if _s.api_docs_enabled is None else _s.api_docs_enabled
    app = FastAPI(
        title="Vigilo Platform API", version="1", lifespan=lifespan,
        docs_url="/docs" if _docs else None,
        redoc_url="/redoc" if _docs else None,
        openapi_url="/openapi.json" if _docs else None,
    )

    # Throttle brute-force login attempts (fastapi-users has none of its own).
    from src.webapi.ratelimit import LoginRateLimitMiddleware
    from src.webapi.security_headers import SecurityHeadersMiddleware
    app.add_middleware(
        LoginRateLimitMiddleware,
        max_failures=_s.login_max_failures,
        window_s=_s.login_failure_window_s,
        trusted_proxies=_s.trusted_proxies,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=_s.hsts_enabled)  # outermost

    # Logout revokes the token (bumps session_epoch); registered BEFORE fastapi-users'
    # auth router so it takes precedence over that router's no-op logout.
    app.include_router(users.logout_router, prefix="/auth/jwt", tags=["auth"])

    # Auth: /auth/jwt/login, /auth/jwt/logout
    app.include_router(
        fastapi_users.get_auth_router(auth_backend), prefix="/auth/jwt", tags=["auth"]
    )
    # Forgot/reset password: /auth/forgot-password (no enumeration) + /auth/reset-password
    app.include_router(
        fastapi_users.get_reset_password_router(), prefix="/auth", tags=["auth"]
    )
    app.include_router(system.router)
    app.include_router(users.router)
    app.include_router(credentials.router)
    app.include_router(admin_config.router)
    app.include_router(repositories.router)
    app.include_router(jobs.router)
    app.include_router(runs.router)
    app.include_router(logs.router)
    app.include_router(reports.router)
    app.include_router(schedules.router)
    app.include_router(webhooks.router)
    app.include_router(dashboard.router)
    app.include_router(invitations.router)
    # Grey-box web platform (feature-flagged inside the routers; see src/greybox_web/api).
    from src.greybox_web.api import build_routers as _greybox_routers
    for _r in _greybox_routers():
        app.include_router(_r)

    return app
