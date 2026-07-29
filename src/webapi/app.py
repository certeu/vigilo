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
        try:
            yield
        finally:
            for t in tasks:
                t.cancel()

    app = FastAPI(title="Vigilo Platform API", version="1", lifespan=lifespan)

    # Throttle brute-force login attempts (fastapi-users has none of its own).
    from src.webapi.ratelimit import LoginRateLimitMiddleware
    from src.webapi.settings import get_settings as _get_settings
    _s = _get_settings()
    app.add_middleware(
        LoginRateLimitMiddleware,
        max_failures=_s.login_max_failures,
        window_s=_s.login_failure_window_s,
    )

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

    return app
