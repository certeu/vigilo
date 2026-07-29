"""Create the first admin from env on startup, if configured."""
from __future__ import annotations

from fastapi_users.password import PasswordHelper
from sqlalchemy import select

from src.webapi.db import _session_maker
from src.webapi.models import ROLE_ADMIN, AdminConfig, User
from src.webapi.settings import get_settings


async def create_first_admin() -> None:
    s = get_settings()
    if not (s.first_admin_email and s.first_admin_password):
        return
    email = s.first_admin_email.lower()
    async with _session_maker()() as session:
        existing = await session.scalar(select(User).where(User.email == email))
        if existing is not None:
            return
        session.add(User(
            email=email,
            hashed_password=PasswordHelper().hash(s.first_admin_password),
            role=ROLE_ADMIN, is_active=True, is_superuser=True, is_verified=True,
        ))
        await session.commit()


async def seed_admin_config() -> None:
    """Create the singleton admin_config row from .env defaults if absent."""
    s = get_settings()
    async with _session_maker()() as session:
        cfg = await session.get(AdminConfig, 1)
        if cfg is not None:
            return
        session.add(AdminConfig(
            id=1, model_small=s.default_model_small, model_medium=s.default_model_medium,
            model_large=s.default_model_large, executor=s.default_executor,
            default_max_concurrent_pipelines=s.default_max_concurrent_pipelines,
            global_concurrent_run_cap=s.global_concurrent_run_cap,
            smtp_host=s.smtp_host, smtp_from=s.smtp_from,
        ))
        await session.commit()
