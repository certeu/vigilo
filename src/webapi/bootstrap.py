"""Create the first admin from env on startup, if configured."""
from __future__ import annotations

from fastapi_users.password import PasswordHelper
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select

from src.webapi.db import _session_maker
from src.webapi.models import ROLE_ADMIN, AdminConfig, User
from src.webapi.settings import get_settings


_EMAIL_ADAPTER = TypeAdapter(EmailStr)


async def create_first_admin() -> None:
    s = get_settings()
    email = (s.first_admin_email or "").strip().lower()
    if not (email and s.first_admin_password):
        return
    async with _session_maker()() as session:
        existing = await session.scalar(select(User).where(User.email == email))
        if existing is not None:
            return
        try:
            email = _EMAIL_ADAPTER.validate_python(email)
        except ValidationError as exc:
            raise ValueError(
                "VIGILO_FIRST_ADMIN_EMAIL must be a valid, non-special-use email address"
            ) from exc
        session.add(User(
            email=email,
            hashed_password=PasswordHelper().hash(s.first_admin_password),
            role=ROLE_ADMIN, is_active=True, is_superuser=True, is_verified=True,
        ))
        await session.commit()


def _seed_models(s) -> dict[str, str]:
    """First-boot executor + models for admin_config.

    The executor is ``VIGILO_DEFAULT_EXECUTOR`` when set, else what the worker
    would auto-detect from the same environment (``get_executor_type``: explicit
    ``VIGILO_EXECUTOR``, else codex / opencode signal variables, else claude).

    Model names are seeded only when explicitly configured (``VIGILO_DEFAULT_MODEL_*``
    or that executor's tier variable, e.g. ``CODEX_LARGE_MODEL``). Otherwise the
    value is ``""`` meaning "defer to the worker": its own tier variables and
    built-ins apply (including the Bedrock IDs ``resolve_model`` builds), instead
    of a hard-coded name being pinned onto every run.
    """
    import os

    from src.types.config import EXECUTOR_MODEL_ENV

    env = os.environ
    fields_set = getattr(s, "model_fields_set", set())
    executor = (env.get("VIGILO_DEFAULT_EXECUTOR")
                or (s.default_executor if "default_executor" in fields_set else "")).strip().lower()
    if executor not in EXECUTOR_MODEL_ENV:
        try:
            from src.ai.executor import get_executor_type
            executor = get_executor_type(env)
        except Exception:  # API image without the executor modules
            executor = (env.get("VIGILO_EXECUTOR") or "claude").strip().lower()
        if executor not in EXECUTOR_MODEL_ENV:
            executor = "claude"
    seeded = {"executor": executor}
    for key, var in EXECUTOR_MODEL_ENV[executor].items():
        explicit = env.get(f"VIGILO_DEFAULT_{key.upper()}")
        if not explicit and f"default_{key}" in fields_set:
            explicit = getattr(s, f"default_{key}", "")
        seeded[key] = (explicit or env.get(var) or "").strip()
    return seeded


async def seed_admin_config() -> None:
    """Create the singleton admin_config row from .env defaults if absent."""
    s = get_settings()
    async with _session_maker()() as session:
        cfg = await session.get(AdminConfig, 1)
        if cfg is not None:
            return
        seeded = _seed_models(s)
        session.add(AdminConfig(
            id=1, model_small=seeded["model_small"], model_medium=seeded["model_medium"],
            model_large=seeded["model_large"], executor=seeded["executor"],
            default_max_concurrent_pipelines=s.default_max_concurrent_pipelines,
            global_concurrent_run_cap=s.global_concurrent_run_cap,
            smtp_host=s.smtp_host, smtp_from=s.smtp_from,
        ))
        await session.commit()
