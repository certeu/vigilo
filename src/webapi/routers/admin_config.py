"""Global admin config (models, executor, concurrency, SMTP). Admin-only in M1."""
from __future__ import annotations

import logging
import os
from collections.abc import Mapping

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.auth.deps import current_active_user, require_admin
from src.webapi.db import get_async_session
from src.webapi.models import AdminConfig, User
from src.webapi.schemas import (
    AdminConfigRead,
    AdminConfigUpdate,
    ExecutorStatus,
    ExecutorStatusRead,
    ModelDefaultsRead,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["admin"])


async def _get_or_create(session: AsyncSession) -> AdminConfig:
    cfg = await session.get(AdminConfig, 1)
    if cfg is None:
        cfg = AdminConfig(id=1)
        session.add(cfg)
        await session.commit()
        await session.refresh(cfg)
    return cfg


@router.get("/admin/config", response_model=AdminConfigRead)
async def get_config(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> AdminConfig:
    return await _get_or_create(session)


@router.put("/admin/config", response_model=AdminConfigRead)
async def put_config(
    payload: AdminConfigUpdate,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> AdminConfig:
    cfg = await _get_or_create(session)
    changes: dict[str, str] = {}
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            old = getattr(cfg, field)
            if old != value:
                # smtp_* / numeric fields are not secrets; log old -> new.
                changes[field] = f"{old!r} -> {value!r}"
            setattr(cfg, field, value)
    if changes:
        logger.info("Admin config changed by %s (%s): %s", admin.id, admin.email, changes)
    await session.commit()
    await session.refresh(cfg)
    return cfg


def worker_model_defaults(env: Mapping[str, str] | None = None) -> dict[str, dict[str, str]]:
    """Per executor, the model each tier resolves to when no admin/repo value is set:
    the tier's environment variable (e.g. ANTHROPIC_MEDIUM_MODEL) or the built-in
    default. Read from this process's environment, which the compose setup shares
    with the worker (same .env); a variable set only on the worker is not seen."""
    from src.ai import claude_executor, codex_executor, opencode_executor

    env = os.environ if env is None else env
    out: dict[str, dict[str, str]] = {}
    for name, mod in (("claude", claude_executor), ("codex", codex_executor),
                      ("opencode", opencode_executor)):
        try:
            out[name] = {f"model_{t}": mod.resolve_model(t, env)
                         for t in ("small", "medium", "large")}
        except Exception as exc:  # pragma: no cover - display only
            logger.warning("could not resolve %s worker defaults: %s", name, exc)
    return out


@router.get("/config/models", response_model=ModelDefaultsRead)
async def get_model_defaults(
    _: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> ModelDefaultsRead:
    """Effective global executor/models, so repository settings can show them, plus
    the worker's fallback model per executor and tier."""
    cfg = await _get_or_create(session)
    return ModelDefaultsRead(
        executor=cfg.executor, model_small=cfg.model_small or "",
        model_medium=cfg.model_medium or "", model_large=cfg.model_large or "",
        worker_defaults=worker_model_defaults(),
    )


def _set(env: Mapping[str, str], name: str) -> bool:
    return bool((env.get(name) or "").strip())


def _status(env: Mapping[str, str], executor: str, mode: str | None,
            needs: list[str], detail: str, any_of: bool = False) -> ExecutorStatus:
    present = [n for n in needs if _set(env, n)]
    missing = [n for n in needs if n not in present]
    ok = bool(present) if any_of else not missing
    return ExecutorStatus(executor=executor, configured=ok, mode=mode if ok else None,
                          present=present, missing=[] if ok else missing, detail=detail)


def executor_statuses(env: Mapping[str, str] | None = None) -> list[ExecutorStatus]:
    """Which executors have credentials/endpoints in this process's environment.

    Presence only; values are never read into the result. The API and worker
    share the repo-root .env, but a variable set only on the worker will not be
    visible here, so "not configured" is a warning rather than proof.
    """
    env = os.environ if env is None else env
    out: list[ExecutorStatus] = []

    # claude: direct API key/OAuth token, or Bedrock, or Foundry.
    if _set(env, "CLAUDE_CODE_USE_BEDROCK"):
        out.append(_status(env, "claude", "bedrock",
                           ["AWS_BEARER_TOKEN_BEDROCK", "AWS_ACCESS_KEY_ID", "AWS_PROFILE"],
                           "Claude via AWS Bedrock (needs AWS credentials).", any_of=True))
    elif _set(env, "CLAUDE_CODE_USE_FOUNDRY"):
        out.append(_status(env, "claude", "foundry",
                           ["ANTHROPIC_FOUNDRY_API_KEY"],
                           "Claude via Azure Foundry (needs ANTHROPIC_FOUNDRY_RESOURCE "
                           "or ANTHROPIC_BASE_URL and an API key)."))
    else:
        out.append(_status(env, "claude", "api key",
                           ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"],
                           "Claude via Anthropic API (or set CLAUDE_CODE_USE_BEDROCK / "
                           "CLAUDE_CODE_USE_FOUNDRY).", any_of=True))

    # codex: an OpenAI-compatible endpoint + key (or OPENAI_API_KEY alone).
    codex_key = _set(env, "CODEX_API_KEY") or _set(env, "OPENAI_API_KEY")
    present = [n for n in ("CODEX_BASE_URL", "CODEX_API_KEY", "OPENAI_API_KEY") if _set(env, n)]
    codex_ok = codex_key
    out.append(ExecutorStatus(
        executor="codex", configured=codex_ok,
        mode=("custom endpoint" if _set(env, "CODEX_BASE_URL") else "openai") if codex_ok else None,
        present=present,
        missing=[] if codex_ok else ["CODEX_BASE_URL", "CODEX_API_KEY"],
        detail="Codex needs CODEX_API_KEY (or OPENAI_API_KEY); set CODEX_BASE_URL for a gateway.",
    ))

    # opencode: LiteLLM gateway.
    out.append(_status(env, "opencode", "gateway", ["LITELLM_BASE_URL", "LITELLM_API_KEY"],
                       "OpenCode talks to a LiteLLM gateway."))
    return out


@router.get("/admin/executors/status", response_model=ExecutorStatusRead)
async def get_executor_status(_: User = Depends(require_admin)) -> ExecutorStatusRead:
    """Credential presence per executor (names only, never values)."""
    return ExecutorStatusRead(executors=executor_statuses())
