"""User endpoints: self (/users/me) + admin management."""
from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi_users import InvalidPasswordException
from fastapi_users.exceptions import UserAlreadyExists
from fastapi_users.jwt import generate_jwt
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.auth.backend import get_jwt_strategy
from src.webapi.auth.deps import current_active_user, require_admin
from src.webapi.auth.users import UserManager, get_user_manager
from src.webapi.db import get_async_session
from src.webapi.mailer_provider import get_mailer
from src.webapi.models import ROLE_ADMIN, Repository, User
from src.webapi.notifications import FakeMailer
from src.webapi.schemas import (
    AdminResetResult,
    ChangePassword,
    TokenResponse,
    UserCreate,
    UserRead,
    UserUpdate,
)
from src.webapi.settings import get_settings

router = APIRouter(tags=["users"])
logger = logging.getLogger(__name__)


async def _other_active_admins(session: AsyncSession, exclude_id: uuid.UUID) -> int:
    """Count active admins other than ``exclude_id`` — guards against lockout."""
    return await session.scalar(
        select(func.count()).select_from(User).where(
            User.role == ROLE_ADMIN, User.is_active.is_(True), User.id != exclude_id
        )
    )


@router.get("/users/me", response_model=UserRead)
async def read_me(user: User = Depends(current_active_user)) -> User:
    return user


@router.post("/users/me/change-password", response_model=TokenResponse)
async def change_password(
    payload: ChangePassword,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
    manager: UserManager = Depends(get_user_manager),
) -> TokenResponse:
    """Change your own password. Requires the current password, enforces the same
    strength rules as signup, invalidates all OTHER sessions, and returns a fresh
    token so this session stays logged in."""
    # 1. Re-prove identity with the current password (constant-time verify).
    verified, _ = manager.password_helper.verify_and_update(
        payload.current_password, user.hashed_password
    )
    if not verified:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    # 2. Enforce strength rules (same path as signup/reset).
    try:
        await manager.validate_password(payload.new_password, user)
    except InvalidPasswordException as exc:
        raise HTTPException(status_code=400, detail=exc.reason)
    # 3. Hash via the SAME helper used at signup; bump epoch to kill other sessions.
    user.hashed_password = manager.password_helper.hash(payload.new_password)
    user.session_epoch = (user.session_epoch or 0) + 1
    await session.commit()
    await session.refresh(user)
    logger.info("User %s (%s) changed their password", user.id, user.email)
    # 4. Issue a fresh token carrying the new epoch so THIS session survives.
    token = await get_jwt_strategy().write_token(user)
    return TokenResponse(access_token=token)


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreate,
    _: User = Depends(require_admin),
    manager: UserManager = Depends(get_user_manager),
) -> User:
    try:
        return await manager.create(payload, safe=False)
    except UserAlreadyExists:
        raise HTTPException(status_code=409, detail="Email already registered")


@router.get("/users", response_model=list[UserRead])
async def list_users(
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> list[User]:
    return list((await session.scalars(select(User))).all())


@router.patch("/users/{user_id}", response_model=UserRead)
async def patch_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> User:
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    data = payload.model_dump(exclude_unset=True)
    new_role = data.get("role", target.role)
    new_active = data.get("is_active", target.is_active)
    # Never let the last active admin be deactivated or demoted (lockout guard).
    was_active_admin = target.role == ROLE_ADMIN and target.is_active
    still_active_admin = new_role == ROLE_ADMIN and new_active
    if was_active_admin and not still_active_admin:
        if await _other_active_admins(session, target.id) == 0:
            raise HTTPException(
                status_code=400,
                detail="Cannot deactivate or demote the last active admin",
            )
    if data.get("role") is not None:
        target.role = data["role"]
    if data.get("is_active") is not None:
        target.is_active = data["is_active"]
    await session.commit()
    await session.refresh(target)
    return target


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: uuid.UUID,
    _: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
) -> None:
    target = await session.get(User, user_id)
    if target is None:
        return
    # Lockout guard: never hard-delete the last active admin.
    if target.role == ROLE_ADMIN and target.is_active:
        if await _other_active_admins(session, target.id) == 0:
            raise HTTPException(status_code=400, detail="Cannot delete the last active admin")
    # Keep-data default: refuse to hard-delete a user who still owns repositories
    # (would orphan/cascade their data). Deactivate them instead (PATCH is_active=false),
    # which preserves their repos/runs under a disabled account.
    owns = await session.scalar(
        select(func.count()).select_from(Repository).where(Repository.created_by == target.id)
    )
    if owns:
        raise HTTPException(
            status_code=409,
            detail="User owns repositories; deactivate the user instead "
                   "(or delete/reassign their repositories first).",
        )
    await session.delete(target)
    await session.commit()


@router.post("/users/{user_id}/reset-password", response_model=AdminResetResult)
async def admin_reset_password(
    user_id: uuid.UUID,
    admin: User = Depends(require_admin),
    session: AsyncSession = Depends(get_async_session),
    manager: UserManager = Depends(get_user_manager),
) -> AdminResetResult:
    """Admin-triggered password reset: mints a single-use, time-limited reset link
    (mirrors the invite-link pattern), emails it, and immediately invalidates the
    target's existing sessions. Audited. Admin-only (require_admin)."""
    target = await session.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found")
    # Mint a reset token identical to fastapi-users' forgot-password token so the
    # public /auth/reset-password endpoint accepts it. The password fingerprint makes
    # it single-use (invalid once the password changes); lifetime makes it expire.
    token = generate_jwt(
        {
            "sub": str(target.id),
            "password_fgpt": manager.password_helper.hash(target.hashed_password),
            "aud": manager.reset_password_token_audience,
        },
        manager.reset_password_token_secret,
        manager.reset_password_token_lifetime_seconds,
    )
    link = f"{(get_settings().ui_base_url or '')}/reset-password?token={token}"
    # Invalidate the target's current sessions right now (kick them out).
    target.session_epoch = (target.session_epoch or 0) + 1
    await session.commit()
    # Audit (security-sensitive): who reset whom, when (timestamp via log record).
    logger.info(
        "Admin %s (%s) triggered a password reset for user %s (%s)",
        admin.id, admin.email, target.id, target.email,
    )
    # Best-effort email of the link (still return it so the admin can share manually).
    mailer = get_mailer()
    email_sent, email_error = False, None
    body = (
        f"An administrator initiated a password reset for your Vigilo account.\n\n"
        f"Set a new password here (link expires soon):\n{link}\n"
    )
    try:
        mailer.send(target.email, "[Vigilo] Password reset", body, None)
        email_sent = not isinstance(mailer, FakeMailer)
        if not email_sent:
            email_error = "SMTP not configured"
    except Exception as exc:
        email_error = f"Email send failed: {type(exc).__name__}: {str(exc)[:200]}"
        logger.warning("admin reset email to %s failed: %s", target.email, exc)
    return AdminResetResult(reset_url=link, email_sent=email_sent, email_error=email_error)
