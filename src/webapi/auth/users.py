"""User database adapter and user manager."""
from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncGenerator

from fastapi import Depends
from fastapi_users import BaseUserManager, InvalidPasswordException, UUIDIDMixin
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.db import get_async_session
from src.webapi.models import User
from src.webapi.settings import get_settings

logger = logging.getLogger(__name__)

# Minimum password rules, applied CONSISTENTLY everywhere fastapi-users hashes a
# password (admin user creation, self change-password, reset, forgot-password reset).
MIN_PASSWORD_LENGTH = 10


async def get_user_db(
    session: AsyncSession = Depends(get_async_session),
) -> AsyncGenerator[SQLAlchemyUserDatabase, None]:
    yield SQLAlchemyUserDatabase(session, User)


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    @property
    def reset_password_token_secret(self) -> str:
        return get_settings().jwt_secret

    @property
    def verification_token_secret(self) -> str:
        return get_settings().jwt_secret

    async def validate_password(self, password: str, user) -> None:
        """Password strength rules — enforced on signup, change, and reset alike."""
        if len(password) < MIN_PASSWORD_LENGTH:
            raise InvalidPasswordException(
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
            )
        email = getattr(user, "email", "") or ""
        if email and email.lower() in password.lower():
            raise InvalidPasswordException("Password must not contain your email.")

    async def on_after_forgot_password(self, user: User, token: str, request=None) -> None:
        """Email a single-use, time-limited reset link (best-effort — never raise)."""
        s = get_settings()
        base = s.ui_base_url or ""
        link = f"{base}/reset-password?token={token}"
        body = (
            "A password reset was requested for your Vigilo account.\n\n"
            f"Reset your password here (link expires in "
            f"{self.reset_password_token_lifetime_seconds // 60} minutes):\n{link}\n\n"
            "If you didn't request this, you can ignore this email."
        )
        try:
            from src.webapi.mailer_provider import get_mailer
            get_mailer().send(user.email, "[Vigilo] Reset your password", body, None)
        except Exception as exc:  # pragma: no cover - best-effort
            logger.warning("forgot-password email to %s failed: %s", user.email, exc)

    async def on_after_reset_password(self, user: User, request=None) -> None:
        """After a successful reset, invalidate all existing sessions + audit."""
        await self.user_db.update(user, {"session_epoch": (user.session_epoch or 0) + 1})
        logger.info("Password reset completed for user %s (%s)", user.id, user.email)

    async def on_after_register(self, user: User, request=None) -> None:
        return None


async def get_user_manager(
    user_db: SQLAlchemyUserDatabase = Depends(get_user_db),
) -> AsyncGenerator[UserManager, None]:
    yield UserManager(user_db)
