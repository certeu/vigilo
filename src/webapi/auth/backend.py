"""JWT auth backend with per-user session invalidation.

Plain JWTs are stateless and can't be revoked. We embed the user's ``session_epoch``
as a claim; on every request the strategy re-loads the user and rejects the token if
its epoch is stale. Bumping ``user.session_epoch`` (on password change/reset) therefore
invalidates every previously-issued token for that user.
"""
from __future__ import annotations

import jwt
from fastapi_users import exceptions, models
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users.jwt import decode_jwt, generate_jwt
from fastapi_users.manager import BaseUserManager

from src.webapi.settings import get_settings

bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")


class EpochJWTStrategy(JWTStrategy):
    """JWTStrategy that binds a token to the user's ``session_epoch``."""

    async def write_token(self, user: models.UP) -> str:
        data = {
            "sub": str(user.id),
            "aud": self.token_audience,
            "epoch": int(getattr(user, "session_epoch", 0) or 0),
        }
        return generate_jwt(
            data, self.encode_key, self.lifetime_seconds, algorithm=self.algorithm
        )

    async def read_token(self, token, user_manager: BaseUserManager):
        if token is None:
            return None
        try:
            data = decode_jwt(
                token, self.decode_key, self.token_audience, algorithms=[self.algorithm]
            )
            user_id = data.get("sub")
            if user_id is None:
                return None
        except jwt.PyJWTError:
            return None
        try:
            parsed_id = user_manager.parse_id(user_id)
            user = await user_manager.get(parsed_id)
        except (exceptions.UserNotExists, exceptions.InvalidID):
            return None
        # Session invalidation: reject tokens issued before the user's current epoch.
        if int(data.get("epoch", 0) or 0) != int(getattr(user, "session_epoch", 0) or 0):
            return None
        return user


def get_jwt_strategy() -> EpochJWTStrategy:
    s = get_settings()
    return EpochJWTStrategy(secret=s.jwt_secret, lifetime_seconds=s.jwt_lifetime_seconds)


auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)
