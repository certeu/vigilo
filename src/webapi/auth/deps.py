"""FastAPIUsers instance + current-user / RBAC dependencies."""
from __future__ import annotations

import uuid

from fastapi import Depends, HTTPException, status
from fastapi_users import FastAPIUsers

from src.webapi.auth.backend import auth_backend
from src.webapi.auth.users import get_user_manager
from src.webapi.models import ROLE_ADMIN, User

fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

current_active_user = fastapi_users.current_user(active=True)


def require_admin(user: User = Depends(current_active_user)) -> User:
    if user.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin role required"
        )
    return user
