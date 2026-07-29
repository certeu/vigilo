from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException

from src.webapi.auth.deps import require_admin
from src.webapi.models import ROLE_ADMIN, ROLE_USER, User


def _user(role: str) -> User:
    return User(id=uuid.uuid4(), email="u@x.eu", hashed_password="h",
                role=role, is_active=True, is_superuser=False, is_verified=True)


class TestRequireAdmin:
    def test_admin_allowed(self):
        u = _user(ROLE_ADMIN)
        assert require_admin(u) is u

    def test_user_forbidden(self):
        with pytest.raises(HTTPException) as ei:
            require_admin(_user(ROLE_USER))
        assert ei.value.status_code == 403
