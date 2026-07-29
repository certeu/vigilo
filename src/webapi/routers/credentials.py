"""Per-user encrypted credentials. Secrets never leave the server."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import ROLE_ADMIN, Credential, User
from src.webapi.schemas import CredentialCreate, CredentialRead
from src.webapi.security.vault import build_vault
from src.webapi.settings import get_settings

router = APIRouter(tags=["credentials"])


def _to_read(c: Credential) -> CredentialRead:
    return CredentialRead(
        id=c.id, kind=c.kind, label=c.label, gitlab_base_url=c.gitlab_base_url,
        created_at=c.created_at, has_secret=bool(c.secret_enc),
    )


@router.post("/credentials", response_model=CredentialRead,
             status_code=status.HTTP_201_CREATED)
async def create_credential(
    payload: CredentialCreate,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> CredentialRead:
    vault = build_vault(get_settings())
    cred = Credential(
        owner_id=user.id, kind=payload.kind, label=payload.label,
        secret_enc=vault.encrypt(payload.secret), gitlab_base_url=payload.gitlab_base_url,
    )
    session.add(cred)
    await session.commit()
    await session.refresh(cred)
    return _to_read(cred)


@router.get("/credentials", response_model=list[CredentialRead])
async def list_credentials(
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> list[CredentialRead]:
    rows = (await session.scalars(
        select(Credential).where(Credential.owner_id == user.id))).all()
    return [_to_read(c) for c in rows]


@router.delete("/credentials/{cred_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_credential(
    cred_id: uuid.UUID,
    user: User = Depends(current_active_user),
    session: AsyncSession = Depends(get_async_session),
) -> None:
    cred = await session.get(Credential, cred_id)
    if cred is None:
        return
    if cred.owner_id != user.id and user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Not your credential")
    await session.delete(cred)
    await session.commit()
