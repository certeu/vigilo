"""Per-user encrypted credentials. Secrets never leave the server."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.webapi.auth.deps import current_active_user
from src.webapi.db import get_async_session
from src.webapi.models import (
    ROLE_ADMIN,
    RUN_TERMINAL,
    Credential,
    Job,
    Repository,
    Run,
    RunSecret,
    User,
)
from src.webapi.schemas import CredentialCreate, CredentialRead
from src.webapi.security.vault import build_vault
from src.webapi.settings import get_settings

router = APIRouter(tags=["credentials"])


def _to_read(c: Credential) -> CredentialRead:
    return CredentialRead(
        id=c.id, kind=c.kind, label=c.label, forge_base_url=c.forge_base_url,
        gitlab_base_url=c.forge_base_url,
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
        secret_enc=vault.encrypt(payload.secret), forge_base_url=payload.forge_base_url,
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
    # Jobs that selected this cookie credential lose the reference (their runs go back
    # to unauthenticated testing) rather than blocking the deletion or pointing at
    # nothing. Runs already in flight keep the copy stored in their own run record
    # until they end.
    # In-flight runs that use this credential (as the job's cookie or the repository's
    # forge credential) lose their stored secret: deleting a credential revokes it now.
    active_runs = (
        select(Run.id)
        .join(Job, Job.id == Run.job_id)
        .join(Repository, Repository.id == Job.repository_id)
        .where(
            Run.status.notin_(tuple(RUN_TERMINAL)),
            or_(Job.target_credential_id == cred_id,
                Repository.default_credential_id == cred_id),
        )
    )
    await session.execute(delete(RunSecret).where(RunSecret.run_id.in_(active_runs)))
    await session.execute(
        update(Job).where(Job.target_credential_id == cred_id).values(target_credential_id=None)
    )
    await session.execute(
        update(Repository).where(Repository.default_credential_id == cred_id)
        .values(default_credential_id=None)
    )
    await session.delete(cred)
    await session.commit()
